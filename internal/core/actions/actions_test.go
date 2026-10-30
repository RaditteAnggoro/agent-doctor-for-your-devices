package actions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/testkit"
)

func actionFixture(t *testing.T) (findings.Report, string) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native Trash execution unsupported on this OS")
	}
	dir := testkit.Dir(t)
	path := testkit.File(t, dir, "old ; harmless.tmp", "synthetic data only")
	st, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	dev, id, hard, sparse := safety.Identity(st)
	return findings.Report{SchemaVersion: "1.0", ScanID: "synthetic-action", Timestamp: time.Now().UTC().Add(-time.Minute), Environment: findings.Environment{OS: runtime.GOOS, Type: "native"}, Scope: findings.Scope{Roots: []string{dir}}, Results: []findings.Result{{Feature: "junk", Findings: []findings.Finding{{ID: "J-000001", Feature: "junk", PossibleConsequences: "Synthetic retention review", Junk: &findings.Junk{File: findings.File{Path: path, Size: st.Size(), Modified: st.ModTime(), Device: dev, Identity: id, Hardlink: &hard, Sparse: sparse}}}}}}}, path
}
func makePlan(t *testing.T, r findings.Report, path string) Plan {
	t.Helper()
	p, e := Build(context.Background(), r, "J-000001", Options{Target: path, Action: "trash", BackupReviewed: true, MaxReadBytes: 1 << 20}, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	return p
}

type fakeBackend struct {
	calls     int
	dest      string
	err       error
	available error
}

func (b *fakeBackend) Available() error { return b.available }
func (b *fakeBackend) Trash(_ context.Context, f Fingerprint) (string, error) {
	b.calls++
	if b.err != nil {
		return "", b.err
	}
	if e := os.Rename(f.Path, b.dest); e != nil {
		return "", e
	}
	return b.dest, nil
}

func TestPlanIsReadOnlyAndExactApprovalRequired(t *testing.T) {
	r, path := actionFixture(t)
	p := makePlan(t, r, path)
	if _, e := os.Stat(path); e != nil {
		t.Fatal("plan changed source", e)
	}
	if p.ApprovalHash == "" || p.Target.SHA256 == "" || p.Target.LogicalBytes != int64(len("synthetic data only")) || len(p.Consequences) < 2 {
		t.Fatal(p)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var saved Plan
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	p = saved
	b := &fakeBackend{dest: filepath.Join(testkit.Dir(t), "restorable.tmp")}
	journal := false
	if _, e := Execute(context.Background(), p, r, "wrong", b, func(Outcome) error { journal = true; return nil }); e == nil || b.calls != 0 || journal {
		t.Fatal("unapproved action dispatched")
	}
	out, e := Execute(context.Background(), p, r, p.ApprovalHash, b, func(o Outcome) error {
		journal = true
		if o.Status != "STARTED" {
			t.Fatal(o)
		}
		return nil
	})
	if e != nil || out.Status != "COMPLETED" || out.FilesTrashed != 1 || out.PermanentDeletions != 0 || !journal || b.calls != 1 {
		t.Fatal(out, e)
	}
	if data, e := os.ReadFile(b.dest); e != nil || string(data) != "synthetic data only" {
		t.Fatal("fake Trash lost data", e)
	}
}
func TestTamperExpiryAndChangedContentFailClosed(t *testing.T) {
	r, path := actionFixture(t)
	p := makePlan(t, r, path)
	edited := p
	edited.Target.Path = path + "other"
	if e := Validate(edited, time.Now()); e == nil {
		t.Fatal("edited plan accepted")
	}
	if e := Validate(p, p.Expires); e == nil {
		t.Fatal("expired plan accepted")
	}
	st, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	// Same length and restored mtime must still fail the content fingerprint.
	if e := os.WriteFile(path, []byte("different contents"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chtimes(path, st.ModTime(), st.ModTime()); e != nil {
		t.Fatal(e)
	}
	b := &fakeBackend{}
	if _, e := Execute(context.Background(), p, r, p.ApprovalHash, b, func(Outcome) error { return nil }); e == nil || b.calls != 0 {
		t.Fatal("changed file dispatched")
	}
}
func TestJournalFailureAndUnknownNativeResult(t *testing.T) {
	r, path := actionFixture(t)
	p := makePlan(t, r, path)
	b := &fakeBackend{}
	if _, e := Execute(context.Background(), p, r, p.ApprovalHash, b, func(Outcome) error { return errors.New("disk full") }); e == nil || b.calls != 0 {
		t.Fatal("unrecorded action dispatched")
	}
	b.err = errors.New("native timeout")
	out, e := Execute(context.Background(), p, r, p.ApprovalHash, b, func(Outcome) error { return nil })
	if e != nil || out.Status != "UNKNOWN" || out.FilesTrashed != 0 || b.calls != 1 {
		t.Fatal(out, e)
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal("unknown outcome test changed data")
	}
}
func TestBlockedPathsLimitsAndOldScans(t *testing.T) {
	r, path := actionFixture(t)
	for _, change := range []func(*findings.Report, *Options){
		func(r *findings.Report, o *Options) { o.BackupReviewed = false },
		func(r *findings.Report, o *Options) { r.Timestamp = time.Now().Add(-25 * time.Hour) },
		func(r *findings.Report, o *Options) { r.Environment.Type = "container" },
		func(r *findings.Report, o *Options) { o.Target = filepath.Join(filepath.Dir(path), "not-in-scan") },
		func(r *findings.Report, o *Options) { o.MaxReadBytes = 1 },
	} {
		rr := r
		o := Options{Target: path, Action: "trash", BackupReviewed: true, MaxReadBytes: 1 << 20}
		change(&rr, &o)
		if _, e := Build(context.Background(), rr, "J-000001", o, time.Now()); e == nil {
			t.Fatal("unsafe plan accepted", o)
		}
	}
	for _, p := range []string{"/synthetic/.ssh/key", "/synthetic/OneDrive/file", "/synthetic/public/uploads/file", "/synthetic/backups/file"} {
		if e := filePolicy(p); e == nil {
			t.Fatal("unsafe file policy", p)
		}
	}
	if runtime.GOOS != "windows" {
		if e := os.Chmod(filepath.Dir(path), 0777); e != nil {
			t.Fatal(e)
		}
		defer os.Chmod(filepath.Dir(path), 0700)
		if _, e := Build(context.Background(), r, "J-000001", Options{Target: path, Action: "trash", BackupReviewed: true, MaxReadBytes: 1000}, time.Now()); e == nil {
			t.Fatal("untrusted parent accepted")
		}
	}
}
func TestDuplicatePlanMustRetainDistinctVerifiedMember(t *testing.T) {
	r, path := actionFixture(t)
	copyPath := testkit.File(t, filepath.Dir(path), "copy.tmp", "synthetic data only")
	base := r.Results[0].Findings[0].Junk.File
	st, _ := os.Stat(copyPath)
	dev, id, hard, sparse := safety.Identity(st)
	other := findings.File{Path: copyPath, Size: st.Size(), Modified: st.ModTime(), Device: dev, Identity: id, Hardlink: &hard, Sparse: sparse}
	fp, e := fingerprint(context.Background(), path, filepath.Dir(path), false, 1000)
	if e != nil {
		t.Fatal(e)
	}
	r.Results[0].Findings = []findings.Finding{{ID: "D-000001", Feature: "duplicates", Duplicate: &findings.Duplicate{MatchType: "EXACT_CONTENT", HashAlgorithm: "SHA-256", Digest: fp.SHA256, Members: []findings.File{base, other}}}}
	o := Options{Target: path, Action: "trash", BackupReviewed: true, MaxReadBytes: 1000}
	if _, e := Build(context.Background(), r, "D-000001", o, time.Now()); e == nil {
		t.Fatal("duplicate without retained copy accepted")
	}
	o.Retain = copyPath
	p, e := Build(context.Background(), r, "D-000001", o, time.Now())
	if e != nil || p.Retain == nil {
		t.Fatal(p, e)
	}
	if e := os.Remove(copyPath); e != nil {
		t.Fatal(e)
	} // synthetic fixture only
	b := &fakeBackend{}
	if _, e := Execute(context.Background(), p, r, p.ApprovalHash, b, func(Outcome) error { return nil }); e == nil || b.calls != 0 {
		t.Fatal("lost retained copy ignored")
	}
}
func TestAppPolicyAndBundleTreeRevalidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file identity required")
	}
	dir := testkit.Dir(t)
	app := filepath.Join(dir, "Synthetic.app")
	testkit.File(t, app, "Contents/Info.plist", "synthetic")
	testkit.File(t, app, "Contents/Resources/data", "before")
	if e := appPolicy(app); e != nil {
		t.Fatal(e)
	}
	before, e := fingerprint(context.Background(), app, dir, true, 1000)
	if e != nil {
		t.Fatal(e)
	}
	dataPath := filepath.Join(app, "Contents/Resources/data")
	info, _ := os.Stat(dataPath)
	testkit.File(t, app, "Contents/Resources/data", "edited")
	if err := os.Chtimes(dataPath, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, e := fingerprint(context.Background(), app, dir, true, 1000)
	if e != nil || after.SHA256 == before.SHA256 {
		t.Fatal("bundle child mutation not detected", e)
	}
	if e := os.MkdirAll(filepath.Join(app, "Contents/Library/SystemExtensions"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := appPolicy(app); e == nil {
		t.Fatal("integrated app accepted")
	}
}

// Opt-in local smoke: only created synthetic files/directories enter native Trash,
// and each is restored immediately. Ordinary CI never touches a real user's Trash.
func TestNativeTrashAndRestoreSynthetic(t *testing.T) {
	if os.Getenv("AGENT_DOCTOR_NATIVE_TRASH_TEST") != "1" || runtime.GOOS != "darwin" {
		t.Skip("opt-in native macOS integration")
	}
	for _, directory := range []bool{false, true} {
		dir := testkit.Dir(t)
		path := testkit.File(t, dir, "agent-doctor-synthetic-"+filepath.Base(filepath.Dir(dir))+" ' ; test.tmp", "synthetic native Trash verification")
		if directory {
			path = filepath.Join(dir, "Synthetic.app")
			testkit.File(t, path, "Contents/Info.plist", "synthetic app metadata")
		}
		f, e := fingerprint(context.Background(), path, dir, directory, 1000)
		if e != nil {
			t.Fatal(e)
		}
		dest, e := Native().Trash(context.Background(), f)
		if e != nil {
			t.Fatal("native Trash returned", e)
		}
		// Restore exactly this known synthetic artifact; never clear or enumerate Trash.
		defer func() {
			if _, e := os.Stat(dest); e == nil {
				if e := os.Rename(dest, path); e != nil {
					t.Errorf("synthetic fixture needs manual restore from %q to %q: %v", dest, path, e)
				}
			}
		}()
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("source still exists", e)
		}
		if e := os.Rename(dest, path); e != nil {
			t.Fatalf("restore synthetic fixture from %q: %v", dest, e)
		}
	}
}

func TestCancellationAfterJournalDoesNotDispatch(t *testing.T) {
	r, path := actionFixture(t)
	p := makePlan(t, r, path)
	b := &fakeBackend{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, e := Execute(ctx, p, r, p.ApprovalHash, b, func(Outcome) error { cancel(); return nil })
	if e != nil || out.Status != "NOT_DISPATCHED" || b.calls != 0 {
		t.Fatal(out, e)
	}
}
func TestBundleHashHonorsReadBudget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file identities required")
	}
	dir := testkit.Dir(t)
	path := filepath.Join(dir, "Synthetic.app")
	testkit.File(t, path, "Contents/Info.plist", "synthetic contents")
	if _, e := fingerprint(context.Background(), path, dir, true, 1); e == nil {
		t.Fatal("bundle fingerprint ignored read limit")
	}
}
