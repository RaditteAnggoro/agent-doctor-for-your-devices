package session

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "sessions")
	return NewStore(dir), dir
}
func testReport() findings.Report {
	return findings.Report{SchemaVersion: "1.0", ScanID: "test-scan-001", Results: []findings.Result{{Feature: "junk", Findings: []findings.Finding{{ID: "J-000001", Feature: "junk"}}}}}
}

func TestSaveReviewCancelRoundTrip(t *testing.T) {
	s, dir := newTestStore(t)
	r := testReport()
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(r); err == nil {
		t.Fatal("overwrote immutable scan")
	}
	loaded, err := s.Load(r.ScanID)
	if err != nil || loaded.ScanID != r.ScanID {
		t.Fatalf("load: %v", err)
	}
	ids, err := s.List()
	if err != nil || len(ids) != 1 || ids[0] != r.ScanID {
		t.Fatalf("list: %v %v", ids, err)
	}
	for _, decision := range []string{"keep", "review-later", "skip", "mark-reviewed"} {
		if err := s.Review(r.ScanID, "J-000001", decision, "synthetic note"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Review(r.ScanID, "J-000001", "maybe", ""); err == nil {
		t.Fatal("ambiguous review accepted")
	}
	if err := s.Review(r.ScanID, "J-000002", "keep", ""); err == nil {
		t.Fatal("unknown finding accepted")
	}
	state, err := s.State(r.ScanID)
	if err != nil || state.Decisions["J-000001"].Decision != "mark-reviewed" {
		t.Fatalf("state: %+v %v", state, err)
	}
	if err := s.Cancel(r.ScanID); err != nil {
		t.Fatal(err)
	}
	state, err = s.State(r.ScanID)
	if err != nil || state.Status != "CANCELLED" {
		t.Fatal(state, err)
	}
	if err := s.Review(r.ScanID, "J-000001", "keep", ""); err == nil {
		t.Fatal("review resumed cancelled session")
	}
	if _, err := s.Load(r.ScanID); err != nil {
		t.Fatal("cancel destroyed report", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("directory privacy", err)
		}
		info, err = os.Stat(filepath.Join(dir, r.ScanID+".json"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("file privacy", err)
		}
	}
}

func TestRejectEscapesLinksAndSpecialFiles(t *testing.T) {
	s, dir := newTestStore(t)
	for _, id := range []string{"../escape", "..", "/absolute", "bad/name", "bad\\name", "", "nul\x00", "test.json"} {
		if _, err := s.Load(id); err == nil {
			t.Errorf("invalid ID %q accepted", id)
		}
	}
	if err := s.Save(testReport()); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(dir), "outside")
	if err := os.WriteFile(outside, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Log("symlink privilege unavailable; remaining checks still run")
		} else {
			t.Fatal(err)
		}
	} else {
		if _, err := s.Load("linked"); err == nil {
			t.Fatal("read linked session")
		}
	}
	linkedDir := filepath.Join(filepath.Dir(dir), "alias")
	if err := os.Symlink(dir, linkedDir); err == nil {
		if _, err := NewStore(linkedDir).List(); err == nil {
			t.Fatal("linked session directory accepted")
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "directory.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("directory"); err == nil {
		t.Fatal("directory loaded as JSON")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "sentinel" {
		t.Fatal("external sentinel changed")
	}
}

func TestConcurrentSaveDoesNotReplaceScan(t *testing.T) {
	s, _ := newTestStore(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Go(func() { results <- s.Save(testReport()) })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful immutable writes = %d", success)
	}
}

func TestPermissionsAndMalformedData(t *testing.T) {
	s, dir := newTestStore(t)
	if err := s.Save(testReport()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(path, []byte(`{"scan_id":"malformed"} trailing`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("malformed"); err == nil {
		t.Fatal("trailing data accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := s.List(); err == nil {
			t.Fatal("public storage accepted")
		}
	}
}
