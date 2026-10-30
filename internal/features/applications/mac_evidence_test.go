package applications

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
)

func canonicalTemp(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func writeFixture(t *testing.T, root, name, data string) string {
	t.Helper()
	p := filepath.Join(root, name)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func openFixture(t *testing.T, path string) *os.Root {
	t.Helper()
	r, e := os.OpenRoot(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestMacBundleEvidenceUsesOnlySyntheticMetadata(t *testing.T) {
	dir := canonicalTemp(t)
	location := filepath.Join(dir, "Example App.app")
	plist := `<plist><dict><key>CFBundleDisplayName</key><string>Example App</string><key>CFBundleIdentifier</key><string>com.example.primary</string><key>CFBundleShortVersionString</key><string>1.2.3</string></dict></plist>`
	writeFixture(t, location, "Contents/Info.plist", plist)
	writeFixture(t, location, "Contents/Resources/data.bin", "synthetic bytes")
	now := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)
	called := []string{}
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		called = append(called, name)
		if name == "ps" {
			if strings.Join(args, " ") != "-axo comm=" {
				t.Fatal("unexpected process fields", args)
			}
			return []byte(location + "/Contents/MacOS/example\n"), nil
		}
		if name != "mdls" || len(args) < 2 || args[len(args)-2] != "--" || args[len(args)-1] != location {
			t.Fatal("unexpected native invocation", name, args)
		}
		return []byte("kMDItemLastUsedDate = 2026-10-20 10:30:00 +0000\nkMDItemVersion = \"1.2.3\"\nkMDItemCFBundleIdentifier = \"com.example.primary\"\n"), nil
	}
	result := findings.Result{}
	apps := macAppsFromRoots(context.Background(), &result, []string{dir}, run, now)
	if len(apps) != 1 || len(called) != 2 {
		t.Fatalf("apps=%+v probes=%v", apps, called)
	}
	f := appFinding(apps[0], "darwin")
	a := f.Application
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		want := int64(len(plist) + len("synthetic bytes"))
		if a.InstallSizeBytes == nil || *a.InstallSizeBytes != want || a.SizeStatus != "COMPLETED" {
			t.Fatalf("wrong footprint: %+v", a)
		}
	} else if a.InstallSizeBytes != nil || a.SizeStatus != "UNKNOWN" {
		t.Fatalf("unknown identity presented as size: %+v", a)
	}
	if a.LastUsage == nil || a.LastUsage.Format(time.RFC3339) != "2026-10-20T10:30:00Z" || a.UsageStatus != "AVAILABLE" || !strings.Contains(a.UsageProvenance, "LaunchServices") {
		t.Fatalf("wrong launch evidence %+v", a)
	}
	if a.Running == nil || !*a.Running || a.BundleID == nil || *a.BundleID != "com.example.primary" || a.SystemApp == nil || *a.SystemApp || a.AppRole != "MAIN" {
		t.Fatalf("incomplete identity/runtime evidence %+v", a)
	}
	if a.InstalledAt != nil || a.UpdatedAt != nil || a.BundleModifiedAt == nil {
		t.Fatal("filesystem mtime confused with installation/update time")
	}
	if f.Recommendation != "INSPECT" || strings.Contains(f.WhyFlagged, "is unused") {
		t.Fatal("usage signal became uninstall claim")
	}
}

func TestFootprintExcludesSymlinksAndDeduplicatesHardlinks(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native macOS footprint requires Unix file identity")
	}
	dir := canonicalTemp(t)
	outside := canonicalTemp(t)
	p := writeFixture(t, dir, "one", "12345")
	writeFixture(t, outside, "secret", "long external data must not be counted")
	if e := os.Link(p, filepath.Join(dir, "hardlink")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(dir, "escape")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(dir, filepath.Join(dir, "cycle")); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0000); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(p, 0600)
	measured := measureBundle(context.Background(), openFixture(t, dir), &sizeBudget{remaining: 100})
	if measured.status != "COMPLETED" || measured.bytes != 5 || measured.symlinks != 2 {
		t.Fatalf("unsafe footprint %+v", measured)
	}
	if !strings.Contains(strings.Join(measured.limitations, " "), "symlink") {
		t.Fatal("missing scope limitation")
	}
}

func TestFootprintBudgetAndCancellationAreExplicit(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native macOS footprint requires Unix file identity")
	}
	dir := canonicalTemp(t)
	writeFixture(t, dir, "a", "123")
	writeFixture(t, dir, "b", "4567")
	root := openFixture(t, dir)
	budget := &sizeBudget{remaining: 1}
	partial := measureBundle(context.Background(), root, budget)
	if partial.status != "PARTIAL" || partial.entries != 1 || budget.remaining != 0 || partial.bytes > 7 {
		t.Fatalf("escaped budget %+v", partial)
	}
	unknown := measureBundle(context.Background(), root, budget)
	if unknown.status != "UNKNOWN" || unknown.entries != 0 {
		t.Fatalf("unmeasured treated as zero %+v", unknown)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := measureBundle(ctx, root, &sizeBudget{remaining: 100})
	if stopped.status != "UNKNOWN" || stopped.entries != 0 || !strings.Contains(strings.Join(stopped.limitations, " "), "cancellation") {
		t.Fatalf("ignored cancellation %+v", stopped)
	}
}

func TestUnknownOrFutureSpotlightDoesNotMeanUnused(t *testing.T) {
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		data string
		err  error
	}{{"kMDItemLastUsedDate = (null)", nil}, {"kMDItemLastUsedDate = 2099-01-01 00:00:00 +0000", nil}, {"kMDItemLastUsedDate = yesterday", nil}, {"", errors.New("denied")}} {
		old := now.Add(-time.Hour)
		a := app{details: findings.Application{LastUsage: &old}}
		applySpotlight(&a, []byte(tc.data), tc.err, now)
		if a.details.LastUsage != nil || a.details.UsageStatus != "UNKNOWN" || a.details.UsageReason == "" {
			t.Fatalf("invented or retained date %+v", a.details)
		}
	}
	a := app{}
	applySpotlight(&a, []byte("kMDItemVersion = \"9.0\"\nkMDItemCFBundleIdentifier = \"org.example.tool\"\nkMDItemLastUsedDate = (null)"), nil, now)
	if a.version != "9.0" || a.details.BundleID == nil {
		t.Fatal("Spotlight version fallback missing")
	}
}

func TestRunningPathBoundaryAndUnknownProbe(t *testing.T) {
	a := app{location: "/Applications/Example.app"}
	applyRunning(&a, []string{"/Applications/Example.app.other/Contents/MacOS/tool"}, nil)
	if a.details.Running == nil || *a.details.Running {
		t.Fatal("prefix sibling counted as running")
	}
	applyRunning(&a, []string{"/Applications/Example.app/Contents/MacOS/tool"}, nil)
	if a.details.Running == nil || !*a.details.Running {
		t.Fatal("bundle child not matched")
	}
	applyRunning(&a, nil, errors.New("timeout"))
	if a.details.Running != nil {
		t.Fatal("probe failure counted as stopped")
	}
}

func TestSystemAndComponentsCarryReviewWarnings(t *testing.T) {
	system := true
	f := appFinding(app{name: "System App", details: findings.Application{SystemApp: &system}}, "darwin")
	if f.Risk != "PROTECTED" || f.Recommendation != "DO_NOT_TOUCH" {
		t.Fatal("system app offered as ordinary uninstall candidate")
	}
	for name, want := range map[string]string{"Product Uninstaller": "UNINSTALLER", "Product Helper": "HELPER", "McAfeeSystemExtensions": "HELPER", "Example": "MAIN"} {
		if got := roleHint(name); got != want {
			t.Fatal(name, got, want)
		}
	}
	names := []app{}
	for i := 0; i < 30; i++ {
		id := "com.example.tool"
		names = append(names, app{name: "Tool", details: findings.Application{BundleID: &id}})
	}
	attachRelatedHints(names)
	if len(names[0].details.RelatedApps) != 20 || !strings.Contains(names[0].details.RelatedApps[0], "dependency not proven") {
		t.Fatal("unbounded or overconfident related hint")
	}
}

func TestReplacedBundleDiscardsStaleEvidence(t *testing.T) {
	dir := canonicalTemp(t)
	location := filepath.Join(dir, "Changed.app")
	writeFixture(t, location, "Contents/Info.plist", `<plist><dict/></plist>`)
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ps" {
			return nil, nil
		}
		if e := os.Rename(location, location+".old"); e != nil {
			t.Fatal(e)
		}
		writeFixture(t, location, "Contents/replacement", "other data")
		return []byte("kMDItemLastUsedDate = 2026-10-01 00:00:00 +0000"), nil
	}
	result := findings.Result{}
	apps := macAppsFromRoots(context.Background(), &result, []string{dir}, run, time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC))
	if len(apps) != 1 {
		t.Fatal(apps)
	}
	a := apps[0]
	if a.size != nil || a.details.LastUsage != nil || a.details.Running != nil || a.details.SizeStatus != "UNKNOWN" {
		t.Fatalf("stale evidence survived replacement %+v", a)
	}
}
