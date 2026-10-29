package safety_test

import (
	"context"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/scanner"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/features/duplicates"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/testkit"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func scope(dir string) findings.Scope {
	return findings.Scope{Roots: []string{dir}, MaxFiles: 100, MaxDepth: 12, MaxBytes: 1 << 20}
}
func TestScopeAndProtectedPaths(t *testing.T) {
	dir := testkit.Dir(t)
	for _, p := range []string{filepath.Join(dir, ".ssh"), filepath.Join(dir, ".env"), filepath.Join(dir, "secrets.pem"), filepath.Join(dir, "live.sqlite"), filepath.Join(dir, "OneDrive"), filepath.Join(dir, "Photos.photoslibrary"), dir + "/../escape", string(os.PathSeparator)} {
		if _, err := safety.Root(p); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
	if safety.Within(dir, dir+"-sibling") {
		t.Fatal("prefix escape")
	}
}
func TestExclusionsAndReadOnly(t *testing.T) {
	dir := testkit.Dir(t)
	a := testkit.File(t, dir, "hello space.txt", "identical")
	b := testkit.File(t, dir, "nested/日本語.txt", "identical")
	testkit.File(t, dir, "excluded/copy", "identical")
	testkit.File(t, dir, ".ssh/key", "identical")
	old := time.Unix(1600000000, 0)
	for _, p := range []string{a, b} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	sc := scope(dir)
	sc.Exclusions = []string{filepath.Join(dir, "excluded")}
	inv := scanner.Walk(context.Background(), sc)
	defer inv.Close()
	if len(inv.Entries) != 2 {
		t.Fatalf("unexpected entries: %v", inv.Entries)
	}
	r := duplicates.Collect(context.Background(), inv, sc.MaxBytes)
	if len(r.Findings) != 1 || len(r.Findings[0].Paths) != 2 {
		t.Fatalf("unexpected groups: %+v", r)
	}
	for _, p := range []string{a, b} {
		data, err := os.ReadFile(p)
		if err != nil || string(data) != "identical" {
			t.Fatal("source changed")
		}
		st, _ := os.Stat(p)
		if !st.ModTime().Equal(old) {
			t.Fatal("source modification time changed")
		}
	}
}
func TestLinksAndStaleIdentity(t *testing.T) {
	dir := testkit.Dir(t)
	outside := testkit.Dir(t)
	testkit.File(t, outside, "private.txt", "not scanned")
	a := testkit.File(t, dir, "a.txt", "same")
	testkit.File(t, dir, "b.txt", "same")
	if runtime.GOOS != "windows" {
		if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dir, filepath.Join(dir, "loop")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(a, filepath.Join(dir, "hardlink")); err != nil {
		if runtime.GOOS == "windows" {
			t.Log("hardlink fixture unavailable; link-count coverage is partial")
		} else {
			t.Fatal(err)
		}
	}
	inv := scanner.Walk(context.Background(), scope(dir))
	defer inv.Close()
	r := duplicates.Collect(context.Background(), inv, 1<<20)
	if len(r.Findings) != 1 || len(r.Findings[0].Paths) != 2 {
		t.Fatalf("links counted or scope escaped: %+v", r)
	}
	var entry scanner.Entry
	for _, e := range inv.Entries {
		if e.File.Path == a {
			entry = e
		}
	}
	if err := os.Rename(a, a+".original"); err != nil {
		t.Fatal(err)
	}
	testkit.File(t, dir, "a.txt", "same")
	if f, err := entry.Open(); err == nil {
		f.Close()
		t.Fatal("stale replaced file was accepted")
	}
}
func TestBudgetsAndCancellation(t *testing.T) {
	dir := testkit.Dir(t)
	testkit.File(t, dir, "a", "abcdef")
	testkit.File(t, dir, "b", "abcdef")
	testkit.File(t, dir, "deep/next/c", "x")
	sc := scope(dir)
	inv := scanner.Walk(context.Background(), sc)
	defer inv.Close()
	r := duplicates.Collect(context.Background(), inv, 5)
	if r.Coverage.Status != "PARTIAL" || len(r.Findings) != 0 || r.Coverage.BytesRead > 5 {
		t.Fatalf("budget escaped: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = duplicates.Collect(ctx, inv, 100)
	if r.Coverage.Status != "CANCELLED" {
		t.Fatal(r.Coverage)
	}
	sc.MaxFiles = 1
	limited := scanner.Walk(context.Background(), sc)
	defer limited.Close()
	if limited.Coverage.Status != "PARTIAL" || limited.Coverage.Visited > 1 {
		t.Fatal(limited.Coverage)
	}
	sc = scope(dir)
	sc.MaxDepth = 0
	limited = scanner.Walk(context.Background(), sc)
	defer limited.Close()
	if limited.Coverage.Status != "PARTIAL" {
		t.Fatal(limited.Coverage)
	}
}

func TestPermissionDeniedIsNotEmptySuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode fixture does not establish Windows ACL denial")
	}
	dir := testkit.Dir(t)
	denied := filepath.Join(dir, "denied")
	if err := os.Mkdir(denied, 0700); err != nil {
		t.Fatal(err)
	}
	testkit.File(t, denied, "private", "content")
	if err := os.Chmod(denied, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(denied, 0700)
	if f, err := os.Open(denied); err == nil {
		f.Close()
		t.Skip("current credentials bypass POSIX permission denial")
	}
	inv := scanner.Walk(context.Background(), scope(denied))
	defer inv.Close()
	if inv.Coverage.Status != "PERMISSION_DENIED" || inv.Coverage.Inaccessible == 0 {
		t.Fatalf("denial mislabeled: %+v", inv.Coverage)
	}
}
