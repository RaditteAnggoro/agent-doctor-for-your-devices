package integration_test

import (
	"context"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/scanner"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/features/duplicates"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/features/junk"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/testkit"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFeatureEvidenceAndNoSizeOnlyClaims(t *testing.T) {
	dir := testkit.Dir(t)
	now := time.Now()
	old := now.Add(-90 * 24 * time.Hour)
	for _, n := range []string{"a/installer.dmg", "b/installer.dmg", "old-document.txt"} {
		p := testkit.File(t, dir, n, "1234")
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	testkit.File(t, dir, "c/same-size.txt", "9999")
	testkit.File(t, dir, "recent.tmp", "data")
	inv := scanner.Walk(context.Background(), findings.Scope{Roots: []string{dir}, MaxFiles: 100, MaxDepth: 10})
	defer inv.Close()
	j := junk.Collect(inv, now)
	if len(j.Findings) != 2 {
		t.Fatalf("age/size incorrectly qualifies junk: %+v", j)
	}
	for _, f := range j.Findings {
		if f.Junk == nil || f.Junk.ReclaimableBytes != nil || f.Recommendation != "INSPECT" {
			t.Fatal("unsafe junk conclusion")
		}
	}
	d := duplicates.Collect(context.Background(), inv, 1<<20)
	if len(d.Findings) != 1 || len(d.Findings[0].Paths) != 3 {
		t.Fatalf("exact content evidence missing: %+v", d)
	}
	for _, p := range d.Findings[0].Paths {
		if filepath.Base(p) == "same-size.txt" {
			t.Fatal("size-only duplicate")
		}
	}
	again := duplicates.Collect(context.Background(), inv, 1<<20)
	if again.Findings[0].ID != d.Findings[0].ID || again.Findings[0].Duplicate.Digest != d.Findings[0].Duplicate.Digest {
		t.Fatal("unstable classification")
	}
}
