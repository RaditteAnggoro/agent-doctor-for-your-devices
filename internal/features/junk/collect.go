package junk

import (
	"fmt"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/scanner"
	"path/filepath"
	"strings"
	"time"
)

func Collect(inv *scanner.Inventory, now time.Time) findings.Result {
	r := findings.Result{Feature: "junk", Support: "SUPPORTED", Coverage: inv.Coverage, Findings: []findings.Finding{}, Warnings: inv.Warnings, CollectionMethod: "bounded metadata walk; category and modification age; no file content reads"}
	for _, e := range inv.Entries {
		p := strings.ToLower(filepath.ToSlash(e.File.Path))
		name := strings.ToLower(filepath.Base(p))
		cat := ""
		risk := "MODERATE"
		switch {
		case strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".temp"):
			cat = "temporary_file"
		case strings.HasSuffix(name, ".dmg") || strings.HasSuffix(name, ".pkg") || strings.HasSuffix(name, ".msi"):
			cat = "installer"
		case strings.Contains(p, "/.cache/") || strings.Contains(p, "/caches/"):
			cat = "user_cache"
		case strings.HasSuffix(name, ".log"):
			cat = "log"
		}
		// Age alone never establishes junk. A recognized category AND age produces
		// a review candidate, retaining explicit uncertainty about active use.
		if cat == "" || now.Sub(e.File.Modified) < 30*24*time.Hour {
			continue
		}
		r.Findings = append(r.Findings, findings.Finding{ID: fmt.Sprintf("J-%06d", len(r.Findings)+1), Feature: "junk", Title: "Manual review: " + cat, Paths: []string{e.File.Path}, Risk: risk, Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Recognized file category with modification time older than 30 days; not evidence that removal is safe.", Evidence: []string{"Category: " + cat, "Modification age exceeds 30 days", fmt.Sprintf("Logical bytes: %d", e.File.Size)}, Limitations: []string{"Active use, ownership by an app, backup status and reliable access time are unknown.", "Content was not opened. Cloud detection uses conservative known path names and is not exhaustive."}, PossibleConsequences: "Removal could lose diagnostic history, offline installers or cached work and require downloads or rebuilding.", ManualInspection: "Reveal the containing folder, check the owning application and backup needs, then decide manually. Keep the file if uncertain.", Junk: &findings.Junk{File: e.File, Basename: filepath.Base(e.File.Path), Kind: "file", Category: cat, ActiveUseHints: []string{"UNKNOWN: ask whether the file or owning app is in active use"}, ReviewStatus: "REVIEW_WITH_CAUTION"}})
	}
	if r.Coverage.Status != "COMPLETED" {
		r.Support = "PARTIAL"
	}
	return r
}
