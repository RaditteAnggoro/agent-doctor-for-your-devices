package decision

import (
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"strings"
	"testing"
	"time"
)

func str(s string) *string   { return &s }
func boolean(b bool) *bool   { return &b }
func integer(n int64) *int64 { return &n }
func result(f findings.Finding, at time.Time) findings.Finding {
	return Annotate(findings.Result{Coverage: findings.Coverage{Status: "COMPLETED"}, Findings: []findings.Finding{f}}, at).Findings[0]
}
func contains(a []string, needle string) bool { return strings.Contains(strings.Join(a, " "), needle) }
func TestApplicationUnknownsDoNotBecomeDisuse(t *testing.T) {
	at := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	f := result(findings.Finding{Feature: "applications", Application: &findings.Application{Name: "Editor", Location: str("/Applications/Editor.app"), UsageReason: "Spotlight not indexed", SizeMethod: "not measured"}}, at)
	if f.Decision.State != "NEEDS_REVIEW" || f.Decision.PotentialLogicalBytes != nil || !contains(f.Decision.MissingEvidence, "Spotlight not indexed") {
		t.Fatalf("unknown evidence lost: %+v", f.Decision)
	}
	if len(f.Decision.Questions) < 3 || len(f.Decision.ActionBlockers) == 0 {
		t.Fatal("missing review preparation")
	}
}
func TestApplicationMeasuredEvidenceStillRequiresUserChoice(t *testing.T) {
	at := time.Now()
	used := at.Add(-180 * 24 * time.Hour)
	f := result(findings.Finding{Feature: "applications", Recommendation: "INSPECT", Application: &findings.Application{Name: "App", Location: str("/Applications/App.app"), InstallSizeBytes: integer(2048), SizeStatus: "COMPLETED", SizeMethod: "bounded logical footprint", LastUsage: &used, UsageProvenance: "Spotlight last-used signal", Running: boolean(true)}}, at)
	if f.Decision.State != "NEEDS_REVIEW" || f.Decision.PotentialLogicalBytes == nil || *f.Decision.PotentialLogicalBytes != 2048 {
		t.Fatal(f.Decision)
	}
	if !contains(f.Decision.Reasons, "180 days") || !contains(f.Decision.ActionBlockers, "Save work") {
		t.Fatal("evidence or running caution missing")
	}
	f.Application.SizeStatus = "PARTIAL"
	f = result(f, at)
	if f.Decision.PotentialLogicalBytes != nil || !contains(f.Decision.MissingEvidence, "lower bound") {
		t.Fatal("partial size presented as full footprint")
	}
}
func TestSystemAndComponentAppsAreBlocked(t *testing.T) {
	for _, a := range []findings.Application{{Name: "System", Location: str("/System/Applications/System.app")}, {Name: "Helper", AppRole: "HELPER"}, {Name: "Uninstaller", AppRole: "UNINSTALLER"}} {
		f := result(findings.Finding{Feature: "applications", Application: &a}, time.Now())
		if f.Decision.State != "BLOCKED" || f.Decision.SuggestedChoice != "KEEP" {
			t.Fatalf("independent component removal not blocked: %+v", f)
		}
	}
}
func TestJunkDistinguishesInstallerFromInstalledApp(t *testing.T) {
	at := time.Now()
	f := result(findings.Finding{Feature: "junk", Junk: &findings.Junk{Category: "installer", File: findings.File{Path: "/synthetic/old.dmg", Size: 123, Modified: at.Add(-90 * 24 * time.Hour), Hardlink: boolean(false)}}}, at)
	if !contains(f.Decision.Reasons, "would not uninstall") || !contains(f.Decision.Reasons, "90 days") || f.Decision.PotentialLogicalBytes == nil {
		t.Fatal(f.Decision)
	}
	if f.Decision.State != "NEEDS_REVIEW" || len(f.Decision.Questions) < 3 {
		t.Fatal("age turned into action approval")
	}
}
func TestDuplicateCopyContextAndVerificationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		path, match string
		blocked     bool
	}{{"/synthetic/copy", "EXACT_CONTENT", false}, {"/synthetic/public/uploads/copy", "EXACT_CONTENT", true}, {"/synthetic/copy", "SIMILAR_IMAGE_REVIEW_ONLY", true}} {
		f := result(findings.Finding{Feature: "duplicates", Duplicate: &findings.Duplicate{MatchType: tc.match, HashAlgorithm: "SHA-256", Digest: strings.Repeat("a", 64), Members: []findings.File{{Path: tc.path, Hardlink: boolean(false)}, {Path: "/synthetic/second", Hardlink: boolean(false)}}, LogicalRedundantBytes: 20}}, time.Now())
		if (f.Decision.State == "BLOCKED") != tc.blocked {
			t.Fatal(tc, f.Decision)
		}
		if len(f.Decision.Questions) < 3 || !contains(f.Decision.MissingEvidence, "Physical storage") {
			t.Fatal("missing per-copy decision context")
		}
	}
}
func TestProtectedAndCloudFilesNeverBecomeRemovalCandidates(t *testing.T) {
	for _, file := range []findings.File{{Path: "/synthetic/.env"}, {Path: "/synthetic/synced", Cloud: true}, {Path: "/synthetic/linked", Symlink: true}} {
		f := result(findings.Finding{Feature: "junk", Junk: &findings.Junk{File: file}}, time.Now())
		if f.Decision.State != "BLOCKED" || f.Decision.SuggestedChoice != "DO_NOT_TOUCH" {
			t.Fatal(f.Decision)
		}
	}
}
func TestPerformanceNeedsContextAndLongEnoughSample(t *testing.T) {
	pid := 1
	f := result(findings.Finding{Feature: "performance", Performance: &findings.Performance{PID: &pid, ObservationSeconds: 0.2}}, time.Now())
	if f.Decision.State != "OBSERVE" || f.Decision.SuggestedChoice != "OBSERVE_LONGER" || !contains(f.Decision.MissingEvidence, "under one second") {
		t.Fatal(f.Decision)
	}
	f = result(findings.Finding{Feature: "performance", Performance: &findings.Performance{MemoryPressureReason: "No reliable source"}}, time.Now())
	if !contains(f.Decision.MissingEvidence, "No reliable source") || !contains(f.Decision.MissingEvidence, "Available memory") {
		t.Fatal(f.Decision)
	}
}
func TestPartialCoverageAndOriginalSlice(t *testing.T) {
	original := findings.Result{Coverage: findings.Coverage{Status: "PARTIAL"}, Findings: []findings.Finding{{Feature: "junk", Junk: &findings.Junk{}}}}
	enriched := Annotate(original, time.Now())
	if original.Findings[0].Decision != nil || !contains(enriched.Findings[0].Decision.MissingEvidence, "coverage is PARTIAL") {
		t.Fatal("mutated caller or omitted coverage")
	}
}
