// Package decision turns measured evidence into questions and review boundaries.
// It cannot approve, plan or execute deletion or uninstallation.
package decision

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
)

// Annotate enriches newly collected findings without modifying the source items
// or the caller's finding slice. Dates are interpreted against the scan timestamp.
func Annotate(result findings.Result, at time.Time) findings.Result {
	result.Findings = append([]findings.Finding(nil), result.Findings...)
	for i := range result.Findings {
		f := &result.Findings[i]
		d := &findings.Decision{State: "NEEDS_REVIEW", SuggestedChoice: "INSPECT", Reasons: []string{}, MissingEvidence: []string{}, ActionBlockers: []string{}, Questions: []string{}, NextSteps: []string{}}
		switch {
		case f.Application != nil:
			application(f, d, at)
		case f.Junk != nil:
			junk(f, d, at)
		case f.Duplicate != nil:
			duplicate(f, d)
		case f.Performance != nil:
			performance(f, d)
		default:
			d.MissingEvidence = append(d.MissingEvidence, "Feature-specific evidence is absent.")
		}
		if result.Coverage.Status != "COMPLETED" {
			d.MissingEvidence = append(d.MissingEvidence, "Collection coverage is "+result.Coverage.Status+"; this is a scoped observation, not a complete device assessment.")
		}
		d.ActionBlockers = append(d.ActionBlockers, "This read-only review is not execution approval. A later action requires exact targets, current identity checks, consequences and explicit user confirmation.")
		f.Decision = d
	}
	return result
}

func application(f *findings.Finding, d *findings.Decision, at time.Time) {
	a := f.Application
	d.ActionType = "MANUAL_UNINSTALL_REVIEW"
	d.Reasons = append(d.Reasons, "An installed application record is available; installation is not evidence of disuse.")
	if a.InstallSizeBytes == nil {
		d.MissingEvidence = append(d.MissingEvidence, "Application footprint unknown: "+known(a.SizeMethod, "not measured in this scan"))
	} else {
		d.Reasons = append(d.Reasons, fmt.Sprintf("Bundle/package logical size: %d bytes; method: %s; status: %s.", *a.InstallSizeBytes, known(a.SizeMethod, "unknown"), known(a.SizeStatus, "not recorded in this scan")))
		if a.SizeStatus == "COMPLETED" {
			n := *a.InstallSizeBytes
			d.PotentialLogicalBytes = &n
		} else {
			d.MissingEvidence = append(d.MissingEvidence, "A complete measured bundle footprint is unavailable; a partial total is a lower bound and package metadata may be an estimate.")
		}
	}
	if a.LastUsage == nil {
		d.MissingEvidence = append(d.MissingEvidence, "Last-use evidence unknown: "+known(a.UsageReason, a.UsageProvenance))
	} else if at.IsZero() || a.LastUsage.After(at) {
		d.MissingEvidence = append(d.MissingEvidence, "Last-use timestamp cannot be compared reliably to this observation.")
	} else {
		days := int64(at.Sub(*a.LastUsage).Hours() / 24)
		d.Reasons = append(d.Reasons, fmt.Sprintf("Last-used source signal: %s (%d days before scan), source: %s. Opening metadata is not a complete activity history.", a.LastUsage.UTC().Format(time.RFC3339), days, known(a.UsageProvenance, "source not recorded")))
	}
	if a.Running == nil {
		d.MissingEvidence = append(d.MissingEvidence, "Running state unknown: "+known(a.RunningReason, "not collected"))
	} else if *a.Running {
		d.Reasons = append(d.Reasons, "The application was observed running in the process snapshot.")
		d.ActionBlockers = append(d.ActionBlockers, "Save work and decide how to close the application before any future uninstall; no process will be stopped by this review.")
	} else {
		d.Reasons = append(d.Reasons, "No matching process was observed in the snapshot; this does not prove the application is unused.")
	}
	d.MissingEvidence = append(d.MissingEvidence, "Private app data, licenses, reliable installation time and actual dependency graph are not measured by the bundle inventory.")
	d.Questions = []string{"Do you still use this app, including occasional or offline work?", "Does another tool, browser extension, VPN or security workflow depend on it?", "Which documents, settings and licenses need backup or retention?"}
	d.NextSteps = []string{"Review the exact installation location, measured size and usage source.", "Check the vendor's official uninstall instructions; identify a dedicated uninstaller if required.", "Record keep, review-later, skip or mark-reviewed; choose exact app/data scope separately for a future phase."}
	if a.UninstallMethod != "" {
		d.NextSteps = append(d.NextSteps, a.UninstallMethod)
	}
	system := a.SystemApp != nil && *a.SystemApp
	if a.Location != nil && strings.HasPrefix(filepath.ToSlash(*a.Location), "/System/") {
		system = true
	}
	if system {
		d.State = "BLOCKED"
		d.SuggestedChoice = "KEEP"
		f.Risk = "PROTECTED"
		f.Recommendation = "DO_NOT_TOUCH"
		d.ActionBlockers = append(d.ActionBlockers, "System application: independent removal is outside this workflow; use OS-supported application management.")
	}
	if a.AppRole == "HELPER" || a.AppRole == "UNINSTALLER" {
		d.State = "BLOCKED"
		d.SuggestedChoice = "KEEP"
		d.ActionBlockers = append(d.ActionBlockers, "This record appears to be a helper or uninstaller. Review it with its parent product rather than removing the component independently.")
	}
	if len(a.RelatedApps) > 0 {
		d.Reasons = append(d.Reasons, "Related-app metadata hints exist; these are not proof of runtime dependencies.")
	}
}

func junk(f *findings.Finding, d *findings.Decision, at time.Time) {
	j := f.Junk
	d.ActionType = "MANUAL_FILE_REVIEW"
	d.Reasons = append(d.Reasons, fmt.Sprintf("Category %s; logical size %d bytes; modification time %s.", j.Category, j.File.Size, j.File.Modified.UTC().Format(time.RFC3339)))
	if !j.File.Modified.IsZero() && !at.IsZero() && !j.File.Modified.After(at) {
		d.Reasons = append(d.Reasons, fmt.Sprintf("%d days since modification; modification age is not last use.", int64(at.Sub(j.File.Modified).Hours()/24)))
	}
	d.MissingEvidence = []string{"Reliable last use and owning app activity are unknown.", "Backup/sync role and physical storage recovery are not established."}
	d.Questions = []string{"Is the file still needed for work, troubleshooting, restoration or offline use?", "Is this the only copy you need, and is a usable backup available?"}
	switch j.Category {
	case "installer":
		d.Questions = append(d.Questions, "Do you still need this specific installer/version for reinstalling or offline recovery?")
		d.Reasons = append(d.Reasons, "An installer file is separate from an installed app; removing this file would not uninstall the application.")
	case "user_cache":
		d.Questions = append(d.Questions, "Is the owning application or build active, and can you afford regeneration/download time?")
	case "log":
		d.Questions = append(d.Questions, "Is this log needed for an active support, audit or troubleshooting case?")
	}
	d.NextSteps = []string{"Inspect the exact path and its purpose, then record keep or review-later if uncertain.", "If later selected for file cleanup, review backup/sync propagation and an OS Trash recovery route before approving exact targets."}
	n := j.File.Size
	d.PotentialLogicalBytes = &n
	protectFile(j.File, d)
}

func duplicate(f *findings.Finding, d *findings.Decision) {
	g := f.Duplicate
	d.ActionType = "COMPARE_DUPLICATES"
	d.SuggestedChoice = "COMPARE_COPIES"
	d.Reasons = append(d.Reasons, fmt.Sprintf("%d members; %s / %s verification; logical redundant bytes %d.", len(g.Members), g.MatchType, g.HashAlgorithm, g.LogicalRedundantBytes))
	if g.MatchType != "EXACT_CONTENT" || g.HashAlgorithm != "SHA-256" || g.Digest == "" {
		d.State = "BLOCKED"
		d.ActionBlockers = append(d.ActionBlockers, "Exact full-content verification is absent; filename, size or visual similarity alone is insufficient.")
	}
	d.MissingEvidence = []string{"The purpose, external references and backup role of each copy are unknown.", "Physical storage recovery, clones and snapshot sharing are unknown."}
	d.Questions = []string{"Which exact path should remain available, and which applications or projects reference each copy?", "Are these intentional backups, exports or app-managed uploads?", "Has each proposed removal target been revalidated since this scan?"}
	d.NextSteps = []string{"Compare every member path, modification date, size and link flags.", "Choose a retained path explicitly; the displayed suggestion is only a neutral review starting point.", "Keep all app-managed or referenced copies until their owners and recovery requirements are established."}
	for _, member := range g.Members {
		protectFile(member, d)
		if managed(member.Path) {
			d.State = "BLOCKED"
			d.SuggestedChoice = "KEEP"
			d.ActionBlockers = appendUnique(d.ActionBlockers, "A path looks like project, backup or managed upload data. Establish references and retention requirements before considering any removal.")
		}
	}
	n := g.LogicalRedundantBytes
	d.PotentialLogicalBytes = &n
}

func performance(f *findings.Finding, d *findings.Decision) {
	p := f.Performance
	d.ActionType = "INVESTIGATE_PROCESS"
	d.State = "OBSERVE"
	d.SuggestedChoice = "OBSERVE_LONGER"
	d.Reasons = append(d.Reasons, "Resource measurements are observations, not proof of a persistent fault or a reason to uninstall an app.")
	if p.PID != nil {
		d.Reasons = append(d.Reasons, fmt.Sprintf("Process sampled for %.3f seconds; %s", p.ObservationSeconds, p.CPUSemantics))
		if p.ObservationSeconds < 1 {
			d.MissingEvidence = append(d.MissingEvidence, "The observation window is under one second; collect a longer sample before attributing sustained load.")
		}
		d.Questions = []string{"Is this process supporting work you are actively doing?", "Does the resource load persist after the current task finishes?"}
		d.ActionBlockers = append(d.ActionBlockers, "Process ownership, dependencies and unsaved work must be understood before any later manual process action.")
		if p.ProcessName != nil && strings.HasPrefix(*p.ProcessName, "/System/") {
			d.ActionBlockers = append(d.ActionBlockers, "This is a system component; keep it running while investigating application workload.")
		}
	} else if p.StartupSource != nil {
		d.Reasons = append(d.Reasons, "Startup metadata presence is observed; enablement and startup impact were not measured.")
		d.MissingEvidence = append(d.MissingEvidence, "Enabled/running state, parent-app ownership and dependencies are unknown.")
		d.Questions = []string{"Do you still need the parent application and its background features?"}
	} else {
		if p.MemoryPressureLevel == nil {
			d.MissingEvidence = append(d.MissingEvidence, "Memory pressure unknown: "+known(p.MemoryPressureReason, "not collected in this scan"))
		}
		if p.MemoryAvailableBytes == nil {
			d.MissingEvidence = append(d.MissingEvidence, "Available memory is unknown; free pages and total RAM alone do not establish memory pressure.")
		}
		if p.SwapUsedBytes == nil {
			d.MissingEvidence = append(d.MissingEvidence, "Swap usage was not measured.")
		}
		d.Questions = []string{"What slowdown or resource symptom are you observing, and during which workload?"}
	}
	d.NextSteps = []string{"Compare resource observations over a longer representative workload in the OS system monitor.", "Review dependencies and active work before choosing any manual action; this report stops no processes and changes no startup entries."}
}

func protectFile(f findings.File, d *findings.Decision) {
	if safety.Protected(f.Path) || f.Symlink || f.Cloud {
		d.State = "BLOCKED"
		d.SuggestedChoice = "DO_NOT_TOUCH"
		d.ActionBlockers = appendUnique(d.ActionBlockers, "Protected, linked or cloud-managed content requires a separate owner-aware review.")
	}
	if f.Hardlink == nil {
		d.MissingEvidence = appendUnique(d.MissingEvidence, "Hardlink count is unknown; logical copies do not establish physical recovery.")
	} else if *f.Hardlink {
		d.ActionBlockers = appendUnique(d.ActionBlockers, "Hardlinked storage may be shared; a directory entry is not an extra physical copy.")
	}
}
func managed(path string) bool {
	p := "/" + strings.ToLower(filepath.ToSlash(path)) + "/"
	for _, hint := range []string{"/public/uploads/", "/uploads/", "/node_modules/", "/src/", "/backup/", "/backups/", "/time machine/"} {
		if strings.Contains(p, hint) {
			return true
		}
	}
	return false
}
func known(value, fallback string) string {
	if value != "" {
		return value
	}
	if fallback != "" {
		return fallback
	}
	return "not available"
}
func appendUnique(a []string, s string) []string {
	for _, x := range a {
		if x == s {
			return a
		}
	}
	return append(a, s)
}
