// Package applications inventories installed-app metadata without inferring usage
// or executing uninstall instructions.
package applications

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/platforms"
)

const maxApps = 10000

type app struct {
	name, version, location, source string
	size                            *int64
	sizeMethod                      string
	details                         findings.Application
}

func Collect(ctx context.Context, env findings.Environment) findings.Result {
	r := findings.Result{Feature: "applications", Support: "PARTIAL", Coverage: findings.Coverage{Status: "PARTIAL"}, Findings: []findings.Finding{}, Warnings: []string{}, Errors: []string{}, Observations: []string{}, CollectionMethod: "bounded read-only native package / app metadata inventory"}
	var apps []app
	switch env.OS {
	case "darwin":
		apps = macApps(ctx, &r)
	case "linux":
		apps = linuxApps(ctx, &r, platforms.Run, platforms.Tool)
	case "windows":
		apps = windowsApps(ctx, &r, platforms.Run)
	default:
		r.Support = "UNSUPPORTED"
		r.Coverage.Status = "UNSUPPORTED"
		r.Warnings = append(r.Warnings, "No application metadata collector for this OS.")
		return r
	}
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].source == apps[j].source {
			return apps[i].name < apps[j].name
		}
		return apps[i].source < apps[j].source
	})
	if len(apps) >= maxApps {
		r.Coverage.Skipped += len(apps) - maxApps
		apps = apps[:maxApps]
		r.Warnings = append(r.Warnings, "Inventory capped at 10000 entries.")
	}
	for _, a := range apps {
		r.Findings = append(r.Findings, appFinding(a, env.OS))
	}
	for i := range r.Findings {
		r.Findings[i].ID = fmt.Sprintf("A-%06d", i+1)
	}
	r.Coverage.Visited = len(apps)
	if ctx.Err() != nil {
		r.Coverage.Status = "CANCELLED"
		r.Warnings = append(r.Warnings, "Cancelled; inventory is incomplete.")
	}
	r.Observations = append(r.Observations, "Last usage, installed time, running state, related services and dependencies are UNKNOWN unless explicitly populated; installed does not mean unused.")
	r.Warnings = append(r.Warnings, "Application metadata is a partial inventory, not a list of recommended uninstall targets. No usage tracking is collected.")
	r.Warnings = append(r.Warnings, env.Limitations...)
	return r
}
func appFinding(a app, osName string) findings.Finding {
	var version, location *string
	if a.version != "" {
		version = &a.version
	}
	paths := []string{}
	if a.location != "" {
		location = &a.location
		paths = append(paths, a.location)
	}
	method := "Use the package manager's official application details and uninstall documentation after checking dependencies; no uninstall command is generated."
	if osName == "darwin" {
		method = "Use the app vendor's official uninstall instructions or macOS application management; do not recursively remove bundles or related files."
	}
	if osName == "windows" {
		method = "Use Windows Settings > Apps > Installed apps; inspect the app's official uninstall flow and dependencies."
	}
	info := a.details
	info.Name, info.Version, info.Location, info.Source = a.name, version, location, a.source
	info.InstallSizeBytes, info.SizeMethod = a.size, a.sizeMethod
	if info.SizeStatus == "" {
		info.SizeStatus = "UNKNOWN"
		if a.size != nil {
			info.SizeStatus = "ESTIMATED"
		}
	}
	if info.AppRole == "" {
		info.AppRole = "UNKNOWN"
	}
	if info.UsageStatus == "" {
		info.UsageStatus = "UNKNOWN"
	}
	if info.UsageProvenance == "" {
		info.UsageProvenance = "UNKNOWN: no reliable last-launch telemetry collected"
	}
	if info.UsageReason == "" {
		info.UsageReason = "No supported usage-history collector for this inventory source; unknown does not mean unused."
	}
	if info.RunningReason == "" {
		info.RunningReason = "Running state was not collected for this inventory source."
	}
	info.RelatedServices = []string{}
	info.DependencyNotes = "UNKNOWN; bundle namespace/name similarities are review hints, not dependency proof. Consult the source package manager/vendor before manual uninstall."
	info.UninstallMethod = method
	risk, recommendation := "UNKNOWN", "INSPECT"
	if info.SystemApp != nil && *info.SystemApp {
		risk, recommendation = "PROTECTED", "DO_NOT_TOUCH"
	}
	evidence := []string{"Metadata source: " + a.source, "Size method: " + info.SizeMethod, "Usage source: " + info.UsageProvenance, "Usage interpretation: " + info.UsageReason, "Running evidence: " + info.RunningReason}
	if info.AppRole == "HELPER" || info.AppRole == "UNINSTALLER" {
		evidence = append(evidence, "Name-based component role hint: "+info.AppRole+"; review with its parent product rather than independently removing it.")
	}
	return findings.Finding{Feature: "applications", Title: a.name, Paths: paths, Risk: risk, Confidence: "MEDIUM", Recommendation: recommendation, WhyFlagged: "Installed application metadata for user review; activity and workflow needs require separate evidence.", Evidence: evidence, Limitations: []string{"Logical bundle size excludes external app data, caches and shared runtimes; it is not promised physical storage recovery.", "Inventory may include system libraries, dependencies and multiple package records.", "Unknown or old launch metadata does not establish disuse; filesystem modification time is not installation/update time.", "Related-app namespace hints are capped at 20 records and do not prove dependency. Measurements are not atomic snapshots."}, PossibleConsequences: "Uninstalling manually may remove tools needed by other applications, disrupt active work, require reinstallation or affect access to locally stored app data.", ManualInspection: "Review size completeness, launch-source limitations, running state and system/component role. Confirm data backup, workflow needs and the vendor's official uninstall process. " + method, Application: &info}
}

func macApps(ctx context.Context, r *findings.Result) []app {
	roots := []string{"/Applications", "/System/Applications"}
	if home, e := os.UserHomeDir(); e == nil {
		roots = append(roots, filepath.Join(home, "Applications"))
	}
	return macAppsFromRoots(ctx, r, roots, platforms.Run, time.Now())
}

func plistStrings(b []byte) map[string]string {
	out := map[string]string{}
	d := xml.NewDecoder(strings.NewReader(string(b)))
	key := ""
	depth := 0
	for {
		tok, e := d.Token()
		if e != nil {
			break
		}
		switch v := tok.(type) {
		case xml.StartElement:
			if v.Name.Local == "dict" {
				depth++
			}
			if depth != 1 {
				continue
			}
			if v.Name.Local == "key" {
				if d.DecodeElement(&key, &v) != nil {
					return out
				}
			}
			if v.Name.Local == "string" && key != "" {
				var value string
				if d.DecodeElement(&value, &v) != nil {
					return out
				}
				out[key] = value
				key = ""
			}
		case xml.EndElement:
			if v.Name.Local == "dict" {
				depth--
			}
		}
	}
	return out
}

type runner func(context.Context, string, ...string) ([]byte, error)

func linuxApps(ctx context.Context, r *findings.Result, run runner, tool func(string) string) []app {
	apps := []app{}
	found := false
	type probe struct {
		name  string
		args  []string
		parse func(string) []app
	}
	probes := []probe{
		{"dpkg-query", []string{"-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\t${Installed-Size}\n"}, parseDPKG},
		{"rpm", []string{"-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SIZE}\n"}, parseRPM},
		{"pacman", []string{"-Q"}, parsePacman},
		{"flatpak", []string{"list", "--app", "--columns=application,version,installation"}, parseFlatpak},
	}
	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		if tool(p.name) == "" {
			continue
		}
		found = true
		b, e := run(ctx, p.name, p.args...)
		if e != nil {
			r.Errors = append(r.Errors, p.name+" metadata probe failed or exceeded its budget.")
			continue
		}
		apps = append(apps, p.parse(string(b))...)
		if len(apps) >= maxApps {
			break
		}
	}
	if !found {
		r.Support = "UNSUPPORTED"
		r.Coverage.Status = "UNSUPPORTED"
		r.Warnings = append(r.Warnings, "No supported installed-package metadata tool found.")
	}
	r.Warnings = append(r.Warnings, "Linux inventory supports available dpkg/rpm/pacman/Flatpak metadata; Snap, AppImage and manual installs are not inventoried. Package records are not all standalone apps.")
	return apps
}
func parseDPKG(s string) []app {
	out := []app{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || !strings.HasPrefix(f[2], "ii") {
			continue
		}
		a := app{name: f[0], version: f[1], source: "dpkg", sizeMethod: "package metadata Installed-Size, KiB (logical estimate)"}
		if n, e := strconv.ParseInt(f[3], 10, 64); e == nil && n >= 0 && n < 1<<50 {
			size := n * 1024
			a.size = &size
		}
		out = append(out, a)
		if len(out) >= maxApps {
			break
		}
	}
	return out
}
func parseRPM(s string) []app {
	out := []app{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		a := app{name: f[0], version: f[1], source: "rpm", sizeMethod: "RPM SIZE metadata, bytes (logical estimate)"}
		if n, e := strconv.ParseInt(f[2], 10, 64); e == nil && n >= 0 {
			a.size = &n
		}
		out = append(out, a)
		if len(out) >= maxApps {
			break
		}
	}
	return out
}
func parsePacman(s string) []app {
	out := []app{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		out = append(out, app{name: f[0], version: f[1], source: "pacman", sizeMethod: "UNKNOWN: not measured"})
		if len(out) >= maxApps {
			break
		}
	}
	return out
}
func parseFlatpak(s string) []app {
	out := []app{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		out = append(out, app{name: f[0], version: f[1], source: "Flatpak", sizeMethod: "UNKNOWN: not measured"})
		if len(out) >= maxApps {
			break
		}
	}
	return out
}

func windowsApps(ctx context.Context, r *findings.Result, run runner) []app {
	// Registry uninstall entries are read as metadata. UninstallString is deliberately
	// not requested, displayed, interpreted or executed. Win32_Product is not used.
	script := `$ErrorActionPreference='Stop'; $paths=@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'); @(foreach ($p in $paths) { Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,InstallLocation,EstimatedSize }) | ConvertTo-Json -Compress`
	b, e := run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if e != nil {
		r.Errors = append(r.Errors, "Windows registry metadata probe failed or exceeded its budget.")
		return nil
	}
	apps, e := parseRegistry(b)
	if e != nil {
		r.Errors = append(r.Errors, "Windows registry metadata could not be parsed.")
	}
	r.Warnings = append(r.Warnings, "Windows inventory contains standard HKCU/HKLM uninstall metadata only; Store apps, portable apps, missing entries and registry duplicates may be absent or ambiguous.")
	return apps
}
func parseRegistry(b []byte) ([]app, error) {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		b = append(append([]byte("["), b...), ']')
	}

	var rows []struct {
		DisplayName, DisplayVersion, InstallLocation string
		EstimatedSize                                *int64
	}
	if e := json.Unmarshal(b, &rows); e != nil {
		return nil, e
	}
	out := []app{}
	for _, row := range rows {
		if row.DisplayName == "" {
			continue
		}
		a := app{name: row.DisplayName, version: row.DisplayVersion, location: row.InstallLocation, source: "Windows registry uninstall metadata", sizeMethod: "UNKNOWN: not measured"}
		if row.EstimatedSize != nil && *row.EstimatedSize >= 0 && *row.EstimatedSize < 1<<50 {
			n := *row.EstimatedSize * 1024
			a.size = &n
			a.sizeMethod = "registry EstimatedSize KiB (vendor estimate)"
		}
		out = append(out, a)
		if len(out) >= maxApps {
			break
		}
	}
	return out, nil
}
