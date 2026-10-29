// Package applications inventories installed-app metadata without inferring usage
// or executing uninstall instructions.
package applications

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/platforms"
)

const maxApps = 10000

type app struct {
	name, version, location, source string
	size                            *int64
	sizeMethod                      string
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
	return findings.Finding{Feature: "applications", Title: a.name, Paths: paths, Risk: "UNKNOWN", Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Installed metadata available for manual inventory review; no evidence that this application is unused.", Evidence: []string{"Metadata source: " + a.source, "Usage evidence: UNKNOWN; ask whether this app supports an active workflow."}, Limitations: []string{"Inventory may include system libraries, dependencies and multiple package records.", "Unknown usage is not evidence of disuse; related services and runtime dependencies were not inferred."}, PossibleConsequences: "Uninstalling manually may remove tools needed by other applications or disrupt active work.", ManualInspection: "Review the name, source and version, then ask whether the user recognizes and still needs it. " + method, Application: &findings.Application{Name: a.name, Version: version, Location: location, Source: a.source, InstallSizeBytes: a.size, SizeMethod: a.sizeMethod, UsageProvenance: "UNKNOWN: no reliable last-launch telemetry collected", RelatedServices: []string{}, DependencyNotes: "UNKNOWN; consult the source package manager/vendor before manual uninstall.", UninstallMethod: method}}
}

func macApps(ctx context.Context, r *findings.Result) []app {
	roots := []string{"/Applications", "/System/Applications"}
	if home, e := os.UserHomeDir(); e == nil {
		roots = append(roots, filepath.Join(home, "Applications"))
	}
	apps := []app{}
	for _, dir := range roots {
		if ctx.Err() != nil {
			break
		}
		st, e := os.Lstat(dir)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			r.Coverage.Inaccessible++
			r.Warnings = append(r.Warnings, "App metadata directory inaccessible or linked: "+dir)
			continue
		}
		root, e := platforms.OpenMetadataDirectory(dir)
		if e != nil {
			r.Coverage.Inaccessible++
			continue
		}
		f, e := root.Open(".")
		if e != nil {
			root.Close()
			continue
		}
		for len(apps) < maxApps && ctx.Err() == nil {
			entries, e := f.ReadDir(100)
			for _, entry := range entries {
				if len(apps) >= maxApps {
					break
				}
				if !strings.HasSuffix(strings.ToLower(entry.Name()), ".app") || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
					continue
				}
				a := app{name: strings.TrimSuffix(entry.Name(), ".app"), location: filepath.Join(dir, entry.Name()), source: "macOS app bundle", sizeMethod: "UNKNOWN: bundle footprint is not recursively measured"}
				// os.Root confines Info.plist reads even if a bundle changes after discovery.
				if info, err := root.Open(filepath.Join(entry.Name(), "Contents", "Info.plist")); err == nil {
					b, err := io.ReadAll(io.LimitReader(info, 256<<10+1))
					info.Close()
					if err == nil && len(b) <= 256<<10 {
						values := plistStrings(b)
						a.version = values["CFBundleShortVersionString"]
						if n := values["CFBundleDisplayName"]; n != "" {
							a.name = n
						}
					}
				}
				apps = append(apps, a)
			}
			if e != nil {
				break
			}
		}
		f.Close()
		root.Close()
	}
	r.Warnings = append(r.Warnings, "macOS inventory covers immediate .app children only. Nested apps, binary plist versions, app receipts, last use and bundle sizes may be unavailable.")
	return apps
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
