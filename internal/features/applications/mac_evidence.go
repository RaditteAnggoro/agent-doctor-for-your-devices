package applications

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/platforms"
)

const (
	maxBundleEntries    = 10000
	maxAllBundleEntries = 50000
	maxBundleDepth      = 48
)

type sizeBudget struct{ remaining int }
type sizeMeasurement struct {
	bytes        int64
	entries      int
	status       string
	limitations  []string
	symlinks     int
	inaccessible int
}

// measureBundle reads directory entries and stat metadata only. It deliberately
// does not open regular-file contents, follow symlinks or cross device boundaries.
func measureBundle(ctx context.Context, root *os.Root, budget *sizeBudget) sizeMeasurement {
	result := sizeMeasurement{status: "COMPLETED", limitations: []string{}}
	before, err := root.Stat(".")
	if err != nil {
		return sizeMeasurement{status: "UNKNOWN", limitations: []string{"Bundle metadata inaccessible."}}
	}
	device, _, _, _ := safety.Identity(before)
	if device == "" {
		return sizeMeasurement{status: "UNKNOWN", limitations: []string{"File identity is unavailable on this platform; a unique logical bundle footprint cannot be measured."}}
	}
	seen := map[string]bool{}
	note := func(msg string) {
		result.status = "PARTIAL"
		for _, s := range result.limitations {
			if s == msg {
				return
			}
		}
		result.limitations = append(result.limitations, msg)
	}
	var walk func(string, int)
	walk = func(rel string, depth int) {
		if ctx.Err() != nil {
			note("Shared bundle measurement time budget or cancellation reached; measured bytes are a lower bound.")
			return
		}
		if result.entries >= maxBundleEntries || budget.remaining <= 0 {
			note("Bundle or shared entry budget reached; measured bytes are a lower bound.")
			return
		}
		st, e := root.Lstat(rel)
		if e != nil || !st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			note("Directory inaccessible or changed into a link; measured bytes are a lower bound.")
			return
		}
		dir, e := root.Open(rel)
		if e != nil {
			note("Directory inaccessible; measured bytes are a lower bound.")
			return
		}
		defer dir.Close()
		opened, e := dir.Stat()
		if e != nil || !os.SameFile(st, opened) {
			note("Directory identity changed during measurement.")
			return
		}
		for {
			if ctx.Err() != nil {
				note("Shared bundle measurement time budget or cancellation reached; measured bytes are a lower bound.")
				return
			}
			entries, e := dir.ReadDir(100)
			for _, entry := range entries {
				if ctx.Err() != nil {
					note("Shared bundle measurement time budget or cancellation reached; measured bytes are a lower bound.")
					return
				}
				if result.entries >= maxBundleEntries || budget.remaining <= 0 {
					note("Bundle or shared entry budget reached; measured bytes are a lower bound.")
					return
				}
				result.entries++
				budget.remaining--
				child := filepath.Join(rel, entry.Name())
				info, err := root.Lstat(child)
				if err != nil {
					result.inaccessible++
					note("Some entries became inaccessible; measured bytes are a lower bound.")
					continue
				}
				if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
					result.symlinks++
					continue
				}
				dev, id, _, _ := safety.Identity(info)
				if device != "" && dev != device {
					note("Nested filesystem skipped; measured bytes are a lower bound.")
					continue
				}
				if info.IsDir() {
					if depth >= maxBundleDepth {
						note("Bundle depth limit reached; measured bytes are a lower bound.")
						continue
					}
					walk(child, depth+1)
					continue
				}
				if !info.Mode().IsRegular() {
					continue
				}
				if id != "" {
					if seen[id] {
						continue
					}
					seen[id] = true
				}
				// On platforms without file IDs, the portable measurement is conservative.
				if id == "" {
					note("File identity unavailable: hardlink deduplication cannot be established.")
				}
				if info.Size() < 0 || info.Size() > math.MaxInt64-result.bytes {
					note("Invalid or overflowing logical size excluded.")
					continue
				}
				result.bytes += info.Size()
			}
			if e == io.EOF {
				return
			}
			if e != nil {
				note("Directory enumeration failed; measured bytes are a lower bound.")
				return
			}
		}
	}
	walk(".", 0)
	// Symlinks are excluded by the definition of this regular-file measurement;
	// their targets may already be counted under their real version directories.
	if result.symlinks > 0 {
		result.limitations = append(result.limitations, fmt.Sprintf("%d symlink/irregular entries excluded from this defined regular-file footprint.", result.symlinks))
	}
	result.limitations = append(result.limitations, "Logical regular-file bytes only: symlinks and directory metadata excluded, hardlinks counted once when identity is available; external app data/caches and physical APFS allocation are not measured.")
	if result.status == "PARTIAL" && result.entries == 0 {
		result.status = "UNKNOWN"
	}
	return result
}

func macAppsFromRoots(ctx context.Context, r *findings.Result, roots []string, run runner, now time.Time) []app {
	apps := []app{}
	sizeCtx, cancelSize := context.WithTimeout(ctx, 8*time.Second)
	defer cancelSize()
	metadataCtx, cancelMetadata := context.WithTimeout(ctx, 8*time.Second)
	defer cancelMetadata()
	budget := &sizeBudget{remaining: maxAllBundleEntries}
	processOutput, processError := run(ctx, "ps", "-axo", "comm=")
	processes := strings.Split(string(processOutput), "\n")
	for _, dir := range roots {
		if ctx.Err() != nil {
			break
		}
		root, e := platforms.OpenMetadataDirectory(dir)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			r.Coverage.Inaccessible++
			r.Warnings = append(r.Warnings, "App metadata directory inaccessible or linked: "+dir)
			continue
		}
		directory, e := root.Open(".")
		if e != nil {
			root.Close()
			r.Coverage.Inaccessible++
			continue
		}
		for len(apps) < maxApps && ctx.Err() == nil {
			entries, e := directory.ReadDir(100)
			for _, entry := range entries {
				if len(apps) >= maxApps || ctx.Err() != nil {
					break
				}
				if !strings.HasSuffix(strings.ToLower(entry.Name()), ".app") || !entry.IsDir() || entry.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
					continue
				}
				expected, e := root.Lstat(entry.Name())
				if e != nil || !expected.IsDir() || expected.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
					r.Coverage.Inaccessible++
					continue
				}
				bundle, e := root.OpenRoot(entry.Name())
				if e != nil {
					r.Coverage.Inaccessible++
					continue
				}
				opened, e := bundle.Stat(".")
				if e != nil || !os.SameFile(expected, opened) {
					bundle.Close()
					r.Coverage.Inaccessible++
					continue
				}
				a := app{name: strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())), location: filepath.Join(dir, entry.Name()), source: "macOS app bundle"}
				a.details.BundleModifiedAt = ptrTime(opened.ModTime())
				system := strings.HasPrefix(filepath.Clean(a.location), "/System/Applications/")
				a.details.SystemApp = &system
				a.details.AppRole = roleHint(a.name)
				if values := readBundlePlist(bundle); len(values) > 0 {
					a.version = values["CFBundleShortVersionString"]
					if name := values["CFBundleDisplayName"]; name != "" {
						a.name = name
					}
					if id := values["CFBundleIdentifier"]; id != "" {
						a.details.BundleID = &id
					}
				}
				size := measureBundle(sizeCtx, bundle, budget)
				a.details.SizeStatus, a.details.SizeEntries, a.details.SizeLimitations = size.status, size.entries, size.limitations
				if size.status != "UNKNOWN" {
					a.size = &size.bytes
				}
				a.sizeMethod = "Sum of regular-file logical stat sizes in bundle; symlinks excluded, hardlinks counted once when file ID available; bounded to 10000 entries/bundle, 50000 entries/shared, depth 48 and 8s shared time. PARTIAL is a lower bound; no physical recovery estimate."
				bundle.Close()
				applyRunning(&a, processes, processError)
				if metadataCtx.Err() != nil {
					a.details.UsageStatus = "UNKNOWN"
					a.details.UsageProvenance = "Spotlight kMDItemLastUsedDate (not collected)"
					a.details.UsageReason = "Shared Spotlight metadata time budget reached; no usage conclusion."
				} else {
					probeCtx, cancel := context.WithTimeout(metadataCtx, 500*time.Millisecond)
					b, err := run(probeCtx, "mdls", "-name", "kMDItemLastUsedDate", "-name", "kMDItemVersion", "-name", "kMDItemCFBundleIdentifier", "--", a.location)
					cancel()
					applySpotlight(&a, b, err, now)
				}
				// Re-check the inventory path after native metadata collection. A changed
				// bundle cannot safely inherit measurements gathered under the old identity.
				after, err := root.Lstat(entry.Name())
				if err != nil || !os.SameFile(expected, after) || !after.ModTime().Equal(expected.ModTime()) {
					a.size = nil
					a.details.SizeStatus = "UNKNOWN"
					a.details.SizeLimitations = append(a.details.SizeLimitations, "Bundle identity or modification time changed during collection; rescan before review.")
					a.details.LastUsage = nil
					a.details.UsageStatus = "UNKNOWN"
					a.details.UsageReason = "Bundle changed during collection; Spotlight evidence was discarded."
					a.details.Running = nil
					a.details.RunningReason = "Bundle changed during collection; running association is unknown."
				}
				apps = append(apps, a)
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				r.Coverage.Inaccessible++
				r.Warnings = append(r.Warnings, "App directory enumeration was incomplete.")
				break
			}
		}
		directory.Close()
		root.Close()
	}
	attachRelatedHints(apps)
	r.Warnings = append(r.Warnings, "macOS inventory covers immediate .app children only. Sizes are bounded logical bundle footprints, excluding external app data and caches. Spotlight timestamps are LaunchServices open signals, not comprehensive usage history; missing values do not establish disuse.")
	return apps
}

func ptrTime(t time.Time) *time.Time { return &t }
func readBundlePlist(root *os.Root) map[string]string {
	// Reject link components before opening the rooted, bounded metadata file.
	for _, p := range []string{"Contents", filepath.Join("Contents", "Info.plist")} {
		st, e := root.Lstat(p)
		if e != nil || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil
		}
	}
	expected, e := root.Lstat(filepath.Join("Contents", "Info.plist"))
	if e != nil || !expected.Mode().IsRegular() {
		return nil
	}
	f, e := root.Open(filepath.Join("Contents", "Info.plist"))
	if e != nil {
		return nil
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || !os.SameFile(expected, st) {
		return nil
	}
	data, e := io.ReadAll(io.LimitReader(f, (256<<10)+1))
	if e != nil || len(data) > 256<<10 {
		return nil
	}
	after, e := f.Stat()
	if e != nil || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
		return nil
	}
	return plistStrings(data)
}
func roleHint(name string) string {
	n := strings.ToLower(name)
	if strings.Contains(n, "uninstaller") || strings.HasSuffix(n, " uninstall") {
		return "UNINSTALLER"
	}
	if strings.Contains(n, "helper") || strings.Contains(n, "systemextensions") || strings.Contains(n, "system extensions") {
		return "HELPER"
	}
	return "MAIN"
}
func applyRunning(a *app, processes []string, err error) {
	if err != nil {
		a.details.Running = nil
		a.details.RunningReason = "Process comm metadata unavailable; running state unknown."
		return
	}
	running := false
	for _, p := range processes {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, a.location+string(os.PathSeparator)) {
			running = true
			break
		}
	}
	a.details.Running = &running
	if running {
		a.details.RunningReason = "A visible process executable path was inside this bundle in the comm-only snapshot."
	} else {
		a.details.RunningReason = "No visible process executable path matched this bundle in one comm-only snapshot; detached helpers or permission-hidden processes may be missed."
	}
}
func applySpotlight(a *app, data []byte, err error, now time.Time) {
	a.details.LastUsage = nil
	a.details.UsageStatus = "UNKNOWN"
	a.details.UsageProvenance = "Spotlight kMDItemLastUsedDate: LaunchServices open signal, not complete activity history"
	if err != nil {
		a.details.UsageReason = "Spotlight metadata unavailable, inaccessible or timed out; no usage conclusion."
		return
	}
	values := spotlightValues(string(data))
	if a.version == "" {
		a.version = values["kMDItemVersion"]
	}
	if a.details.BundleID == nil {
		if id := values["kMDItemCFBundleIdentifier"]; id != "" {
			a.details.BundleID = &id
		}
	}
	raw := values["kMDItemLastUsedDate"]
	if raw == "" {
		a.details.UsageReason = "No last-used value in Spotlight (not indexed, excluded or never recorded); this is not proof the app was never used."
		return
	}
	used, e := time.Parse("2006-01-02 15:04:05 -0700", raw)
	if e != nil || used.IsZero() || used.After(now) {
		a.details.UsageReason = "Spotlight last-used value is invalid or in the future; timestamp omitted."
		return
	}
	a.details.LastUsage = &used
	a.details.UsageStatus = "AVAILABLE"
	a.details.UsageReason = "Last observed LaunchServices open metadata only. Activity after launch or launches outside LaunchServices may not update it; ask the user whether the app is still needed."
}
func spotlightValues(s string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "kMDItemLastUsedDate" && key != "kMDItemVersion" && key != "kMDItemCFBundleIdentifier" {
			continue
		}
		if value == "(null)" || value == "null" || value == "" {
			continue
		}
		if strings.HasPrefix(value, "\"") {
			unquoted, e := strconv.Unquote(value)
			if e != nil {
				continue
			}
			value = unquoted
		}
		values[key] = value
	}
	return values
}
func attachRelatedHints(apps []app) {
	groups := map[string][]int{}
	for i := range apps {
		if apps[i].details.BundleID != nil {
			if prefix := bundleNamespace(*apps[i].details.BundleID); prefix != "" {
				groups[prefix] = append(groups[prefix], i)
			}
		}
	}
	for i := range apps {
		if apps[i].details.BundleID == nil {
			continue
		}
		matches := groups[bundleNamespace(*apps[i].details.BundleID)]
		for _, j := range matches {
			if i == j {
				continue
			}
			if len(apps[i].details.RelatedApps) >= 20 {
				break
			}
			apps[i].details.RelatedApps = append(apps[i].details.RelatedApps, apps[j].name+" (shared bundle-ID namespace hint; dependency not proven)")
		}
		sort.Strings(apps[i].details.RelatedApps)
	}
}

func bundleNamespace(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:2], ".")
}
