// Package performance collects bounded metadata samples; it never stops processes.
package performance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/platforms"
)

type process struct {
	pid         int
	name, owner string
	rss         int64
	cpu         float64
}
type runner func(context.Context, string, ...string) ([]byte, error)

const DefaultSampleDuration = 3 * time.Second

func Collect(ctx context.Context, env findings.Environment) findings.Result {
	return CollectWithDuration(ctx, env, DefaultSampleDuration)
}

// CollectWithDuration compares process CPU counters over a bounded observation
// interval. It does not classify an application as unused or safe to stop.
func CollectWithDuration(ctx context.Context, env findings.Environment, duration time.Duration) findings.Result {
	r := findings.Result{Feature: "performance", Support: "PARTIAL", Coverage: findings.Coverage{Status: "PARTIAL"}, Findings: []findings.Finding{}, Warnings: []string{}, Errors: []string{}, Observations: []string{}, CollectionMethod: "bounded native metadata; two cumulative CPU samples; no process arguments"}
	if duration < time.Second || duration > 30*time.Second {
		r.Coverage.Status = "FAILED"
		r.Errors = append(r.Errors, "sample duration must be between 1s and 30s")
		return r
	}
	if ctx.Err() != nil {
		r.Coverage.Status = "CANCELLED"
		r.Warnings = append(r.Warnings, "Cancelled before collection.")
		return r
	}
	if env.OS != "darwin" && env.OS != "linux" && env.OS != "windows" {
		r.Support = "UNSUPPORTED"
		r.Coverage.Status = "UNSUPPORTED"
		r.Warnings = append(r.Warnings, "No performance adapter for this OS.")
		return r
	}
	procs, seconds, err := sampleFor(ctx, env.OS, platforms.Run, duration, waitFor)
	if err != nil {
		r.Errors = append(r.Errors, "Process samples unavailable: "+err.Error())
	}
	if ctx.Err() != nil {
		r.Coverage.Status = "CANCELLED"
		r.Warnings = append(r.Warnings, "Cancelled during sampling.")
		return r
	}
	sort.Slice(procs, func(i, j int) bool {
		if procs[i].rss == procs[j].rss {
			return procs[i].pid < procs[j].pid
		}
		return procs[i].rss > procs[j].rss
	})
	r.Coverage.Visited = len(procs)
	if len(procs) > 25 {
		r.Coverage.Skipped = len(procs) - 25
		procs = procs[:25]
		r.Warnings = append(r.Warnings, "Process report contains the 25 largest visible RSS/working-set samples only; it is not a complete ranking by CPU.")
	}
	for _, p := range procs {
		r.Findings = append(r.Findings, processFinding(p, seconds))
	}
	p := &findings.Performance{LogicalCPUs: runtime.NumCPU(), MemoryPressureReason: "Pressure classification is not collected by this adapter; free memory and swap amount alone do not establish pressure.", CPUSemantics: "Not applicable to system metadata.", ObservedImpact: "Capacity observations are not a diagnosis of workload health.", DependencyNotes: "System services and container limits may affect these observations."}
	if env.OS == "linux" {
		b, e := platforms.ReadSmall("/proc/meminfo", 64<<10)
		if e == nil {
			p.MemoryTotalBytes, p.MemoryAvailableBytes, p.SwapUsedBytes = parseMemory(string(b))
			p.MemoryFreeBytes = linuxMemoryField(string(b), "MemFree")
		}
	}
	if env.OS == "darwin" {
		r.Warnings = append(r.Warnings, collectDarwinMemory(ctx, p, platforms.Run)...)
		r.Observations = append(r.Observations, "macOS free bytes and compressor occupancy are page counts from vm_stat multiplied by its reported page size; free bytes are not available/reclaimable memory. Swap amount comes from sysctl vm.swapusage display units and may be rounded; it is not a swap rate.")
	}
	if env.OS == "windows" {
		if b, e := platforms.Run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress`); e == nil {
			total, available := parseWindowsMemory(b)
			p.MemoryTotalBytes = total
			p.MemoryAvailableBytes = available
			p.MemoryFreeBytes = available
		}
	}
	if cwd, e := os.Getwd(); e == nil {
		p.DiskTotalBytes, p.DiskAvailableBytes = platforms.Disk(cwd)
	}
	r.Findings = append(r.Findings, findings.Finding{Feature: "performance", Title: "System capacity in this execution environment", Risk: "UNKNOWN", Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Baseline capacity metadata for interpreting process samples.", Evidence: []string{"Nullable metrics are unmeasured, unsupported or inaccessible; disk capacity is the current working-directory filesystem only."}, Limitations: []string{"Memory pressure is not inferred from free memory or a swap amount; available memory, startup enablement and host-level metrics may be unavailable.", "Container /proc and filesystem values may reflect host-wide rather than cgroup limits; they are not ChromeOS or Windows host measurements."}, PossibleConsequences: "No settings or processes were changed.", ManualInspection: procedure(env.OS), Performance: p})
	startup(ctx, &r, env.OS)
	r.Observations = append(r.Observations, fmt.Sprintf("CPU samples separated by %.3f seconds; CPU is delta cumulative process time / actual elapsed time, 100%% = one logical core. Short/coarse native counters may show zero.", seconds), "Unknown app dependencies and a busy sample do not justify stopping a process.", "Logical CPU count describes the Go-visible execution environment, not guaranteed physical host capacity. Disk capacity covers the current working-directory filesystem only.")
	for i := range r.Findings {
		r.Findings[i].ID = fmt.Sprintf("P-%06d", i+1)
	}
	if len(env.Limitations) > 0 {
		r.Warnings = append(r.Warnings, env.Limitations...)
	}
	if ctx.Err() != nil {
		r.Coverage.Status = "CANCELLED"
		r.Warnings = append(r.Warnings, "Cancelled during system or startup metadata collection; retained findings are incomplete.")
	}
	return r
}

func processFinding(p process, seconds float64) findings.Finding {
	running := true
	return findings.Finding{Feature: "performance", Title: "Observed process: " + p.name, Risk: "UNKNOWN", Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Visible process resource sample; inclusion is not evidence of a persistent problem.", Evidence: []string{"Measured resident memory / Windows working set; cumulative CPU sampled twice; no command-line arguments collected."}, Limitations: []string{"Short observation window; shared memory can be counted in multiple RSS values.", "PID reuse, process exits and native counter resolution can limit CPU measurements."}, PossibleConsequences: "Stopping a process manually may interrupt work or dependent services.", ManualInspection: "Identify the owning app and whether it is in active use; observe it for longer before drawing conclusions. " + procedure(""), Performance: &findings.Performance{LogicalCPUs: runtime.NumCPU(), PID: &p.pid, ProcessName: &p.name, CPUPercent: &p.cpu, CPUSemantics: "100% = one logical core; delta cumulative CPU seconds / actual elapsed seconds. Counter precision is OS dependent.", RSSBytes: &p.rss, ObservationSeconds: seconds, Owner: &p.owner, Running: &running, DependencyNotes: "Unknown; ask the user before any manual process action.", ObservedImpact: "One short sample; no sustained problem established."}}
}

// waitFor is separate from counter collection so tests can control the wait
// boundary without sleeping or issuing real process probes.
func waitFor(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sampleFor(ctx context.Context, osName string, run runner, duration time.Duration, wait func(context.Context, time.Duration) error) ([]process, float64, error) {
	probe := func() ([]process, error) {
		if osName == "windows" {
			b, e := run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; @(Get-Process | Where-Object {$null -ne $_.CPU} | Select-Object Id,ProcessName,CPU,WorkingSet64) | ConvertTo-Json -Compress`)
			if e != nil {
				return nil, e
			}
			return parseWindows(b)
		}
		b, e := run(ctx, "ps", "-axo", "pid=,uid=,rss=,time=,comm=")
		if e != nil {
			return nil, e
		}
		return parsePS(string(b)), nil
	}
	first, e := probe()
	if e != nil {
		return nil, 0, e
	}
	start := time.Now()
	if err := wait(ctx, duration); err != nil {
		return nil, 0, err
	}
	second, e := probe()
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return nil, 0, fmt.Errorf("observation interval was not measurable")
	}
	if e != nil {
		return nil, elapsed, e
	}
	before := map[int]process{}
	for _, p := range first {
		before[p.pid] = p
	}
	out := []process{}
	for _, p := range second {
		old, ok := before[p.pid]
		if !ok || old.name != p.name || p.cpu < old.cpu {
			continue
		}
		p.cpu = (p.cpu - old.cpu) / elapsed * 100
		if math.IsNaN(p.cpu) || math.IsInf(p.cpu, 0) {
			continue
		}
		out = append(out, p)
	}
	return out, elapsed, nil
}
func parsePS(s string) []process {
	out := []process{}
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		pid, e := strconv.Atoi(fields[0])
		uid := fields[1]
		rss, re := strconv.ParseInt(fields[2], 10, 64)
		cpu, ce := cpuTime(fields[3])
		if e != nil || re != nil || ce != nil || pid <= 0 || rss < 0 || rss > math.MaxInt64/1024 {
			continue
		}
		// comm, unlike args/command, contains only executable identity. Preserve spaces.
		name := strings.Join(fields[4:], " ")
		out = append(out, process{pid: pid, name: name, owner: uid, rss: rss * 1024, cpu: cpu})
	}
	return out
}
func parseWindows(b []byte) ([]process, error) {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		b = append(append([]byte("["), b...), ']')
	}

	var rows []struct {
		Id           int
		ProcessName  string
		CPU          *float64
		WorkingSet64 int64
	}
	if e := json.Unmarshal(b, &rows); e != nil {
		return nil, e
	}
	out := []process{}
	for _, r := range rows {
		if r.Id > 0 && r.CPU != nil && *r.CPU >= 0 && !math.IsNaN(*r.CPU) && !math.IsInf(*r.CPU, 0) && r.WorkingSet64 >= 0 {
			out = append(out, process{pid: r.Id, name: r.ProcessName, owner: "unknown", rss: r.WorkingSet64, cpu: *r.CPU})
		}
	}
	return out, nil
}
func cpuTime(s string) (float64, error) {
	days := 0.0
	if i := strings.IndexByte(s, '-'); i >= 0 {
		n, e := strconv.ParseFloat(s[:i], 64)
		if e != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, fmt.Errorf("invalid CPU day count")
		}
		days = n
		s = s[i+1:]
	}
	fields := strings.Split(s, ":")
	if len(fields) < 2 || len(fields) > 3 {
		return 0, fmt.Errorf("invalid CPU time")
	}
	v := 0.0
	for _, f := range fields {
		n, e := strconv.ParseFloat(f, 64)
		if e != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, fmt.Errorf("invalid CPU time")
		}
		v = v*60 + n
	}
	value := days*86400 + v
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("CPU time overflow")
	}
	return value, nil
}
func parseMemory(s string) (*int64, *int64, *int64) {
	values := map[string]int64{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != "kB" {
			continue
		}
		n, e := strconv.ParseInt(f[1], 10, 64)
		if e == nil && n >= 0 && n < 1<<53 {
			values[strings.TrimSuffix(f[0], ":")] = n * 1024
		}
	}
	ptr := func(k string) *int64 {
		n, ok := values[k]
		if !ok {
			return nil
		}
		return &n
	}
	total, available := ptr("MemTotal"), ptr("MemAvailable")
	var used *int64
	if t, ok := values["SwapTotal"]; ok {
		if free, ok := values["SwapFree"]; ok && free <= t {
			n := t - free
			used = &n
		}
	}
	return total, available, used
}
func procedure(osName string) string {
	switch osName {
	case "darwin":
		return "Use Activity Monitor to compare CPU and Memory over time; inspect Login Items in System Settings."
	case "windows":
		return "Use Task Manager Processes/Startup apps and Settings; review dependencies before changing anything."
	case "linux":
		return "Compare with your system monitor over time; inspect your desktop Startup Applications and systemd user service settings."
	}
	return "Use your OS system monitor to compare CPU and memory over time; keep all processes running while reviewing."
}

func startup(ctx context.Context, r *findings.Result, osName string) {
	home, e := os.UserHomeDir()
	if e != nil {
		return
	}
	var roots []string
	switch osName {
	case "darwin":
		roots = []string{filepath.Join(home, "Library", "LaunchAgents")}
	case "linux":
		roots = []string{filepath.Join(home, ".config", "autostart"), filepath.Join(home, ".config", "systemd", "user")}
	default:
		r.Warnings = append(r.Warnings, "Windows startup inventory is not implemented; use Task Manager Startup apps.")
		return
	}
	count := 0
	for _, dir := range roots {
		st, e := os.Lstat(dir)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			r.Warnings = append(r.Warnings, "Startup metadata directory inaccessible or linked.")
			continue
		}
		root, e := platforms.OpenMetadataDirectory(dir)
		if e != nil {
			r.Coverage.Inaccessible++
			continue
		}
		file, e := root.Open(".")
		if e != nil {
			root.Close()
			continue
		}
		for count < 100 && ctx.Err() == nil {
			entries, e := file.ReadDir(50)
			for _, entry := range entries {
				if count >= 100 {
					break
				}
				if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
					continue
				}
				count++
				path := filepath.Join(dir, entry.Name())
				source := path
				r.Findings = append(r.Findings, findings.Finding{Feature: "performance", Title: "Startup metadata reference: " + entry.Name(), Paths: []string{path}, Risk: "UNKNOWN", Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Startup metadata exists; enabled/running state is not established.", Evidence: []string{"Filename and source directory only; configuration contents and command arguments were not read."}, Limitations: []string{"Not a complete startup inventory; symlinks, system entries and nested units are omitted."}, PossibleConsequences: "Changing startup entries could affect dependent applications or services.", ManualInspection: "Confirm in OS settings whether this startup entry is enabled and still needed; filename presence does not measure startup cost. " + procedure(osName), Performance: &findings.Performance{StartupSource: &source, CPUSemantics: "Not measured for startup references.", DependencyNotes: "Unknown; no unit or plist contents are parsed.", ObservedImpact: "Presence only; no startup performance impact measured."}})
			}
			if e != nil {
				break
			}
		}
		file.Close()
		root.Close()
	}
	r.Warnings = append(r.Warnings, "Startup review is limited to at most 100 user-level metadata filenames, with no enablement or dependency analysis.")
}

// The system vm_stat text format reports page counts and page size. These
// independent snapshots do not reproduce Activity Monitor's pressure assessment.
// Format/provenance: developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html
// and apple-oss-distributions/system_cmds vm_stat/vm_stat.c. No upstream code copied.
func collectDarwinMemory(ctx context.Context, p *findings.Performance, run runner) []string {
	warnings := []string{}
	p.MemoryPressureReason = "Not measured: vm_stat free pages, compressor occupancy and a single swap amount do not establish macOS memory pressure. Compare Activity Monitor's Memory Pressure graph over time."
	if b, e := run(ctx, "sysctl", "-n", "hw.memsize"); e == nil {
		if n, e := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); e == nil && n > 0 {
			p.MemoryTotalBytes = &n
		} else {
			warnings = append(warnings, "macOS total memory metadata had an unsupported format.")
		}
	} else {
		warnings = append(warnings, "macOS total memory metadata unavailable.")
	}
	if b, e := run(ctx, "vm_stat"); e == nil {
		p.MemoryFreeBytes, p.MemoryCompressedBytes = parseVMStat(string(b))
		if p.MemoryFreeBytes == nil || p.MemoryCompressedBytes == nil {
			warnings = append(warnings, "macOS free/compressed page counters were missing or could not be parsed; missing values remain unknown.")
		}
	} else {
		warnings = append(warnings, "macOS vm_stat metadata unavailable; free/compressed memory remains unknown.")
	}
	if b, e := run(ctx, "sysctl", "-n", "vm.swapusage"); e == nil {
		p.SwapUsedBytes = parseSwapUsage(string(b))
		if p.SwapUsedBytes == nil {
			warnings = append(warnings, "macOS swap usage had an unsupported format; swap remains unknown.")
		}
	} else {
		warnings = append(warnings, "macOS swap usage metadata unavailable.")
	}
	return warnings
}

func parseVMStat(s string) (free, compressed *int64) {
	lines := strings.Split(s, "\n")
	if len(lines) == 0 {
		return nil, nil
	}
	var pageSize int64
	if n, e := fmt.Sscanf(strings.TrimSpace(lines[0]), "Mach Virtual Memory Statistics: (page size of %d bytes)", &pageSize); e != nil || n != 1 || pageSize < 512 || pageSize > 1<<30 || pageSize&(pageSize-1) != 0 {
		return nil, nil
	}
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		var target **int64
		switch strings.TrimSpace(key) {
		case "Pages free":
			target = &free
		case "Pages occupied by compressor":
			target = &compressed
		default:
			continue
		}
		n, e := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(value), "."), 10, 64)
		if e != nil || n < 0 || n > math.MaxInt64/pageSize {
			*target = nil
			continue
		}
		bytes := n * pageSize
		*target = &bytes
	}
	return free, compressed
}

// sysctl's textual sizes may already be rounded by the native tool. M/G denote
// binary multiples in this format; the resulting byte count remains an estimate
// of the displayed amount, never an IO rate or physical recovery estimate.
func parseSwapUsage(s string) *int64 {
	fields := strings.Fields(s)
	for i := 0; i+2 < len(fields); i++ {
		if fields[i] != "used" || fields[i+1] != "=" {
			continue
		}
		value := fields[i+2]
		multiplier := int64(1)
		for suffix, m := range map[string]int64{"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40} {
			if strings.HasSuffix(value, suffix) {
				multiplier = m
				value = strings.TrimSuffix(value, suffix)
				break
			}
		}
		// Accept only decimal native quantities; reject signs, exponent forms and
		// locale separators so malformed metrics cannot become plausible values.
		if value == "" {
			return nil
		}
		dot := false
		for _, r := range value {
			if r == '.' && !dot {
				dot = true
				continue
			}
			if r < '0' || r > '9' {
				return nil
			}
		}
		n, ok := new(big.Rat).SetString(value)
		if !ok || n.Sign() < 0 {
			return nil
		}
		n.Mul(n, new(big.Rat).SetInt64(multiplier))
		bytes := new(big.Int).Quo(n.Num(), n.Denom())
		if !bytes.IsInt64() {
			return nil
		}
		v := bytes.Int64()
		return &v
	}
	return nil
}

func parseWindowsMemory(b []byte) (total, available *int64) {
	var m struct{ TotalVisibleMemorySize, FreePhysicalMemory *int64 }
	if json.Unmarshal(b, &m) != nil {
		return nil, nil
	}
	bytes := func(v *int64) *int64 {
		if v == nil || *v < 0 || *v > math.MaxInt64/1024 {
			return nil
		}
		n := *v * 1024
		return &n
	}
	total = bytes(m.TotalVisibleMemorySize)
	if total != nil && *total == 0 {
		total = nil
	}
	available = bytes(m.FreePhysicalMemory)
	if total != nil && available != nil && *available > *total {
		available = nil
	}
	return total, available
}

func linuxMemoryField(s, key string) *int64 {
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != key+":" || fields[2] != "kB" {
			continue
		}
		n, e := strconv.ParseInt(fields[1], 10, 64)
		if e != nil || n < 0 || n > math.MaxInt64/1024 {
			return nil
		}
		n *= 1024
		return &n
	}
	return nil
}
