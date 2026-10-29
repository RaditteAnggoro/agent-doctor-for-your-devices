// Package performance collects bounded metadata samples; it never stops processes.
package performance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
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

func Collect(ctx context.Context, env findings.Environment) findings.Result {
	r := findings.Result{Feature: "performance", Support: "PARTIAL", Coverage: findings.Coverage{Status: "PARTIAL"}, Findings: []findings.Finding{}, Warnings: []string{}, Errors: []string{}, Observations: []string{}, CollectionMethod: "bounded native metadata; two cumulative CPU samples; no process arguments"}
	if env.OS != "darwin" && env.OS != "linux" && env.OS != "windows" {
		r.Support = "UNSUPPORTED"
		r.Coverage.Status = "UNSUPPORTED"
		r.Warnings = append(r.Warnings, "No performance adapter for this OS.")
		return r
	}
	procs, seconds, err := sample(ctx, env.OS, platforms.Run)
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
		r.Warnings = append(r.Warnings, "Process report contains the 25 largest visible RSS/working-set samples only.")
	}
	for _, p := range procs {
		r.Findings = append(r.Findings, processFinding(p, seconds))
	}
	p := &findings.Performance{CPUSemantics: "Not applicable to system metadata.", ObservedImpact: "Capacity observations are not a diagnosis of workload health.", DependencyNotes: "System services and container limits may affect these observations."}
	if env.OS == "linux" {
		b, e := platforms.ReadSmall("/proc/meminfo", 64<<10)
		if e == nil {
			p.MemoryTotalBytes, p.MemoryAvailableBytes, p.SwapUsedBytes = parseMemory(string(b))
		}
	}
	if env.OS == "darwin" {
		if b, e := platforms.Run(ctx, "sysctl", "-n", "hw.memsize"); e == nil {
			if n, e := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); e == nil {
				p.MemoryTotalBytes = &n
			}
		}
	}
	if env.OS == "windows" {
		if b, e := platforms.Run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress`); e == nil {
			var m struct{ TotalVisibleMemorySize, FreePhysicalMemory int64 }
			if json.Unmarshal(b, &m) == nil && m.TotalVisibleMemorySize > 0 {
				total, available := m.TotalVisibleMemorySize*1024, m.FreePhysicalMemory*1024
				p.MemoryTotalBytes = &total
				p.MemoryAvailableBytes = &available
			}
		}
	}
	if cwd, e := os.Getwd(); e == nil {
		p.DiskTotalBytes, p.DiskAvailableBytes = platforms.Disk(cwd)
	}
	r.Findings = append(r.Findings, findings.Finding{Feature: "performance", Title: "System capacity in this execution environment", Risk: "UNKNOWN", Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Baseline capacity metadata for interpreting process samples.", Evidence: []string{"Nullable metrics are unmeasured, unsupported or inaccessible; disk capacity is the current working-directory filesystem only."}, Limitations: []string{"Memory pressure, swap on some OSes, startup enablement and host-level metrics may be unavailable.", "Container /proc and filesystem values may reflect host-wide rather than cgroup limits; they are not ChromeOS or Windows host measurements."}, PossibleConsequences: "No settings or processes were changed.", ManualInspection: procedure(env.OS), Performance: p})
	startup(ctx, &r, env.OS)
	r.Observations = append(r.Observations, fmt.Sprintf("CPU samples separated by %.3f seconds; CPU is delta cumulative process time / actual elapsed time, 100%% = one logical core. Short/coarse native counters may show zero.", seconds), "Unknown app dependencies and a busy sample do not justify stopping a process.")
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
	return findings.Finding{Feature: "performance", Title: "Observed process: " + p.name, Risk: "UNKNOWN", Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Visible process resource sample; inclusion is not evidence of a persistent problem.", Evidence: []string{"Measured resident memory / Windows working set; cumulative CPU sampled twice; no command-line arguments collected."}, Limitations: []string{"Short observation window; shared memory can be counted in multiple RSS values.", "PID reuse, process exits and native counter resolution can limit CPU measurements."}, PossibleConsequences: "Stopping a process manually may interrupt work or dependent services.", ManualInspection: "Check whether this process belongs to your active work. " + procedure(""), Performance: &findings.Performance{PID: &p.pid, ProcessName: &p.name, CPUPercent: &p.cpu, CPUSemantics: "100% = one logical core; delta cumulative CPU seconds / actual elapsed seconds. Counter precision is OS dependent.", RSSBytes: &p.rss, ObservationSeconds: seconds, Owner: &p.owner, Running: &running, DependencyNotes: "Unknown; ask the user before any manual process action.", ObservedImpact: "One short sample; no sustained problem established."}}
}

func sample(ctx context.Context, osName string, run runner) ([]process, float64, error) {
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
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case <-timer.C:
	}
	second, e := probe()
	elapsed := time.Since(start).Seconds()
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
		if e != nil || re != nil || ce != nil || pid <= 0 || rss < 0 {
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
		if r.Id > 0 && r.CPU != nil && r.WorkingSet64 >= 0 {
			out = append(out, process{pid: r.Id, name: r.ProcessName, owner: "unknown", rss: r.WorkingSet64, cpu: *r.CPU})
		}
	}
	return out, nil
}
func cpuTime(s string) (float64, error) {
	days := 0.0
	if i := strings.IndexByte(s, '-'); i >= 0 {
		n, e := strconv.ParseFloat(s[:i], 64)
		if e != nil {
			return 0, e
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
	return days*86400 + v, nil
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
				r.Findings = append(r.Findings, findings.Finding{Feature: "performance", Title: "Startup metadata reference: " + entry.Name(), Paths: []string{path}, Risk: "UNKNOWN", Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Startup metadata exists; enabled/running state is not established.", Evidence: []string{"Filename and source directory only; configuration contents and command arguments were not read."}, Limitations: []string{"Not a complete startup inventory; symlinks, system entries and nested units are omitted."}, PossibleConsequences: "Changing startup entries could affect dependent applications or services.", ManualInspection: procedure(osName), Performance: &findings.Performance{StartupSource: &source, CPUSemantics: "Not measured for startup references.", DependencyNotes: "Unknown; no unit or plist contents are parsed.", ObservedImpact: "Presence only; no startup performance impact measured."}})
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
