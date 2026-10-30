package performance

import (
	"context"
	"errors"
	"fmt"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"math"
	"strings"
	"testing"
	"time"
)

func TestSampleReportsMeasuredDeltaAndNoArguments(t *testing.T) {
	calls := 0
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "ps" || strings.Contains(strings.Join(args, " "), "args") || strings.Contains(strings.Join(args, " "), "command") {
			t.Fatal("unsafe process probe")
		}
		calls++
		if calls == 1 {
			return []byte("42 501 1024 0:01.00 editor with spaces\n"), nil
		}
		return []byte("42 501 2048 0:01.10 editor with spaces\n"), nil
	}
	procs, elapsed, e := sampleFor(context.Background(), "darwin", run, 3*time.Second, func(_ context.Context, d time.Duration) error {
		if d != 3*time.Second {
			t.Fatalf("wrong requested observation window %s", d)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if len(procs) != 1 || procs[0].rss != 2097152 || procs[0].name != "editor with spaces" || elapsed <= 0 {
		t.Fatalf("%+v %.3f", procs, elapsed)
	}
	if math.Abs(procs[0].cpu-.10/elapsed*100) > 1e-8 {
		t.Fatalf("incorrect CPU denominator: %v", procs[0].cpu)
	}
	f := processFinding(procs[0], elapsed)
	if f.Performance.CPUPercent == nil || f.Performance.ObservationSeconds != elapsed || f.Recommendation != "INSPECT" {
		t.Fatalf("%+v", f)
	}
}
func TestCancellationAndFailedProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, _, e := sampleFor(ctx, "linux", func(context.Context, string, ...string) ([]byte, error) { calls++; return []byte(""), nil }, 3*time.Second, func(ctx context.Context, _ time.Duration) error { return ctx.Err() })
	if !errors.Is(e, context.Canceled) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, e)
	}
	_, _, e = sampleFor(context.Background(), "linux", func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("unavailable") }, 3*time.Second, func(context.Context, time.Duration) error { return nil })
	if e == nil {
		t.Fatal("probe failure hidden")
	}
}
func TestMemoryUnknownIsNull(t *testing.T) {
	total, available, swap := parseMemory("MemTotal: 1024 kB\nMemFree: 999 kB\nSwapTotal: 10 kB\nSwapFree: 3 kB\n")
	if total == nil || *total != 1048576 || available != nil || swap == nil || *swap != 7168 {
		t.Fatal("incorrect memory provenance or units")
	}
	_, _, swap = parseMemory("SwapTotal: 10 kB\n")
	if swap != nil {
		t.Fatal("missing metric became zero")
	}
}
func TestCPUTimeAndPIDReuse(t *testing.T) {
	for input, want := range map[string]float64{"01:30.50": 90.5, "01:02:03": 3723, "2-01:02:03": 176523} {
		got, e := cpuTime(input)
		if e != nil || got != want {
			t.Errorf("%s %f %v", input, got, e)
		}
	}
	for _, invalid := range []string{"invalid", "NaN-01:00", "-1-01:00", "Inf-01:00", "1e308-01:00"} {
		if _, e := cpuTime(invalid); e == nil {
			t.Fatalf("invalid CPU time accepted: %s", invalid)
		}
	}
	calls := 0
	procs, _, e := sampleFor(context.Background(), "linux", func(context.Context, string, ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("42 501 1 0:10 a\n"), nil
		}
		return []byte("42 501 1 0:01 b\n"), nil
	}, 3*time.Second, func(context.Context, time.Duration) error { return nil })
	if e != nil || len(procs) != 0 {
		t.Fatal("reused PID was compared")
	}
}

func TestSingleWindowsProcessRecord(t *testing.T) {
	procs, e := parseWindows([]byte(`{"Id":42,"ProcessName":"App","CPU":2.5,"WorkingSet64":2048}`))
	if e != nil || len(procs) != 1 || procs[0].rss != 2048 {
		t.Fatalf("%+v %v", procs, e)
	}
}

func TestCancelledCollectionRetainsCancelledCoverage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Collect(ctx, findings.Environment{OS: "linux"})
	if r.Coverage.Status != "CANCELLED" || len(r.Findings) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestVMStatUsesReportedPageSizeAndOccupiedCompression(t *testing.T) {
	for _, pageSize := range []int64{4096, 16384} {
		s := fmt.Sprintf("Mach Virtual Memory Statistics: (page size of %d bytes)\nPages free: 17.\nPages stored in compressor: 800.\nPages occupied by compressor: 3.\n", pageSize)
		free, compressed := parseVMStat(s)
		if free == nil || *free != 17*pageSize || compressed == nil || *compressed != 3*pageSize {
			t.Fatalf("bad page units: %v %v", free, compressed)
		}
	}
	free, compressed := parseVMStat("Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 0.\n")
	if free == nil || *free != 0 || compressed != nil {
		t.Fatal("missing compression became zero or measured zero lost")
	}
	for _, input := range []string{"bad header\nPages free: 1.\n", "Mach Virtual Memory Statistics: (page size of 0 bytes)\nPages free: 1.\n", "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 9223372036854775807.\n"} {
		free, compressed := parseVMStat(input)
		if free != nil || compressed != nil {
			t.Fatal("malformed/overflow metric accepted")
		}
	}
}
func TestSwapUsageUnitsAndMissingValues(t *testing.T) {
	for input, want := range map[string]int64{
		"total = 2048.00M used = 512.25M free = 1535.75M (encrypted)": 537133056,
		"total = 0.00M used = 0.00M free = 0.00M":                     0,
		"total = 4G used = 1.5G free = 2.5G":                          1610612736,
		"used = 1234":                                                 1234,
	} {
		v := parseSwapUsage(input)
		if v == nil || *v != want {
			t.Fatalf("%q => %v expected %d", input, v, want)
		}
	}
	for _, input := range []string{"", "total = 512M", "used = unknown", "used = -1M", "used = NaN", "used = 99999999999999999999T", "used = 1,2M", "used = 1e3M"} {
		if parseSwapUsage(input) != nil {
			t.Fatalf("invalid swap accepted: %q", input)
		}
	}
}
func TestDarwinMemoryEvidenceAndUnknownPressure(t *testing.T) {
	p := &findings.Performance{}
	calls := []string{}
	warnings := collectDarwinMemory(context.Background(), p, func(_ context.Context, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "sysctl -n hw.memsize":
			return []byte("8589934592\n"), nil
		case "vm_stat ":
			return []byte("Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 12.\nPages occupied by compressor: 20.\n"), nil
		case "sysctl -n vm.swapusage":
			return []byte("total = 2048M used = 128M free = 1920M\n"), nil
		default:
			t.Fatalf("unexpected probe %q", call)
			return nil, nil
		}
	})
	if len(warnings) != 0 || len(calls) != 3 || p.MemoryTotalBytes == nil || *p.MemoryTotalBytes != 8589934592 || p.MemoryFreeBytes == nil || *p.MemoryFreeBytes != 196608 || p.MemoryCompressedBytes == nil || *p.MemoryCompressedBytes != 327680 || p.SwapUsedBytes == nil || *p.SwapUsedBytes != 134217728 {
		t.Fatalf("memory evidence missing: %+v %v", p, warnings)
	}
	if p.MemoryAvailableBytes != nil || p.MemoryPressureLevel != nil || p.MemoryPressureReason == "" {
		t.Fatal("free pages misclassified as pressure/available memory")
	}
	p = &findings.Performance{}
	warnings = collectDarwinMemory(context.Background(), p, func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("permission denied") })
	if len(warnings) != 3 || p.MemoryTotalBytes != nil || p.MemoryFreeBytes != nil || p.MemoryCompressedBytes != nil || p.SwapUsedBytes != nil {
		t.Fatalf("probe failure became data: %+v %v", p, warnings)
	}
}
func TestWindowsMemoryMissingMetricDoesNotBecomeZero(t *testing.T) {
	total, available := parseWindowsMemory([]byte(`{"TotalVisibleMemorySize":1024}`))
	if total == nil || *total != 1048576 || available != nil {
		t.Fatal("missing free metric became zero")
	}
	total, available = parseWindowsMemory([]byte(`{"TotalVisibleMemorySize":1024,"FreePhysicalMemory":0}`))
	if total == nil || available == nil || *available != 0 {
		t.Fatal("measured zero lost")
	}
	_, available = parseWindowsMemory([]byte(`{"TotalVisibleMemorySize":1,"FreePhysicalMemory":2}`))
	if available != nil {
		t.Fatal("impossible available memory accepted")
	}
}
func TestCollectDurationValidationDoesNotProbeDevice(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second, 500 * time.Millisecond, 31 * time.Second} {
		r := CollectWithDuration(context.Background(), findings.Environment{OS: "darwin"}, d)
		if r.Coverage.Status != "FAILED" || len(r.Findings) != 0 || len(r.Errors) != 1 {
			t.Fatalf("invalid sample window accepted: %+v", r)
		}
	}
	if DefaultSampleDuration != 3*time.Second {
		t.Fatal("unexpected default")
	}
}
