package performance

import (
	"context"
	"errors"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"math"
	"strings"
	"testing"
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
	procs, elapsed, e := sample(context.Background(), "darwin", run)
	if e != nil {
		t.Fatal(e)
	}
	if len(procs) != 1 || procs[0].rss != 2097152 || procs[0].name != "editor with spaces" || elapsed < .19 {
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
	_, _, e := sample(ctx, "linux", func(context.Context, string, ...string) ([]byte, error) { calls++; return []byte(""), nil })
	if !errors.Is(e, context.Canceled) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, e)
	}
	_, _, e = sample(context.Background(), "linux", func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("unavailable") })
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
	if _, e := cpuTime("invalid"); e == nil {
		t.Fatal("invalid CPU time accepted")
	}
	calls := 0
	procs, _, e := sample(context.Background(), "linux", func(context.Context, string, ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("42 501 1 0:10 a\n"), nil
		}
		return []byte("42 501 1 0:01 b\n"), nil
	})
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
