package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/cli"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/testkit"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := cli.Run(context.Background(), args, strings.NewReader(input), &out, &err)
	return code, out.String(), err.String()
}
func TestManualReviewLifecycle(t *testing.T) {
	dir := testkit.Dir(t)
	store := testkit.Dir(t)
	testkit.File(t, dir, "a.txt", "same")
	testkit.File(t, dir, "b.txt", "same")
	code, out, err := run(t, "", "scan", "--feature", "duplicates", "--scope", dir, "--store", "--data-dir", store, "--format", "json", "--confirm-environment")
	if code != 0 {
		t.Fatal(code, out, err)
	}
	var report findings.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results[0].Findings) != 1 {
		t.Fatal(out)
	}
	id := report.Results[0].Findings[0].ID
	common := []string{"--scan", report.ScanID, "--data-dir", store}
	for _, command := range []string{"inspect", "explain", "reveal"} {
		args := append([]string{command, id}, common...)
		if code, out, err := run(t, "", args...); code != 0 {
			t.Fatal(command, code, out, err)
		}
	}
	args := append([]string{"review", id}, common...)
	args = append(args, "--decision", "keep")
	if code, out, err := run(t, "", args...); code != 0 {
		t.Fatal(code, out, err)
	}
	for _, format := range []string{"json", "markdown", "csv"} {
		dest := filepath.Join(testkit.Dir(t), "report."+format)
		args = append([]string{"export"}, common...)
		args = append(args, "--format", format, "--feature", "duplicates", "--output", dest)
		if code, out, err := run(t, "", args...); code != 0 {
			t.Fatal(code, out, err)
		}
		if st, err := os.Stat(dest); err != nil || st.Size() == 0 {
			t.Fatal("missing export")
		}
		if code, _, _ := run(t, "", args...); code == 0 {
			t.Fatal("export overwrote existing destination")
		}
	}
	for _, args := range [][]string{{"session", "list", "--data-dir", store}, {"session", "resume", report.ScanID, "--data-dir", store}, {"session", "cancel", report.ScanID, "--data-dir", store}} {
		if code, out, err := run(t, "", args...); code != 0 {
			t.Fatal(code, out, err)
		}
	}
}
func TestNoScopeAndAmbiguousOnboarding(t *testing.T) {
	if code, _, _ := run(t, "", "scan", "--all", "--confirm-environment"); code != 64 {
		t.Fatal("implicit whole-disk permission")
	}
	code, _, err := run(t, "maybe\n", "scan", "--interactive")
	if code != 64 || !strings.HasPrefix(err, "Which device OS") {
		t.Fatal(code, err)
	}
	code, _, err = run(t, "cancel\n", "scan", "--interactive")
	if code != 130 || !strings.Contains(err, "0 files removed") {
		t.Fatal(code, err)
	}
}
func TestNoPersistenceWithoutStore(t *testing.T) {
	dir := testkit.Dir(t)
	storage := filepath.Join(testkit.Dir(t), "not-created")
	testkit.File(t, dir, "a", "a")
	code, _, err := run(t, "", "scan", "--feature", "duplicates", "--scope", dir, "--data-dir", storage, "--confirm-environment")
	if code != 0 {
		t.Fatal(code, err)
	}
	if _, err := os.Stat(storage); !os.IsNotExist(err) {
		t.Fatal("implicit persistence")
	}
}

func TestResumeJSONIsSingleValueAndShareSafe(t *testing.T) {
	dir := testkit.Dir(t)
	store := testkit.Dir(t)
	testkit.File(t, dir, "private-a", "same")
	testkit.File(t, dir, "private-b", "same")
	code, out, errs := run(t, "", "scan", "--feature", "duplicates", "--scope", dir, "--store", "--data-dir", store, "--format", "json", "--confirm-environment")
	if code != 0 {
		t.Fatal(code, errs)
	}
	var report findings.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	code, _, errs = run(t, "", "review", "D-000001", "--scan", report.ScanID, "--data-dir", store, "--decision", "keep", "--note", "secret private path /my-home/very-private")
	if code != 0 {
		t.Fatal(code, errs)
	}
	code, out, errs = run(t, "", "session", "resume", report.ScanID, "--data-dir", store, "--format", "json", "--share-safe")
	if code != 0 {
		t.Fatal(code, errs)
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatal("resume is not one JSON value", err)
	}
	if envelope["report"] == nil || envelope["review_state"] == nil || strings.Contains(out, "very-private") || strings.Contains(out, "secret private") || strings.Contains(out, dir) {
		t.Fatal("resume leaked sensitive fields", out)
	}
}
