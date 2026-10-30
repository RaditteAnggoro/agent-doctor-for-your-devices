package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/cli"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/actions"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/testkit"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
	code, _, err := run(t, "\n\nmaybe\nbatal\n", "scan", "--interactive")
	if code != 130 || !strings.Contains(err, "belum nangkap pilihan OS") || strings.Contains(err, "Sip, aku mulai cek") {
		t.Fatal(code, err)
	}
	code, _, err = run(t, "cancel\n", "scan", "--interactive")
	if code != 130 || !strings.Contains(err, "0 file dihapus") {
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

func TestActionCommandsRequireSeparateExplicitOptIn(t *testing.T) {
	for _, command := range []string{"plan", "apply"} {
		code, _, errs := run(t, "", command, "--data-dir", testkit.Dir(t))
		if code != 64 || !strings.Contains(errs, "enable-actions") {
			t.Fatal(command, code, errs)
		}
	}
	code, _, errs := run(t, "", "plan", "--enable-actions", "--share-safe", "--data-dir", testkit.Dir(t))
	if code != 64 || !strings.Contains(errs, "private targets") {
		t.Fatal(code, errs)
	}
}

// Explicit opt-in native integration uses only generated temporary artifacts.
func TestNativeCLIActionJournalAndReplay(t *testing.T) {
	if os.Getenv("AGENT_DOCTOR_NATIVE_TRASH_TEST") != "1" || runtime.GOOS != "darwin" {
		t.Skip("opt-in native macOS integration")
	}
	dir := testkit.Dir(t)
	store := testkit.Dir(t)
	path := testkit.File(t, dir, "agent-doctor-native-cli-synthetic.tmp", "synthetic CLI Trash fixture")
	old := time.Now().Add(-60 * 24 * time.Hour)
	if e := os.Chtimes(path, old, old); e != nil {
		t.Fatal(e)
	}
	code, text, errs := run(t, "", "scan", "--feature", "junk", "--scope", dir, "--store", "--data-dir", store, "--format", "json", "--confirm-environment")
	if code != 0 {
		t.Fatal(code, errs)
	}
	var r findings.Report
	if e := json.Unmarshal([]byte(text), &r); e != nil {
		t.Fatal(e)
	}
	code, text, errs = run(t, "", "plan", "--enable-actions", "--scan", r.ScanID, "--finding", "J-000001", "--action", "trash", "--target", path, "--backup-reviewed", "--data-dir", store, "--format", "json")
	if code != 0 {
		t.Fatal(code, errs)
	}
	var plan actions.Plan
	if e := json.Unmarshal([]byte(text), &plan); e != nil {
		t.Fatal(e)
	}
	code, text, errs = run(t, "", "apply", "--enable-actions", "--plan", plan.ID, "--approve", plan.ApprovalHash, "--data-dir", store)
	if code != 0 {
		t.Fatal(code, text, errs)
	}
	var result actions.Outcome
	if e := json.Unmarshal([]byte(text), &result); e != nil {
		t.Fatal(e)
	}
	// Recover this known synthetic artifact immediately, even on a failed assertion.
	defer func() {
		if result.TrashLocation != "" {
			if _, e := os.Stat(result.TrashLocation); e == nil {
				if e := os.Rename(result.TrashLocation, path); e != nil {
					t.Errorf("restore known synthetic fixture from %q: %v", result.TrashLocation, e)
				}
			}
		}
	}()
	if result.Status != "COMPLETED" || result.FilesTrashed != 1 || result.PermanentDeletions != 0 {
		t.Fatal(result)
	}
	if e := os.Rename(result.TrashLocation, path); e != nil {
		t.Fatal("synthetic restore", e)
	}
	code, _, errs = run(t, "", "apply", "--enable-actions", "--plan", plan.ID, "--approve", plan.ApprovalHash, "--data-dir", store)
	if code != 0 || !strings.Contains(errs, "no new native action") {
		t.Fatal("replay failed", code, errs)
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal("replay executed again")
	}
}

func TestInteractiveIntroStaysOutOfSavedReport(t *testing.T) {
	dir := testkit.Dir(t)
	store := testkit.Dir(t)
	file := testkit.File(t, dir, "old.tmp", "synthetic file")
	old := time.Now().Add(-90 * 24 * time.Hour)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	name := "TemanUjiRahasia"
	issue := "KonteksUjiRahasia"
	input := name + "\n" + issue + "\n5\nya\n1\n1\n" + dir + "\nya\n"
	code, out, errs := run(t, input, "scan", "--interactive", "--store", "--data-dir", store, "--format", "json")
	if code != 0 {
		t.Fatal(code, errs)
	}
	var report findings.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal("interactive chatter entered JSON stdout", err)
	}
	if len(report.SelectedFeatures) != 1 || report.SelectedFeatures[0] != "junk" || len(report.Scope.Roots) != 1 || report.Scope.Roots[0] != dir {
		t.Fatal("wrong scope or feature")
	}
	if strings.Contains(out, name) || strings.Contains(out, issue) {
		t.Fatal("intro leaked into report")
	}
	if !strings.Contains(errs, name) || !strings.Contains(errs, "Sip, aku mulai cek") {
		t.Fatal("greeting or progress missing", errs)
	}
	entries, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(store, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), name) || strings.Contains(string(b), issue) {
			t.Fatal("intro persisted in session storage")
		}
	}
}
func TestIntroYesDoesNotReplaceFinalScanConfirmation(t *testing.T) {
	dir := testkit.Dir(t)
	storage := filepath.Join(testkit.Dir(t), "not-created")
	input := "ya\nya\n5\nya\n1\n1\n" + dir + "\ntidak\n"
	code, out, errs := run(t, input, "scan", "--interactive", "--store", "--data-dir", storage, "--format", "json")
	if code != 130 || out != "" || strings.Contains(errs, "Sip, aku mulai cek") {
		t.Fatal("intro accepted as scan approval", code, out, errs)
	}
	if _, err := os.Stat(storage); !os.IsNotExist(err) {
		t.Fatal("saved session before final confirmation")
	}
}
