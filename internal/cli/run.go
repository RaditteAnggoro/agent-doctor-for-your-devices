// Package cli separates read-only scans from explicitly approved experimental actions.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/buildinfo"
	decisionguide "github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/decision"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/discovery"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/reports"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/reviewer"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/safety"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/scanner"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/session"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/features/applications"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/features/duplicates"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/features/junk"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/features/performance"
)

const help = `Agent Doctor For Your Devices — Scan first. Understand everything. Decide yourself.
Scans are read-only. Experimental action plans require separate exact-target approval.

Mau mulai ngobrol? Jalankan agent-doctor scan --interactive.
Nama panggilan dan keluhan boleh dilewati dengan Enter, skip, atau lewati.

agent-doctor doctor | version | about
agent-doctor scan --interactive
agent-doctor scan --all --read-only --scope DIR [--scope DIR] [--store]
agent-doctor scan --feature junk|duplicates --scope DIR
agent-doctor scan --feature performance|applications
agent-doctor report --scan ID [--summary] [--feature NAME] [--format markdown|json|csv]
agent-doctor inspect|explain|reveal FINDING --scan ID
agent-doctor review FINDING --scan ID --decision keep|review-later|skip|mark-reviewed [--note TEXT]
agent-doctor session list|resume ID|cancel ID
agent-doctor export --scan ID --format markdown|json|csv --output FILE [--share-safe]
agent-doctor plan --enable-actions --scan ID --finding ID --action trash|uninstall --target PATH --backup-reviewed [--keep PATH] [--bundle-only]
agent-doctor apply --enable-actions --plan ID --approve SHA256
agent-doctor action-status --plan ID

Session commands require a scan saved using --store. --data-dir DIR selects session storage.
Scan limits: --max-files 10000 --max-depth 12 --max-bytes 1073741824 --timeout 30s.
--sample-duration 3s sets CPU observation (1s..30s).
--exclude DIR is repeatable. CSV requires one --feature. --store explicitly writes private local reports.
Remote/container/WSL/Crostini scans require --confirm-environment after doctor review.
Reveal provides containing-folder paths for manual navigation; it never launches files.
Exit codes: 0 success, 1 internal/storage error, 2 partial, 3 unsupported,
4 permission denied, 64 invalid arguments, 130 interrupted.
`

type listFlag []string

func (s *listFlag) String() string     { return strings.Join(*s, ",") }
func (s *listFlag) Set(v string) error { *s = append(*s, v); return nil }

// reorder permits flags after positional IDs, while honoring -- for literal IDs.
func reorder(args []string) []string {
	flags := []string{}
	pos := []string{}
	bools := map[string]bool{"all": true, "read-only": true, "interactive": true, "store": true, "summary": true, "share-safe": true, "confirm-environment": true, "help": true, "enable-actions": true, "backup-reviewed": true, "bundle-only": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			name := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
			if !strings.Contains(a, "=") && !bools[name] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}
func jsonOut(w io.Writer, v any) error {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		return err
	}
	var safe strings.Builder
	for _, r := range b.String() {
		if unicode.In(r, unicode.Cf) {
			if r <= 0xffff {
				fmt.Fprintf(&safe, "\\u%04x", r)
			} else {
				a, b := utf16.EncodeRune(r)
				fmt.Fprintf(&safe, "\\u%04x\\u%04x", a, b)
			}
		} else {
			safe.WriteRune(r)
		}
	}
	_, err := io.WriteString(w, safe.String())
	return err
}
func errCode(w io.Writer, code int, err error) int {
	fmt.Fprintf(w, "Error: %s\n", terminal(err.Error()))
	return code
}
func terminal(s string) string { return reports.Text(s) }
func Run(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(out, help)
		return 0
	}
	command := args[0]
	if command == "version" {
		fmt.Fprintln(out, buildinfo.Version)
		return 0
	}
	if command == "about" {
		fmt.Fprintf(out, "%s %s\nOriginal creator: %s\nMIT license (original work), 2026\nSource: https://github.com/%s\n%s\nNo telemetry or network calls.\n", buildinfo.ProductName, buildinfo.Version, buildinfo.OriginalCreator, buildinfo.OriginSlug, buildinfo.OriginMarker)
		return 0
	}
	if command == "doctor" {
		if len(args) > 1 {
			return errCode(stderr, 64, errors.New("doctor accepts no flags"))
		}
		if err := jsonOut(out, discovery.Detect()); err != nil {
			return errCode(stderr, 1, err)
		}
		return 0
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	scanID := fs.String("scan", "", "saved scan ID")
	dataDir := fs.String("data-dir", "", "session directory")
	format := fs.String("format", "markdown", "markdown, json or csv")
	feature := fs.String("feature", "", "comma-separated scan features; single report feature")
	all := fs.Bool("all", false, "all four features")
	interactive := fs.Bool("interactive", false, "ngobrol singkat, lalu pilih pemeriksaan")
	store := fs.Bool("store", false, "write session report")
	_ = fs.Bool("read-only", true, "all operations are read-only toward targets")
	confirmEnv := fs.Bool("confirm-environment", false, "confirm execution environment is the target")
	summary := fs.Bool("summary", false, "counts and coverage only")
	share := fs.Bool("share-safe", false, "redact data-derived strings")
	output := fs.String("output", "", "export destination (must not exist)")
	decision := fs.String("decision", "", "review decision")
	note := fs.String("note", "", "local review note")
	maxFiles := fs.Int("max-files", 10000, "entry budget")
	maxDepth := fs.Int("max-depth", 12, "maximum directory depth")
	maxBytes := fs.Int64("max-bytes", 1<<30, "hash and verification byte budget")
	timeout := fs.Duration("timeout", 30*time.Second, "scan time budget")
	sampleDuration := fs.Duration("sample-duration", 3*time.Second, "CPU observation window (1s..30s)")
	actionEnabled := fs.Bool("enable-actions", false, "enable experimental exact-target actions")
	backupReviewed := fs.Bool("backup-reviewed", false, "acknowledge backup and retention review")
	bundleOnly := fs.Bool("bundle-only", false, "confirm bundle-only uninstall after vendor review")
	findingID := fs.String("finding", "", "finding ID for an action plan")
	actionName := fs.String("action", "", "trash or uninstall")
	targetPath := fs.String("target", "", "exact selected source path")
	keepPath := fs.String("keep", "", "exact duplicate member to retain")
	planID := fs.String("plan", "", "saved immutable action plan ID")
	approval := fs.String("approve", "", "explicit reviewed plan SHA-256")
	var roots, exclusions listFlag
	fs.Var(&roots, "scope", "approved directory")
	fs.Var(&exclusions, "exclude", "excluded directory")
	if err := fs.Parse(reorder(args[1:])); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, help)
			return 0
		}
		return 64
	}
	if command == "scan" {
		if fs.NArg() != 0 {
			return errCode(stderr, 64, errors.New("unexpected scan arguments"))
		}
		if *interactive {
			in = bufio.NewReaderSize(in, 8193)
			if err := onboard(ctx, in, stderr, feature, all, &roots, confirmEnv); err != nil {
				if errors.Is(err, context.Canceled) {
					fmt.Fprintln(stderr, "Oke, kita berhenti di sini. 0 file dihapus, 0 aplikasi di-uninstall, 0 proses dihentikan.")
					return 130
				}
				return errCode(stderr, 64, err)
			}
		}
		env := discovery.Detect()
		if (env.Type != "native" || env.Remote) && !*confirmEnv {
			return errCode(stderr, 64, fmt.Errorf("execution environment %s (host %s): run doctor, then explicitly pass --confirm-environment to scan this environment", env.Type, env.HostOS))
		}
		if *sampleDuration < time.Second || *sampleDuration > 30*time.Second {
			return errCode(stderr, 64, errors.New("sample-duration must be between 1s and 30s"))
		}
		if *maxFiles < 1 || *maxFiles > 100000 || *maxDepth < 0 || *maxDepth > 64 || *maxBytes < 0 || *maxBytes > 64<<30 || *timeout <= 0 || *timeout > 10*time.Minute {
			return errCode(stderr, 64, errors.New("invalid resource limits: files 1..100000, depth 0..64, bytes 0..64GiB, timeout 0..10m"))
		}
		features := []string{}
		if *all {
			features = []string{"junk", "performance", "applications", "duplicates"}
		} else {
			seen := map[string]bool{}
			for _, f := range strings.Split(*feature, ",") {
				f = strings.TrimSpace(f)
				if f != "junk" && f != "performance" && f != "applications" && f != "duplicates" {
					return errCode(stderr, 64, errors.New("select --feature junk,performance,applications,duplicates or --all"))
				}
				if !seen[f] {
					features = append(features, f)
					seen[f] = true
				}
			}
		}
		walkNeeded := false
		for _, f := range features {
			if f == "junk" || f == "duplicates" {
				walkNeeded = true
			}
		}
		if walkNeeded && len(roots) == 0 {
			return errCode(stderr, 64, errors.New("filesystem scans require explicit --scope; --all grants no whole-disk permission"))
		}
		scope := findings.Scope{Roots: []string{}, Exclusions: []string{}, MaxFiles: *maxFiles, MaxDepth: *maxDepth, MaxBytes: *maxBytes}
		for _, p := range roots {
			p, err := safety.Root(p)
			if err != nil {
				return errCode(stderr, 64, err)
			}
			scope.Roots = append(scope.Roots, p)
		}
		for _, p := range exclusions {
			abs, err := filepath.Abs(p)
			if err != nil {
				return errCode(stderr, 64, err)
			}
			scope.Exclusions = append(scope.Exclusions, filepath.Clean(abs))
		}
		if *format != "markdown" && *format != "json" && *format != "csv" {
			return errCode(stderr, 64, errors.New("unknown format"))
		}
		if *format == "csv" && len(features) != 1 {
			return errCode(stderr, 64, errors.New("CSV requires a single --feature"))
		}
		if *interactive {
			if err := interactiveSummary(stderr, env, features, scope, *timeout, *sampleDuration, *store, *dataDir); err != nil {
				return errCode(stderr, 64, err)
			}
			// onboard returns a buffered reader so prefetched input remains available.
			answer, err := readAnswer(ctx, in)
			if err != nil || !affirmative(answer) {
				fmt.Fprintln(stderr, "Oke, kita berhenti di sini. 0 file dihapus, 0 aplikasi di-uninstall, 0 proses dihentikan.")
				return 130
			}
		}
		start := time.Now()
		scanCtx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		var idBytes [12]byte
		if _, err := rand.Read(idBytes[:]); err != nil {
			return errCode(stderr, 1, err)
		}
		zone, _ := time.Now().Zone()
		report := findings.Report{SchemaVersion: "1.0", Product: buildinfo.ProductName, Version: buildinfo.Version, ScanID: "scan-" + hex.EncodeToString(idBytes[:]), Timestamp: start.UTC(), DisplayTimezone: zone, Environment: env, Scope: scope, SelectedFeatures: features, Method: "read-only-v1", Permissions: "current user only; no escalation", AccuracyNotes: []string{"No changes to file contents, applications or processes. Filesystem access time may be updated by the OS when reading.", "Unknown measurements remain null; snapshot evidence can become stale."}, Results: []findings.Result{}}
		if *interactive {
			fmt.Fprintln(stderr, "Sip, aku mulai cek sesuai pilihan tadi. Hasilnya muncul setelah selesai.")
		} else {
			fmt.Fprintln(stderr, "Scanning the selected execution environment in read-only mode; limits and exclusions apply.")
		}
		var inventory *scanner.Inventory
		if walkNeeded {
			inventory = scanner.Walk(scanCtx, scope)
			defer inventory.Close()
		}
		for _, f := range features {
			if scanCtx.Err() != nil {
				report.Results = append(report.Results, findings.Result{Feature: f, Support: "SKIPPED", Coverage: findings.Coverage{Status: "CANCELLED"}, Findings: []findings.Finding{}, Warnings: []string{"Scan interrupted or time budget reached"}})
				continue
			}
			var r findings.Result
			switch f {
			case "junk":
				r = junk.Collect(inventory, start)
			case "duplicates":
				r = duplicates.Collect(scanCtx, inventory, *maxBytes)
			case "performance":
				r = performance.CollectWithDuration(scanCtx, env, *sampleDuration)
			case "applications":
				r = applications.Collect(scanCtx, env)
			}
			report.Results = append(report.Results, decisionguide.Annotate(r, start))
		}
		report.ElapsedSeconds = time.Since(start).Seconds()
		if *store {
			st, err := getStore(*dataDir)
			if err != nil {
				return errCode(stderr, 1, err)
			}
			if err := st.Save(report); err != nil {
				return errCode(stderr, 1, err)
			}
			fmt.Fprintf(stderr, "Saved local report %s (exact paths may be sensitive).\n", report.ScanID)
		}
		reportFeature := ""
		if len(features) == 1 {
			reportFeature = features[0]
		}
		if err := displayReport(out, report, *format, reportFeature, *share); err != nil {
			return errCode(stderr, 1, err)
		}
		if ctx.Err() != nil {
			return 130
		}
		if scanCtx.Err() != nil {
			return 2
		}
		return coverageCode(report)
	}
	st, err := getStore(*dataDir)
	if err != nil {
		return errCode(stderr, 1, err)
	}
	if command == "plan" || command == "apply" || command == "action-status" {
		if *share {
			return errCode(stderr, 64, errors.New("action plans and journals require exact private targets; use share-safe export for scan reports instead"))
		}
		if *format != "markdown" && *format != "json" {
			return errCode(stderr, 64, errors.New("action output supports markdown or json"))
		}
		if fs.NArg() != 0 {
			return errCode(stderr, 64, errors.New("use action flags without positional arguments"))
		}
		if *timeout <= 0 || *timeout > 10*time.Minute {
			return errCode(stderr, 64, errors.New("action timeout must be 0..10m"))
		}
		return runAction(ctx, command, st, actionFlags{Enabled: *actionEnabled, BackupReviewed: *backupReviewed, BundleOnly: *bundleOnly, ScanID: *scanID, FindingID: *findingID, Action: *actionName, Target: *targetPath, Keep: *keepPath, PlanID: *planID, Approval: *approval, Format: *format, MaxBytes: *maxBytes, Timeout: *timeout}, out, stderr)
	}
	if command == "session" {
		if fs.NArg() < 1 {
			return errCode(stderr, 64, errors.New("session requires list, resume ID or cancel ID"))
		}
		switch fs.Arg(0) {
		case "list":
			if fs.NArg() != 1 {
				return 64
			}
			ids, err := st.List()
			if err != nil {
				return errCode(stderr, 1, err)
			}
			for _, id := range ids {
				fmt.Fprintln(out, id)
			}
			return 0
		case "resume":
			if fs.NArg() != 2 {
				return 64
			}
			if *format != "markdown" && *format != "json" {
				return errCode(stderr, 64, errors.New("session resume supports markdown or json; use report for CSV"))
			}
			r, err := st.Load(fs.Arg(1))
			if err != nil {
				return errCode(stderr, 1, err)
			}
			state, err := st.State(r.ScanID)
			if err != nil {
				return errCode(stderr, 1, err)
			}
			if *share {
				state.ScanID = "redacted-scan"
				for id, d := range state.Decisions {
					d.Note = "[REDACTED]"
					d.UpdatedAt = time.Time{}
					state.Decisions[id] = d
				}
			}
			if *format == "json" {
				var b strings.Builder
				if err := reports.Write(&b, r, "json", *feature, *share); err != nil {
					return errCode(stderr, 1, err)
				}
				if err := jsonOut(out, map[string]any{"report": json.RawMessage(b.String()), "review_state": state}); err != nil {
					return errCode(stderr, 1, err)
				}
			} else {
				if err := displayReport(out, r, "markdown", *feature, *share); err != nil {
					return errCode(stderr, 1, err)
				}
				if err := jsonOut(out, state); err != nil {
					return errCode(stderr, 1, err)
				}
			}
			return 0
		case "cancel":
			if fs.NArg() != 2 {
				return 64
			}
			if err := st.Cancel(fs.Arg(1)); err != nil {
				return errCode(stderr, 1, err)
			}
			fmt.Fprintln(out, "Review session cancelled; report retained. No source items changed.")
			return 0
		default:
			return errCode(stderr, 64, errors.New("unknown session subcommand"))
		}
	}
	if *scanID == "" {
		return errCode(stderr, 64, errors.New("--scan is required"))
	}
	r, err := st.Load(*scanID)
	if err != nil {
		return errCode(stderr, 1, err)
	}
	switch command {
	case "report":
		if fs.NArg() != 0 {
			return 64
		}
		if *summary {
			if *share {
				if err := displayReport(out, r, "markdown", *feature, true); err != nil {
					return errCode(stderr, 1, err)
				}
				return 0
			}
			for _, res := range r.Results {
				if *feature == "" || res.Feature == *feature {
					fmt.Fprintf(out, "%s: %s; support %s; %d findings; %d inaccessible\n", terminal(res.Feature), terminal(res.Coverage.Status), terminal(res.Support), len(res.Findings), res.Coverage.Inaccessible)
				}
			}
			fmt.Fprintln(out, "0 files removed, 0 apps uninstalled, 0 processes stopped.")
			return 0
		}
		if err := displayReport(out, r, *format, *feature, *share); err != nil {
			return errCode(stderr, 64, err)
		}
		return 0
	case "export":
		if fs.NArg() != 0 || *output == "" {
			return errCode(stderr, 64, errors.New("export requires --output FILE"))
		}
		if err := export(r, *format, *feature, *share, *output); err != nil {
			return errCode(stderr, 1, err)
		}
		fmt.Fprintln(out, "Report exported to", terminal(*output))
		return 0
	case "inspect", "explain", "reveal", "review":
		if fs.NArg() != 1 {
			return errCode(stderr, 64, errors.New("one finding ID is required"))
		}
		id := fs.Arg(0)
		if command == "review" {
			if err := st.Review(*scanID, id, *decision, *note); err != nil {
				return errCode(stderr, 64, err)
			}
			fmt.Fprintln(out, "Review decision saved; no source items changed.")
			return 0
		}
		if command == "reveal" {
			paths, err := reviewer.Reveal(r, id)
			if err != nil {
				return errCode(stderr, 1, err)
			}
			for _, p := range paths {
				fmt.Fprintf(out, "Navigate manually to containing folder: %q\n", p)
			}
			return 0
		}
		if command == "inspect" {
			i, err := reviewer.Inspect(r, id)
			if err != nil {
				return errCode(stderr, 1, err)
			}
			if err := jsonOut(out, i); err != nil {
				return 1
			}
			return 0
		}
		f, err := reviewer.Find(r, id)
		if err != nil {
			return errCode(stderr, 64, err)
		}
		if err := jsonOut(out, f); err != nil {
			return 1
		}
		return 0
	default:
		return errCode(stderr, 64, errors.New("unknown command; see --help"))
	}
}
func getStore(dir string) (*session.Store, error) {
	if dir == "" {
		var err error
		dir, err = session.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	return session.NewStore(dir), nil
}
func coverageCode(r findings.Report) int {
	code := 0
	for _, v := range r.Results {
		switch v.Coverage.Status {
		case "COMPLETED", "SKIPPED":
		case "PERMISSION_DENIED":
			if code == 0 {
				code = 4
			}
		case "UNSUPPORTED":
			if code == 0 {
				code = 3
			}
		default:
			code = 2
		}
	}
	return code
}
func export(r findings.Report, format, feature string, share bool, path string) error {
	// Render before creating a destination, so argument errors cannot leave a file.
	var b strings.Builder
	if err := reports.Write(&b, r, format, feature, share); err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := safety.NoSymlink(filepath.Dir(abs)); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(abs), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, werr := io.WriteString(f, b.String())
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func readAnswer(ctx context.Context, in io.Reader) (string, error) {
	r, ok := in.(*bufio.Reader)
	if !ok {
		r = bufio.NewReaderSize(in, 8193)
	}
	type answer struct {
		value string
		err   error
	}
	ch := make(chan answer, 1)
	go func() {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > 8192 {
			ch <- answer{"", errors.New("response exceeds 8192 bytes")}
			return
		}
		if err != nil && len(line) == 0 {
			ch <- answer{"", context.Canceled}
			return
		}
		ch <- answer{strings.TrimSpace(string(line)), nil}
	}()
	select {
	case <-ctx.Done():
		return "", context.Canceled
	case a := <-ch:
		return a.value, a.err
	}
}

// Bound interactive terminal display; saved reports and redirected exports remain complete.
func displayReport(out io.Writer, r findings.Report, format, feature string, share bool) error {
	f, tty := out.(*os.File)
	if tty {
		st, err := f.Stat()
		tty = err == nil && st.Mode()&os.ModeCharDevice != 0
	}
	if tty && format == "markdown" {
		results := make([]findings.Result, len(r.Results))
		copy(results, r.Results)
		r.Results = results
		for i := range r.Results {
			if len(r.Results[i].Findings) > 20 {
				total := len(r.Results[i].Findings)
				r.Results[i].Findings = r.Results[i].Findings[:20]
				r.Results[i].Warnings = append(append([]string{}, r.Results[i].Warnings...), fmt.Sprintf("Terminal preview: first 20 of %d findings. Use report/export for the stored complete inventory, or redirect scan output to a file.", total))
			}
		}
	}
	return reports.Write(out, r, format, feature, share)
}
