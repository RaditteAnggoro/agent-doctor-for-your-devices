package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
)

func syntheticReport() findings.Report {
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	file := findings.File{Path: "/synthetic/資料/file.tmp", Size: 5, Modified: stamp, Device: "synthetic-device", Identity: "synthetic-id"}
	base := findings.Finding{ID: "J-000001", Feature: "junk", Title: "=HYPERLINK(\"https://invalid.test\")\n\x1b[31m<script>[x](bad)", Paths: []string{file.Path}, Risk: "MODERATE", Confidence: "MEDIUM", Recommendation: "INSPECT", WhyFlagged: "Synthetic category and age", Evidence: []string{"Synthetic metadata"}, Limitations: []string{"Synthetic fixture only"}, PossibleConsequences: "Loss of wanted data", ManualInspection: "Review exact path manually", Junk: &findings.Junk{File: file, Basename: "=formula.tmp", Kind: "file", Category: "temporary_file", ReviewStatus: "REVIEW_WITH_CAUTION"}}
	dup := base
	dup.ID = "D-000001"
	dup.Feature = "duplicates"
	dup.Title = "Exact synthetic match"
	dup.Junk = nil
	second := file
	second.Path = "/synthetic/copy.tmp"
	second.Identity = "second-id"
	dup.Duplicate = &findings.Duplicate{MatchType: "EXACT_CONTENT", HashAlgorithm: "SHA-256", Digest: strings.Repeat("a", 64), Members: []findings.File{file, second}, SuggestedRetain: file.Path, RetainReason: "Neutral path ordering", LogicalRedundantBytes: 5, BackupWarning: "Unknown"}
	perf := base
	perf.ID = "P-000001"
	perf.Feature = "performance"
	perf.Title = "Synthetic observation"
	perf.Junk = nil
	perf.Performance = &findings.Performance{CPUSemantics: "Unavailable", ObservationSeconds: 1, ObservedImpact: "Unknown"}
	app := base
	app.ID = "A-000001"
	app.Feature = "applications"
	app.Title = "Synthetic application"
	app.Junk = nil
	app.Application = &findings.Application{Name: "Synthetic App", Source: "synthetic", UsageProvenance: "UNKNOWN", UninstallMethod: "Use the OS interface"}
	r := findings.Report{SchemaVersion: "1.0", Product: "Agent Doctor For Your Devices", Version: "0.1.0", ScanID: "synthetic-scan-001", Timestamp: stamp, DisplayTimezone: "UTC", Environment: findings.Environment{OS: "synthetic", HostOS: "synthetic", Architecture: "synthetic", Type: "fixture"}, Scope: findings.Scope{Roots: []string{"/synthetic"}, MaxFiles: 100, MaxDepth: 5, MaxBytes: 10000}, SelectedFeatures: []string{"junk", "performance", "applications", "duplicates"}, Method: "synthetic", Permissions: "No actual device access", AccuracyNotes: []string{"SYNTHETIC: not actual observations"}}
	for _, f := range []findings.Finding{base, perf, app, dup} {
		r.Results = append(r.Results, findings.Result{Feature: f.Feature, Support: "SUPPORTED", Coverage: findings.Coverage{Status: "COMPLETED"}, Findings: []findings.Finding{f}, CollectionMethod: "synthetic metadata"})
	}
	return r
}

func TestFormatsAndUntrustedText(t *testing.T) {
	r := syntheticReport()
	var jsonBuf, md, csvBuf bytes.Buffer
	if err := Write(&jsonBuf, r, "json", "", false); err != nil {
		t.Fatal(err)
	}
	var decoded findings.Report
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Results[0].Findings[0].Paths[0] != r.Results[0].Findings[0].Paths[0] {
		t.Fatal("JSON lost exact local path")
	}
	if bytes.Contains(jsonBuf.Bytes(), []byte{27}) {
		t.Fatal("raw terminal escape in JSON")
	}
	if err := Write(&md, r, "markdown", "", false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(md.String(), "<script>") || bytes.Contains(md.Bytes(), []byte{27}) || strings.Contains(md.String(), "### J-000001 — =HYPERLINK(\"https://invalid.test\")\n") {
		t.Fatal("unsafe Markdown heading")
	}
	if !strings.Contains(md.String(), "Logical redundant bytes: 5") || !strings.Contains(md.String(), "0 files removed / 0 apps uninstalled / 0 processes stopped") {
		t.Fatal("missing totals")
	}
	if err := Write(&csvBuf, r, "csv", "junk", false); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&csvBuf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var titleIndex int
	for i, h := range rows[0] {
		if h == "title" {
			titleIndex = i
		}
	}
	if !strings.HasPrefix(rows[1][titleIndex], "'=HYPERLINK") {
		t.Fatal("CSV formula was not neutralized")
	}
	if err := Write(&bytes.Buffer{}, r, "csv", "", false); err == nil {
		t.Fatal("mixed-feature CSV accepted")
	}
	var dup bytes.Buffer
	if err := Write(&dup, r, "csv", "duplicates", false); err != nil {
		t.Fatal(err)
	}
	groups, err := csv.NewReader(&dup).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 3 {
		t.Fatal("duplicate group members not exported")
	}
}

func TestShareSafeRemovesNestedAndUnexpectedStrings(t *testing.T) {
	r := syntheticReport()
	secret := "private-customer-secret-987"
	r.Results[0].Warnings = []string{secret}
	r.Results[1].Findings[0].Performance.Owner = &secret
	r.Results[2].Findings[0].Application.DependencyNotes = secret
	r.Results[3].Findings[0].Duplicate.Members[0].Identity = secret
	for _, format := range []string{"json", "markdown", "csv"} {
		var b bytes.Buffer
		feature := ""
		if format == "csv" {
			feature = "applications"
		}
		if err := Write(&b, r, format, feature, true); err != nil {
			t.Fatal(err)
		}
		for _, needle := range []string{secret, "/synthetic", "file.tmp", "Synthetic App", "synthetic-scan-001"} {
			if strings.Contains(b.String(), needle) {
				t.Fatalf("%s leaked %q", format, needle)
			}
		}
	}
}

func TestCSVPrefixes(t *testing.T) {
	for _, s := range []string{"=1+1", "+SUM(A1)", "-2", "@call()", "\t=cmd()", "\r@cmd()", " \t+cmd()", "\u202e=cmd()"} {
		if !strings.HasPrefix(csvCell(s), "'") {
			t.Errorf("not escaped: %q", s)
		}
	}
	if got := csvCell("ordinary, Unicode 資料"); got != "ordinary, Unicode 資料" {
		t.Fatal(got)
	}
}

func TestLargeIntegersStayExact(t *testing.T) {
	r := syntheticReport()
	const size int64 = 9007199254740993
	r.Results[0].Findings[0].Junk.File.Size = size
	for _, format := range []string{"json", "markdown", "csv"} {
		var b bytes.Buffer
		if err := Write(&b, r, format, "junk", false); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "9007199254740993") {
			t.Fatalf("%s rounded large integer", format)
		}
	}
}

func TestJSONFormatControlsRemainExactButVisible(t *testing.T) {
	r := syntheticReport()
	path := "/synthetic/\u202efile\U000e0001.tmp"
	r.Results[0].Findings[0].Paths = []string{path}
	var b bytes.Buffer
	if err := Write(&b, r, "json", "junk", false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\u202e\U000e0001") {
		t.Fatal("raw invisible formatting character")
	}
	var decoded findings.Report
	if err := json.Unmarshal(b.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Results[0].Findings[0].Paths[0] != path {
		t.Fatal("exact JSON path was lost")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }
func TestWriteErrorsPropagate(t *testing.T) {
	for _, format := range []string{"json", "markdown", "csv"} {
		if err := Write(failingWriter{}, syntheticReport(), format, "junk", false); err == nil {
			t.Fatal(format)
		}
	}
}

func TestEmptyPartialCSVPreservesCoverage(t *testing.T) {
	r := syntheticReport()
	r.Results[0].Findings = nil
	r.Results[0].Coverage.Status = "PERMISSION_DENIED"
	r.Results[0].Warnings = []string{"Synthetic inaccessible root"}
	var b bytes.Buffer
	if err := Write(&b, r, "csv", "junk", false); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || !strings.Contains(b.String(), "PERMISSION_DENIED") || !strings.Contains(b.String(), "coverage") {
		t.Fatal("empty inventory lost collection state")
	}
}

// validateSchema implements the vocabulary used by this project's schemas.
// It tests the serialized contract against the independently maintained schema,
// including negative cases; it is not a general-purpose JSON Schema engine.
func validateSchema(t *testing.T, schema map[string]any, value any) bool {
	t.Helper()
	if ref, ok := schema["$ref"].(string); ok {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "schemas", ref))
		if err != nil {
			t.Fatal(err)
		}
		var s map[string]any
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatal(err)
		}
		return validateSchema(t, s, value)
	}
	for _, op := range []string{"oneOf", "anyOf"} {
		if choices, ok := schema[op].([]any); ok {
			matches := 0
			for _, raw := range choices {
				if validateSchema(t, raw.(map[string]any), value) {
					matches++
				}
			}
			if (op == "oneOf" && matches != 1) || (op == "anyOf" && matches == 0) {
				return false
			}
		}
	}
	if want, ok := schema["const"]; ok && !reflect.DeepEqual(want, value) {
		return false
	}
	if choices, ok := schema["enum"].([]any); ok {
		found := false
		for _, want := range choices {
			if reflect.DeepEqual(want, value) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if typ, ok := schema["type"]; ok {
		types := []any{typ}
		if list, ok := typ.([]any); ok {
			types = list
		}
		matched := false
		for _, raw := range types {
			switch raw {
			case "null":
				matched = matched || value == nil
			case "string":
				_, ok := value.(string)
				matched = matched || ok
			case "boolean":
				_, ok := value.(bool)
				matched = matched || ok
			case "number":
				_, ok := value.(float64)
				matched = matched || ok
			case "integer":
				n, ok := value.(float64)
				matched = matched || (ok && n == float64(int64(n)))
			case "object":
				_, ok := value.(map[string]any)
				matched = matched || ok
			case "array":
				_, ok := value.([]any)
				matched = matched || ok
			}
		}
		if !matched {
			return false
		}
	}
	if s, ok := value.(string); ok {
		if p, ok := schema["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(s) {
			return false
		}
	}
	if n, ok := value.(float64); ok {
		if min, ok := schema["minimum"].(float64); ok && n < min {
			return false
		}
	}
	if array, ok := value.([]any); ok {
		if min, ok := schema["minItems"].(float64); ok && len(array) < int(min) {
			return false
		}
		if max, ok := schema["maxItems"].(float64); ok && len(array) > int(max) {
			return false
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for _, v := range array {
				if !validateSchema(t, items, v) {
					return false
				}
			}
		}
	}
	if object, ok := value.(map[string]any); ok {
		if required, ok := schema["required"].([]any); ok {
			for _, key := range required {
				if _, ok := object[key.(string)]; !ok {
					return false
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		for key, v := range object {
			if raw, ok := props[key]; ok {
				if !validateSchema(t, raw.(map[string]any), v) {
					return false
				}
			} else if allowed, ok := schema["additionalProperties"].(bool); ok && !allowed {
				return false
			} else if extra, ok := schema["additionalProperties"].(map[string]any); ok {
				if !validateSchema(t, extra, v) {
					return false
				}
			}
		}
	}
	return true
}

func TestSerializedReportsMatchPublishedSchema(t *testing.T) {
	data, err := os.ReadFile("../../../schemas/scan-report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile("../../../examples/sample-findings.json")
	if err != nil {
		t.Fatal(err)
	}
	var exampleValue any
	if err := json.Unmarshal(example, &exampleValue); err != nil {
		t.Fatal(err)
	}
	if !validateSchema(t, schema, exampleValue) {
		t.Fatal("published synthetic example violates schema")
	}
	for _, shareSafe := range []bool{false, true} {
		var b bytes.Buffer
		if err := Write(&b, syntheticReport(), "json", "", shareSafe); err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(b.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if !validateSchema(t, schema, value) {
			t.Fatalf("serialized report violates schema; shareSafe=%v", shareSafe)
		}
		value["actual_changes"].(map[string]any)["files_removed"] = float64(1)
		if validateSchema(t, schema, value) {
			t.Fatal("schema accepted nonzero changes")
		}
	}
	var b bytes.Buffer
	_ = Write(&b, syntheticReport(), "json", "", false)
	var value map[string]any
	_ = json.Unmarshal(b.Bytes(), &value)
	first := value["results"].([]any)[0].(map[string]any)["findings"].([]any)[0].(map[string]any)
	delete(first, "junk")
	if validateSchema(t, schema, value) {
		t.Fatal("schema accepted finding without feature evidence")
	}
}
