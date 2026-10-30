// Package reports renders complete, non-executable review inventories.
package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
)

var findingIDPattern = regexp.MustCompile(`^[JPAD]-[0-9]{6}$`)

// Text makes untrusted text safe for a terminal without hiding control bytes.
func Text(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			fmt.Fprintf(&b, "\\u{%04x}", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func markdown(s string) string {
	s = Text(s)
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "|", "\\|", "#", "\\#")
	return r.Replace(s)
}

// Write emits the full selected inventory. CSV intentionally requires a single
// feature so process samples cannot be confused with files or applications.
func Write(w io.Writer, report findings.Report, format, feature string, shareSafe bool) error {
	if feature != "" {
		if !validFeature(feature) {
			return fmt.Errorf("unknown feature %q", Text(feature))
		}
		filtered := make([]findings.Result, 0)
		for _, r := range report.Results {
			if r.Feature == feature {
				filtered = append(filtered, r)
			}
		}
		report.Results = filtered
		report.SelectedFeatures = []string{feature}
	}
	if format != "json" && format != "markdown" && format != "csv" {
		return errors.New("format must be markdown, json, or csv")
	}
	if format == "csv" && feature == "" {
		return errors.New("CSV requires --feature junk|performance|applications|duplicates; export each feature separately")
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if shareSafe {
		redact(value, "")
	}
	if format == "json" {
		var encoded bytes.Buffer
		enc := json.NewEncoder(&encoded)
		enc.SetIndent("", "  ")
		if err := enc.Encode(value); err != nil {
			return err
		}
		// JSON escapes retain exact decoded values while preventing invisible
		// direction/format controls from changing a terminal's presentation.
		var visible strings.Builder
		for _, r := range encoded.String() {
			if unicode.In(r, unicode.Cf) {
				if r <= 0xffff {
					fmt.Fprintf(&visible, "\\u%04x", r)
				} else {
					a, b := utf16.EncodeRune(r)
					fmt.Fprintf(&visible, "\\u%04x\\u%04x", a, b)
				}
			} else {
				visible.WriteRune(r)
			}
		}
		_, err := io.WriteString(w, visible.String())
		return err
	}
	if format == "csv" {
		return writeCSV(w, value, feature)
	}
	return writeMarkdown(w, value)
}

func validFeature(s string) bool {
	return s == "junk" || s == "performance" || s == "applications" || s == "duplicates"
}

// Only enumerations with validated values survive redaction. Arbitrary native
// tool output, usernames, identities, hashes, filenames and even notes disappear.
func redact(v any, key string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok {
				if k == "scan_id" {
					x[k] = "redacted-scan"
				} else if !publicValue(k, s) {
					x[k] = "[REDACTED]"
				}
			} else {
				redact(val, k)
			}
		}
	case []any:
		for i, val := range x {
			if s, ok := val.(string); ok {
				if !publicValue(key, s) {
					x[i] = "[REDACTED]"
				}
			} else {
				redact(val, key)
			}
		}
	}
}

func publicValue(key, value string) bool {
	if key == "id" && findingIDPattern.MatchString(value) {
		return true
	}
	var permitted string
	switch key {
	case "product":
		permitted = "Agent Doctor For Your Devices"
	case "version":
		permitted = "0.1.0|0.2.0|0.3.0"
	case "schema_version":
		permitted = "1.0|1|0.1.0"
	case "feature", "selected_features":
		permitted = "junk|performance|applications|duplicates"
	case "support":
		permitted = "SUPPORTED|PARTIAL|UNSUPPORTED|PERMISSION_DENIED|NOT_TESTED|SKIPPED"
	case "status":
		permitted = "COMPLETED|PARTIAL|UNSUPPORTED|PERMISSION_DENIED|SKIPPED|FAILED|CANCELLED"
	case "risk":
		permitted = "LOW|MODERATE|HIGH|PROTECTED|UNKNOWN"
	case "confidence":
		permitted = "HIGH|MEDIUM|LOW|UNVERIFIED"
	case "recommendation":
		permitted = "KEEP|INSPECT|REVIEW_LATER|MANUAL_ACTION_POSSIBLE|DO_NOT_TOUCH"
	case "match_type":
		permitted = "EXACT_CONTENT|SIMILAR_IMAGE_REVIEW_ONLY|POSSIBLE_SAME_NAME_UNVERIFIED"
	case "hash_algorithm":
		permitted = "SHA-256|SHA256"
	case "review_status":
		permitted = "REVIEW_LOW_RISK|REVIEW_WITH_CAUTION|KEEP_RECOMMENDED|PROTECTED|UNKNOWN"
	case "state":
		permitted = "NEEDS_REVIEW|BLOCKED|OBSERVE"
	case "suggested_choice":
		permitted = "INSPECT|KEEP|DO_NOT_TOUCH|COMPARE_COPIES|OBSERVE_LONGER"
	case "action_type":
		permitted = "MANUAL_UNINSTALL_REVIEW|MANUAL_FILE_REVIEW|INVESTIGATE_PROCESS|COMPARE_DUPLICATES"
	case "size_status":
		permitted = "COMPLETED|PARTIAL|ESTIMATED|UNKNOWN"
	case "usage_status":
		permitted = "AVAILABLE|UNKNOWN"
	case "app_role":
		permitted = "MAIN|HELPER|UNINSTALLER|UNKNOWN"
	case "kind":
		permitted = "file|directory"
	}
	for _, p := range strings.Split(permitted, "|") {
		if p != "" && p == value {
			return true
		}
	}
	return false
}

func writeCSV(w io.Writer, report map[string]any, feature string) error {
	rows := []map[string]string{}
	metadata := map[string]any{}
	for k, v := range report {
		if k != "results" {
			metadata[k] = v
		}
	}
	results, _ := report["results"].([]any)
	for _, raw := range results {
		r, _ := raw.(map[string]any)
		items, _ := r["findings"].([]any)
		resultMetadata := map[string]any{}
		for k, v := range r {
			if k != "findings" {
				resultMetadata[k] = v
			}
		}
		if len(items) == 0 {
			rows = append(rows, map[string]string{"record_type": "coverage", "scan_id": str(report["scan_id"]), "feature": feature, "scan_metadata": str(metadata), "collection_metadata": str(resultMetadata), "coverage": str(r["coverage"])})
		}
		for _, rawItem := range items {
			f, _ := rawItem.(map[string]any)
			flat := make(map[string]string)
			flatten(flat, "", f)
			flat["scan_id"] = str(report["scan_id"])
			flat["coverage"] = str(r["coverage"])
			flat["record_type"] = "finding"
			flat["scan_metadata"] = str(metadata)
			flat["collection_metadata"] = str(resultMetadata)
			if feature == "duplicates" {
				d, _ := f["duplicate"].(map[string]any)
				members, _ := d["members"].([]any)
				delete(flat, "duplicate.members")
				for i, member := range members {
					row := make(map[string]string)
					for k, v := range flat {
						row[k] = v
					}
					row["member_index"] = fmt.Sprint(i + 1)
					if m, ok := member.(map[string]any); ok {
						flatten(row, "member.", m)
					}
					rows = append(rows, row)
				}
			} else {
				rows = append(rows, flat)
			}
		}
	}
	keys := map[string]bool{"scan_id": true, "id": true, "feature": true, "coverage": true}
	for _, row := range rows {
		for k := range row {
			keys[k] = true
		}
	}
	header := make([]string, 0, len(keys))
	for k := range keys {
		header = append(header, k)
	}
	sort.Strings(header)
	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		values := make([]string, len(header))
		for i, k := range header {
			values[i] = csvCell(row[k])
		}
		if err := cw.Write(values); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func flatten(out map[string]string, prefix string, value map[string]any) {
	for k, v := range value {
		if m, ok := v.(map[string]any); ok {
			flatten(out, prefix+k+".", m)
		} else {
			out[prefix+k] = str(v)
		}
	}
}
func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(data)
}
func csvCell(s string) string {
	// Prefix before stripping controls: spreadsheet importers differ in whether
	// leading whitespace and control bytes are ignored before formula evaluation.
	trimmed := strings.TrimLeftFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.In(r, unicode.Cf) })
	unsafe := len(s) > 0 && (unicode.IsControl([]rune(s)[0]) || unicode.In([]rune(s)[0], unicode.Cf))
	if len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		unsafe = true
	}
	if unsafe {
		return "'" + Text(s)
	}
	return Text(s)
}
