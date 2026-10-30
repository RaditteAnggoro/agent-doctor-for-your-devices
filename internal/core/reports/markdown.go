package reports

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

func object(v any) map[string]any { x, _ := v.(map[string]any); return x }
func values(v any) []any          { x, _ := v.([]any); return x }
func known(v any) string {
	if v == nil || v == "" {
		return "UNKNOWN (not collected in this scan)"
	}
	return str(v)
}
func boolean(v any) string {
	if x, ok := v.(bool); ok {
		if x {
			return "Yes"
		}
		return "No"
	}
	if v == "[REDACTED]" {
		return str(v)
	}
	return "UNKNOWN"
}
func brief(v any) string {
	if v == nil || v == "" {
		return "UNKNOWN"
	}
	return str(v)
}
func dateSummary(v any, at time.Time) string {
	if v == nil || v == "" {
		return "UNKNOWN"
	}
	d, e := time.Parse(time.RFC3339Nano, str(v))
	if e != nil {
		return str(v)
	}
	if d.IsZero() {
		return "UNKNOWN"
	}
	if !at.IsZero() && !d.After(at) {
		return fmt.Sprintf("%s (%d days)", d.Format("2006-01-02"), int64(at.Sub(d).Hours()/24))
	}
	return d.Format("2006-01-02")
}
func sizeSummary(a map[string]any) string {
	s := bytesText(a["install_size_bytes"])
	if a["install_size_bytes"] == nil {
		s = "UNKNOWN"
	}
	if a["size_status"] == "PARTIAL" && a["install_size_bytes"] != nil {
		s = "at least " + s
	}
	return s + " / " + brief(a["size_status"])
}
func bytesText(v any) string {
	n, ok := v.(json.Number)
	if !ok {
		return known(v)
	}
	i, err := n.Int64()
	if err != nil || i < 0 {
		return n.String() + " bytes"
	}
	if i < 1000 {
		return fmt.Sprintf("%d bytes", i)
	}
	unit, div := "KB", float64(1000)
	if i >= 1e9 {
		unit, div = "GB", 1e9
	} else if i >= 1e6 {
		unit, div = "MB", 1e6
	}
	return fmt.Sprintf("%.2f %s (%d bytes)", float64(i)/div, unit, i)
}
func dateText(v any, at time.Time) string {
	if v == nil || v == "" {
		return "UNKNOWN (not collected in this scan)"
	}
	text := str(v)
	d, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return text
	}
	if d.IsZero() {
		return "UNKNOWN"
	}
	if !at.IsZero() && !d.After(at) {
		return fmt.Sprintf("%s (%d days before scan)", text, int64(at.Sub(d).Hours()/24))
	}
	return text
}
func table(b *strings.Builder, headers []string, rows [][]string) {
	for _, h := range headers {
		fmt.Fprintf(b, "| %s ", markdown(h))
	}
	fmt.Fprintln(b, "|")
	for range headers {
		fmt.Fprint(b, "| --- ")
	}
	fmt.Fprintln(b, "|")
	for _, row := range rows {
		for _, cell := range row {
			fmt.Fprintf(b, "| %s ", markdown(cell))
		}
		fmt.Fprintln(b, "|")
	}
	fmt.Fprintln(b)
}
func rowFields(b *strings.Builder, data map[string]any, excluded ...string) {
	skip := map[string]bool{}
	for _, k := range excluded {
		skip[k] = true
	}
	flat := map[string]string{}
	var visit func(map[string]any, string)
	visit = func(data map[string]any, prefix string) {
		for key, v := range data {
			if prefix == "" && skip[key] {
				continue
			}
			label := prefix + strings.ReplaceAll(key, "_", " ")
			if child, ok := v.(map[string]any); ok {
				visit(child, label+" / ")
			} else if list, ok := v.([]any); ok {
				parts := []string{}
				for _, x := range list {
					parts = append(parts, known(x))
				}
				if len(parts) == 0 {
					flat[label] = "None recorded"
				} else {
					flat[label] = strings.Join(parts, "; ")
				}
			} else {
				flat[label] = known(v)
			}
		}
	}
	visit(data, "")
	keys := []string{}
	for key := range flat {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := [][]string{}
	for _, key := range keys {
		rows = append(rows, []string{key, flat[key]})
	}
	if len(rows) > 0 {
		table(b, []string{"Evidence field", "Recorded value"}, rows)
	}
}
func bullets(b *strings.Builder, label string, v any) {
	xs := values(v)
	if len(xs) == 0 {
		return
	}
	fmt.Fprintf(b, "**%s**\n\n", label)
	for _, x := range xs {
		fmt.Fprintf(b, "- %s\n", markdown(known(x)))
	}
	fmt.Fprintln(b)
}

func writeMarkdown(w io.Writer, r map[string]any) error {
	var b strings.Builder
	at, _ := time.Parse(time.RFC3339Nano, str(r["timestamp"]))
	fmt.Fprint(&b, "# Agent Doctor For Your Devices — Review report\n\n")
	fmt.Fprintf(&b, "Scan: %s · Mode: READ-ONLY\n\n", markdown(known(r["scan_id"])))
	fmt.Fprint(&b, "Use these measurements, their sources and the questions below to decide what to inspect or keep. No finding approves uninstall or deletion. All items are retained; unknown values remain unknown.\n\n")
	results := values(r["results"])
	for _, raw := range results {
		x := object(raw)
		feature := str(x["feature"])
		coverage := object(x["coverage"])
		items := values(x["findings"])
		fmt.Fprintf(&b, "## %s\n\nSupport: %s · Coverage: %s · Findings: %d\n\n", markdown(feature), markdown(known(x["support"])), markdown(known(coverage["status"])), len(items))
		if len(items) == 0 {
			if coverage["status"] == "COMPLETED" {
				fmt.Fprint(&b, "No candidates found within the measured scope.\n\n")
			} else {
				fmt.Fprint(&b, "Collection was incomplete or unavailable; an empty list is not evidence of no issues.\n\n")
			}
		}
		featureSummary(&b, feature, items, at)
		fmt.Fprintf(&b, "Collection method: %s\n\n", markdown(known(x["collection_method"])))
		rowFields(&b, coverage)
		bullets(&b, "Coverage warnings", x["warnings"])
		bullets(&b, "Collection errors", x["errors"])
		bullets(&b, "Observations", x["observations"])
		var logical int64
		overflow := false
		for _, item := range items {
			f := object(item)
			fmt.Fprintf(&b, "### %s — %s\n\nRisk: %s · Confidence: %s · Guidance: %s\n\n", markdown(known(f["id"])), markdown(known(f["title"])), markdown(known(f["risk"])), markdown(known(f["confidence"])), markdown(known(f["recommendation"])))
			fmt.Fprintf(&b, "**Why review:** %s\n\n**Possible consequences:** %s\n\n**Manual inspection:** %s\n\n", markdown(known(f["why_flagged"])), markdown(known(f["possible_consequences"])), markdown(known(f["manual_inspection"])))
			bullets(&b, "Exact locations", f["paths"])
			bullets(&b, "Evidence", f["evidence"])
			bullets(&b, "Limitations", f["limitations"])
			decisionCard(&b, object(f["decision"]))
			key := map[string]string{"junk": "junk", "applications": "application", "performance": "performance", "duplicates": "duplicate"}[feature]
			data := object(f[key])
			if feature == "duplicates" {
				duplicateMembers(&b, data, at)
				rowFields(&b, data, "members")
			} else {
				rowFields(&b, data)
			}
			var amount any
			if feature == "duplicates" {
				amount = data["logical_redundant_bytes"]
			}
			if feature == "junk" {
				amount = object(data["file"])["size"]
			}
			if feature == "junk" || feature == "duplicates" {
				n, ok := amount.(json.Number)
				if !ok {
					overflow = true
				} else {
					i, e := n.Int64()
					if e != nil || i < 0 || logical > math.MaxInt64-i {
						overflow = true
					} else {
						logical += i
					}
				}
			}
		}
		logicalText := fmt.Sprint(logical)
		if overflow {
			logicalText = "UNKNOWN (total exceeds representable range)"
		}
		if feature == "junk" {
			fmt.Fprintf(&b, "Candidate logical bytes: %s. Physical reclaimable space: UNKNOWN.\n\n", logicalText)
		}
		if feature == "duplicates" {
			fmt.Fprintf(&b, "Logical redundant bytes: %s. Physical reclaimable space: UNKNOWN.\n\n", logicalText)
		}
	}
	fmt.Fprint(&b, "## Scan provenance and scope\n\n")
	metadata := map[string]any{}
	for k, v := range r {
		if k != "results" {
			metadata[k] = v
		}
	}
	rowFields(&b, metadata)
	changes := object(r["actual_changes"])
	fmt.Fprintf(&b, "Changes: %v files removed / %v apps uninstalled / %v processes stopped.\n", changes["files_removed"], changes["apps_uninstalled"], changes["processes_stopped"])
	_, err := io.WriteString(w, b.String())
	return err
}

func featureSummary(b *strings.Builder, feature string, items []any, at time.Time) {
	rows := [][]string{}
	for _, raw := range items {
		f := object(raw)
		decision := object(f["decision"])
		choice := known(decision["state"])
		if len(decision) == 0 {
			choice = "Not assessed in this scan"
		}
		switch feature {
		case "applications":
			a := object(f["application"])
			rows = append(rows, []string{known(f["id"]), known(a["name"]), brief(a["version"]), sizeSummary(a), dateSummary(a["last_usage"], at), boolean(a["running"]), boolean(a["system_app"]) + " / " + known(a["app_role"]), known(f["risk"]) + " / " + choice})
		case "junk":
			j := object(f["junk"])
			file := object(j["file"])
			rows = append(rows, []string{known(f["id"]), known(file["path"]), bytesText(file["size"]), dateText(file["modified"], at), known(j["category"]), known(f["risk"]) + " / " + choice})
		case "duplicates":
			d := object(f["duplicate"])
			rows = append(rows, []string{known(f["id"]), known(d["match_type"]), fmt.Sprint(len(values(d["members"]))), bytesText(d["logical_redundant_bytes"]), bytesText(d["physical_reclaimable_bytes"]), known(f["risk"]) + " / " + choice})
		case "performance":
			p := object(f["performance"])
			name := known(p["process_name"])
			if p["process_name"] == nil {
				name = known(f["title"])
			}
			rows = append(rows, []string{known(f["id"]), name, known(p["cpu_percent"]), bytesText(p["rss_bytes"]), known(p["observation_seconds"]), known(f["risk"]) + " / " + choice})
		}
	}
	if len(rows) == 0 {
		return
	}
	switch feature {
	case "applications":
		table(b, []string{"ID", "Application", "Version", "Logical app size / measurement", "Last-used signal", "Running", "System / role", "Risk / review state"}, rows)
		fmt.Fprint(b, "Last-used metadata is a source-specific opening/launch signal, not complete activity history; its provenance and missing-data reasons are recorded in each application card. Missing data never proves that an application is unused. A PARTIAL size is a measured lower bound; package estimates and logical size do not promise physical storage recovery.\n\n")
	case "junk":
		table(b, []string{"ID", "Exact path", "Logical size", "Modified / age", "Category", "Risk / review state"}, rows)
		fmt.Fprint(b, "Modification age is not last use. Confirm offline reuse, active work and backup needs before any future removal review.\n\n")
	case "duplicates":
		table(b, []string{"Group ID", "Match", "Members", "Logical redundant size", "Physical recovery", "Risk / review state"}, rows)
		fmt.Fprint(b, "Review every member and its role. Matching content can be intentional backup or project/application data; none of these files is selected for deletion.\n\n")
	case "performance":
		table(b, []string{"ID", "Process / observation", "CPU % (100% = one logical core)", "RSS / working set", "Window seconds", "Risk / review state"}, rows)
		fmt.Fprint(b, "Rows are limited by collector coverage and are not a complete CPU ranking. RSS can include shared pages. Compare the actual observation window with the workload before diagnosing persistent slowness.\n\n")
	}
}
func decisionCard(b *strings.Builder, d map[string]any) {
	if len(d) == 0 {
		fmt.Fprint(b, "**Decision preparation:** Not assessed in this stored scan. Review the recorded evidence and collect missing facts before a later action.\n\n")
		return
	}
	fmt.Fprintf(b, "**Decision preparation:** %s · Suggested choice: %s · Review type: %s\n\n", markdown(known(d["state"])), markdown(known(d["suggested_choice"])), markdown(known(d["action_type"])))
	bullets(b, "Reasons for this choice", d["reasons"])
	bullets(b, "Missing evidence", d["missing_evidence"])
	bullets(b, "Before any later action", d["action_blockers"])
	bullets(b, "Questions for your decision", d["questions"])
	bullets(b, "Next review steps", d["next_steps"])
	fmt.Fprintf(b, "Potential logical bytes under review: %s. This is not a physical recovery estimate or action approval.\n\n", markdown(bytesText(d["potential_logical_bytes"])))
}
func duplicateMembers(b *strings.Builder, d map[string]any, at time.Time) {
	rows := [][]string{}
	for _, raw := range values(d["members"]) {
		m := object(raw)
		flags := fmt.Sprintf("hardlink=%s; symlink=%s; sparse=%s; clone=%s; cloud=%s", boolean(m["hardlink"]), boolean(m["symlink"]), boolean(m["sparse"]), boolean(m["clone"]), boolean(m["cloud"]))
		rows = append(rows, []string{known(m["path"]), bytesText(m["size"]), dateText(m["modified"], at), flags, known(m["device"]) + " / " + known(m["identity"])})
	}
	table(b, []string{"Member exact path", "Logical size", "Modified / age", "Link / allocation observations", "Device / file identity"}, rows)
}
