// Run from the repository root: go run ./scripts/refresh-examples.go
// Only a labelled synthetic fixture is accepted; never use a device report.
package main

import (
	"encoding/json"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/decision"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/findings"
	"github.com/RaditteAnggoro/agent-doctor-for-your-devices/internal/core/reports"
	"os"
)

func main() {
	data, err := os.ReadFile("examples/sample-findings.json")
	must(err)
	var r findings.Report
	must(json.Unmarshal(data, &r))
	if r.Method != "synthetic" {
		panic("only synthetic fixtures may generate examples")
	}
	for i, x := range r.Results {
		r.Results[i] = decision.Annotate(x, r.Timestamp)
	}
	for _, o := range []struct{ path, format, feature string }{{"examples/sample-findings.json", "json", ""}, {"examples/sample-summary.md", "markdown", ""}, {"examples/sample-review.csv", "csv", "junk"}, {"examples/sample-duplicates.csv", "csv", "duplicates"}} {
		f, err := os.Create(o.path)
		must(err)
		must(reports.Write(f, r, o.format, o.feature, false))
		must(f.Close())
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
