package par3bench

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/procmeasure"
)

func rssResults() *Results {
	results := &Results{
		Schema: ResultsSchema, Profile: "unit", Ops: []string{OpCreate, OpVerify}, Repeats: 3, Workers: []int{1},
		Variants: Variants([]int{1}, nil, nil), Durabilities: KnownDurabilities,
		Configs: []ConfigSummary{
			{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}, InputBlocks: 30, CanonicalSource: ToolReference},
			{Config: Config{ID: "v", BlockSize: MiB, Recovery: 3, Codec: "fft"}, InputBlocks: 30, CanonicalSource: ToolCandidate},
		},
		Status: StatusOK,
	}
	add := func(config, op, variant, tool, durability string, rss []int64) {
		for repeat, peak := range rss {
			results.Runs = append(results.Runs, RunRecord{Config: config, Op: op, Variant: variant, Tool: tool, Durability: durability, Repeat: repeat + 1,
				Status: StatusOK, Measurement: Measurement{WallSeconds: 1, UserSeconds: 1, MaxRSSBytes: peak << 20, RSSSource: procmeasure.RSSSourceRusage}})
		}
	}
	add("u", OpCreate, "reference", ToolReference, "", []int64{20, 20, 24})
	add("u", OpCreate, "rarpar-w1", ToolCandidate, DurabilityDurable, []int64{28, 30, 32})
	add("u", OpCreate, "rarpar-w1-buffered", ToolCandidate, DurabilityBuffered, []int64{60, 58, 64})
	add("u", OpVerify, "reference", ToolReference, "", []int64{40, 40, 40})
	add("u", OpVerify, "rarpar-w1", ToolCandidate, DurabilityDurable, []int64{10, 10, 10})
	add("v", OpCreate, "rarpar-w1", ToolCandidate, DurabilityDurable, []int64{12, 12, 12})
	results.Runs = append(results.Runs, RunRecord{Config: "v", Op: OpCreate, Variant: "reference", Tool: ToolReference, Canonical: true, Warmup: true,
		Status: StatusDNF, Failure: "timeout", Measurement: Measurement{WallSeconds: 1200, ExitCode: -1}})
	return results
}

// Every rarpar row is listed against its scenario's reference, worst (lowest)
// reference/rarpar ratio first; a row whose reference did not finish has no
// ratio and comes last.
func TestRSSSummaryIsWorstRatioFirst(t *testing.T) {
	summary := RSSSummary(rssResults())
	type got struct {
		scenario, variant string
		ratio             float64
		note              string
	}
	var rows []got
	for _, scenario := range summary {
		ratio := -1.0
		if scenario.Ratio != nil {
			ratio = *scenario.Ratio
		}
		rows = append(rows, got{scenario.Scenario, scenario.Variant, ratio, scenario.Note})
	}
	want := []got{
		{"u/create", "rarpar-w1-buffered", 1.0 / 3, ""},
		{"u/create", "rarpar-w1", 2.0 / 3, ""},
		{"u/verify", "rarpar-w1", 4, ""},
		{"v/create", "rarpar-w1", -1, "reference DNF"},
	}
	if len(rows) != len(want) {
		t.Fatalf("summary %#v", rows)
	}
	for index := range want {
		if rows[index] != want[index] {
			t.Fatalf("row %d = %#v, want %#v (all %#v)", index, rows[index], want[index], rows)
		}
	}
	first := summary[0]
	if first.RarparMedianBytes != 60<<20 || first.RarparMinBytes != 58<<20 || first.RarparMaxBytes != 64<<20 || first.ReferenceMedianBytes != 20<<20 || first.ReferenceMaxBytes != 24<<20 {
		t.Fatalf("figures %#v", first)
	}
	if first.RarparSource != procmeasure.RSSSourceRusage || first.ReferenceSource != procmeasure.RSSSourceRusage {
		t.Fatalf("sources %#v", first)
	}
	results := rssResults()
	results.RSSSummary = summary
	encoded, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"rss_summary":[{"scenario":"u/create","variant":"rarpar-w1-buffered","rarpar_median_bytes":62914560`) {
		t.Fatalf("results JSON lacks the machine-readable summary: %s", encoded)
	}
}

func TestReportShowsPeakRSSPerScenario(t *testing.T) {
	report := RenderReport(rssResults())
	for _, want := range []string{
		"## Peak RSS per scenario",
		"| scenario | variant | rarpar MiB | reference MiB | RSS ratio | source | note |",
		"| u/create | rarpar-w1-buffered | 60.0 [58.0–64.0] | 20.0 [20.0–24.0] | 0.333 | rusage | - |",
		"| u/verify | rarpar-w1 | 10.0 [10.0–10.0] | 40.0 [40.0–40.0] | 4.000 | rusage | - |",
		"| v/create | rarpar-w1 | 12.0 [12.0–12.0] | - | - | rusage | reference DNF |",
		procmeasure.MultiProcessNote,
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q:\n%s", want, report)
		}
	}
	section := report[strings.Index(report, "## Peak RSS per scenario"):strings.Index(report, "## u — create")]
	if strings.Index(section, "rarpar-w1-buffered") > strings.Index(section, "| u/verify |") {
		t.Fatalf("the summary is not worst ratio first:\n%s", section)
	}
}
