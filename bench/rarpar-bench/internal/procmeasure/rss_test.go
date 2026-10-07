package procmeasure

import (
	"strings"
	"testing"
)

func TestCompleteRSSScenarioFlagsDifferentSources(t *testing.T) {
	scenario := RSSScenario{Scenario: "fixture", RarparMedianBytes: 30 << 20, ReferenceMedianBytes: 20 << 20, RarparSource: RSSSourceShim, ReferenceSource: RSSSourceRusage}
	CompleteRSSScenario(&scenario)
	if scenario.Ratio == nil || *scenario.Ratio != 2.0/3.0 {
		t.Fatalf("ratio %v", scenario.Ratio)
	}
	if !strings.Contains(scenario.Note, "measured differently") {
		t.Fatalf("note %q", scenario.Note)
	}
	alone := RSSScenario{Scenario: "fixture", RarparMedianBytes: 30 << 20, RarparSource: RSSSourceRusage}
	CompleteRSSScenario(&alone)
	if alone.Ratio != nil || alone.Note != "" {
		t.Fatalf("a scenario without a reference got %#v", alone)
	}
}

func TestSortAndRenderRSSSummary(t *testing.T) {
	ratio := func(value float64) *float64 { return &value }
	scenarios := []RSSScenario{
		{Scenario: "fixture-b", RarparMedianBytes: 1 << 20, RarparMinBytes: 1 << 20, RarparMaxBytes: 1 << 20, RarparSource: RSSSourceRusage, Note: "no reference row"},
		{Scenario: "fixture-c", RarparMedianBytes: 10 << 20, RarparMinBytes: 9 << 20, RarparMaxBytes: 11 << 20, ReferenceMedianBytes: 20 << 20, ReferenceMinBytes: 20 << 20, ReferenceMaxBytes: 20 << 20, Ratio: ratio(2), RarparSource: RSSSourceRusage, ReferenceSource: RSSSourceRusage},
		{Scenario: "fixture-a", RarparMedianBytes: 30 << 20, RarparMinBytes: 30 << 20, RarparMaxBytes: 30 << 20, ReferenceMedianBytes: 10 << 20, ReferenceMinBytes: 10 << 20, ReferenceMaxBytes: 10 << 20, Ratio: ratio(1.0 / 3), RarparSource: RSSSourcePeakWorkingSet, ReferenceSource: RSSSourcePeakWorkingSet},
	}
	SortRSSScenarios(scenarios)
	if scenarios[0].Scenario != "fixture-a" || scenarios[1].Scenario != "fixture-c" || scenarios[2].Scenario != "fixture-b" {
		t.Fatalf("order %s %s %s", scenarios[0].Scenario, scenarios[1].Scenario, scenarios[2].Scenario)
	}
	var b strings.Builder
	RenderRSSSummary(&b, scenarios)
	want := strings.Join([]string{
		"| scenario | rarpar MiB | reference MiB | RSS ratio | source | note |",
		"|---|---|---|---|---|---|",
		"| fixture-a | 30.0 [30.0–30.0] | 10.0 [10.0–10.0] | 0.333 | peak-working-set | - |",
		"| fixture-c | 10.0 [9.0–11.0] | 20.0 [20.0–20.0] | 2.000 | rusage | - |",
		"| fixture-b | 1.0 [1.0–1.0] | - | - | rusage | no reference row |",
	}, "\n")
	if !strings.Contains(b.String(), want) {
		t.Fatalf("rendered:\n%s\nwant:\n%s", b.String(), want)
	}
	for _, tag := range []string{"- `peak-working-set`: ", "- `rusage`: "} {
		if !strings.Contains(b.String(), tag) {
			t.Fatalf("source legend lacks %q:\n%s", tag, b.String())
		}
	}
}

func TestPeakStats(t *testing.T) {
	if median, low, high := PeakStats([]int64{30, 10, 20, 40}); median != 25 || low != 10 || high != 40 {
		t.Fatalf("got %d %d %d", median, low, high)
	}
	if median, low, high := PeakStats(nil); median != 0 || low != 0 || high != 0 {
		t.Fatalf("empty got %d %d %d", median, low, high)
	}
}
