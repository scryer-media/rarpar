package par3bench

import (
	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/procmeasure"
)

// RSSSummary compares every rarpar row's peak RSS with its scenario's
// reference row (same configuration, operation and target), worst
// rarpar/reference ratio first. Engine rows are not the shipped CLI and are
// left out, as they are from the ratio columns.
func RSSSummary(results *Results) []procmeasure.RSSScenario {
	type key struct{ config, op, variant string }
	peaks := map[key][]int64{}
	sources := map[key][]string{}
	for _, run := range results.Runs {
		if run.Warmup || run.Status != StatusOK || run.MaxRSSBytes <= 0 {
			continue
		}
		k := key{run.Config, run.Op, run.Variant}
		peaks[k] = append(peaks[k], run.MaxRSSBytes)
		sources[k] = append(sources[k], run.RSSSource)
	}
	rows := Summarize(results)
	references := map[string]Row{}
	for _, row := range rows {
		if row.Tool == ToolReference {
			references[row.Config+"/"+row.Op+"@"+row.Target] = row
		}
	}
	scenarios := []procmeasure.RSSScenario{}
	for _, row := range rows {
		if row.Tool != ToolCandidate {
			continue
		}
		ours := key{row.Config, row.Op, row.Variant}
		if len(peaks[ours]) == 0 {
			continue
		}
		scenario := procmeasure.RSSScenario{Scenario: row.Config + "/" + row.Op, Variant: row.Variant, RarparSource: procmeasure.JoinSources(sources[ours])}
		if row.Target != "" {
			scenario.Scenario += "@" + row.Target
		}
		scenario.RarparMedianBytes, scenario.RarparMinBytes, scenario.RarparMaxBytes = procmeasure.PeakStats(peaks[ours])
		reference, found := references[row.Config+"/"+row.Op+"@"+row.Target]
		theirs := key{row.Config, row.Op, reference.Variant}
		switch {
		case !found:
			scenario.Note = "no reference row"
		case reference.DNF != "":
			scenario.Note = "reference DNF"
		case len(peaks[theirs]) == 0:
			scenario.Note = "no successful reference run"
		default:
			scenario.ReferenceMedianBytes, scenario.ReferenceMinBytes, scenario.ReferenceMaxBytes = procmeasure.PeakStats(peaks[theirs])
			scenario.ReferenceSource = procmeasure.JoinSources(sources[theirs])
		}
		procmeasure.CompleteRSSScenario(&scenario)
		scenarios = append(scenarios, scenario)
	}
	procmeasure.SortRSSScenarios(scenarios)
	return scenarios
}
