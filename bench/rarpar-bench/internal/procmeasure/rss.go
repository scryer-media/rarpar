package procmeasure

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Peak resident set sources. Every one of them reads the tool's own process,
// never a wrapper's: the harness launches each tool as its direct child, or
// through something that execs into it in place (taskset), or, where a
// collector has to sit between the harness and the tool (perf stat), through
// the rss-exec shim, which is the tool's parent and reads the tool's rusage.
const (
	// RSSSourceRusage is the direct child's wait4 rusage ru_maxrss (bytes on
	// macOS, KiB normalised to bytes on Linux), the figure /usr/bin/time
	// prints as the maximum resident set size. The direct child is the tool.
	RSSSourceRusage = "rusage"
	// RSSSourceRusageTasksetExec is the same rusage read through taskset,
	// which execs the tool in place: same pid, and Linux keeps the larger of
	// the pre-exec and post-exec peaks, so taskset's own small image (a few
	// MiB at most) is the only floor under the tool's figure.
	RSSSourceRusageTasksetExec = "rusage-taskset-exec"
	// RSSSourceShim is the tool's wait4 rusage read by the rss-exec shim,
	// the tool's parent under a collector such as perf stat that would
	// otherwise be the measured child. The shim's own memory is not counted.
	RSSSourceShim = "rusage-shim"
	// RSSSourcePeakWorkingSet is Windows PeakWorkingSetSize from
	// K32GetProcessMemoryInfo on a handle held across the child's exit.
	RSSSourcePeakWorkingSet = "peak-working-set"
)

// FailureMissingRSS classifies a run whose process exited but whose peak RSS
// the harness did not capture. It is a harness failure, never a silent zero.
const FailureMissingRSS = "harness-missing-rss"

// DescribeRSSSource explains a source tag for reports and error messages.
func DescribeRSSSource(source string) string {
	switch source {
	case RSSSourceRusage:
		return "rusage ru_maxrss of the tool as the harness's direct child"
	case RSSSourceRusageTasksetExec:
		return "rusage ru_maxrss of the tool, launched through taskset which execs it in place"
	case RSSSourceShim:
		return "rusage ru_maxrss of the tool, read by the rss-exec shim that perf stat launches (perf counters include the shim's start-up)"
	case RSSSourcePeakWorkingSet:
		return "Windows PeakWorkingSetSize of the tool's process, read through a handle held across its exit"
	case "":
		return "no peak RSS recorded"
	default:
		return source
	}
}

// MultiProcessNote is the caveat every RSS report carries: a peak resident
// set is one process's figure.
const MultiProcessNote = "Peak RSS is one process's high-water mark. On POSIX the figure also covers descendants the tool reaped (the largest single peak, not their sum); on Windows it is the tool's process alone. rarpar, UnRAR, par2cmdline-turbo and par3cmdline run as one multi-threaded process on the measured paths, so the figure is the tool's whole footprint."

// RSSScenario compares one scenario's peak resident set: rarpar's peak
// against the reference's, both medians [min, max] over the measured runs.
type RSSScenario struct {
	Scenario string `json:"scenario"`
	// Variant names the rarpar row when a scenario has several.
	Variant              string `json:"variant,omitempty"`
	RarparMedianBytes    int64  `json:"rarpar_median_bytes"`
	RarparMinBytes       int64  `json:"rarpar_min_bytes"`
	RarparMaxBytes       int64  `json:"rarpar_max_bytes"`
	ReferenceMedianBytes int64  `json:"reference_median_bytes,omitempty"`
	ReferenceMinBytes    int64  `json:"reference_min_bytes,omitempty"`
	ReferenceMaxBytes    int64  `json:"reference_max_bytes,omitempty"`
	// Ratio is rarpar/reference medians: above 1 rarpar peaked higher. It is
	// absent when the scenario has no reference figure.
	Ratio           *float64 `json:"ratio,omitempty"`
	RarparSource    string   `json:"rarpar_rss_source"`
	ReferenceSource string   `json:"reference_rss_source,omitempty"`
	// Note says why there is no ratio, or that the two sides were not
	// measured the same way.
	Note string `json:"note,omitempty"`
}

// PeakStats is the median, min and max of a set of peaks, in bytes.
func PeakStats(values []int64) (median, low, high int64) {
	if len(values) == 0 {
		return 0, 0, 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	middle := len(sorted) / 2
	median = sorted[middle]
	if len(sorted)%2 == 0 {
		median = int64(math.Round((float64(sorted[middle-1]) + float64(sorted[middle])) / 2))
	}
	return median, sorted[0], sorted[len(sorted)-1]
}

// JoinSources renders the distinct sources of a set of runs, sorted.
func JoinSources(sources []string) string {
	seen := map[string]bool{}
	var distinct []string
	for _, source := range sources {
		if source != "" && !seen[source] {
			seen[source] = true
			distinct = append(distinct, source)
		}
	}
	sort.Strings(distinct)
	return strings.Join(distinct, "+")
}

// CompleteRSSScenario fills the ratio and the comparability note once both
// sides' figures and sources are set.
func CompleteRSSScenario(scenario *RSSScenario) {
	if scenario.ReferenceMedianBytes > 0 && scenario.RarparMedianBytes > 0 {
		value := float64(scenario.RarparMedianBytes) / float64(scenario.ReferenceMedianBytes)
		scenario.Ratio = &value
	}
	if scenario.Ratio != nil && scenario.RarparSource != scenario.ReferenceSource {
		scenario.Note = fmt.Sprintf("measured differently: rarpar %s, reference %s", scenario.RarparSource, scenario.ReferenceSource)
	}
}

// SortRSSScenarios orders the summary worst rarpar ratio first, so an RSS
// regression is at the top; scenarios without a ratio follow, by name.
func SortRSSScenarios(scenarios []RSSScenario) {
	sort.SliceStable(scenarios, func(i, j int) bool {
		left, right := scenarios[i], scenarios[j]
		if (left.Ratio == nil) != (right.Ratio == nil) {
			return left.Ratio != nil
		}
		if left.Ratio != nil && *left.Ratio != *right.Ratio {
			return *left.Ratio > *right.Ratio
		}
		if left.Scenario != right.Scenario {
			return left.Scenario < right.Scenario
		}
		return left.Variant < right.Variant
	})
}

// MiB renders a byte count in MiB.
func MiB(bytes int64) string {
	return fmt.Sprintf("%.1f", float64(bytes)/(1<<20))
}

// MiBRange renders median [min–max] in MiB, or "-" for no figure.
func MiBRange(median, low, high int64) string {
	if median <= 0 {
		return "-"
	}
	return fmt.Sprintf("%s [%s–%s]", MiB(median), MiB(low), MiB(high))
}

// RenderRSSSummary writes the "Peak RSS per scenario" Markdown section.
func RenderRSSSummary(b *strings.Builder, scenarios []RSSScenario) {
	fmt.Fprintln(b, "## Peak RSS per scenario")
	fmt.Fprintln(b)
	if len(scenarios) == 0 {
		fmt.Fprintln(b, "No scenario has a measured rarpar peak.")
		fmt.Fprintln(b)
		return
	}
	fmt.Fprintln(b, "Peak resident set, MiB, median [min–max] over the measured runs. Ratio is rarpar/reference medians: above 1.000 rarpar peaked higher. Sorted worst ratio first.")
	fmt.Fprintln(b, MultiProcessNote)
	fmt.Fprintln(b)
	variants := false
	for _, scenario := range scenarios {
		if scenario.Variant != "" {
			variants = true
			break
		}
	}
	header, rule := "| scenario |", "|---|"
	if variants {
		header, rule = header+" variant |", rule+"---|"
	}
	fmt.Fprintln(b, header+" rarpar MiB | reference MiB | RSS ratio | source | note |")
	fmt.Fprintln(b, rule+"---|---|---|---|---|")
	for _, scenario := range scenarios {
		line := fmt.Sprintf("| %s |", scenario.Scenario)
		if variants {
			line += fmt.Sprintf(" %s |", dash(scenario.Variant))
		}
		ratio := "-"
		if scenario.Ratio != nil {
			ratio = fmt.Sprintf("%.3f", *scenario.Ratio)
		}
		source := scenario.RarparSource
		if scenario.ReferenceSource != "" && scenario.ReferenceSource != scenario.RarparSource {
			source = "rarpar " + scenario.RarparSource + ", reference " + scenario.ReferenceSource
		}
		line += fmt.Sprintf(" %s | %s | %s | %s | %s |",
			MiBRange(scenario.RarparMedianBytes, scenario.RarparMinBytes, scenario.RarparMaxBytes),
			MiBRange(scenario.ReferenceMedianBytes, scenario.ReferenceMinBytes, scenario.ReferenceMaxBytes),
			ratio, dash(source), dash(scenario.Note))
		fmt.Fprintln(b, line)
	}
	fmt.Fprintln(b)
	var tags []string
	for _, scenario := range scenarios {
		tags = append(tags, strings.Split(scenario.RarparSource, "+")...)
		tags = append(tags, strings.Split(scenario.ReferenceSource, "+")...)
	}
	for _, tag := range strings.Split(JoinSources(tags), "+") {
		if tag != "" {
			fmt.Fprintf(b, "- `%s`: %s\n", tag, DescribeRSSSource(tag))
		}
	}
	fmt.Fprintln(b)
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
