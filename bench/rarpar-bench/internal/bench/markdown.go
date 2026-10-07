package bench

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/procmeasure"
)

// RenderReportMarkdown renders the human-readable companion of report.json:
// one row per compared case with wall, CPU and peak RSS medians [min–max]
// and their rarpar/reference ratios, after the peak RSS per scenario summary.
func RenderReportMarkdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# rarpar benchmark: %s\n\n", report.Plan.ID)
	fmt.Fprintf(&b, "- Machine: %s, %s/%s, %s, %d logical CPUs\n", report.Machine.Label, report.Machine.OS, report.Machine.Architecture, report.Machine.CPU, report.Machine.CPUCount)
	fmt.Fprintf(&b, "- Candidate: %s (sha256 %s)\n", report.Candidate.Version, shortDigest(report.Candidate.SHA256))
	if report.Reference != nil {
		fmt.Fprintf(&b, "- RAR reference: %s (sha256 %s)\n", report.Reference.Version, shortDigest(report.Reference.SHA256))
	}
	if report.ReferencePAR2 != nil {
		fmt.Fprintf(&b, "- PAR2 reference: %s (sha256 %s)\n", report.ReferencePAR2.Version, shortDigest(report.ReferencePAR2.SHA256))
	}
	fmt.Fprintf(&b, "- Protocol: %d warmup + %d measured runs per case, lane %s, PAR2 placement %s, collector %s\n\n", report.Plan.Warmups, report.Plan.Repeats, report.Plan.Lane, report.Plan.Par2Placement, report.CollectorMode)
	procmeasure.RenderRSSSummary(&b, report.RSSSummary)
	if len(report.Comparisons) > 0 {
		fmt.Fprintln(&b, "## Cases")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Wall and CPU (user+sys) are seconds, RSS is peak MiB; cells are median [min–max]. Ratios are rarpar/reference medians: below 1.000 rarpar used less (report.json's `ratio` is the inverse wall ratio, the relative speed).")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "| case | workload | reference | side | wall s | CPU s | RSS MiB | wall ratio | CPU ratio | RSS ratio |")
		fmt.Fprintln(&b, "|---|---|---|---|---|---|---|---|---|---|")
		for _, comparison := range report.Comparisons {
			wallRatio := "-"
			if comparison.Ratio > 0 {
				wallRatio = fmt.Sprintf("%.3f", 1/comparison.Ratio)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | rarpar | %s | %s | %s | %s | %s | %s |\n",
				comparison.CaseID, markdownCell(comparison.Workload), comparison.ReferenceLabel,
				nanosRange(comparison.Candidate.Median, comparison.Candidate.Min, comparison.Candidate.Max),
				nanosRange(comparison.CandidateCPUNanos.Median, comparison.CandidateCPUNanos.Min, comparison.CandidateCPUNanos.Max),
				procmeasure.MiBRange(comparison.CandidateRSSBytes.Median, comparison.CandidateRSSBytes.Min, comparison.CandidateRSSBytes.Max),
				wallRatio, ratioText(comparison.CPURatio), ratioText(comparison.RSSRatio))
			fmt.Fprintf(&b, "| | | | reference | %s | %s | %s | 1.000 | 1.000 | 1.000 |\n",
				nanosRange(comparison.Reference.Median, comparison.Reference.Min, comparison.Reference.Max),
				nanosRange(comparison.ReferenceCPUNanos.Median, comparison.ReferenceCPUNanos.Min, comparison.ReferenceCPUNanos.Max),
				procmeasure.MiBRange(comparison.ReferenceRSSBytes.Median, comparison.ReferenceRSSBytes.Min, comparison.ReferenceRSSBytes.Max))
		}
		fmt.Fprintln(&b)
	}
	if len(report.Omitted) > 0 {
		fmt.Fprintln(&b, "## Omitted")
		fmt.Fprintln(&b)
		for _, omitted := range report.Omitted {
			fmt.Fprintf(&b, "- %s\n", omitted)
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

// MarkdownPath is where `report` writes the Markdown beside a JSON report.
func MarkdownPath(jsonPath string) string {
	if filepath.Ext(jsonPath) == ".md" {
		return jsonPath + ".md"
	}
	return strings.TrimSuffix(jsonPath, filepath.Ext(jsonPath)) + ".md"
}

func nanosRange(median, low, high int64) string {
	if median <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.3f [%.3f–%.3f]", float64(median)/1e9, float64(low)/1e9, float64(high)/1e9)
}

func ratioText(value *float64) string {
	if value == nil {
		return "-"
	}
	return fmt.Sprintf("%.3f", *value)
}

func markdownCell(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "|", "\\|"), "\n", " ")
}

func shortDigest(digest string) string {
	if len(digest) > 16 {
		return digest[:16]
	}
	return digest
}
