package bench

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const chartWidth = 1200

func RenderCharts(report Report, out string) ([]string, error) {
	return RenderChartSet([]Report{report}, out)
}

type chartGroup struct {
	report      Report
	comparisons []Comparison
}

func RenderChartSet(reports []Report, out string) ([]string, error) {
	if len(reports) == 0 {
		return nil, fmt.Errorf("at least one benchmark report is required")
	}
	collectorMode := reports[0].CollectorMode
	if collectorMode != wallClockCollector && collectorMode != perfStatCollector {
		return nil, fmt.Errorf("unsupported benchmark collector mode %q", collectorMode)
	}
	for _, report := range reports {
		if report.SchemaVersion != ReportSchemaVersion || report.InputSHA256 == "" {
			return nil, fmt.Errorf("invalid benchmark report")
		}
		if report.CollectorMode != collectorMode {
			return nil, fmt.Errorf("benchmark reports must use the same collector mode")
		}
		if report.CorpusDigest != reports[0].CorpusDigest || report.Machine != reports[0].Machine {
			return nil, fmt.Errorf("benchmark reports must use the same corpus and machine")
		}
	}
	if err := ensureEmptyDir(out); err != nil {
		return nil, err
	}
	var paths []string
	for _, family := range []string{"rar", "par2"} {
		var groups []chartGroup
		for _, report := range reports {
			var comparisons []Comparison
			for _, comparison := range report.Comparisons {
				if comparison.Family == family {
					comparisons = append(comparisons, comparison)
				}
			}
			if len(comparisons) != 0 {
				groups = append(groups, chartGroup{report: report, comparisons: comparisons})
			}
		}
		if len(groups) == 0 {
			continue
		}
		if err := validateChartGroups(family, groups); err != nil {
			return nil, err
		}
		name := "rarpar-" + family + "-benchmark.svg"
		content, err := renderSVGGroups(family, groups)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(out, name)
		if err := osWriteFile(path, content); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	if err := writeJSON(filepath.Join(out, "chart-summary.json"), map[string]any{
		"schema_version": ReportSchemaVersion,
		"collector_mode": reportValues(reports, func(report Report) string { return report.CollectorMode }),
		"report_sha256":  reportValues(reports, func(report Report) string { return report.InputSHA256 }),
		"corpus_digest":  reports[0].CorpusDigest,
		"plan_id":        reportValues(reports, func(report Report) string { return report.Plan.ID }),
		"charts":         chartNames(paths),
		"omitted":        reportOmissions(reports),
	}); err != nil {
		return nil, err
	}
	return paths, nil
}

func validateChartGroups(family string, groups []chartGroup) error {
	base := groups[0]
	baseCases := comparisonCaseIDs(base.report.Plan, base.comparisons)
	baseReference := familyReferenceDigest(family, base.report)
	baseLabel := base.comparisons[0].ReferenceLabel
	for _, group := range groups[1:] {
		if group.report.CollectorMode != base.report.CollectorMode {
			return fmt.Errorf("%s reports do not use the same collector mode", family)
		}
		if group.report.Plan.Seed != base.report.Plan.Seed ||
			group.report.Plan.Warmups != base.report.Plan.Warmups ||
			group.report.Plan.Repeats != base.report.Plan.Repeats ||
			group.report.Plan.Par2Placement != base.report.Plan.Par2Placement ||
			strings.Join(comparisonCaseIDs(group.report.Plan, group.comparisons), "\x00") != strings.Join(baseCases, "\x00") {
			return fmt.Errorf("%s reports do not use the same run plan", family)
		}
		if familyReferenceDigest(family, group.report) != baseReference || group.comparisons[0].ReferenceLabel != baseLabel {
			return fmt.Errorf("%s reports do not use the same reference binary", family)
		}
	}
	return nil
}

func comparisonCaseIDs(plan Plan, comparisons []Comparison) []string {
	sort.SliceStable(comparisons, func(left, right int) bool {
		return caseOrder(plan, comparisons[left].CaseID) < caseOrder(plan, comparisons[right].CaseID)
	})
	ids := make([]string, len(comparisons))
	for index, comparison := range comparisons {
		ids[index] = comparison.CaseID
	}
	return ids
}

func familyReferenceDigest(family string, report Report) string {
	if family == "par2" {
		return referenceDigest(report.ReferencePAR2)
	}
	return referenceDigest(report.Reference)
}

func reportValues(reports []Report, value func(Report) string) []string {
	values := make([]string, len(reports))
	for index, report := range reports {
		values[index] = value(report)
	}
	return values
}

func reportOmissions(reports []Report) []string {
	var omissions []string
	for _, report := range reports {
		omissions = append(omissions, report.Omitted...)
	}
	return omissions
}

func chartNames(paths []string) []string {
	names := make([]string, len(paths))
	for index, path := range paths {
		names[index] = filepath.Base(path)
	}
	return names
}

func renderSVG(report Report, family string, comparisons []Comparison) ([]byte, error) {
	return renderSVGGroups(family, []chartGroup{{report: report, comparisons: comparisons}})
}

func renderSVGGroups(family string, groups []chartGroup) ([]byte, error) {
	rowCount := 0
	for index := range groups {
		orderComparisonsByRelativeSpeed(groups[index].report.Plan, groups[index].comparisons)
		rowCount += len(groups[index].comparisons)
	}
	height := 198 + rowCount*54 + (len(groups)-1)*30
	if height < 330 {
		height = 330
	}
	first := groups[0]
	title := fmt.Sprintf("rarpar %s relative speed benchmark", strings.ToUpper(family))
	description := fmt.Sprintf("Measured %s workloads on %s across %d execution lane(s). Relative speed is reference elapsed time divided by rarpar elapsed time.", strings.ToUpper(family), first.report.Machine.Label, len(groups))
	var document bytes.Buffer
	fmt.Fprintf(&document, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-labelledby=\"title desc\">\n", chartWidth, height, chartWidth, height)
	fmt.Fprintf(&document, "  <title id=\"title\">%s</title>\n  <desc id=\"desc\">%s</desc>\n", escapeXML(title), escapeXML(description))
	document.WriteString(svgStyle)
	reports := make([]Report, len(groups))
	for index, group := range groups {
		reports[index] = group.report
	}
	fmt.Fprintf(&document, "  <metadata>schema=%d; report_sha256=%s; corpus_digest=%s; plan_id=%s; candidate_sha256=%s; reference_sha256=%s; lane=%s; collector=%s; par2_placement=%s</metadata>\n", first.report.SchemaVersion, strings.Join(reportValues(reports, func(report Report) string { return report.InputSHA256 }), ","), first.report.CorpusDigest, strings.Join(reportValues(reports, func(report Report) string { return report.Plan.ID }), ","), strings.Join(reportValues(reports, func(report Report) string { return report.Candidate.SHA256 }), ","), familyReferenceDigest(family, first.report), strings.Join(reportValues(reports, func(report Report) string { return report.Plan.Lane }), ","), first.report.CollectorMode, first.report.Plan.Par2Placement)
	fmt.Fprintf(&document, "  <rect class=\"bg\" width=\"%d\" height=\"%d\"/>\n", chartWidth, height)
	fmt.Fprintf(&document, "  <text class=\"title\" x=\"48\" y=\"48\">%s</text>\n", escapeXML(title))
	fmt.Fprintf(&document, "  <text class=\"subtitle\" x=\"48\" y=\"75\">Lower elapsed time is better. Bars show the faster side's multiplier on a symmetric log scale.</text>\n")
	document.WriteString(legendSVG(first.comparisons[0].ReferenceLabel, chartHasGPU(groups)))
	document.WriteString("  <text class=\"column\" x=\"48\" y=\"112\">Workload / elapsed time</text>\n  <text class=\"column\" x=\"620\" y=\"112\">Relative speed</text>\n")
	axisStart, parity, axisEnd := 620.0, 885.0, 1150.0
	axisBottom := height - 44
	fmt.Fprintf(&document, "  <g aria-label=\"Relative speed axis\">\n")
	for _, tick := range []struct {
		ratio float64
		label string
	}{{0.125, "8x"}, {0.25, "4x"}, {0.5, "2x"}, {1, "1x parity"}, {2, "2x"}, {4, "4x"}, {8, "8x"}} {
		x := ratioX(tick.ratio, axisStart, parity, axisEnd)
		class := "grid"
		if tick.ratio == 1 {
			class = "parity"
		}
		fmt.Fprintf(&document, "    <line class=\"%s\" x1=\"%.1f\" y1=\"121\" x2=\"%.1f\" y2=\"%d\"/><text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">%s</text>\n", class, x, x, axisBottom-14, x, axisBottom+4, tick.label)
	}
	fmt.Fprintf(&document, "    <text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">%s faster</text>\n", (axisStart+parity)/2, axisBottom+24, escapeXML(first.comparisons[0].ReferenceLabel))
	fmt.Fprintf(&document, "    <text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">rarpar faster</text>\n", (parity+axisEnd)/2, axisBottom+24)
	document.WriteString("  </g>\n")
	y := 132
	document.WriteString(fmt.Sprintf("  <g aria-label=\"%s benchmarks\">\n", escapeXML(strings.ToUpper(family))))
	for groupIndex, group := range groups {
		machineDetails := group.report.Plan.Lane
		if family == "par2" {
			machineDetails += " / " + group.report.Plan.Par2Placement + " placement"
		}
		fmt.Fprintf(&document, "    <text class=\"machine\" x=\"48\" y=\"%d\">%s / %s / %s</text>\n", y+8, escapeXML(group.report.Machine.Label), escapeXML(group.report.Machine.Architecture), escapeXML(machineDetails))
		y += 12
		for _, comparison := range group.comparisons {
			label := truncate(comparison.Workload, 66)
			fmt.Fprintf(&document, "    <text class=\"workload\" x=\"48\" y=\"%d\">%s</text>\n", y+24, escapeXML(label))
			fmt.Fprintf(&document, "    <text class=\"timing\" x=\"48\" y=\"%d\">%s -> %s</text>\n", y+40, formatDuration(comparison.Reference.Median), formatDuration(comparison.Candidate.Median))
			x := ratioX(comparison.Ratio, axisStart, parity, axisEnd)
			class := barClass(comparison)
			if comparison.Ratio >= 1 {
				fmt.Fprintf(&document, "    <rect class=\"%s\" x=\"%.1f\" y=\"%d\" width=\"%.1f\" height=\"14\" rx=\"2\"/>\n", class, parity, y+16, x-parity)
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">%.1fx</text>\n", x+8, y+28, comparison.Ratio)
			} else {
				fmt.Fprintf(&document, "    <rect class=\"%s\" x=\"%.1f\" y=\"%d\" width=\"%.1f\" height=\"14\" rx=\"2\"/>\n", class, x, y+16, parity-x)
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\" text-anchor=\"end\">%.1fx</text>\n", x-8, y+28, 1/comparison.Ratio)
			}
			fmt.Fprintf(&document, "    <line class=\"rule\" x1=\"48\" y1=\"%d\" x2=\"1150\" y2=\"%d\"/>\n", y+50, y+50)
			y += 54
		}
		if groupIndex+1 < len(groups) {
			y += 30
		}
	}
	document.WriteString("  </g>\n</svg>\n")
	return document.Bytes(), nil
}

func orderComparisonsByRelativeSpeed(plan Plan, comparisons []Comparison) {
	sort.SliceStable(comparisons, func(left, right int) bool {
		if comparisons[left].Ratio != comparisons[right].Ratio {
			return comparisons[left].Ratio > comparisons[right].Ratio
		}
		return caseOrder(plan, comparisons[left].CaseID) < caseOrder(plan, comparisons[right].CaseID)
	})
}

func ratioX(ratio, start, parity, end float64) float64 {
	clamped := math.Max(0.125, math.Min(8, ratio))
	return parity + math.Log2(clamped)*(end-parity)/3
}

func barClass(comparison Comparison) string {
	if comparison.Ratio < 1 {
		return "slower"
	}
	if comparison.Backend == "metal" || comparison.Backend == "wgpu" {
		return "gpu"
	}
	return "cpu"
}

func chartHasGPU(groups []chartGroup) bool {
	for _, group := range groups {
		for _, comparison := range group.comparisons {
			if comparison.Backend == "metal" || comparison.Backend == "wgpu" {
				return true
			}
		}
	}
	return false
}

func legendSVG(reference string, hasGPU bool) string {
	var legend strings.Builder
	fmt.Fprintf(&legend, "  <g aria-label=\"Legend\"><rect class=\"slower\" x=\"570\" y=\"84\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"592\" y=\"96\">%s faster</text>", escapeXML(reference))
	if hasGPU {
		legend.WriteString("<rect class=\"cpu\" x=\"720\" y=\"84\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"742\" y=\"96\">rarpar / CPU</text><rect class=\"gpu\" x=\"890\" y=\"84\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"912\" y=\"96\">rarpar / GPU</text>")
	} else {
		legend.WriteString("<rect class=\"cpu\" x=\"890\" y=\"84\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"912\" y=\"96\">rarpar / CPU</text>")
	}
	legend.WriteString("</g>\n")
	return legend.String()
}

func formatDuration(nanos int64) string {
	if nanos >= 1_000_000_000 {
		return fmt.Sprintf("%.2f s", float64(nanos)/1_000_000_000)
	}
	if nanos >= 1_000_000 {
		return fmt.Sprintf("%.1f ms", float64(nanos)/1_000_000)
	}
	return fmt.Sprintf("%.0f us", float64(nanos)/1_000)
}

func truncate(value string, length int) string {
	runes := []rune(value)
	if len(runes) <= length {
		return value
	}
	return string(runes[:length-3]) + "..."
}

func escapeXML(value string) string {
	var buffer bytes.Buffer
	_ = xml.EscapeText(&buffer, []byte(value))
	return buffer.String()
}

func referenceDigest(reference *BinaryIdentity) string {
	if reference == nil {
		return "none"
	}
	return reference.SHA256
}

func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

const svgStyle = `  <style>
    .bg { fill: #ffffff; } text { font-family: Arial, sans-serif; fill: #172033; }
    .title { font-size: 28px; font-weight: 600; } .subtitle { font-size: 14px; fill: #667085; }
    .column { font-size: 12px; font-weight: 600; fill: #667085; letter-spacing: .04em; text-transform: uppercase; }
    .machine { font-size: 15px; font-weight: 600; } .workload { font-size: 13px; font-weight: 500; }
    .timing { font-size: 12px; fill: #667085; } .tick { font-size: 11px; fill: #667085; } .ratio { font-size: 12px; font-weight: 600; }
    .grid { stroke: #d7dce5; stroke-width: 1; } .parity { stroke: #172033; stroke-width: 1.5; } .rule { stroke: #e7eaf0; stroke-width: 1; }
    .cpu { fill: #2563eb; } .gpu { fill: #7c3aed; } .slower { fill: #d97706; }
    @media (prefers-color-scheme: dark) { .bg { fill: #0d1117; } text { fill: #e6edf3; } .subtitle, .column, .timing, .tick { fill: #9ca7b5; } .grid { stroke: #30363d; } .parity { stroke: #e6edf3; } .rule { stroke: #21262d; } .cpu { fill: #58a6ff; } .gpu { fill: #bc8cff; } .slower { fill: #f2a65a; } }
  </style>
`
