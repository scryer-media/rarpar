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
	if report.SchemaVersion != ReportSchemaVersion || report.InputSHA256 == "" {
		return nil, fmt.Errorf("invalid benchmark report")
	}
	if err := ensureEmptyDir(out); err != nil {
		return nil, err
	}
	var paths []string
	for _, family := range []string{"rar", "par2"} {
		var comparisons []Comparison
		for _, comparison := range report.Comparisons {
			if comparison.Family == family {
				comparisons = append(comparisons, comparison)
			}
		}
		if len(comparisons) == 0 {
			continue
		}
		name := "rarpar-" + family + "-benchmark.svg"
		content, err := renderSVG(report, family, comparisons)
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
		"report_sha256":  report.InputSHA256,
		"corpus_digest":  report.CorpusDigest,
		"plan_id":        report.Plan.ID,
		"charts":         chartNames(paths),
		"omitted":        report.Omitted,
	}); err != nil {
		return nil, err
	}
	return paths, nil
}

func chartNames(paths []string) []string {
	names := make([]string, len(paths))
	for index, path := range paths {
		names[index] = filepath.Base(path)
	}
	return names
}

func renderSVG(report Report, family string, comparisons []Comparison) ([]byte, error) {
	sort.SliceStable(comparisons, func(left, right int) bool {
		return caseOrder(report.Plan, comparisons[left].CaseID) < caseOrder(report.Plan, comparisons[right].CaseID)
	})
	height := 178 + len(comparisons)*54
	if height < 330 {
		height = 330
	}
	title := fmt.Sprintf("rarpar %s relative speed benchmark", strings.ToUpper(family))
	description := fmt.Sprintf("Measured %s workloads on %s. Relative speed is reference elapsed time divided by rarpar elapsed time.", strings.ToUpper(family), report.Machine.Label)
	var document bytes.Buffer
	fmt.Fprintf(&document, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-labelledby=\"title desc\">\n", chartWidth, height, chartWidth, height)
	fmt.Fprintf(&document, "  <title id=\"title\">%s</title>\n  <desc id=\"desc\">%s</desc>\n", escapeXML(title), escapeXML(description))
	document.WriteString(svgStyle)
	fmt.Fprintf(&document, "  <metadata>schema=%d; report_sha256=%s; corpus_digest=%s; plan_id=%s; candidate_sha256=%s; rar_reference_sha256=%s; par2_reference_sha256=%s; lane=%s; par2_placement=%s</metadata>\n", report.SchemaVersion, report.InputSHA256, report.CorpusDigest, report.Plan.ID, report.Candidate.SHA256, referenceDigest(report.Reference), referenceDigest(report.ReferencePAR2), report.Plan.Lane, report.Plan.Par2Placement)
	fmt.Fprintf(&document, "  <rect class=\"bg\" width=\"%d\" height=\"%d\"/>\n", chartWidth, height)
	fmt.Fprintf(&document, "  <text class=\"title\" x=\"48\" y=\"48\">%s</text>\n", escapeXML(title))
	fmt.Fprintf(&document, "  <text class=\"subtitle\" x=\"48\" y=\"75\">Lower elapsed time is better. Ratio = %s time / rarpar time. Log scale keeps large gains compact.</text>\n", escapeXML(comparisons[0].ReferenceLabel))
	document.WriteString(legendSVG(family, comparisons[0].ReferenceLabel))
	document.WriteString("  <text class=\"column\" x=\"48\" y=\"112\">Workload / elapsed time</text>\n  <text class=\"column\" x=\"620\" y=\"112\">Relative speed</text>\n")
	axisStart, parity, axisEnd := 620.0, 752.5, 1150.0
	axisBottom := height - 44
	fmt.Fprintf(&document, "  <g aria-label=\"Relative speed axis\">\n")
	for _, tick := range []struct {
		ratio float64
		label string
	}{{0.5, "0.5x"}, {1, "1x parity"}, {2, "2x"}, {4, "4x"}, {8, "8x"}} {
		x := ratioX(tick.ratio, axisStart, parity, axisEnd)
		class := "grid"
		if tick.ratio == 1 {
			class = "parity"
		}
		fmt.Fprintf(&document, "    <line class=\"%s\" x1=\"%.1f\" y1=\"121\" x2=\"%.1f\" y2=\"%d\"/><text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">%s</text>\n", class, x, x, axisBottom-14, x, axisBottom+4, tick.label)
	}
	document.WriteString("  </g>\n")
	y := 144
	machineDetails := report.Plan.Lane
	if family == "par2" {
		machineDetails += " / " + report.Plan.Par2Placement + " placement"
	}
	fmt.Fprintf(&document, "  <g aria-label=\"%s benchmarks\"><text class=\"machine\" x=\"48\" y=\"140\">%s / %s / %s</text>\n", escapeXML(strings.ToUpper(family)), escapeXML(report.Machine.Label), escapeXML(report.Machine.Architecture), escapeXML(machineDetails))
	for _, comparison := range comparisons {
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
			fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\" text-anchor=\"end\">%.1fx</text>\n", x-8, y+28, comparison.Ratio)
		}
		fmt.Fprintf(&document, "    <line class=\"rule\" x1=\"48\" y1=\"%d\" x2=\"1150\" y2=\"%d\"/>\n", y+50, y+50)
		y += 54
	}
	document.WriteString("  </g>\n</svg>\n")
	return document.Bytes(), nil
}

func ratioX(ratio, start, parity, end float64) float64 {
	clamped := math.Max(0.5, math.Min(8, ratio))
	if clamped <= 1 {
		return parity + math.Log2(clamped)*(parity-start)
	}
	return parity + math.Log2(clamped)*(end-parity)/3
}

func barClass(comparison Comparison) string {
	if comparison.Ratio < 1 {
		return "slower"
	}
	return "cpu"
}

func legendSVG(_ string, reference string) string {
	return fmt.Sprintf("  <g aria-label=\"Legend\"><rect class=\"cpu\" x=\"760\" y=\"39\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"782\" y=\"51\">rarpar / CPU</text><rect class=\"slower\" x=\"920\" y=\"39\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"942\" y=\"51\">%s faster</text></g>\n", escapeXML(reference))
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
    .cpu { fill: #2563eb; } .slower { fill: #d97706; }
    @media (prefers-color-scheme: dark) { .bg { fill: #0d1117; } text { fill: #e6edf3; } .subtitle, .column, .timing, .tick { fill: #9ca7b5; } .grid { stroke: #30363d; } .parity { stroke: #e6edf3; } .rule { stroke: #21262d; } .cpu { fill: #58a6ff; } .gpu { fill: #bc8cff; } .slower { fill: #f2a65a; } }
  </style>
`
