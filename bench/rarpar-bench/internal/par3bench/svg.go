package par3bench

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

const par3ChartWidth = 1200

// RenderSVGs writes one static SVG per operation in results, named
// rarpar-par3-<op>.svg, and returns their paths. Each row is one set and one
// rarpar row against the reference row: the bar is reference/rarpar median
// wall time on the same symmetric log scale as the RAR and PAR2 charts, and
// the line under it carries wall, CPU (user+sys) and peak RSS medians for
// both sides with the measured run count. A repair row's label also says
// whether it is like for like with the reference on bytes written (it keeps
// a numbered .1 backup, as par3cmdline does) or repairs in place (see
// repairModeLabel). Every rarpar row is drawn; engine rows have no reference
// ratio and stay in the Markdown report. The output is a pure function of
// results.json: no timestamps or local paths.
func RenderSVGs(results *Results, out string) ([]string, error) {
	if err := ValidateResults(results); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	rows := Summarize(results)
	var paths []string
	for _, op := range results.Ops {
		content, ok := renderOpSVG(results, rows, op)
		if !ok {
			continue
		}
		path := filepath.Join(out, "rarpar-par3-"+op+".svg")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return paths, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

type par3ChartRow struct {
	label     string
	reference Row
	candidate Row
	dnf       string
}

func renderOpSVG(results *Results, rows []Row, op string) ([]byte, bool) {
	references := map[string]Row{}
	for _, row := range rows {
		if row.Op == op && row.Tool == ToolReference {
			references[row.Config+"@"+row.Target] = row
		}
	}
	carriers := map[string]bool{}
	for _, config := range results.Configs {
		carriers[config.ID] = config.Carrier != ""
	}
	var chart []par3ChartRow
	for _, row := range rows {
		if row.Op != op || row.Tool != ToolCandidate || row.Wall.N == 0 {
			continue
		}
		reference, ok := references[row.Config+"@"+row.Target]
		if !ok {
			continue
		}
		label := row.Config + " / " + row.Variant
		if row.Target != "" {
			label += " @" + row.Target
		}
		if op == OpRepair {
			label += repairModeLabel(row, carriers[row.Config])
		}
		chart = append(chart, par3ChartRow{label: label, reference: reference, candidate: row, dnf: reference.DNF})
	}
	if len(chart) == 0 {
		return nil, false
	}
	height := 198 + len(chart)*54
	if height < 330 {
		height = 330
	}
	title := "rarpar PAR3 " + op + " against par3cmdline"
	description := fmt.Sprintf("PAR3 %s on %s. Relative speed is par3cmdline median wall time divided by rarpar median wall time; each row also lists CPU time and peak RSS for both.", op, results.Machine.Label)
	if op == OpRepair {
		description += " par3cmdline retains a numbered .1 copy of every file it repairs. Rows marked retains file do too, so they write the same bytes as the reference; rows marked in place repair in place and write no copy."
	}
	var document bytes.Buffer
	fmt.Fprintf(&document, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-labelledby=\"title desc\">\n", par3ChartWidth, height, par3ChartWidth, height)
	fmt.Fprintf(&document, "  <title id=\"title\">%s</title>\n  <desc id=\"desc\">%s</desc>\n", bench.EscapeXML(title), bench.EscapeXML(description))
	document.WriteString(bench.SVGStyle())
	fmt.Fprintf(&document, "  <metadata>schema=%s; profile=%s; op=%s; candidate_sha256=%s; reference_sha256=%s; warmups=%d; repeats=%d</metadata>\n",
		bench.EscapeXML(results.Schema), bench.EscapeXML(results.Profile), op, results.Candidate.SHA256, results.Reference.SHA256, results.Warmups, results.Repeats)
	fmt.Fprintf(&document, "  <rect class=\"bg\" width=\"%d\" height=\"%d\"/>\n", par3ChartWidth, height)
	fmt.Fprintf(&document, "  <text class=\"title\" x=\"48\" y=\"48\">%s</text>\n", bench.EscapeXML(title))
	fmt.Fprintf(&document, "  <text class=\"subtitle\" x=\"48\" y=\"75\">%s. Lower is better; bars show the faster side's wall-time multiplier.</text>\n",
		bench.EscapeXML(fmt.Sprintf("%s / %s / %s, %d logical CPUs", firstNonEmpty(results.Machine.Label, results.Machine.CPU), results.Machine.OS, results.Machine.Architecture, results.Machine.CPUCount)))
	fmt.Fprintf(&document, "  <g aria-label=\"Legend\"><rect class=\"slower\" x=\"570\" y=\"84\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"592\" y=\"96\">par3cmdline faster</text><rect class=\"cpu\" x=\"890\" y=\"84\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"912\" y=\"96\">rarpar faster</text></g>\n")
	document.WriteString("  <text class=\"column\" x=\"48\" y=\"112\">Set / rarpar row / wall, CPU, peak RSS (reference -&gt; rarpar)</text>\n  <text class=\"column\" x=\"620\" y=\"112\">Relative speed</text>\n")
	axisStart, parity, axisEnd := 620.0, 885.0, 1150.0
	axisBottom := height - 44
	document.WriteString("  <g aria-label=\"Relative speed axis\">\n")
	for _, tick := range []struct {
		ratio float64
		label string
	}{{0.125, "8x"}, {0.25, "4x"}, {0.5, "2x"}, {1, "1x parity"}, {2, "2x"}, {4, "4x"}, {8, "8x"}} {
		x := bench.RatioX(tick.ratio, axisStart, parity, axisEnd)
		class := "grid"
		if tick.ratio == 1 {
			class = "parity"
		}
		fmt.Fprintf(&document, "    <line class=\"%s\" x1=\"%.1f\" y1=\"121\" x2=\"%.1f\" y2=\"%d\"/><text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">%s</text>\n", class, x, x, axisBottom-14, x, axisBottom+4, tick.label)
	}
	fmt.Fprintf(&document, "    <text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">par3cmdline faster</text>\n", (axisStart+parity)/2, axisBottom+24)
	fmt.Fprintf(&document, "    <text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">rarpar faster</text>\n", (parity+axisEnd)/2, axisBottom+24)
	document.WriteString("  </g>\n")
	fmt.Fprintf(&document, "  <g aria-label=\"PAR3 %s rows\">\n", op)
	y := 132
	for _, row := range chart {
		fmt.Fprintf(&document, "    <text class=\"workload\" x=\"48\" y=\"%d\">%s</text>\n", y+24, bench.EscapeXML(row.label))
		fmt.Fprintf(&document, "    <text class=\"timing\" x=\"48\" y=\"%d\">%s</text>\n", y+40, bench.EscapeXML(par3TimingLine(row)))
		if row.dnf != "" || row.reference.Wall.N == 0 {
			fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">reference did not finish</text>\n", parity, y+28)
		} else {
			ratio := row.reference.Wall.Median / row.candidate.Wall.Median
			x := bench.RatioX(ratio, axisStart, parity, axisEnd)
			if ratio >= 1 {
				fmt.Fprintf(&document, "    <rect class=\"cpu\" x=\"%.1f\" y=\"%d\" width=\"%.1f\" height=\"14\" rx=\"2\"/>\n", parity, y+16, x-parity)
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">%.1fx</text>\n", x+8, y+28, ratio)
			} else {
				fmt.Fprintf(&document, "    <rect class=\"slower\" x=\"%.1f\" y=\"%d\" width=\"%.1f\" height=\"14\" rx=\"2\"/>\n", x, y+16, parity-x)
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\" text-anchor=\"end\">%.1fx</text>\n", x-8, y+28, 1/ratio)
			}
		}
		fmt.Fprintf(&document, "    <line class=\"rule\" x1=\"48\" y1=\"%d\" x2=\"1150\" y2=\"%d\"/>\n", y+50, y+50)
		y += 54
	}
	document.WriteString("  </g>\n</svg>\n")
	return document.Bytes(), true
}

// repairModeLabel is a repair row's label suffix: which rarpar row is like
// for like with the reference on bytes written (it keeps a numbered .1
// backup, as par3cmdline does) and which repairs in place. A PAR-inside
// set's one row runs the compatible rs, like for like when its repairs kept
// the damaged carrier as a backup.
func repairModeLabel(row Row, carrier bool) string {
	switch {
	case carrier && row.LeftBackup == "true":
		return " — compatible rs, retains file like the reference: like for like"
	case carrier:
		return " — compatible rs"
	case row.Backup:
		return " — retains file like the reference: like for like"
	default:
		return " — in place, no backup"
	}
}

// par3TimingLine is "wall 4.65 -> 0.93 s | CPU 4.43 -> 2.36 s | RSS 321 -> 29 MiB | n=7".
func par3TimingLine(row par3ChartRow) string {
	parts := []string{
		fmt.Sprintf("wall %s -> %s s", chartSeconds(row.reference.Wall), chartSeconds(row.candidate.Wall)),
		fmt.Sprintf("CPU %s -> %s s", chartSeconds(row.reference.CPU), chartSeconds(row.candidate.CPU)),
		fmt.Sprintf("peak RSS %s -> %s MiB", chartMiB(row.reference.RSS), chartMiB(row.candidate.RSS)),
		fmt.Sprintf("n=%d", row.candidate.Wall.N),
	}
	return strings.Join(parts, "  |  ")
}

func chartSeconds(s Stat) string {
	if s.N == 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f", s.Median)
}

func chartMiB(s Stat) string {
	if s.N == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f", s.Median/(1<<20))
}
