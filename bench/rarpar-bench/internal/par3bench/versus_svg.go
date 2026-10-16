package par3bench

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// VersusChartInput is one machine's suite results and the name its rows
// carry on the chart; an empty Name uses the machine label from the results.
type VersusChartInput struct {
	Name    string
	Results *Results
}

const (
	versusChartTop      = 132
	versusChartHeader   = 28
	versusChartArmRow   = 24
	versusChartGroupGap = 10
)

// RenderVersusSVGs writes one static SVG per posting shape and op across
// every input, named rarpar-par3-versus-<shape>-<op>.svg, and returns their
// paths. It draws the suite rows of each shape's sets (see VersusArms), so
// PAR2 (par2-rs, par2cmdline-turbo), the reference (par3cmdline) and rarpar
// par3, each codec, sit on one scale: the bar is the baseline arm's median wall
// time divided by the arm's, on the same symmetric log scale as the other
// charts, and each row carries the arm's median wall, CPU (user+sys) and peak
// RSS. The baseline is par2cmdline-turbo when every machine ran it, otherwise
// par2-rs. A repair row says whether the arm retained a numbered .1 of every
// file it repaired or repaired in place, so like for like on bytes written
// can be read off the chart. A shape must mean the same thing on every input
// (dataset, block size, recovery and damage), or the render fails. The output
// is a pure function of the inputs: no timestamps or local paths.
func RenderVersusSVGs(inputs []VersusChartInput, out string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no suite results to render")
	}
	shapes, err := versusChartShapes(inputs)
	if err != nil {
		return nil, err
	}
	if len(shapes) == 0 {
		return nil, fmt.Errorf("no set in the inputs names a posting shape")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	rows := make([][]Row, len(inputs))
	for i, input := range inputs {
		rows[i] = Summarize(input.Results)
	}
	var paths []string
	for _, shape := range shapes {
		for _, op := range VersusOps {
			content, ok := renderVersusSVG(inputs, rows, shape, op)
			if !ok {
				continue
			}
			path := filepath.Join(out, "rarpar-par3-versus-"+shape+"-"+op+".svg")
			if err := os.WriteFile(path, content, 0o644); err != nil {
				return paths, err
			}
			paths = append(paths, path)
		}
	}
	return paths, nil
}

// versusChartShapes is every shape in the inputs, in first-seen order, after
// checking each one has the same definition everywhere it ran.
func versusChartShapes(inputs []VersusChartInput) ([]string, error) {
	type seen struct {
		set  *ConfigSummary
		name string
	}
	byID := map[string]seen{}
	var order []string
	for _, input := range inputs {
		if input.Results == nil {
			return nil, fmt.Errorf("input %q has no results", input.Name)
		}
		for _, shape := range VersusShapes(input.Results) {
			previous, ok := byID[shape.ID]
			if !ok {
				byID[shape.ID] = seen{set: shape.Set(), name: versusInputName(input)}
				order = append(order, shape.ID)
				continue
			}
			if err := sameShape(previous.set, shape.Set()); err != nil {
				return nil, fmt.Errorf("shape %s differs between %s and %s (%v); render them separately", shape.ID, previous.name, versusInputName(input), err)
			}
		}
	}
	return order, nil
}

func versusInputName(input VersusChartInput) string {
	if input.Name != "" {
		return input.Name
	}
	if input.Results == nil {
		return ""
	}
	return firstNonEmpty(input.Results.Machine.Label, input.Results.Machine.CPU)
}

func versusShape(results *Results, id string) (VersusShape, bool) {
	for _, shape := range VersusShapes(results) {
		if shape.ID == id {
			return shape, true
		}
	}
	return VersusShape{}, false
}

type versusChartGroup struct {
	name     string
	subtitle string
	arms     []VersusArm
	baseline *Row
}

func renderVersusSVG(inputs []VersusChartInput, rows [][]Row, id, op string) ([]byte, bool) {
	var groups []versusChartGroup
	var armLists [][]VersusArm
	var set *ConfigSummary
	measured := false
	for i, input := range inputs {
		shape, ok := versusShape(input.Results, id)
		if !ok {
			continue
		}
		if set == nil {
			set = shape.Set()
		}
		arms := VersusArms(input.Results, rows[i], shape, op)
		for _, arm := range arms {
			measured = measured || arm.Measured()
		}
		_, _, workers := versusRarparRows(input.Results)
		results := input.Results
		groups = append(groups, versusChartGroup{
			name: versusInputName(input),
			subtitle: fmt.Sprintf("%s / %s, %d logical CPUs, rarpar par3 at %d workers, %d run(s) per arm",
				results.Machine.OS, results.Machine.Architecture, results.Machine.CPUCount, workers, set.MeasuredRepeats),
			arms: arms,
		})
		armLists = append(armLists, arms)
	}
	if !measured {
		return nil, false
	}
	baseline := versusBaseline(armLists)
	for i := range groups {
		for _, arm := range groups[i].arms {
			if arm.Name == baseline && arm.Measured() {
				groups[i].baseline = arm.Row
				break
			}
		}
	}
	height := versusChartTop + 82
	for _, group := range groups {
		height += versusChartHeader + len(group.arms)*versusChartArmRow + versusChartGroupGap
	}
	title := fmt.Sprintf("PAR2 against PAR3: %s, %s", id, op)
	setLine := fmt.Sprintf("Damage %s (%d blocks). %s.", set.Damage.Name, set.Damage.LostBlocks(), versusShapeNote(set.Note))
	description := fmt.Sprintf("PAR2 (par2-rs, par2cmdline-turbo) and PAR3 (par3cmdline and rarpar par3, Cauchy and FFT) %s of posting shape %s on %d machine(s). %s Relative speed is %s median wall time divided by each arm's median wall time; each row also lists the arm's CPU time and peak RSS. par3cmdline is single-threaded and the PAR2 tools run at their default thread count. Every repair was checked against the inputs' SHA-256.",
		op, id, len(groups), setLine, baseline)
	if op == OpRepair {
		description += " Arms marked retains file left a numbered .1 copy of every file they repaired, as par2cmdline-turbo and par3cmdline do; arms marked in place wrote none. Only arms with the same mark write the same bytes."
	}
	var document bytes.Buffer
	fmt.Fprintf(&document, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-labelledby=\"title desc\">\n", par3ChartWidth, height, par3ChartWidth, height)
	fmt.Fprintf(&document, "  <title id=\"title\">%s</title>\n  <desc id=\"desc\">%s</desc>\n", bench.EscapeXML(title), bench.EscapeXML(description))
	document.WriteString(bench.SVGStyle())
	var digests []string
	for _, input := range inputs {
		if _, ok := versusShape(input.Results, id); ok {
			digests = append(digests, fmt.Sprintf("%s:%s:%d/%d", versusInputName(input), input.Results.Candidate.SHA256, input.Results.Warmups, input.Results.Repeats))
		}
	}
	fmt.Fprintf(&document, "  <metadata>%s</metadata>\n", bench.EscapeXML(fmt.Sprintf("schema=%s; shape=%s; op=%s; baseline=%s; inputs=%s", ResultsSchema, id, op, baseline, strings.Join(digests, ", "))))
	fmt.Fprintf(&document, "  <rect class=\"bg\" width=\"%d\" height=\"%d\"/>\n", par3ChartWidth, height)
	fmt.Fprintf(&document, "  <text class=\"title\" x=\"48\" y=\"48\">%s</text>\n", bench.EscapeXML(title))
	fmt.Fprintf(&document, "  <text class=\"subtitle\" x=\"48\" y=\"75\">%s</text>\n", bench.EscapeXML(setLine))
	fmt.Fprintf(&document, "  <g aria-label=\"Legend\"><rect class=\"slower\" x=\"570\" y=\"84\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"592\" y=\"96\">%s faster</text><rect class=\"cpu\" x=\"890\" y=\"84\" width=\"14\" height=\"14\" rx=\"2\"/><text class=\"subtitle\" x=\"912\" y=\"96\">arm faster</text></g>\n", bench.EscapeXML(baseline))
	fmt.Fprintf(&document, "  <text class=\"column\" x=\"48\" y=\"112\">Machine / arm / median wall, CPU, peak RSS</text>\n  <text class=\"column\" x=\"620\" y=\"112\">%s</text>\n", bench.EscapeXML("Speed against "+baseline))
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
	fmt.Fprintf(&document, "    <text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">%s</text>\n", (axisStart+parity)/2, axisBottom+24, bench.EscapeXML(baseline+" faster"))
	fmt.Fprintf(&document, "    <text class=\"tick\" x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">arm faster</text>\n", (parity+axisEnd)/2, axisBottom+24)
	document.WriteString("  </g>\n")
	fmt.Fprintf(&document, "  <g aria-label=\"%s\">\n", bench.EscapeXML(id+" "+op+" rows"))
	y := versusChartTop
	for _, group := range groups {
		fmt.Fprintf(&document, "    <text class=\"machine\" x=\"48\" y=\"%d\">%s</text><text class=\"timing\" x=\"%d\" y=\"%d\">%s</text>\n",
			y+20, bench.EscapeXML(group.name), 48+versusTextWidth(group.name, 8.6)+14, y+20, bench.EscapeXML(group.subtitle))
		y += versusChartHeader
		for _, arm := range group.arms {
			fmt.Fprintf(&document, "    <text class=\"workload\" x=\"64\" y=\"%d\">%s</text>\n", y+16, bench.EscapeXML(arm.Label(op)))
			fmt.Fprintf(&document, "    <text class=\"timing\" x=\"360\" y=\"%d\">%s</text>\n", y+16, bench.EscapeXML(versusTimingLine(arm)))
			switch {
			case !arm.Measured():
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">%s</text>\n", parity+8, y+16, bench.EscapeXML(versusMissing(arm)))
			case arm.Name == baseline:
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">baseline</text>\n", parity+8, y+16)
			case group.baseline == nil:
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">%s</text>\n", parity+8, y+16, bench.EscapeXML("no "+baseline+" run"))
			default:
				ratio := group.baseline.Wall.Median / arm.Row.Wall.Median
				x := bench.RatioX(ratio, axisStart, parity, axisEnd)
				if ratio >= 1 {
					fmt.Fprintf(&document, "    <rect class=\"cpu\" x=\"%.1f\" y=\"%d\" width=\"%.1f\" height=\"12\" rx=\"2\"/>\n", parity, y+5, x-parity)
					fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">%s</text>\n", x+8, y+16, versusRatioText(ratio))
				} else {
					fmt.Fprintf(&document, "    <rect class=\"slower\" x=\"%.1f\" y=\"%d\" width=\"%.1f\" height=\"12\" rx=\"2\"/>\n", x, y+5, parity-x)
					fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\" text-anchor=\"end\">%s</text>\n", x-8, y+16, versusRatioText(1/ratio))
				}
			}
			y += versusChartArmRow
		}
		fmt.Fprintf(&document, "    <line class=\"rule\" x1=\"48\" y1=\"%d\" x2=\"1150\" y2=\"%d\"/>\n", y+versusChartGroupGap/2, y+versusChartGroupGap/2)
		y += versusChartGroupGap
	}
	document.WriteString("  </g>\n</svg>\n")
	return document.Bytes(), true
}

// versusShapeNote is a set's note without the FFT set's codec remark, so
// the shape reads the same from either set.
func versusShapeNote(note string) string {
	note, _, _ = strings.Cut(note, "; FFT on both sides")
	return strings.TrimSuffix(note, ".")
}

// versusMissing says why an arm has no bar.
func versusMissing(arm VersusArm) string {
	if arm.Row != nil && arm.Row.DNF != "" {
		return "did not finish"
	}
	return "no successful run"
}

// versusTimingLine is "2.18 s wall  ·  3.86 s CPU  ·  232 MiB".
func versusTimingLine(arm VersusArm) string {
	if !arm.Measured() {
		return "-"
	}
	return fmt.Sprintf("%.2f s wall  ·  %.2f s CPU  ·  %.0f MiB", arm.Row.Wall.Median, arm.Row.CPU.Median, arm.Row.RSS.Median/(1<<20))
}

// versusRatioText keeps two significant figures below 10x and none above,
// so a bar clamped at the 8x end still says how far past it the arm was.
func versusRatioText(ratio float64) string {
	if ratio >= 9.95 {
		return fmt.Sprintf("%.0fx", ratio)
	}
	return fmt.Sprintf("%.1fx", ratio)
}

// versusTextWidth estimates a label's rendered width at perChar pixels a
// character, enough to place the text that follows it on the same line.
func versusTextWidth(text string, perChar float64) int {
	return int(float64(len([]rune(text)))*perChar + 0.5)
}
