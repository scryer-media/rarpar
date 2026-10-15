package par3bench

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// VersusChartInput is one machine's comparison and the name its rows carry
// on the chart; an empty Name uses the machine label from the results.
type VersusChartInput struct {
	Name    string
	Results *VersusResults
}

const (
	versusChartTop      = 132
	versusChartHeader   = 28
	versusChartArmRow   = 24
	versusChartGroupGap = 10
)

// RenderVersusSVGs writes one static SVG per comparison and op across every
// input, named rarpar-par3-versus-<config>-<op>.svg, and returns their paths.
// Each machine is a group of rows, one per arm that ran, so PAR2 (par2-rs,
// par2cmdline-turbo) and PAR3 (Cauchy, FFT) sit on one scale: the bar is the
// baseline arm's median wall time divided by the arm's, on the same symmetric
// log scale as the other charts, and each row carries the arm's median wall,
// CPU (user+sys) and peak RSS. The baseline is par2cmdline-turbo when every
// machine ran it, otherwise par2-rs. A repair row says whether the arm kept a
// numbered .1 backup of what it repaired or repaired in place, so like for
// like on bytes written can be read off the chart. A comparison must mean the
// same thing on every input (dataset, block size, recovery and damage), or the
// render fails. The output is a pure function of the inputs: no timestamps or
// local paths.
func RenderVersusSVGs(inputs []VersusChartInput, out string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no versus results to render")
	}
	configs, err := versusChartConfigs(inputs)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	cells := make([]map[string]VersusCell, len(inputs))
	for i, input := range inputs {
		cells[i] = VersusCells(input.Results)
	}
	var paths []string
	for _, config := range configs {
		for _, op := range VersusOps {
			content, ok := renderVersusSVG(inputs, cells, config, op)
			if !ok {
				continue
			}
			path := filepath.Join(out, "rarpar-par3-versus-"+config.ID+"-"+op+".svg")
			if err := os.WriteFile(path, content, 0o644); err != nil {
				return paths, err
			}
			paths = append(paths, path)
		}
	}
	return paths, nil
}

// versusChartConfigs is every comparison in the inputs, in first-seen order,
// after checking each one has the same definition everywhere it ran.
func versusChartConfigs(inputs []VersusChartInput) ([]VersusConfig, error) {
	type seen struct {
		config  VersusConfig
		dataset Dataset
		name    string
	}
	byID := map[string]seen{}
	var order []VersusConfig
	for _, input := range inputs {
		if input.Results == nil {
			return nil, fmt.Errorf("versus input %q has no results", input.Name)
		}
		if input.Results.Schema != VersusSchema {
			return nil, fmt.Errorf("versus input %q: schema %q, want %q", versusInputName(input), input.Results.Schema, VersusSchema)
		}
		for _, config := range input.Results.Configs {
			dataset, _ := versusDataset(input.Results, config.Dataset)
			previous, ok := byID[config.ID]
			if !ok {
				byID[config.ID] = seen{config: config, dataset: dataset, name: versusInputName(input)}
				order = append(order, config)
				continue
			}
			if !sameVersusConfig(previous.config, config) || !reflect.DeepEqual(previous.dataset, dataset) {
				return nil, fmt.Errorf("comparison %s differs between %s and %s; render them separately", config.ID, previous.name, versusInputName(input))
			}
		}
	}
	return order, nil
}

func sameVersusConfig(a, b VersusConfig) bool {
	return a.Dataset == b.Dataset && a.BlockSize == b.BlockSize && a.Recovery == b.Recovery && reflect.DeepEqual(a.Damage, b.Damage)
}

func versusDataset(results *VersusResults, id string) (Dataset, bool) {
	for _, dataset := range results.Datasets {
		if dataset.ID == id {
			return dataset, true
		}
	}
	return Dataset{}, false
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

type versusChartGroup struct {
	name     string
	subtitle string
	rows     []versusChartRow
	baseline *VersusCell
}

type versusChartRow struct {
	arm  string
	cell *VersusCell
}

func renderVersusSVG(inputs []VersusChartInput, cells []map[string]VersusCell, config VersusConfig, op string) ([]byte, bool) {
	var groups []versusChartGroup
	baseline := ArmPAR2Turbo
	for i, input := range inputs {
		if !versusHasConfig(input.Results, config.ID) {
			continue
		}
		if _, ok := cells[i][config.ID+"/"+op+"/"+ArmPAR2Turbo]; !ok {
			baseline = ArmPAR2
		}
	}
	measured := false
	for i, input := range inputs {
		results := input.Results
		var local VersusConfig
		found := false
		for _, candidate := range results.Configs {
			if candidate.ID == config.ID {
				local, found = candidate, true
			}
		}
		if !found {
			continue
		}
		group := versusChartGroup{
			name:     versusInputName(input),
			subtitle: fmt.Sprintf("%s / %s, %d logical CPUs, %d run(s) per arm", results.Machine.OS, results.Machine.Architecture, results.Machine.CPUCount, results.Repeats),
		}
		if cell, ok := cells[i][config.ID+"/"+op+"/"+baseline]; ok {
			group.baseline = &cell
		}
		for _, arm := range VersusOpArms(local.Arms, op, results.InPlaceUnsupported) {
			if arm == ArmPAR2Turbo && results.PAR2Turbo == nil {
				continue
			}
			row := versusChartRow{arm: arm}
			if cell, ok := cells[i][config.ID+"/"+op+"/"+arm]; ok {
				row.cell = &cell
				measured = true
			}
			group.rows = append(group.rows, row)
		}
		groups = append(groups, group)
	}
	if !measured {
		return nil, false
	}
	height := versusChartTop + 82
	for _, group := range groups {
		height += versusChartHeader + len(group.rows)*versusChartArmRow + versusChartGroupGap
	}
	dataset, _ := versusDataset(inputs[0].Results, config.Dataset)
	for _, input := range inputs {
		if found, ok := versusDataset(input.Results, config.Dataset); ok {
			dataset = found
			break
		}
	}
	title := fmt.Sprintf("PAR2 against PAR3: %s, %s", config.ID, op)
	setLine := fmt.Sprintf("%s. Recovery %d (%.1f%%), damage %s (%d blocks).", strings.TrimSuffix(config.Note, "."), config.Recovery, config.RecoveryPercent(dataset), config.Damage.Name, config.Damage.LostBlocks())
	description := fmt.Sprintf("PAR2 (par2-rs, par2cmdline-turbo) and PAR3 (rarpar par3, Cauchy and FFT) %s of comparison %s on %d machine(s). %s Relative speed is %s median wall time divided by each arm's median wall time; each row also lists the arm's CPU time and peak RSS. Every repair was checked against the inputs' SHA-256.",
		op, config.ID, len(groups), setLine, baseline)
	if op == OpRepair {
		description += " Arms marked keeps .1 left a numbered backup of every file they repaired, as par2cmdline-turbo does; arms marked in place wrote none. Only arms with the same mark write the same bytes."
	}
	var document bytes.Buffer
	fmt.Fprintf(&document, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-labelledby=\"title desc\">\n", par3ChartWidth, height, par3ChartWidth, height)
	fmt.Fprintf(&document, "  <title id=\"title\">%s</title>\n  <desc id=\"desc\">%s</desc>\n", bench.EscapeXML(title), bench.EscapeXML(description))
	document.WriteString(bench.SVGStyle())
	var digests []string
	for _, input := range inputs {
		if versusHasConfig(input.Results, config.ID) {
			digests = append(digests, fmt.Sprintf("%s:%s:%d/%d", versusInputName(input), input.Results.Candidate.SHA256, input.Results.Warmups, input.Results.Repeats))
		}
	}
	fmt.Fprintf(&document, "  <metadata>%s</metadata>\n", bench.EscapeXML(fmt.Sprintf("schema=%s; config=%s; op=%s; baseline=%s; inputs=%s", VersusSchema, config.ID, op, baseline, strings.Join(digests, ", "))))
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
	fmt.Fprintf(&document, "  <g aria-label=\"%s\">\n", bench.EscapeXML(config.ID+" "+op+" rows"))
	y := versusChartTop
	for _, group := range groups {
		fmt.Fprintf(&document, "    <text class=\"machine\" x=\"48\" y=\"%d\">%s</text><text class=\"timing\" x=\"%d\" y=\"%d\">%s</text>\n",
			y+20, bench.EscapeXML(group.name), 48+versusTextWidth(group.name, 8.6)+14, y+20, bench.EscapeXML(group.subtitle))
		y += versusChartHeader
		for _, row := range group.rows {
			fmt.Fprintf(&document, "    <text class=\"workload\" x=\"64\" y=\"%d\">%s</text>\n", y+16, bench.EscapeXML(versusArmLabel(row, op)))
			fmt.Fprintf(&document, "    <text class=\"timing\" x=\"330\" y=\"%d\">%s</text>\n", y+16, bench.EscapeXML(versusTimingLine(row.cell)))
			switch {
			case row.cell == nil:
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">no successful run</text>\n", parity+8, y+16)
			case row.arm == baseline:
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">baseline</text>\n", parity+8, y+16)
			case group.baseline == nil:
				fmt.Fprintf(&document, "    <text class=\"ratio\" x=\"%.1f\" y=\"%d\">%s</text>\n", parity+8, y+16, bench.EscapeXML("no "+baseline+" run"))
			default:
				ratio := group.baseline.WallSeconds / row.cell.WallSeconds
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

func versusHasConfig(results *VersusResults, id string) bool {
	for _, config := range results.Configs {
		if config.ID == id {
			return true
		}
	}
	return false
}

// versusArmLabel is the arm, and at repair what its runs left beside the
// repaired files: "par3-fft, in place" or "par2cmdline-turbo, keeps .1". A
// PAR3 arm's -backup twin is named as its codec arm; the mark tells them apart.
func versusArmLabel(row versusChartRow, op string) string {
	label := versusSetArm(row.arm)
	if op != OpRepair || row.cell == nil {
		return label
	}
	switch row.cell.Backups {
	case "true":
		return label + ", keeps .1"
	case "false":
		return label + ", in place"
	default:
		return label + ", backups varied"
	}
}

// versusTimingLine is "2.18 s wall  ·  3.86 s CPU  ·  232 MiB".
func versusTimingLine(cell *VersusCell) string {
	if cell == nil {
		return "-"
	}
	return fmt.Sprintf("%.2f s wall  ·  %.2f s CPU  ·  %.0f MiB", cell.WallSeconds, cell.CPUSeconds, float64(cell.MaxRSSBytes)/(1<<20))
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
