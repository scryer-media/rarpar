package par3bench

import (
	"fmt"
	"math"
	"strings"
)

// RenderTables is the Markdown for the PAR3 tables of the benchmark page,
// one column per input machine, in input order: the summary (geometric mean
// of the reference ÷ rarpar wall-time ratio over the plain sets, per op and
// worker count, plus any PAR-inside set), then per set at the given worker
// count each op's rarpar median wall time with that ratio after it, as
// "4.4 (14×)", then the peak RSS range across the machines. Every input must
// carry the same sets. Workers 0 takes each machine's largest worker count.
func RenderTables(inputs []VersusChartInput, workers int) (string, error) {
	if len(inputs) == 0 {
		return "", fmt.Errorf("no suite results to tabulate")
	}
	configs := inputs[0].Results.Configs
	for _, input := range inputs[1:] {
		if len(input.Results.Configs) != len(configs) {
			return "", fmt.Errorf("%s ran %d sets, %s ran %d", versusInputName(inputs[0]), len(configs), versusInputName(input), len(input.Results.Configs))
		}
		for i, config := range input.Results.Configs {
			if config.ID != configs[i].ID {
				return "", fmt.Errorf("set %d is %s on %s and %s on %s", i, configs[i].ID, versusInputName(inputs[0]), config.ID, versusInputName(input))
			}
			if err := sameShape(&configs[i], &config); err != nil {
				return "", fmt.Errorf("set %s differs between %s and %s: %v", config.ID, versusInputName(inputs[0]), versusInputName(input), err)
			}
		}
	}
	tables := make([]tableRows, len(inputs))
	for i, input := range inputs {
		tables[i] = newTableRows(Summarize(input.Results))
		for _, count := range input.Results.Workers {
			tables[i].largest = max(tables[i].largest, count)
		}
		tables[i].most = workers
		if workers == 0 {
			tables[i].most = tables[i].largest
		}
	}
	many := fmt.Sprintf("%d workers", workers)
	if workers == 0 {
		many = "most workers"
	}
	names := make([]string, len(inputs))
	for i, input := range inputs {
		names[i] = versusInputName(input)
	}
	var b strings.Builder
	header := func(first string) {
		fmt.Fprintf(&b, "| %s | %s |\n|---|%s\n", first, strings.Join(names, " | "), strings.Repeat("---:|", len(names)))
	}
	type column struct {
		title   string
		op      string
		workers int
		backup  bool
	}
	var plain, carriers []ConfigSummary
	for _, config := range configs {
		if config.Carrier == "" {
			plain = append(plain, config)
		} else {
			carriers = append(carriers, config)
		}
	}
	var columns []column
	for _, op := range []string{OpCreate, OpVerify} {
		for _, count := range []int{1, workers} {
			columns = append(columns, column{fmt.Sprintf("%s, %s", opTitle(op), workerTitle(count, many)), op, count, false})
		}
	}
	for _, count := range []int{1, workers} {
		columns = append(columns, column{fmt.Sprintf("Repair retaining files, %s", workerTitle(count, many)), OpRepair, count, true})
	}
	columns = append(columns, column{"Repair in place, " + many, OpRepair, workers, false})
	columns = dedupeColumns(columns, func(c column) string { return c.title })
	b.WriteString("**Summary.** Geometric mean of the reference ÷ rarpar wall-time ratio over the plain sets; above 1 means rarpar is faster.\n\n")
	titles := []string{"Machine"}
	for _, c := range columns {
		titles = append(titles, c.title)
	}
	for _, config := range carriers {
		for _, op := range []string{OpVerify, OpRepair} {
			titles = append(titles, fmt.Sprintf("`%s` %s", config.ID, op))
		}
	}
	fmt.Fprintf(&b, "| %s |\n|---|%s\n", strings.Join(titles, " | "), strings.Repeat("---:|", len(titles)-1))
	for i, name := range names {
		cells := []string{name}
		for _, c := range columns {
			var ratios []float64
			for _, config := range plain {
				if ratio, ok := tables[i].ratio(config.ID, c.op, c.workers, c.backup); ok {
					ratios = append(ratios, ratio)
				}
			}
			cells = append(cells, geomeanText(ratios, len(plain)))
		}
		// A PAR-inside set runs its one rarpar row at the run's largest
		// worker count (see carrierRuns), whatever --workers reads.
		for _, config := range carriers {
			for _, op := range []string{OpVerify, OpRepair} {
				ratio, ok := tables[i].ratio(config.ID, op, tables[i].largest, false)
				if !ok {
					cells = append(cells, "–")
					continue
				}
				cells = append(cells, speedText(ratio))
			}
		}
		fmt.Fprintf(&b, "| %s |\n", strings.Join(cells, " | "))
	}
	for _, c := range []column{{"Create", OpCreate, workers, false}, {"Verify", OpVerify, workers, false},
		{"Repair retaining files", OpRepair, workers, true}, {"Repair in place", OpRepair, workers, false}} {
		fmt.Fprintf(&b, "\n**%s, %s.** rarpar median wall seconds (reference ÷ rarpar).\n\n", c.title, workerTitle(workers, many))
		header("Set")
		for _, config := range plain {
			cells := []string{"`" + config.ID + "`"}
			for i := range inputs {
				cells = append(cells, tables[i].cell(config.ID, c.op, c.workers, c.backup))
			}
			fmt.Fprintf(&b, "| %s |\n", strings.Join(cells, " | "))
		}
	}
	fmt.Fprintf(&b, "\n**Peak memory.** Peak RSS in MiB, %s, as the range across the machines.\n\n", workerTitle(workers, many))
	b.WriteString("| Set | Create, rarpar | Create, reference | Repair, rarpar | Repair, reference |\n|---|---:|---:|---:|---:|\n")
	for _, config := range plain {
		cells := []string{"`" + config.ID + "`"}
		for _, op := range []string{OpCreate, OpRepair} {
			for _, reference := range []bool{false, true} {
				var values []float64
				for i := range inputs {
					row := tables[i].rarpar(config.ID, op, workers, false)
					if reference {
						row = tables[i].reference(config.ID, op)
					}
					if row != nil && row.RSS.N > 0 {
						values = append(values, row.RSS.Median/(1<<20))
					}
				}
				cells = append(cells, rangeText(values))
			}
		}
		fmt.Fprintf(&b, "| %s |\n", strings.Join(cells, " | "))
	}
	return b.String(), nil
}

func dedupeColumns[T any](list []T, key func(T) string) []T {
	seen := map[string]bool{}
	var out []T
	for _, item := range list {
		if !seen[key(item)] {
			seen[key(item)] = true
			out = append(out, item)
		}
	}
	return out
}

func opTitle(op string) string {
	if op == "" {
		return op
	}
	return strings.ToUpper(op[:1]) + op[1:]
}

// tableRows indexes one machine's summarized rows for the tables; most is
// the worker count the "most workers" columns read, largest the run's
// largest worker count.
type tableRows struct {
	rows    []Row
	most    int
	largest int
}

func newTableRows(rows []Row) tableRows { return tableRows{rows: rows} }

// workerTitle is "1 worker" for one, else the many-workers title.
func workerTitle(count int, many string) string {
	if count == 1 {
		return "1 worker"
	}
	return many
}

// reference is the reference row of a set and op, on the first target.
func (t tableRows) reference(config, op string) *Row {
	for i := range t.rows {
		row := &t.rows[i]
		if row.Config == config && row.Op == op && row.Tool == ToolReference {
			return row
		}
	}
	return nil
}

// rarpar is the plain rarpar row (no kernel) of a set, op, worker count and
// repair mode, on the reference's target.
func (t tableRows) rarpar(config, op string, workers int, backup bool) *Row {
	if workers == 0 {
		workers = t.most
	}
	reference := t.reference(config, op)
	for i := range t.rows {
		row := &t.rows[i]
		if row.Config != config || row.Op != op || row.Tool != ToolCandidate || row.Backup != backup {
			continue
		}
		if reference != nil && row.Target != reference.Target {
			continue
		}
		if row.Variant == rarparVariantName(workers, backup, row.Target) {
			return row
		}
	}
	return nil
}

// rarparVariantName is the name Variants gives a plain rarpar row, with the
// target suffix a multi-target run adds.
func rarparVariantName(workers int, backup bool, target string) string {
	name := fmt.Sprintf("rarpar-w%d", workers)
	if backup {
		name += "-backup"
	}
	if target != "" {
		name += "@" + target
	}
	return name
}

// ratio is reference ÷ rarpar median wall time, when both measured.
func (t tableRows) ratio(config, op string, workers int, backup bool) (float64, bool) {
	reference, candidate := t.reference(config, op), t.rarpar(config, op, workers, backup)
	if reference == nil || candidate == nil || reference.DNF != "" || reference.Wall.N == 0 || candidate.Wall.N == 0 {
		return 0, false
	}
	return reference.Wall.Median / candidate.Wall.Median, true
}

// cell is "4.4 (14×)": rarpar's median wall seconds, then the ratio.
func (t tableRows) cell(config, op string, workers int, backup bool) string {
	candidate := t.rarpar(config, op, workers, backup)
	if candidate == nil || candidate.Wall.N == 0 {
		return "–"
	}
	if ratio, ok := t.ratio(config, op, workers, backup); ok {
		return fmt.Sprintf("%s (%s)", secondsText(candidate.Wall.Median), speedText(ratio))
	}
	if reference := t.reference(config, op); reference != nil && reference.DNF != "" {
		return secondsText(candidate.Wall.Median) + " (reference DNF)"
	}
	return secondsText(candidate.Wall.Median)
}

// secondsText is one decimal, or two below 0.1 s so a fast row never reads
// "0.0".
func secondsText(seconds float64) string {
	if seconds < 0.095 {
		return fmt.Sprintf("%.2f", seconds)
	}
	return fmt.Sprintf("%.1f", seconds)
}

// speedText keeps one decimal below 10× and none above: "4.4×", "14×".
func speedText(ratio float64) string {
	if ratio >= 9.95 {
		return fmt.Sprintf("%.0f×", ratio)
	}
	return fmt.Sprintf("%.1f×", ratio)
}

// geomeanText is the geometric mean of the ratios, marked when some sets
// had no ratio.
func geomeanText(ratios []float64, want int) string {
	if len(ratios) == 0 {
		return "–"
	}
	sum := 0.0
	for _, ratio := range ratios {
		sum += math.Log(ratio)
	}
	text := speedText(math.Exp(sum / float64(len(ratios))))
	if len(ratios) < want {
		text += fmt.Sprintf(" (%d of %d sets)", len(ratios), want)
	}
	return text
}

// rangeText is "54–58", or one figure when the range is a point.
func rangeText(values []float64) string {
	if len(values) == 0 {
		return "–"
	}
	low, high := values[0], values[0]
	for _, value := range values {
		low, high = math.Min(low, value), math.Max(high, value)
	}
	if math.Round(low) == math.Round(high) {
		return fmt.Sprintf("%.0f", low)
	}
	return fmt.Sprintf("%.0f–%.0f", low, high)
}
