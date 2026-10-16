package par3bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// versusSuiteFixture is one machine's suite run of the smoke shape (its
// Cauchy set carrying the PAR2 rows, and its FFT set), every row measured
// once at the given walls, keyed "set/op/variant". A repair by
// par2cmdline-turbo, the reference or a -backup row leaves a .1.
func versusSuiteFixture(label string, turbo bool, walls map[string]float64) *Results {
	profile := smokeProfile()
	results := &Results{Schema: ResultsSchema, Profile: "unit", Repeats: 1, Status: StatusOK, Workers: []int{1, 4},
		Machine: machineFixture(label), Ops: []string{OpCreate, OpVerify, OpRepair}, Variants: append(Variants([]int{1, 4}, nil), PAR2Rows()...)}
	if turbo {
		results.PAR2Turbo = &Binary{SHA256: "turbo"}
	}
	for _, config := range profile.Configs {
		if config.Shape == "" {
			continue
		}
		summary := ConfigSummary{Config: config, DatasetBytes: 8 << 20, MeasuredRepeats: 1}
		summary.InputBlocks = 514
		results.Configs = append(results.Configs, summary)
	}
	for key, wall := range walls {
		parts := strings.SplitN(key, "/", 3)
		run := RunRecord{Config: parts[0], Op: parts[1], Variant: parts[2], Status: StatusOK,
			Measurement: Measurement{WallSeconds: wall, UserSeconds: wall * 2, MaxRSSBytes: 64 << 20}}
		for _, variant := range results.Variants {
			if variant.Name == run.Variant {
				run.Tool = variant.Tool
			}
		}
		if run.Op == OpRepair {
			check := RepairCheck{Match: true}
			if run.Variant == ToolPAR2Turbo || run.Variant == "reference" || strings.HasSuffix(run.Variant, "-backup") {
				check.ExtraFiles, check.Backups = []string{"s0.bin.1"}, []string{"s0.bin.1"}
			}
			run.Repair = &check
		}
		results.Runs = append(results.Runs, run)
	}
	return results
}

func machineFixture(label string) (machine bench.Machine) {
	machine.Label, machine.OS, machine.Architecture, machine.CPUCount = label, "linux", "amd64", 4
	return machine
}

func TestVersusArmsPickEveryToolForAShape(t *testing.T) {
	walls := map[string]float64{
		"smoke-gf16/repair/par2-rs": 4, "smoke-gf16/repair/par2cmdline-turbo": 6, "smoke-gf16/repair/reference": 8,
		"smoke-fft/repair/reference": 9, "smoke-gf16/repair/rarpar-w4": 1, "smoke-gf16/repair/rarpar-w4-backup": 3,
		"smoke-gf16/repair/rarpar-w1": 2, "smoke-fft/repair/rarpar-w4": 0.5, "smoke-fft/repair/rarpar-w4-backup": 2,
	}
	results := versusSuiteFixture("x", true, walls)
	shapes := VersusShapes(results)
	if len(shapes) != 1 || shapes[0].ID != "smoke" || shapes[0].Cauchy.ID != "smoke-gf16" || shapes[0].FFT.ID != "smoke-fft" {
		t.Fatalf("shapes %+v", shapes)
	}
	var labels []string
	for _, arm := range VersusArms(results, Summarize(results), shapes[0], OpRepair) {
		labels = append(labels, arm.Label(OpRepair))
	}
	want := "par2-rs, in place|par2cmdline-turbo, retains file|par3cmdline (Cauchy), retains file|par3cmdline (FFT), retains file|" +
		"rarpar par3 (Cauchy), in place|rarpar par3 (Cauchy), retains file|rarpar par3 (FFT), in place|rarpar par3 (FFT), retains file"
	if strings.Join(labels, "|") != want {
		t.Fatalf("arms\n%s\nwant\n%s", strings.Join(labels, "|"), want)
	}
}

func TestRenderVersusSVGsDrawsEveryArmAgainstTurbo(t *testing.T) {
	walls := map[string]float64{
		"smoke-gf16/create/par2-rs": 2, "smoke-gf16/create/par2cmdline-turbo": 2, "smoke-gf16/create/reference": 16,
		"smoke-fft/create/reference": 8, "smoke-gf16/create/rarpar-w4": 1, "smoke-fft/create/rarpar-w4": 0.5,
		"smoke-gf16/repair/par2-rs": 4, "smoke-gf16/repair/par2cmdline-turbo": 6, "smoke-gf16/repair/rarpar-w4": 1,
		"smoke-gf16/repair/rarpar-w4-backup": 12, "smoke-fft/repair/rarpar-w4": 0.25,
	}
	inputs := []VersusChartInput{{Name: "Zen 4", Results: versusSuiteFixture("zen4", true, walls)}, {Results: versusSuiteFixture("n1", true, walls)}}
	out := t.TempDir()
	paths, err := RenderVersusSVGs(inputs, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || filepath.Base(paths[0]) != "rarpar-par3-versus-smoke-create.svg" || filepath.Base(paths[1]) != "rarpar-par3-versus-smoke-repair.svg" {
		t.Fatalf("charts %v", paths)
	}
	create, _ := os.ReadFile(paths[0])
	for _, want := range []string{"baseline=par2cmdline-turbo", ">Zen 4<", ">n1<", "2.00 s wall  ·  4.00 s CPU  ·  64 MiB",
		">baseline<", "2.0x", "4.0x", "8.0x", "par3cmdline (Cauchy)", "par3cmdline (FFT)", "rarpar par3 at 4 workers", "Speed against par2cmdline-turbo"} {
		if !strings.Contains(string(create), want) {
			t.Fatalf("create chart lacks %q:\n%s", want, create)
		}
	}
	repair, _ := os.ReadFile(paths[1])
	for _, want := range []string{"par2-rs, in place", "par2cmdline-turbo, retains file", "rarpar par3 (Cauchy), in place", "rarpar par3 (Cauchy), retains file",
		"rarpar par3 (FFT), in place", "24x", "no successful run", "class=\"slower\""} {
		if !strings.Contains(string(repair), want) {
			t.Fatalf("repair chart lacks %q:\n%s", want, repair)
		}
	}
	if strings.Contains(string(repair), "keeps .1") {
		t.Fatal("repair chart still says keeps .1")
	}
	again := t.TempDir()
	if _, err := RenderVersusSVGs(inputs, again); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(again, filepath.Base(paths[1])))
	if string(second) != string(repair) {
		t.Fatal("rendering is not deterministic")
	}
}

// A machine without par2cmdline-turbo moves the whole chart onto par2-rs, so
// every bar on it shares one baseline.
func TestRenderVersusSVGsFallsBackToPAR2RS(t *testing.T) {
	walls := map[string]float64{"smoke-gf16/create/par2-rs": 2, "smoke-gf16/create/par2cmdline-turbo": 1, "smoke-gf16/create/rarpar-w4": 1}
	inputs := []VersusChartInput{{Results: versusSuiteFixture("a", true, walls)}, {Results: versusSuiteFixture("b", false, walls)}}
	paths, err := RenderVersusSVGs(inputs, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("charts %v", paths)
	}
	create, _ := os.ReadFile(paths[0])
	if !strings.Contains(string(create), "baseline=par2-rs") || strings.Count(string(create), ">par2cmdline-turbo</text>") != 1 {
		t.Fatalf("chart did not fall back to par2-rs with one turbo row:\n%s", create)
	}
}

func TestRenderVersusSVGsRefusesDifferentShapes(t *testing.T) {
	walls := map[string]float64{"smoke-gf16/create/par2-rs": 1, "smoke-gf16/create/rarpar-w4": 1}
	other := versusSuiteFixture("b", false, walls)
	other.Configs[0].Recovery++
	_, err := RenderVersusSVGs([]VersusChartInput{{Results: versusSuiteFixture("a", false, walls)}, {Results: other}}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "differs between a and b") {
		t.Fatalf("err = %v", err)
	}
	if _, err := RenderVersusSVGs(nil, t.TempDir()); err == nil {
		t.Fatal("rendered no inputs")
	}
}

func TestRenderTablesPutsTimeBeforeTheRatio(t *testing.T) {
	walls := map[string]float64{
		"smoke-gf16/create/reference": 61.6, "smoke-gf16/create/rarpar-w4": 4.4, "smoke-gf16/create/rarpar-w1": 8.8,
		"smoke-fft/create/reference": 9, "smoke-fft/create/rarpar-w4": 2, "smoke-fft/create/rarpar-w1": 4,
		"smoke-gf16/repair/reference": 10, "smoke-gf16/repair/rarpar-w4-backup": 5, "smoke-gf16/repair/rarpar-w4": 1,
		"smoke-gf16/verify/reference": 1, "smoke-gf16/verify/rarpar-w4": 0.04,
	}
	inputs := []VersusChartInput{{Name: "Zen 4", Results: versusSuiteFixture("zen4", true, walls)}, {Name: "N1", Results: versusSuiteFixture("n1", true, walls)}}
	tables, err := RenderTables(inputs, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| Set | Zen 4 | N1 |", "| `smoke-gf16` | 4.4 (14×) | 4.4 (14×) |", "| `smoke-fft` | 2.0 (4.5×) |",
		"**Repair retaining files, 4 workers.**", "| `smoke-gf16` | 5.0 (2.0×) |", "| `smoke-gf16` | 1.0 (10×) |", "Create, 1 worker", "| Zen 4 | 4.0× | 7.9× |", "| `smoke-gf16` | 0.04 (25×) |"} {
		if !strings.Contains(tables, want) {
			t.Fatalf("tables lack %q:\n%s", want, tables)
		}
	}
}

// A repair arm with no successful run still says which repair mode its row
// selects, so the rarpar in-place and backup rows stay apart on the chart.
func TestVersusArmsLabelUnmeasuredRepairRowsByMode(t *testing.T) {
	results := versusSuiteFixture("x", true, map[string]float64{"smoke-gf16/repair/reference": 8})
	var labels []string
	for _, arm := range VersusArms(results, Summarize(results), VersusShapes(results)[0], OpRepair) {
		if strings.HasPrefix(arm.Name, "rarpar") {
			labels = append(labels, arm.Label(OpRepair))
		}
	}
	want := "rarpar par3 (Cauchy), in place|rarpar par3 (Cauchy), retains file|rarpar par3 (FFT), in place|rarpar par3 (FFT), retains file"
	if strings.Join(labels, "|") != want {
		t.Fatalf("labels %s", strings.Join(labels, "|"))
	}
}

// A multi-target run names every row NAME@TARGET; every arm, not only the
// rarpar ones, reads the first target's rows.
func TestVersusArmsReadEveryToolOnTheFirstTarget(t *testing.T) {
	walls := map[string]float64{"smoke-gf16/create/par2-rs@fast": 2, "smoke-gf16/create/par2cmdline-turbo@fast": 2,
		"smoke-gf16/create/reference@fast": 16, "smoke-fft/create/reference@fast": 8, "smoke-gf16/create/rarpar-w4@fast": 1,
		"smoke-fft/create/rarpar-w4@fast": 0.5, "smoke-gf16/create/par2cmdline-turbo@slow": 9}
	results := versusSuiteFixture("x", true, nil)
	results.Variants = MatrixRows([]int{1, 4}, nil, nil, nil, []string{ToolReference, ToolCandidate, ToolPAR2, ToolPAR2Turbo},
		[]Target{{Name: "fast"}, {Name: "slow"}})
	for key, wall := range walls {
		parts := strings.SplitN(key, "/", 3)
		run := RunRecord{Config: parts[0], Op: parts[1], Variant: parts[2], Status: StatusOK, Measurement: Measurement{WallSeconds: wall}}
		for _, variant := range results.Variants {
			if variant.Name == run.Variant {
				run.Tool, run.Target = variant.Tool, variant.Target
			}
		}
		results.Runs = append(results.Runs, run)
	}
	for _, arm := range VersusArms(results, Summarize(results), VersusShapes(results)[0], OpCreate) {
		if !arm.Measured() {
			t.Errorf("%s has no run on the first target", arm.Name)
		} else if arm.Name == ArmPAR2Turbo && arm.Row.Wall.Median != 2 {
			t.Errorf("par2cmdline-turbo read the %s row", arm.Row.Target)
		}
	}
}

// A group says how many runs its arms asked for from its own run, and names
// any arm whose median rests on fewer.
func TestRenderVersusSVGsCountsRunsPerMachine(t *testing.T) {
	walls := map[string]float64{"smoke-gf16/create/par2-rs": 2, "smoke-gf16/create/rarpar-w4": 1}
	short := versusSuiteFixture("b", false, walls)
	for i := range short.Configs {
		short.Configs[i].MeasuredRepeats = 3
	}
	paths, err := RenderVersusSVGs([]VersusChartInput{{Results: versusSuiteFixture("a", false, walls)}, {Results: short}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	chart, _ := os.ReadFile(paths[0])
	for _, want := range []string{"4 workers, 1 run(s) per arm</text>", "4 workers, 3 run(s) per arm; succeeded: par2-rs 1/3; rarpar par3 (Cauchy) 1/3</text>"} {
		if !strings.Contains(string(chart), want) {
			t.Fatalf("chart lacks %q:\n%s", want, chart)
		}
	}
}

func TestRenderVersusSVGsRefusesMixedComparisons(t *testing.T) {
	walls := map[string]float64{"smoke-gf16/create/par2-rs": 1, "smoke-gf16/create/rarpar-w4": 1}
	for name, change := range map[string]func(*Results){
		"damage file": func(r *Results) {
			r.Configs[0].Damage.Targets = append([]DamageTarget(nil), r.Configs[0].Damage.Targets...)
			r.Configs[0].Damage.Targets[0].File, r.Configs[0].Damage.Targets[1].File = r.Configs[0].Damage.Targets[1].File, r.Configs[0].Damage.Targets[0].File
			r.Configs[0].Damage.Targets[0].Blocks++
			r.Configs[0].Damage.Targets[1].Blocks--
		},
		"layout":  func(r *Results) { r.Configs[0].PAR2SourceBlocks++ },
		"version": func(r *Results) { r.Candidate.Version = "rarpar 0.9.0" },
		"shape":   func(r *Results) { r.Configs[0].Shape, r.Configs[1].Shape = "../smoke", "../smoke" },
	} {
		other := versusSuiteFixture("b", false, walls)
		change(other)
		parent := t.TempDir()
		if _, err := RenderVersusSVGs([]VersusChartInput{{Results: versusSuiteFixture("a", false, walls)}, {Results: other}}, filepath.Join(parent, "out")); err == nil {
			t.Errorf("%s: rendered a mixed comparison", name)
		}
		if entries, _ := os.ReadDir(parent); len(entries) != 0 {
			t.Errorf("%s: wrote %d entries", name, len(entries))
		}
	}
}

// A PAR-inside set has one rarpar row, at the run's largest worker count, so
// its summary cells read that row whatever worker count the tables show.
func TestRenderTablesReadsCarrierRowsAtTheirWorkerCount(t *testing.T) {
	walls := map[string]float64{"smoke-gf16/create/reference": 4, "smoke-gf16/create/rarpar-w1": 2,
		"zip/verify/reference": 6, "zip/verify/rarpar-w4": 2, "zip/repair/reference": 8, "zip/repair/rarpar-w4": 2}
	results := versusSuiteFixture("x", false, walls)
	results.Configs = append(results.Configs, ConfigSummary{Config: Config{ID: "zip", Dataset: "smoke", Carrier: CarrierZIP}})
	tables, err := RenderTables([]VersusChartInput{{Name: "Zen 4", Results: results}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tables, "| 3.0× | 4.0× |\n") {
		t.Fatalf("carrier cells:\n%s", tables)
	}
}
