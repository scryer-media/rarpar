package par3bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// versusChartFixture is one machine's comparison with every arm measured
// once: create and repair at the given walls, repairs leaving a .1 where the
// arm keeps a backup.
func versusChartFixture(label string, turbo bool, walls map[string]float64) *VersusResults {
	config := versusSmokeProfile().Configs[0]
	config.Arms = []string{ArmPAR2, ArmPAR3Cauchy, ArmPAR3FFT}
	if turbo {
		config.Arms = []string{ArmPAR2, ArmPAR2Turbo, ArmPAR3Cauchy, ArmPAR3FFT}
	}
	results := &VersusResults{Schema: VersusSchema, Profile: "unit", Repeats: 1, Status: StatusOK,
		Machine: machineFixture(label), Datasets: versusSmokeProfile().Datasets, Configs: []VersusConfig{config}}
	if turbo {
		results.PAR2Turbo = &Binary{SHA256: "turbo"}
	}
	for _, op := range VersusOps {
		for _, arm := range VersusOpArms(config.Arms, op, false) {
			wall, ok := walls[op+"/"+arm]
			if !ok {
				continue
			}
			run := VersusRun{Config: config.ID, Op: op, Arm: arm, Status: StatusOK,
				Measurement: Measurement{WallSeconds: wall, UserSeconds: wall * 2, MaxRSSBytes: 64 << 20}}
			if op == OpRepair {
				check := RepairCheck{Match: true}
				if arm == ArmPAR2Turbo || isPAR3BackupArm(arm) {
					check.ExtraFiles = []string{"v0.bin.1"}
					check.Backups = []string{"v0.bin.1"}
				}
				run.Repair = &check
			}
			results.Runs = append(results.Runs, run)
		}
	}
	return results
}

func machineFixture(label string) (machine bench.Machine) {
	machine.Label, machine.OS, machine.Architecture, machine.CPUCount = label, "linux", "amd64", 4
	return machine
}

func TestRenderVersusSVGsDrawsEveryArmAgainstTurbo(t *testing.T) {
	walls := map[string]float64{
		"create/" + ArmPAR2: 2, "create/" + ArmPAR2Turbo: 2, "create/" + ArmPAR3Cauchy: 1, "create/" + ArmPAR3FFT: 0.5,
		"repair/" + ArmPAR2: 4, "repair/" + ArmPAR2Turbo: 6, "repair/" + ArmPAR3Cauchy: 1,
		"repair/" + ArmPAR3CauchyBackup: 12, "repair/" + ArmPAR3FFT: 0.25,
	}
	inputs := []VersusChartInput{{Name: "Zen 4", Results: versusChartFixture("zen4", true, walls)}, {Results: versusChartFixture("n1", true, walls)}}
	out := t.TempDir()
	paths, err := RenderVersusSVGs(inputs, out)
	if err != nil {
		t.Fatal(err)
	}
	id := inputs[0].Results.Configs[0].ID
	if len(paths) != 2 || filepath.Base(paths[0]) != "rarpar-par3-versus-"+id+"-create.svg" || filepath.Base(paths[1]) != "rarpar-par3-versus-"+id+"-repair.svg" {
		t.Fatalf("charts %v", paths)
	}
	create, _ := os.ReadFile(paths[0])
	for _, want := range []string{"baseline=par2cmdline-turbo", ">Zen 4<", ">n1<", "2.00 s wall  ·  4.00 s CPU  ·  64 MiB",
		">baseline<", "2.0x", "4.0x", "Speed against par2cmdline-turbo"} {
		if !strings.Contains(string(create), want) {
			t.Fatalf("create chart lacks %q:\n%s", want, create)
		}
	}
	repair, _ := os.ReadFile(paths[1])
	for _, want := range []string{"par2-rs, in place", "par2cmdline-turbo, keeps .1", "par3-cauchy, in place", "par3-cauchy, keeps .1",
		"par3-fft, in place", "24x", "no successful run", "class=\"slower\""} {
		if !strings.Contains(string(repair), want) {
			t.Fatalf("repair chart lacks %q:\n%s", want, repair)
		}
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
	walls := map[string]float64{"create/" + ArmPAR2: 2, "create/" + ArmPAR2Turbo: 1, "create/" + ArmPAR3Cauchy: 1, "create/" + ArmPAR3FFT: 1}
	inputs := []VersusChartInput{{Results: versusChartFixture("a", true, walls)}, {Results: versusChartFixture("b", false, walls)}}
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

func TestRenderVersusSVGsRefusesDifferentComparisons(t *testing.T) {
	walls := map[string]float64{"create/" + ArmPAR2: 1, "create/" + ArmPAR3Cauchy: 1}
	other := versusChartFixture("b", false, walls)
	other.Configs[0].Recovery++
	_, err := RenderVersusSVGs([]VersusChartInput{{Results: versusChartFixture("a", false, walls)}, {Results: other}}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "differs between a and b") {
		t.Fatalf("err = %v", err)
	}
	if _, err := RenderVersusSVGs(nil, t.TempDir()); err == nil {
		t.Fatal("rendered no inputs")
	}
}
