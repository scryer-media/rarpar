package par3bench

import (
	"math"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersusProfilesValidateAndCoverEveryRowKind(t *testing.T) {
	for name, profile := range VersusProfiles() {
		if err := profile.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var equal, fft10, fft30 bool
		for _, config := range profile.Configs {
			dataset, _ := profile.Dataset(config.Dataset)
			percent := math.Round(config.RecoveryPercent(dataset))
			fftOnly := !contains(config.Arms, ArmPAR3Cauchy)
			switch {
			case !fftOnly:
				equal = true
				for _, arm := range []string{ArmPAR2, ArmPAR2Turbo, ArmPAR3Cauchy, ArmPAR3FFT} {
					if !contains(config.Arms, arm) {
						t.Errorf("%s/%s: equal-count row lacks %s", name, config.ID, arm)
					}
				}
			case percent == 10:
				fft10 = true
			case percent == 30:
				fft30 = true
			default:
				t.Errorf("%s/%s: FFT-only row at %.1f%% recovery, want 10%% or 30%%", name, config.ID, config.RecoveryPercent(dataset))
			}
		}
		if !equal || !fft10 || !fft30 {
			t.Errorf("%s: rows equal=%t fft10=%t fft30=%t, want all three kinds", name, equal, fft10, fft30)
		}
	}
}

func TestVersusValidateRefusesAOneSidedComparison(t *testing.T) {
	profile := versusSmokeProfile()
	profile.Configs[0].Arms = []string{ArmPAR3Cauchy, ArmPAR3FFT}
	if err := profile.Validate(); err == nil || !strings.Contains(err.Error(), "PAR2") {
		t.Fatalf("got %v, want a refusal naming the missing PAR2 arm", err)
	}
}

func TestVersusArmsShareTheBlockSizeAndRecoveryCount(t *testing.T) {
	config := versusSmokeProfile().Configs[0]
	options := VersusOptions{Candidate: "/bin/rarpar", PAR2Turbo: "/bin/par2"}
	names := []string{"v0.bin"}
	want := map[string][]string{
		ArmPAR2:       {"par", "create", "--block-size 65536", "--recovery-count 8"},
		ArmPAR2Turbo:  {"c -q", "-s65536", "-c8", "-B/data"},
		ArmPAR3Cauchy: {"par3 create", "-s 65536", "-c 8"},
		ArmPAR3FFT:    {"par3 create", "-s 65536", "-c 8", "--codec fft", "--capacity-log2 3"},
	}
	for arm, parts := range want {
		line := strings.Join(versusCreateCommand(options, config, "/data", "/out", arm, names).Args, " ")
		for _, part := range parts {
			if !strings.Contains(line, part) {
				t.Errorf("%s create %q lacks %q", arm, line, part)
			}
		}
		if arm == ArmPAR3Cauchy && strings.Contains(line, "--codec") {
			t.Errorf("cauchy create %q names a codec", line)
		}
	}
	if got := armsFor(config, VersusOptions{}); contains(got, ArmPAR2Turbo) {
		t.Fatalf("arms without a par2cmdline-turbo binary: %v", got)
	}
}

// The PAR3 arms run buffered, as the PAR3 suite's rarpar rows do: --buffered
// where an older candidate's help lists it, nothing on 0.7.0 and later, and
// never --fsync. The PAR2 arms take no PAR3 switch.
func TestVersusPAR3ArmsRunBuffered(t *testing.T) {
	config := versusSmokeProfile().Configs[0]
	names := []string{"v0.bin"}
	older := VersusOptions{Candidate: "/bin/rarpar", PAR2Turbo: "/bin/par2", buffered: map[string][]string{OpCreate: {"--buffered"}}}
	current := VersusOptions{Candidate: "/bin/rarpar", PAR2Turbo: "/bin/par2", buffered: map[string][]string{OpCreate: {}, OpRepair: {}}}
	for _, arm := range []string{ArmPAR3Cauchy, ArmPAR3FFT} {
		if line := strings.Join(versusCreateCommand(older, config, "/data", "/out", arm, names).Args, " "); !strings.HasSuffix(line, " --buffered") {
			t.Errorf("%s create on an older candidate %q lacks --buffered", arm, line)
		}
		// The older candidate's repair lists neither switch: plain command.
		if line := strings.Join(versusRepairCommand(older, "/s", arm).Args, " "); line != "--quiet par3 repair "+carrierName {
			t.Errorf("%s repair on an older candidate = %q", arm, line)
		}
		for _, line := range []string{
			strings.Join(versusCreateCommand(current, config, "/data", "/out", arm, names).Args, " "),
			strings.Join(versusRepairCommand(current, "/s", arm).Args, " "),
		} {
			if strings.Contains(line, "--buffered") || strings.Contains(line, "--fsync") {
				t.Errorf("%s on 0.7.0 = %q, want no durability switch", arm, line)
			}
		}
	}
	for _, arm := range []string{ArmPAR2, ArmPAR2Turbo} {
		for _, line := range []string{
			strings.Join(versusCreateCommand(older, config, "/data", "/out", arm, names).Args, " "),
			strings.Join(versusRepairCommand(older, "/s", arm).Args, " "),
		} {
			if strings.Contains(line, "--buffered") || strings.Contains(line, "--fsync") {
				t.Errorf("%s = %q carries a PAR3 switch", arm, line)
			}
		}
	}
}

// Every PAR3 arm's repair runs in place, and its -backup twin repairs the
// same set keeping a numbered .1; the backup switch each takes comes from
// the candidate's repair --help, as the PAR3 suite reads it.
func TestVersusPAR3RepairArmsAndTheirBackupTwins(t *testing.T) {
	arms := []string{ArmPAR2, ArmPAR2Turbo, ArmPAR3Cauchy, ArmPAR3FFT}
	if got := strings.Join(VersusOpArms(arms, OpCreate, false), ","); got != "par2-rs,par2cmdline-turbo,par3-cauchy,par3-fft" {
		t.Fatalf("create arms %s", got)
	}
	if got := strings.Join(VersusOpArms(arms, OpRepair, false), ","); got != "par2-rs,par2cmdline-turbo,par3-cauchy,par3-cauchy-backup,par3-fft,par3-fft-backup" {
		t.Fatalf("repair arms %s", got)
	}
	if got := strings.Join(VersusOpArms(arms, OpRepair, true), ","); got != "par2-rs,par2cmdline-turbo,par3-cauchy-backup,par3-fft-backup" {
		t.Fatalf("repair arms without an in-place mode %s", got)
	}
	if versusSetArm(ArmPAR3FFTBackup) != ArmPAR3FFT || versusSetArm(ArmPAR2) != ArmPAR2 || isPAR3BackupArm(ArmPAR2+"-backup") {
		t.Fatal("a twin repairs its PAR3 arm's set; no other arm has a twin")
	}
	help := map[string]string{
		"--backup":    "      --fsync   fsync every file installed\n      --backup  Keep a numbered backup of every file repaired\n",
		"--no-backup": "      --fsync      fsync every file installed\n      --no-backup  Do not keep a numbered backup\n",
		"neither":     "      --verbose  Print progress\n",
	}
	want := map[string]map[string]string{
		"--backup": {
			ArmPAR3Cauchy: "--quiet par3 repair set.par3", ArmPAR3CauchyBackup: "--quiet par3 repair set.par3 --backup",
			ArmPAR3FFT: "--quiet par3 repair set.par3", ArmPAR3FFTBackup: "--quiet par3 repair set.par3 --backup",
		},
		"--no-backup": {
			ArmPAR3Cauchy: "--quiet par3 repair set.par3 --no-backup", ArmPAR3CauchyBackup: "--quiet par3 repair set.par3",
			ArmPAR3FFT: "--quiet par3 repair set.par3 --no-backup", ArmPAR3FFTBackup: "--quiet par3 repair set.par3",
		},
		"neither": {ArmPAR3CauchyBackup: "--quiet par3 repair set.par3", ArmPAR3FFTBackup: "--quiet par3 repair set.par3"},
	}
	for name, screen := range help {
		backup, inPlaceOK := versusBackupArgs(screen)
		if inPlaceOK != (name != "neither") || len(backup) != len(want[name]) {
			t.Fatalf("%s: args %v in place %t", name, backup, inPlaceOK)
		}
		options := VersusOptions{Candidate: "/bin/rarpar", buffered: map[string][]string{OpRepair: {}}, backup: backup, inPlaceUnsupported: !inPlaceOK}
		for arm, line := range want[name] {
			if got := strings.Join(versusRepairCommand(options, "/s", arm).Args, " "); got != line {
				t.Errorf("%s: %s repair %q, want %q", name, arm, got, line)
			}
		}
		// PAR2 arms never take a PAR3 switch.
		if got := strings.Join(versusRepairCommand(options, "/s", ArmPAR2).Args, " "); strings.Contains(got, "backup") {
			t.Errorf("%s: par2-rs repair %q", name, got)
		}
	}
}

// The report names which PAR3 repair arm is like for like with each PAR2
// arm on bytes written, from what each repair left behind.
func TestVersusReportSaysWhichRepairIsLikeForLike(t *testing.T) {
	config := versusSmokeProfile().Configs[0]
	config.Arms = []string{ArmPAR2, ArmPAR3Cauchy}
	backupArgs, _ := versusBackupArgs("      --backup  Keep a numbered backup\n")
	results := &VersusResults{Schema: VersusSchema, Profile: "unit", Repeats: 1, Status: StatusOK,
		Datasets: versusSmokeProfile().Datasets, Configs: []VersusConfig{config},
		BufferedArgs: map[string][]string{OpCreate: {}, OpRepair: {}}, BackupArgs: backupArgs}
	add := func(op, arm string, wall float64, left ...string) {
		run := VersusRun{Config: config.ID, Op: op, Arm: arm, Status: StatusOK,
			Measurement: Measurement{WallSeconds: wall, UserSeconds: wall, MaxRSSBytes: 8 << 20}}
		if op == OpRepair {
			check := RepairCheck{Match: true, ExtraFiles: left}
			for _, name := range left {
				if strings.HasSuffix(name, ".1") {
					check.Backups = append(check.Backups, name)
				}
			}
			run.Repair = &check
		}
		results.Runs = append(results.Runs, run)
	}
	add(OpCreate, ArmPAR2, 4)
	add(OpCreate, ArmPAR3Cauchy, 2)
	add(OpRepair, ArmPAR2, 3, "v0.bin.1")
	add(OpRepair, ArmPAR3Cauchy, 1)
	add(OpRepair, ArmPAR3CauchyBackup, 1.5, "v0.bin.1")
	report := RenderVersusReport(results)
	for _, line := range []string{
		"| op | par2 arm | par3 arm | par2 ÷ par3 | like for like on bytes written |",
		"| repair | par2-rs | par3-cauchy | 3.00 | no |",
		"| repair | par2-rs | par3-cauchy-backup | 2.00 | yes: both keep a numbered backup |",
		"| create | par2-rs | par3-cauchy | 2.00 | – |",
		"| repair | par3-cauchy-backup | 1 | 1.500 | 1.500 | 8.0 [8.0–8.0] | v0.bin.1 |",
		"| repair | par3-cauchy | 1 | 1.000 | 1.000 | 8.0 [8.0–8.0] | none |",
		"| create | par3-cauchy | 1 | 2.000 | 2.000 | 8.0 [8.0–8.0] | – |",
		"On this candidate the in-place arms run plain and the `-backup` arms with `--backup`.",
	} {
		if !strings.Contains(report, line) {
			t.Fatalf("report lacks %q:\n%s", line, report)
		}
	}
	for _, c := range []struct {
		par2, par3 VersusCell
		want       string
	}{
		{VersusCell{Backups: "false"}, VersusCell{Backups: "false"}, "yes: neither keeps a backup"},
		{VersusCell{Backups: "true"}, VersusCell{Backups: "true"}, "yes: both keep a numbered backup"},
		{VersusCell{Backups: "true"}, VersusCell{Backups: "false"}, "no"},
		{VersusCell{Backups: "false/true"}, VersusCell{Backups: "true"}, "–"},
		{VersusCell{}, VersusCell{Backups: "true"}, "–"},
	} {
		if got := likeForLike(c.par2, c.par3); got != c.want {
			t.Errorf("likeForLike(%q, %q) = %q, want %q", c.par2.Backups, c.par3.Backups, got, c.want)
		}
	}
}

// A v1 comparison (its PAR3 arms may have run durable and kept a backup) is
// refused with a pointer to the harness that wrote it.
func TestReadVersusResultsRefusesV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	if err := writeJSONFile(path, &VersusResults{Schema: "rarpar-par3-versus-v1"}); err != nil {
		t.Fatal(err)
	}
	_, err := ReadVersusResults(path)
	if err == nil || !strings.Contains(err.Error(), `want "rarpar-par3-versus-v2"`) ||
		!strings.Contains(err.Error(), "read it with the harness that wrote it") {
		t.Fatalf("a v1 comparison: %v", err)
	}
	if err := writeJSONFile(path, &VersusResults{Schema: VersusSchema}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVersusResults(path); err != nil {
		t.Fatalf("a v2 comparison: %v", err)
	}
}
