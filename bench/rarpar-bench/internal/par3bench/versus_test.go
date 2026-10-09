package par3bench

import (
	"math"
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
