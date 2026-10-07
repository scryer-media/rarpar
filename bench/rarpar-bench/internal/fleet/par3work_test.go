package fleet

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPAR3WorkMustBeDedicated(t *testing.T) {
	cases := []struct{ name, work, want string }{
		{"root", `work = "/"`, "is a filesystem root"},
		{"homes", `work = "/home"`, "holds the home directories"},
		{"home", `work = "/home/bench"`, "is a home directory"},
		{"home with a trailing slash", `work = "/home/bench/"`, "is a home directory"},
		{"dot dot", `work = "/home/bench/p3/../.."`, "must not contain a .. component"},
		{"holds the corpus", `work = "/home/bench/bench"`, "holds paths.corpus"},
		{"inside the corpus", `work = "/home/bench/bench/corpus/p3"`, "lies inside paths.corpus"},
		{"holds the scratch", `work = "/dev/shm"`, "holds paths.scratch"},
		{"is the staging", `work = "/home/bench/fleet-stage"`, "holds paths.staging"},
		{"windows drive", `work = "C:\\"`, "is a filesystem root"},
		{"windows home", `work = "c:/users/bench"`, "is a home directory"},
		{"windows bench root", `work = "C:\\Bench"`, "holds paths.staging"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			old := `work = "/home/bench/p3"`
			if strings.Contains(testCase.work, `C:`) || strings.Contains(testCase.work, `c:`) {
				old = `work = "C:\\p3"`
			}
			_, err := DecodeConfig("fleet.toml", mutate(t, old, testCase.work))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("want an error containing %q, got %v", testCase.want, err)
			}
		})
	}
	// The example's own work paths are dedicated.
	loadExample(t)
}

// runPAR3Section runs the generated POSIX macro-par3 section against work,
// with a reference that does not exist, and returns the failures it records.
func runPAR3Section(t *testing.T, work string) string {
	t.Helper()
	machine := Machine{Name: "lumen", PAR3: PAR3Plan{Work: work}}
	section := par3Section(machine, RemoteLayout{}, filepath.Join(t.TempDir(), "absent-par3"))
	log := filepath.Join(t.TempDir(), "failures")
	script := "fail() { echo \"$1\" >> '" + log + "'; }\nlog() { :; }\ngate() { :; }\n" + section
	path := filepath.Join(t.TempDir(), "section.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", path).CombinedOutput(); err != nil {
		t.Fatalf("section failed: %v\n%s", err, output)
	}
	failures, _ := os.ReadFile(log)
	return strings.TrimSpace(string(failures))
}

func TestPAR3WorkCleanupTouchesOnlyWhatTheRunnerMade(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX shell")
	}
	t.Run("made by the runner is removed whole", func(t *testing.T) {
		work := filepath.Join(t.TempDir(), "p3")
		if failures := runPAR3Section(t, work); failures != "par3-reference-missing" {
			t.Fatalf("failures = %q", failures)
		}
		if _, err := os.Stat(work); !os.IsNotExist(err) {
			t.Fatalf("the runner's own work directory survived: %v", err)
		}
	})
	t.Run("an empty directory is adopted and only emptied", func(t *testing.T) {
		work := t.TempDir()
		if failures := runPAR3Section(t, work); failures != "par3-reference-missing" {
			t.Fatalf("failures = %q", failures)
		}
		entries, err := os.ReadDir(work)
		if err != nil || len(entries) != 0 {
			t.Fatalf("adopted directory = %v, %v; want it kept and empty", entries, err)
		}
	})
	t.Run("a directory with other files is refused and kept", func(t *testing.T) {
		work := t.TempDir()
		keep := filepath.Join(work, "holiday-notes.txt")
		if err := os.WriteFile(keep, []byte("mine"), 0o644); err != nil {
			t.Fatal(err)
		}
		if failures := runPAR3Section(t, work); failures != "par3-work-not-dedicated" {
			t.Fatalf("failures = %q", failures)
		}
		if data, err := os.ReadFile(keep); err != nil || string(data) != "mine" {
			t.Fatalf("a file the runner did not make was touched: %q, %v", data, err)
		}
		if _, err := os.Stat(filepath.Join(work, par3WorkMarker)); !os.IsNotExist(err) {
			t.Fatalf("a refused directory was marked: %v", err)
		}
	})
	t.Run("leftovers of an interrupted run keep their cleanup", func(t *testing.T) {
		parent := t.TempDir()
		work := filepath.Join(parent, "p3")
		if err := os.MkdirAll(filepath.Join(work, "data"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, par3WorkMarker), []byte("created\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if failures := runPAR3Section(t, work); failures != "par3-reference-missing" {
			t.Fatalf("failures = %q", failures)
		}
		if _, err := os.Stat(work); !os.IsNotExist(err) {
			t.Fatalf("the interrupted run's work directory survived: %v", err)
		}
	})
	t.Run("a marker naming nothing known is refused", func(t *testing.T) {
		work := t.TempDir()
		if err := os.WriteFile(filepath.Join(work, par3WorkMarker), []byte("someone-else\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if failures := runPAR3Section(t, work); failures != "par3-work-not-dedicated" {
			t.Fatalf("failures = %q", failures)
		}
		if _, err := os.Stat(filepath.Join(work, par3WorkMarker)); err != nil {
			t.Fatalf("a refused directory was cleaned: %v", err)
		}
	})
}
