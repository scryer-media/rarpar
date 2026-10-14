//go:build !windows

package par3bench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A --reference that cannot answer -V is refused before any row runs, so its
// later non-zero exits cannot pass for reference DNFs.
func TestIdentifyRejectsAFailedVersionProbe(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "not-par3")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho 'unknown option' >&2\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &runner{results: &Results{}, guards: map[string]Binary{}}
	_, err := r.identify(t.Context(), stub, "-V")
	if err == nil || !strings.Contains(err.Error(), "exited 2") {
		t.Fatalf("identify = %v, want a version probe failure", err)
	}
	if _, guarded := r.guards[stub]; guarded {
		t.Fatal("a binary that failed its probe must not be registered")
	}
}

// The buffered probe reads each writing op's own --help from the candidate:
// an older candidate gets --buffered where it lists it and the plain command,
// with a note, where it lists neither switch; a 0.7.0+ candidate takes no
// argument; and a help screen that does not print stops the run instead of
// guessing.
func TestProbeBufferedReadsEachOpsHelp(t *testing.T) {
	dir := t.TempDir()
	write := func(name, script string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	older := write("rarpar-0.6", "#!/bin/sh\n"+
		"[ \"$1 $3\" = 'par3 --help' ] || exit 2\n"+
		"case \"$2\" in\n"+
		"create) echo 'Usage: rarpar par3 create [OPTIONS] <OUTPUT> <FILES>...'; echo '      --buffered  Flush buffers without requesting durable storage barriers' ;;\n"+
		"repair) echo 'Usage: rarpar par3 repair [OPTIONS] <SET>' ;;\n"+
		"*) exit 2 ;;\n"+
		"esac\n")
	current := write("rarpar-0.7", "#!/bin/sh\n"+
		"[ \"$1 $3\" = 'par3 --help' ] || exit 2\n"+
		"echo \"Usage: rarpar par3 $2 [OPTIONS]\"\n"+
		"echo '      --fsync  After a successful run, fsync every file installed'\n")
	broken := write("rarpar-broken", "#!/bin/sh\necho 'unknown subcommand' >&2\nexit 2\n")
	ops := []string{OpCreate, OpVerify, OpRepair}
	probe := func(candidate string) (*runner, error) {
		r := &runner{options: Options{Candidate: candidate, Ops: ops}, results: &Results{BufferedArgs: map[string][]string{}}}
		return r, r.probeBuffered(t.Context())
	}

	r, err := probe(older)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.results.BufferedArgs[OpCreate], " "); got != "--buffered" {
		t.Errorf("older create args %q, want --buffered", got)
	}
	if _, probed := r.results.BufferedArgs[OpRepair]; probed || strings.Join(r.results.BufferedUnsupported, ",") != OpRepair {
		t.Errorf("older repair: args %v unsupported %v, want no buffered mode", r.results.BufferedArgs, r.results.BufferedUnsupported)
	}
	if len(r.results.Notes) != 1 || r.results.Notes[0] != noBufferedModeNote(OpRepair) {
		t.Errorf("older notes %q", r.results.Notes)
	}

	r, err = probe(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{OpCreate, OpRepair} {
		if args, probed := r.results.BufferedArgs[op]; !probed || len(args) != 0 {
			t.Errorf("0.7.0 %s args %v (probed %t), want none: the bench never passes --fsync", op, args, probed)
		}
	}
	if len(r.results.BufferedUnsupported) != 0 || len(r.results.Notes) != 0 {
		t.Errorf("0.7.0: unsupported %v notes %q", r.results.BufferedUnsupported, r.results.Notes)
	}
	if _, probed := r.results.BufferedArgs[OpVerify]; probed {
		t.Error("verify writes nothing and must not be probed")
	}

	if _, err := probe(broken); err == nil || !strings.Contains(err.Error(), "par3 create --help") {
		t.Fatalf("a failed help probe = %v, want an error naming the probe", err)
	}
}

// The backup probe reads `rarpar par3 repair --help` and gives every rarpar
// repair row its own arguments. A candidate listing --backup (after 0.7.0,
// in place by default) runs rarpar-wN plain and rarpar-wN-backup with
// --backup; one listing --no-backup (0.7.0 and earlier, backup by default)
// runs rarpar-wN with --no-backup and rarpar-wN-backup plain; one listing
// neither runs only the backup rows, plain, with a note. Create and verify
// never take a backup switch.
func TestProbeBackupGivesEachRepairRowItsArgs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, repairHelp string) string {
		path := filepath.Join(dir, name)
		script := "#!/bin/sh\n" +
			"[ \"$1 $3\" = 'par3 --help' ] || exit 2\n" +
			"case \"$2\" in\n" +
			"create) echo 'Usage: rarpar par3 create [OPTIONS] <OUTPUT> <FILES>...'; echo '      --fsync  fsync every file installed' ;;\n" +
			"repair) echo 'Usage: rarpar par3 repair [OPTIONS] <SET>'; " + repairHelp + " ;;\n" +
			"*) exit 2 ;;\n" +
			"esac\n"
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	inPlaceDefault := write("rarpar-next", "echo '      --fsync   fsync every file installed'; echo '      --backup  Keep a numbered backup (<file>.1) of every file repaired'")
	backupDefault := write("rarpar-0.7", "echo '      --fsync      fsync every file installed'; echo '      --no-backup  Do not keep a numbered backup of repaired files'")
	neither := write("rarpar-0.6", "echo '      --verbose  Print progress'")
	broken := write("rarpar-broken", "exit 3")

	kernel := KernelVariant{Name: "gfni-off", Env: []string{"WEAVER_GF8_GFNI=0"}}
	ops := []string{OpCreate, OpVerify, OpRepair}
	probe := func(candidate string) (*runner, error) {
		r := &runner{
			options: Options{Candidate: candidate, Ops: ops, Workers: []int{1, 8}},
			results: &Results{Variants: Variants([]int{1, 8}, []KernelVariant{kernel}), BufferedArgs: map[string][]string{}},
		}
		if err := r.probeBuffered(t.Context()); err != nil {
			return r, err
		}
		return r, r.probeBackup(t.Context())
	}
	// commands renders, per row that runs op on a plain set, the arguments
	// after `--quiet --par3-workers N`.
	commands := func(r *runner, op string) string {
		config := Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}
		var lines []string
		for _, variant := range r.results.Variants {
			if variant.Tool != ToolCandidate || !r.rowRuns(config, variant, op) {
				continue
			}
			var args []string
			if op == OpCreate {
				args = r.createCommand(config, Dataset{}, "/d", "/o", variant).Args
			} else {
				args = r.checkCommand(op, "/s", variant, config).Args
			}
			lines = append(lines, variant.Name+": "+strings.Join(args[3:], " "))
		}
		return strings.Join(lines, "\n")
	}
	cases := []struct {
		name, candidate string
		backupArgs      map[string]string
		repair          string
		inPlaceMissing  bool
	}{
		{
			name: "--backup listed", candidate: inPlaceDefault,
			backupArgs: map[string]string{
				"rarpar-w1": "", "rarpar-w1-backup": "--backup", "rarpar-w8": "", "rarpar-w8-backup": "--backup",
				"rarpar-w1-gfni-off": "", "rarpar-w8-gfni-off": "",
			},
			repair: "rarpar-w1: par3 repair set.par3\n" +
				"rarpar-w1-backup: par3 repair set.par3 --backup\n" +
				"rarpar-w8: par3 repair set.par3\n" +
				"rarpar-w8-backup: par3 repair set.par3 --backup\n" +
				"rarpar-w1-gfni-off: par3 repair set.par3\n" +
				"rarpar-w8-gfni-off: par3 repair set.par3",
		},
		{
			name: "--no-backup listed", candidate: backupDefault,
			backupArgs: map[string]string{
				"rarpar-w1": "--no-backup", "rarpar-w1-backup": "", "rarpar-w8": "--no-backup", "rarpar-w8-backup": "",
				"rarpar-w1-gfni-off": "--no-backup", "rarpar-w8-gfni-off": "--no-backup",
			},
			repair: "rarpar-w1: par3 repair set.par3 --no-backup\n" +
				"rarpar-w1-backup: par3 repair set.par3\n" +
				"rarpar-w8: par3 repair set.par3 --no-backup\n" +
				"rarpar-w8-backup: par3 repair set.par3\n" +
				"rarpar-w1-gfni-off: par3 repair set.par3 --no-backup\n" +
				"rarpar-w8-gfni-off: par3 repair set.par3 --no-backup",
		},
		{
			name: "neither listed", candidate: neither,
			backupArgs: map[string]string{"rarpar-w1-backup": "", "rarpar-w8-backup": ""},
			repair: "rarpar-w1-backup: par3 repair set.par3\n" +
				"rarpar-w8-backup: par3 repair set.par3",
			inPlaceMissing: true,
		},
	}
	for _, c := range cases {
		r, err := probe(c.candidate)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(r.results.BackupArgs) != len(c.backupArgs) {
			t.Errorf("%s: backup args %v, want rows %v", c.name, r.results.BackupArgs, c.backupArgs)
		}
		for row, want := range c.backupArgs {
			args, probed := r.results.BackupArgs[row]
			if !probed || args == nil || strings.Join(args, " ") != want {
				t.Errorf("%s: %s backup args %q (probed %t), want %q", c.name, row, args, probed, want)
			}
		}
		if got := commands(r, OpRepair); got != c.repair {
			t.Errorf("%s: repair commands\n%s\nwant\n%s", c.name, got, c.repair)
		}
		// Create and verify run every non-backup row with no backup switch.
		wantCreate := "rarpar-w1: par3 create /o/set.par3 --base-path /d -s 1048576 -c 3\n" +
			"rarpar-w8: par3 create /o/set.par3 --base-path /d -s 1048576 -c 3\n" +
			"rarpar-w1-gfni-off: par3 create /o/set.par3 --base-path /d -s 1048576 -c 3\n" +
			"rarpar-w8-gfni-off: par3 create /o/set.par3 --base-path /d -s 1048576 -c 3"
		if got := commands(r, OpCreate); got != wantCreate {
			t.Errorf("%s: create commands\n%s\nwant\n%s", c.name, got, wantCreate)
		}
		wantVerify := strings.ReplaceAll(wantCreate, "create /o/set.par3 --base-path /d -s 1048576 -c 3", "verify set.par3")
		if got := commands(r, OpVerify); got != wantVerify {
			t.Errorf("%s: verify commands\n%s\nwant\n%s", c.name, got, wantVerify)
		}
		if r.results.InPlaceUnsupported != c.inPlaceMissing {
			t.Errorf("%s: in-place unsupported %t", c.name, r.results.InPlaceUnsupported)
		}
		hasNote := contains(r.results.Notes, noInPlaceRepairNote())
		if hasNote != c.inPlaceMissing {
			t.Errorf("%s: notes %q", c.name, r.results.Notes)
		}
		// The per-row arguments are recorded in results.json, empty lists
		// included: a row that takes nothing was probed, not skipped.
		data, err := json.Marshal(r.results)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"backup_args":{`) ||
			!strings.Contains(string(data), `"rarpar-w1-backup":[`) {
			t.Errorf("%s: results JSON lacks backup_args: %s", c.name, data)
		}
	}
	// A help screen that does not print stops the run instead of guessing.
	r := &runner{options: Options{Candidate: broken, Ops: ops}, results: &Results{Variants: Variants([]int{1}, nil)}}
	if err := r.probeBackup(t.Context()); err == nil || !strings.Contains(err.Error(), "par3 repair --help") ||
		!strings.Contains(err.Error(), "--backup/--no-backup") {
		t.Fatalf("a failed backup probe = %v, want an error naming the probe", err)
	}
	// A run without repair does not probe.
	r = &runner{options: Options{Candidate: broken, Ops: []string{OpCreate}}, results: &Results{Variants: Variants([]int{1}, nil)}}
	if err := r.probeBackup(t.Context()); err != nil || r.results.BackupArgs != nil {
		t.Fatalf("a run without repair probed for backups: %v %v", err, r.results.BackupArgs)
	}
}
