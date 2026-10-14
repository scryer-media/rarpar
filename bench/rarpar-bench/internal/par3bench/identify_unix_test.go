//go:build !windows

package par3bench

import (
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
