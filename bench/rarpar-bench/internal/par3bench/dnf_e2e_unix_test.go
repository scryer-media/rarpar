//go:build !windows

package par3bench

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// candidateForE2E is a real rarpar build: RARPAR_BENCH_CANDIDATE, or the
// workspace's target/release/rarpar. The test skips without one.
func candidateForE2E(t *testing.T) string {
	t.Helper()
	path := os.Getenv("RARPAR_BENCH_CANDIDATE")
	if path == "" {
		path, _ = filepath.Abs(filepath.Join("..", "..", "..", "..", "target", "release", "rarpar"))
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		t.Skipf("no rarpar candidate at %s (set RARPAR_BENCH_CANDIDATE)", path)
	}
	return path
}

// The whole DNF flow against a stub reference that fails the way the real
// one does past its name-buffer limit: the canonical seed is DNF, rarpar
// seeds the canonical carriers, every reference row is DNF, every rarpar row
// is ok, ratios read "-", and the saved results reload.
func TestReferenceExit6IsDNFEndToEnd(t *testing.T) {
	candidate := candidateForE2E(t)
	dir := t.TempDir()
	reference := filepath.Join(dir, "par3-stub")
	stub := "#!/bin/sh\nif [ \"$1\" = -V ]; then echo 'par3cmdline stub'; exit 0; fi\necho 'Failed to open Recovery File: No such file or directory' >&2\nexit 6\n"
	if err := os.WriteFile(reference, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	profile, err := LookupProfile("smoke")
	if err != nil {
		t.Fatal(err)
	}
	if profile, err = profile.Select([]string{"smoke-gf8"}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	results, err := RunSuite(t.Context(), Options{
		Reference: reference, Candidate: candidate, Work: filepath.Join(dir, "w"), Out: out,
		Profile: profile, Ops: []string{OpCreate, OpVerify, OpRepair}, Warmups: 0, Repeats: 1,
		Workers: []int{1}, Log: io.Discard,
	})
	if err != nil {
		t.Fatalf("a DNF reference must not fail the run: %v", err)
	}
	if results.Status != StatusOK || len(results.Failures) != 0 {
		t.Fatalf("status %s failures %v", results.Status, results.Failures)
	}
	if results.Configs[0].CanonicalSource != ToolCandidate {
		t.Fatalf("canonical source %q, want rarpar's fallback", results.Configs[0].CanonicalSource)
	}
	var seedDNF bool
	referenceRows := map[string]string{}
	for _, run := range results.Runs {
		switch {
		case run.Tool == ToolReference && run.Canonical:
			seedDNF = run.Status == StatusDNF && run.Failure == "exit-6" && strings.Contains(run.StderrLine, "Failed to open Recovery File")
		case run.Tool == ToolReference:
			referenceRows[run.Op] = run.Status + "/" + run.Failure
		default:
			if run.Status != StatusOK {
				t.Errorf("rarpar row %s/%s: %s %s", run.Op, run.Variant, run.Status, run.Failure)
			}
			if run.MaxRSSBytes <= 0 {
				t.Errorf("rarpar row %s/%s has no peak RSS", run.Op, run.Variant)
			}
		}
	}
	if !seedDNF {
		t.Fatal("the canonical seed create must be recorded as DNF exit-6 with the stub's stderr line")
	}
	for _, op := range []string{OpVerify, OpRepair} {
		if referenceRows[op] != StatusDNF+"/exit-6" {
			t.Errorf("reference %s row = %q, want dnf/exit-6", op, referenceRows[op])
		}
	}
	if _, ran := referenceRows[OpCreate]; ran {
		t.Error("the timed reference create must not run after its seed was DNF")
	}
	reloaded, err := ReadResults(filepath.Join(out, "results.json"))
	if err != nil {
		t.Fatalf("results.json must reload: %v", err)
	}
	report := RenderReport(reloaded)
	for _, want := range []string{"| reference | none (never syncs) | DNF |", "| rarpar-w1 | durable (default) |", "exit 6: Failed to open Recovery File"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q:\n%s", want, report)
		}
	}
	for _, line := range strings.Split(report, "\n") {
		if strings.HasPrefix(line, "| rarpar-w1 ") && !strings.Contains(line, "| - | - | - |") {
			t.Fatalf("ratios against a DNF reference must read '-': %s", line)
		}
	}
}
