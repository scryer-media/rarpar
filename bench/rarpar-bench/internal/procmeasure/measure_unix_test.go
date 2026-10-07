//go:build !windows

package procmeasure

import (
	"context"
	"testing"
)

func TestRunMeasuresAndReportsExitCodes(t *testing.T) {
	result := Run(context.Background(), Command{Path: "sh", Args: []string{"-c", "head -c 4000000 /dev/zero | cat >/dev/null; echo out; echo err >&2; exit 3"}})
	if result.Failure != "" {
		t.Fatalf("unexpected failure %s: %v", result.Failure, result.Err)
	}
	if result.ExitCode != 3 || result.Stdout != "out\n" || result.Stderr != "err\n" {
		t.Fatalf("got exit %d stdout %q stderr %q", result.ExitCode, result.Stdout, result.Stderr)
	}
	if result.WallSeconds <= 0 || result.MaxRSSBytes <= 0 {
		t.Fatalf("missing measurements: %+v", result.Measurement)
	}
	missing := Run(context.Background(), Command{Path: "/nonexistent/par3"})
	if missing.Failure != "start-failed" {
		t.Fatalf("missing binary classified as %q", missing.Failure)
	}
}
