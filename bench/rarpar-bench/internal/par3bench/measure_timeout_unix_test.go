//go:build !windows

package par3bench

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A reference run past its timeout is killed and classified as a timeout,
// which runConfig records as DNF.
func TestRunClassifiesATimeout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "slow.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho started >&2\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result := Run(t.Context(), Command{Path: script, Timeout: 200 * time.Millisecond})
	if result.Failure != "timeout" {
		t.Fatalf("failure %q, want timeout", result.Failure)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("the timed-out process was not killed promptly (%v)", elapsed)
	}
	failure, _ := referenceCreateProblem(result, t.TempDir(), Config{Recovery: 1})
	if failure != "timeout" {
		t.Fatalf("classified as %q", failure)
	}
}
