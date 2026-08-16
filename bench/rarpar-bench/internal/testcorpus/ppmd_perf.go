package testcorpus

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ppmdPerfScript is the one generator that is still a script: a portable Python
// program that builds a deterministic 32 MiB payload and hands it to the pinned
// RAR 6.24 image, which is what writes both archives. It stays Python because it
// already runs anywhere python3 does and because the payload's SHA-256 is pinned
// by tests/integration.rs — porting it would move that hash for no gain.
const ppmdPerfScript = "crates/unrar-rs/tests/fixtures/generate_ppmd_perf.py"

// generatePPMdPerf writes the RAR4 order-16 PPMd performance corpus and the
// classic-volume (.rar/.r00/.r01/.r02) set, both from the pinned rarlab-6.24
// image.
func generatePPMdPerf(ctx context.Context, e *env) error {
	return runPython(ctx, e, ppmdPerfScript, "--all", "--docker", e.docker, "--image", e.rar4.Image)
}

func runPython(ctx context.Context, e *env, script string, args ...string) error {
	python := os.Getenv("PYTHON")
	if python == "" {
		python = "python3"
	}
	full := append([]string{filepath.Join(e.repoRoot, filepath.FromSlash(script))}, args...)
	command := exec.CommandContext(ctx, python, full...)
	command.Dir = e.repoRoot
	command.Stdout = io.Discard
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", python, script, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
