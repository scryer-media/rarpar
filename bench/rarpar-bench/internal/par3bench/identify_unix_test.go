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
