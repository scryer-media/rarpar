package par3bench

import (
	"strings"
	"testing"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// The embedded macOS port applies to one commit; the pin must be that commit.
func TestMacOSPatchMatchesTheReferencePin(t *testing.T) {
	if !strings.Contains(bench.PAR3Reference.URL, macOSPatchCommit) {
		t.Fatalf("bench.PAR3Reference pins %s, but the macOS patch is for %s", bench.PAR3Reference.URL, macOSPatchCommit)
	}
}
