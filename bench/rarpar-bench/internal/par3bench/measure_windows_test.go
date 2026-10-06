//go:build windows

package par3bench

import (
	"context"
	"testing"
)

// Peak working set comes from K32GetProcessMemoryInfo on a handle opened at
// start and held across exit; it must be present for a process that has
// already exited, which is exactly when PeakWorkingSet64 reads null.
func TestRunMeasuresPeakWorkingSet(t *testing.T) {
	result := Run(context.Background(), Command{Path: "cmd.exe", Args: []string{"/c", "exit 0"}})
	if result.Failure != "" {
		t.Fatalf("unexpected failure %s: %v", result.Failure, result.Err)
	}
	if result.MaxRSSBytes <= 0 {
		t.Fatalf("peak working set missing: %+v", result.Measurement)
	}
}
