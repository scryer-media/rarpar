package par3bench

import (
	"context"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/procmeasure"
)

// The process measurement is shared with the general bench harness so the
// two suites read wall, CPU and peak RSS the same way; these names keep the
// par3bench call sites unchanged.
type (
	Measurement = procmeasure.Measurement
	Command     = procmeasure.Command
	Result      = procmeasure.Result
)

// Run executes a command and measures it.
func Run(ctx context.Context, command Command) Result { return procmeasure.Run(ctx, command) }

// PinSupported reports whether --pin-cpus can take effect on this host.
func PinSupported() bool { return procmeasure.PinSupported() }
