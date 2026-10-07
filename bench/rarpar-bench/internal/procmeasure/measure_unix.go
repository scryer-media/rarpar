//go:build !windows

package procmeasure

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// pinnedCommand wraps the command in taskset on Linux. macOS has no CPU
// affinity API for ordinary processes, so a pin request is reported as not
// applied rather than silently pretended.
func pinnedCommand(command Command) (string, []string, string) {
	if command.PinCPUs == "" || runtime.GOOS != "linux" {
		return command.Path, command.Args, ""
	}
	args := append([]string{"-c", command.PinCPUs, command.Path}, command.Args...)
	return "taskset", args, command.PinCPUs
}

// PinSupported reports whether --pin-cpus can take effect on this host.
func PinSupported() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("taskset")
	return err == nil
}

type probe struct{ pinned string }

func attachProbe(*exec.Cmd, string) probe { return probe{} }

func (probe) finish(*Measurement) {}

func fillRusage(measurement *Measurement, state *os.ProcessState) {
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage == nil {
		return
	}
	maxRSS := int64(usage.Maxrss)
	if runtime.GOOS != "darwin" {
		// Linux and the BSDs report KiB; Darwin reports bytes.
		maxRSS *= 1024
	}
	measurement.MaxRSSBytes = maxRSS
	measurement.BlockInOps = int64(usage.Inblock)
	measurement.BlockOutOps = int64(usage.Oublock)
}

func isQuarantineError(error) bool { return false }

// configureKill puts the child in its own process group and makes the context
// cancel kill that whole group, so a timed-out run takes its descendants with
// it.
func configureKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}

// NativeRSSSource is where Run and Track read the peak resident set here.
const NativeRSSSource = RSSSourceRusage

const nativeRSSSource = NativeRSSSource

func closeOnExec(fd int) { syscall.CloseOnExec(fd) }
