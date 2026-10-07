// Package procmeasure measures one child process: wall time from the parent's
// monotonic clock, and CPU time, peak resident set and I/O counters from the
// kernel's accounting of the exited child. It is shared by every benchmark
// harness so the candidate and the references are measured the same way.
package procmeasure

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Measurement is what one timed process run costs. Wall time is the parent's
// monotonic clock around start-to-exit; CPU and memory come from the kernel's
// accounting of the exited child.
type Measurement struct {
	WallSeconds float64 `json:"wall_seconds"`
	UserSeconds float64 `json:"user_seconds"`
	SysSeconds  float64 `json:"sys_seconds"`
	// MaxRSSBytes is the peak resident set, required on every row: the
	// child's own rusage ru_maxrss on macOS (bytes, the figure
	// `/usr/bin/time -l` prints as "maximum resident set size") and Linux
	// (KiB, normalised; `/usr/bin/time -v` "Maximum resident set size"), and
	// PeakWorkingSetSize from K32GetProcessMemoryInfo on a handle held
	// across the child's exit on Windows (Process.PeakWorkingSet64 reads
	// null once the process has exited, so it is not used).
	MaxRSSBytes int64 `json:"max_rss_bytes"`
	// RSSSource names where MaxRSSBytes came from (one of the RSSSource*
	// constants), so a reader can tell that two compared rows were measured
	// the same way. Empty when no peak was captured.
	RSSSource string `json:"rss_source,omitempty"`
	// BlockInOps / BlockOutOps are ru_inblock / ru_oublock: block I/O the
	// kernel charged to the process (POSIX). Page-cache hits are free, so these
	// track real device traffic, not syscalls.
	BlockInOps  int64 `json:"block_in_ops,omitempty"`
	BlockOutOps int64 `json:"block_out_ops,omitempty"`
	// Windows GetProcessIoCounters: every read/write/other I/O operation the
	// process issued, cache hits included, and the bytes moved.
	ReadOps    int64 `json:"read_ops,omitempty"`
	WriteOps   int64 `json:"write_ops,omitempty"`
	OtherOps   int64 `json:"other_ops,omitempty"`
	ReadBytes  int64 `json:"read_bytes,omitempty"`
	WriteBytes int64 `json:"write_bytes,omitempty"`
	ExitCode   int   `json:"exit_code"`
	// Pinned reports the CPU set the process was confined to, when any.
	Pinned string `json:"pinned,omitempty"`
}

// Command is one process to run and measure.
type Command struct {
	Path string
	Args []string
	Dir  string
	// Env entries are appended to the harness's own environment.
	Env []string
	// PinCPUs is an inclusive CPU range "0-7" (Linux via taskset, Windows via
	// the process affinity mask); empty leaves scheduling alone.
	PinCPUs string
	// Timeout bounds the run; zero means no bound beyond the context.
	Timeout time.Duration
}

// Result is a finished run: its measurement, its captured output tails and a
// classified failure, if any.
type Result struct {
	Measurement
	Stdout string
	Stderr string
	// Failure is empty on a clean exit status the caller then judges, or a
	// class: "start-failed", "binary-quarantined", "timeout", "signal".
	Failure string
	Err     error
}

const outputTail = 4096

// killWaitDelay bounds how long Wait lingers for the output pipes after the
// child exits or is killed.
const killWaitDelay = 5 * time.Second

func tail(buffer *bytes.Buffer) string {
	data := buffer.Bytes()
	if len(data) > outputTail {
		data = data[len(data)-outputTail:]
	}
	return string(data)
}

// Tracker measures one started child. Track it straight after Start and call
// Finish once Wait has returned: on Windows the tracker holds the process
// handle that keeps the exited child's peak working set and I/O counters
// readable, and applies a CPU pin.
type Tracker struct {
	probe  probe
	pinned string
}

// Track begins measuring a started command. pin is an inclusive CPU range to
// confine it to where the platform applies affinity after start (Windows);
// pass "" to leave scheduling alone.
func Track(cmd *exec.Cmd, pin string) *Tracker {
	return &Tracker{probe: attachProbe(cmd, pin)}
}

// Finish fills measurement from the exited command: CPU time, exit code, the
// peak resident set and its source, and the I/O counters. It releases the
// tracker's handle and must be called exactly once, after Wait.
func (t *Tracker) Finish(cmd *exec.Cmd, measurement *Measurement) {
	if state := cmd.ProcessState; state != nil {
		measurement.UserSeconds = state.UserTime().Seconds()
		measurement.SysSeconds = state.SystemTime().Seconds()
		measurement.ExitCode = state.ExitCode()
		fillRusage(measurement, state)
	}
	t.probe.finish(measurement)
	if t.probe.pinned != "" {
		measurement.Pinned = t.probe.pinned
	}
	if measurement.MaxRSSBytes > 0 && measurement.RSSSource == "" {
		measurement.RSSSource = nativeRSSSource
	}
}

// ConfigureKill makes cancelling cmd's context end the whole tree it starts,
// not only the direct child: the platform hook kills the process group
// (POSIX), and WaitDelay closes the pipes so a surviving grandchild cannot
// hold Wait open. Call it before Start.
func ConfigureKill(cmd *exec.Cmd) {
	configureKill(cmd)
	cmd.WaitDelay = killWaitDelay
}

// Run executes a command and measures it.
func Run(ctx context.Context, command Command) Result {
	if command.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, command.Timeout)
		defer cancel()
	}
	path, args, pinned := pinnedCommand(command)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = command.Dir
	cmd.Env = append(os.Environ(), command.Env...)
	// A timeout must end the whole tree, not only the direct child.
	ConfigureKill(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	started := time.Now()
	if err := cmd.Start(); err != nil {
		result := Result{Err: err, Failure: "start-failed"}
		if isQuarantineError(err) {
			result.Failure = "binary-quarantined"
		}
		return result
	}
	tracker := Track(cmd, command.PinCPUs)
	waitErr := cmd.Wait()
	wall := time.Since(started)

	result := Result{Stdout: tail(&stdout), Stderr: tail(&stderr)}
	result.WallSeconds = wall.Seconds()
	if pinned != "" {
		result.Pinned = pinned
		// taskset execs the tool in place: the pid, and so the rusage, is
		// the tool's, with taskset's own small image as the only floor.
		result.RSSSource = RSSSourceRusageTasksetExec
	}
	tracker.Finish(cmd, &result.Measurement)
	if result.MaxRSSBytes <= 0 {
		result.RSSSource = ""
	}
	if ctx.Err() != nil {
		result.Failure = "timeout"
		result.Err = ctx.Err()
		return result
	}
	if errors.Is(waitErr, exec.ErrWaitDelay) {
		// The process itself exited; only an orphaned descendant still held
		// the output pipes, which WaitDelay then closed.
		waitErr = nil
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			if result.ExitCode < 0 {
				result.Failure = "signal"
				result.Err = waitErr
			}
			return result
		}
		result.Failure = "start-failed"
		result.Err = waitErr
	}
	return result
}

// Describe renders a command line for logs and evidence.
func (command Command) Describe() string {
	parts := append([]string{command.Path}, command.Args...)
	for i, part := range parts {
		if strings.ContainsAny(part, " \t\"'") {
			parts[i] = fmt.Sprintf("%q", part)
		}
	}
	line := strings.Join(parts, " ")
	if len(command.Env) > 0 {
		line = strings.Join(command.Env, " ") + " " + line
	}
	return line
}
