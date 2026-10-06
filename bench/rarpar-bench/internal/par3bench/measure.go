package par3bench

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
	// MaxRSSBytes is the peak resident set (POSIX ru_maxrss, normalised to
	// bytes) or the peak working set on Windows.
	MaxRSSBytes int64 `json:"max_rss_bytes"`
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

func tail(buffer *bytes.Buffer) string {
	data := buffer.Bytes()
	if len(data) > outputTail {
		data = data[len(data)-outputTail:]
	}
	return string(data)
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
	probe := attachProbe(cmd, command.PinCPUs)
	waitErr := cmd.Wait()
	wall := time.Since(started)

	result := Result{Stdout: tail(&stdout), Stderr: tail(&stderr)}
	result.WallSeconds = wall.Seconds()
	if pinned != "" {
		result.Pinned = pinned
	}
	if state := cmd.ProcessState; state != nil {
		result.UserSeconds = state.UserTime().Seconds()
		result.SysSeconds = state.SystemTime().Seconds()
		result.ExitCode = state.ExitCode()
		fillRusage(&result.Measurement, state)
	}
	probe.finish(&result.Measurement)
	if probe.pinned != "" {
		result.Pinned = probe.pinned
	}
	if ctx.Err() != nil {
		result.Failure = "timeout"
		result.Err = ctx.Err()
		return result
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
