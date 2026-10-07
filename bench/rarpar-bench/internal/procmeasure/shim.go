package procmeasure

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// ShimArg is the hidden first argument that turns the harness binary into
// the rss-exec shim. A collector that must be the harness's direct child
// (perf stat) launches the shim instead of the tool; the shim launches the
// tool as its own child, waits for it, and writes the tool's rusage to a
// report descriptor. Without it the harness would read the collector's
// rusage, whose peak is the larger of the collector's and the tool's.
const ShimArg = "__rss-exec"

// ShimReport is what the shim measured of the tool.
type ShimReport struct {
	MaxRSSBytes int64   `json:"max_rss_bytes"`
	RSSSource   string  `json:"rss_source"`
	UserSeconds float64 `json:"user_seconds"`
	SysSeconds  float64 `json:"sys_seconds"`
	ExitCode    int     `json:"exit_code"`
	Error       string  `json:"error,omitempty"`
}

// ShimArgs is the argument list (after the executable) that runs program
// under the shim, reporting on file descriptor reportFD.
func ShimArgs(reportFD int, program string, args []string) []string {
	return append([]string{ShimArg, strconv.Itoa(reportFD), "--", program}, args...)
}

// MaybeRunShim runs the shim and exits when the process was started as one.
// The harness's main, and the TestMain of any package that exercises the
// shim through os.Executable, call it first.
func MaybeRunShim() {
	if len(os.Args) > 1 && os.Args[1] == ShimArg {
		os.Exit(runShim(os.Args[2:]))
	}
}

func runShim(args []string) int {
	if len(args) < 3 || args[1] != "--" {
		fmt.Fprintln(os.Stderr, "rss-exec: usage: "+ShimArg+" FD -- PROGRAM [ARGS...]")
		return 125
	}
	fd, err := strconv.Atoi(args[0])
	if err != nil || fd < 3 {
		fmt.Fprintln(os.Stderr, "rss-exec: report descriptor must be 3 or above")
		return 125
	}
	// The report descriptor is the shim's alone: the tool must not inherit
	// it.
	closeOnExec(fd)
	report := os.NewFile(uintptr(fd), "rss-report")
	cmd := exec.Command(args[2], args[3:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		writeShimReport(report, ShimReport{ExitCode: 127, Error: err.Error()})
		fmt.Fprintln(os.Stderr, "rss-exec:", err)
		return 127
	}
	tracker := Track(cmd, "")
	_ = cmd.Wait()
	var measurement Measurement
	tracker.Finish(cmd, &measurement)
	source := ""
	if measurement.MaxRSSBytes > 0 {
		source = RSSSourceShim
	}
	writeShimReport(report, ShimReport{
		MaxRSSBytes: measurement.MaxRSSBytes,
		RSSSource:   source,
		UserSeconds: measurement.UserSeconds,
		SysSeconds:  measurement.SysSeconds,
		ExitCode:    measurement.ExitCode,
	})
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		// Killed by a signal: report it the way a shell does.
		return 128 + int(status.Signal())
	}
	return measurement.ExitCode
}

func writeShimReport(report *os.File, value ShimReport) {
	data, _ := json.Marshal(value)
	_, _ = report.Write(data)
	_ = report.Close()
}

// ReadShimReport reads the shim's report from the parent's end of the pipe.
// The caller closes its copy of the write end first.
func ReadShimReport(reader io.Reader) (ShimReport, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return ShimReport{}, err
	}
	if len(data) == 0 {
		return ShimReport{}, fmt.Errorf("the rss-exec shim wrote no report")
	}
	var report ShimReport
	if err := json.Unmarshal(data, &report); err != nil {
		return ShimReport{}, fmt.Errorf("rss-exec shim report: %w", err)
	}
	if report.Error != "" {
		return report, fmt.Errorf("rss-exec shim: %s", report.Error)
	}
	return report, nil
}
