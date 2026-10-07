package procmeasure

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
)

// touchEnv makes the test binary a child that touches that many MiB of
// fresh memory and exits: a process whose peak resident set is known to be
// at least that large.
const touchEnv = "PROCMEASURE_TEST_TOUCH_MIB"

func TestMain(m *testing.M) {
	MaybeRunShim()
	if value := os.Getenv(touchEnv); value != "" {
		mebibytes, err := strconv.Atoi(value)
		if err != nil {
			os.Exit(2)
		}
		buffer := make([]byte, mebibytes<<20)
		for index := 0; index < len(buffer); index += 4096 {
			buffer[index] = 1
		}
		runtime.KeepAlive(buffer)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const touchedMiB = 96

func self(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// The peak a child reaches is what Run records, tagged with this platform's
// source.
func TestRunRecordsTheChildsPeak(t *testing.T) {
	result := Run(context.Background(), Command{Path: self(t), Env: []string{touchEnv + "=" + strconv.Itoa(touchedMiB)}})
	if result.Failure != "" || result.ExitCode != 0 {
		t.Fatalf("child failed: %s exit %d: %v %s", result.Failure, result.ExitCode, result.Err, result.Stderr)
	}
	if result.MaxRSSBytes < touchedMiB<<20 {
		t.Fatalf("peak %d bytes, want at least %d MiB", result.MaxRSSBytes, touchedMiB)
	}
	if result.RSSSource != NativeRSSSource {
		t.Fatalf("rss source %q, want %q", result.RSSSource, NativeRSSSource)
	}
}

// A run that never started carries no peak and no source.
func TestRunWithoutAProcessHasNoPeak(t *testing.T) {
	result := Run(context.Background(), Command{Path: "/nonexistent/fixture-tool"})
	if result.Failure != "start-failed" || result.MaxRSSBytes != 0 || result.RSSSource != "" {
		t.Fatalf("got %+v", result)
	}
}

// The shim reports the tool's rusage, not its own: the tool touches far more
// memory than the shim, and the report carries the tool's figure and exit
// code with the shim source.
func TestShimReportsTheToolsPeak(t *testing.T) {
	path := self(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	cmd := exec.Command(path, ShimArgs(3, path, nil)...)
	cmd.Env = append(os.Environ(), touchEnv+"="+strconv.Itoa(touchedMiB))
	cmd.ExtraFiles = []*os.File{writer}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("shim: %v", err)
	}
	report, err := ReadShimReport(reader)
	if err != nil {
		t.Fatal(err)
	}
	if report.MaxRSSBytes < touchedMiB<<20 || report.RSSSource != RSSSourceShim || report.ExitCode != 0 {
		t.Fatalf("report %+v, want the tool's >= %d MiB peak from %s", report, touchedMiB, RSSSourceShim)
	}
}

// A tool the shim cannot start is reported as an error, not a zero peak.
func TestShimReportsAStartFailure(t *testing.T) {
	path := self(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	cmd := exec.Command(path, ShimArgs(3, "/nonexistent/fixture-tool", nil)...)
	cmd.ExtraFiles = []*os.File{writer}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	_ = cmd.Wait()
	if cmd.ProcessState.ExitCode() != 127 {
		t.Fatalf("shim exit %d, want 127", cmd.ProcessState.ExitCode())
	}
	if _, err := ReadShimReport(reader); err == nil {
		t.Fatal("a start failure read as a report")
	}
}
