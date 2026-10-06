package par3bench

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// IOCounts is the syscall-level I/O work of one run, from `strace -f -c`.
// It is collected in a separate, untimed pass: strace slows every syscall, so
// the timed runs never carry it. Extra reads, opens, stats and fsyncs are a
// regression on network filesystems even when local wall time is flat.
type IOCounts struct {
	Reads  int64 `json:"reads"`
	Writes int64 `json:"writes"`
	Opens  int64 `json:"opens"`
	Stats  int64 `json:"stats"`
	Syncs  int64 `json:"syncs"`
	Seeks  int64 `json:"seeks"`
	Total  int64 `json:"total"`
	// Calls is the full per-syscall table.
	Calls map[string]int64 `json:"calls"`
}

var ioClasses = map[string]string{
	"read": "reads", "pread64": "reads", "readv": "reads", "preadv": "reads", "preadv2": "reads",
	"write": "writes", "pwrite64": "writes", "writev": "writes", "pwritev": "writes", "pwritev2": "writes",
	"copy_file_range": "writes", "sendfile": "writes",
	"open": "opens", "openat": "opens", "openat2": "opens", "creat": "opens",
	"stat": "stats", "lstat": "stats", "fstat": "stats", "newfstatat": "stats", "statx": "stats", "fstatat64": "stats",
	"fsync": "syncs", "fdatasync": "syncs", "sync_file_range": "syncs", "syncfs": "syncs", "sync": "syncs",
	"lseek": "seeks",
}

// ParseStraceSummary reads the table `strace -c` writes.
func ParseStraceSummary(text string) (IOCounts, error) {
	counts := IOCounts{Calls: map[string]int64{}}
	scanner := bufio.NewScanner(strings.NewReader(text))
	header := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "% time") {
			header = true
			continue
		}
		if !header || line == "" || strings.HasPrefix(line, "---") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		name := fields[len(fields)-1]
		if name == "total" {
			continue
		}
		calls, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return IOCounts{}, fmt.Errorf("strace summary row %q: %w", line, err)
		}
		counts.Calls[name] += calls
		counts.Total += calls
		switch ioClasses[name] {
		case "reads":
			counts.Reads += calls
		case "writes":
			counts.Writes += calls
		case "opens":
			counts.Opens += calls
		case "stats":
			counts.Stats += calls
		case "syncs":
			counts.Syncs += calls
		case "seeks":
			counts.Seeks += calls
		}
	}
	if !header {
		return IOCounts{}, fmt.Errorf("no strace summary table found")
	}
	return counts, scanner.Err()
}

// IOCountSupported reports whether the syscall-count pass can run here.
func IOCountSupported() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "syscall counts need strace (Linux); Windows rows carry GetProcessIoCounters per timed run instead"
	}
	if _, err := exec.LookPath("strace"); err != nil {
		return false, "strace is not installed"
	}
	return true, ""
}

// CountIO runs the command once under `strace -f -c` and parses the summary.
func CountIO(ctx context.Context, command Command, scratch string) (IOCounts, error) {
	summary := filepath.Join(scratch, "strace-summary.txt")
	_ = os.Remove(summary)
	wrapped := command
	wrapped.Path = "strace"
	wrapped.Args = append([]string{"-f", "-c", "-o", summary, "--", command.Path}, command.Args...)
	result := Run(ctx, wrapped)
	if result.Failure != "" {
		return IOCounts{}, fmt.Errorf("strace pass %s: %v", result.Failure, result.Err)
	}
	data, err := os.ReadFile(summary)
	if err != nil {
		return IOCounts{}, err
	}
	return ParseStraceSummary(string(data))
}
