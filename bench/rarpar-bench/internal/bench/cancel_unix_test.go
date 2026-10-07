//go:build !windows

package bench

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Cancelling a perf run ends the whole tree. perf is the direct child, and
// the rss-exec shim and the tool run under it; killing perf alone left them
// running, and Wait then waited on the output pipes they held. The tool
// holds a FIFO open for writing, so the read below reaches end of file only
// once the tool itself has exited.
func TestCancelledPerfRunEndsTheWholeTree(t *testing.T) {
	binary := testBinary(t)
	bin := t.TempDir()
	if err := os.Symlink(binary, filepath.Join(bin, "perf")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	alive := filepath.Join(t.TempDir(), "alive")
	for _, fifo := range []string{alive, alive + ".never"} {
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(holdEnv, alive)
	directory := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, _, err := timedCommand(ctx, binary, nil, directory, false, false, true)
		done <- err
	}()
	// Opening blocks until the tool opens its end.
	file, err := os.Open(alive)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("tool did not start: %q, %v", line, err)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("a cancelled run reported success")
	}
	if rest, err := io.ReadAll(reader); err != nil || len(rest) != 0 {
		t.Fatalf("after the tool: %q, %v", rest, err)
	}
}
