//go:build !windows

package par3bench

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A reference run past its timeout is killed and classified as a timeout,
// which runConfig records as DNF. The child sleeps far longer than the limit,
// so the classification does not depend on how fast the host is; the test
// runner, not an assertion, bounds how long the kill may take.
func TestRunClassifiesATimeout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "slow.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho started >&2\nexec sleep 3600\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	result := Run(t.Context(), Command{Path: script, Timeout: 200 * time.Millisecond})
	if result.Failure != "timeout" {
		t.Fatalf("failure %q, want timeout", result.Failure)
	}
	failure, _ := referenceCreateProblem(result, t.TempDir(), Config{Recovery: 1})
	if failure != "timeout" {
		t.Fatalf("classified as %q", failure)
	}
}

// Cancelling a run kills its whole process group: a grandchild that inherited
// the output pipes is killed too, rather than left running. The test cancels
// only once the grandchild has recorded its pid, then waits for that pid to
// disappear; a group kill that missed it leaves the test hanging until the
// runner's limit, which fails it.
func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	script := filepath.Join(dir, "tree.sh")
	body := "#!/bin/sh\nsh -c 'echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\" && exec sleep 3600' grandchild " + shellWord(pidFile) + " &\nexec sleep 3600\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pid := make(chan int, 1)
	go func() {
		for {
			if data, err := os.ReadFile(pidFile); err == nil {
				if value, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
					pid <- value
					cancel()
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	result := Run(ctx, Command{Path: script})
	if result.Failure != "timeout" {
		t.Fatalf("failure %q, want the cancellation classified as timeout", result.Failure)
	}
	grandchild := <-pid
	// The killed grandchild is reparented and reaped by init; wait for that.
	for {
		if err := syscall.Kill(grandchild, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func shellWord(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
