//go:build !windows

package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAWS is an aws CLI that logs every call; with failSend "fail" it fails
// `ssm send-command`.
func fakeAWS(t *testing.T, failSend string) (*AWS, string) {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls.log")
	script := `#!/bin/sh
echo "$*" >> '` + calls + `'
case "$*" in
*"ssm send-command"*)
  case '` + failSend + `' in
  fail) echo "AccessDenied" >&2; exit 254 ;;
  esac ;;
esac
exit 0
`
	cli := filepath.Join(dir, "aws")
	if err := os.WriteFile(cli, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &AWS{CLI: cli, Region: "us-east-1"}, calls
}

func channelFor(t *testing.T, aws *AWS) *ssmChannel {
	t.Helper()
	return &ssmChannel{aws: aws, machine: "lumen", instanceID: "i-0fab1e", bucket: "transfer-bucket",
		prefix: "rarpar-fleet/run/lumen", scratch: t.TempDir()}
}

func removals(t *testing.T, calls string) []string {
	t.Helper()
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	var removed []string
	for _, line := range strings.Split(string(data), "\n") {
		// The send-command parameters carry the instance-side `aws s3 rm`
		// too; only the orchestrator's own calls count.
		if strings.Contains(line, "s3 rm --quiet s3://") && !strings.Contains(line, "send-command") {
			removed = append(removed, line[strings.Index(line, "s3://"):])
		}
	}
	return removed
}

// A command whose invocation fails before the instance runs it still has its
// staged script deleted from S3, by the orchestrator.
func TestFailedInvocationDeletesTheStagedScript(t *testing.T) {
	aws, calls := fakeAWS(t, "fail")
	channel := channelFor(t, aws)
	if _, _, err := channel.run(t.Context(), "printf '%s' token > ecr-token\n"); err == nil {
		t.Fatal("a failed send-command must fail the run")
	}
	removed := removals(t, calls)
	if len(removed) != 1 || removed[0] != "s3://transfer-bucket/rarpar-fleet/run/lumen/cmd-0001" {
		t.Fatalf("staged script removals: %q", removed)
	}
}

// A command cancelled before its script reaches the instance still has the
// staged object deleted, though its context is already done.
func TestCancelledCommandDeletesTheStagedScript(t *testing.T) {
	aws, calls := fakeAWS(t, "")
	channel := channelFor(t, aws)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := channel.run(ctx, "true\n"); err == nil {
		t.Fatal("a cancelled run must fail")
	}
	removed := removals(t, calls)
	if len(removed) != 1 || removed[0] != "s3://transfer-bucket/rarpar-fleet/run/lumen/cmd-0001" {
		t.Fatalf("staged script removals: %q", removed)
	}
}
