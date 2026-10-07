package fleet

// SSM access for cloud machines.
//
// Some orchestrating networks cannot hold an SSH session to an EC2 public
// address (the resolver or firewall drops it, sometimes minutes into a run).
// SSM RunCommand needs no inbound path at all: the instance's agent polls
// Systems Manager over HTTPS, so the instance needs only an instance profile
// with AmazonSSMManagedInstanceCore and read/write on the transfer bucket.
//
// RunCommand caps captured output at 24,000 characters and puts its parameters
// in the account's command history, so:
//   - every script rides an S3 object and the command line only fetches and
//     runs it (secrets such as an ECR token never land in command history);
//   - every file moves as a tar object under s3://<bucket>/<prefix>/ and is
//     deleted right after the transfer;
//   - only small control output (sentinels, probes) is read from RunCommand.
//
// UNVALIDATED against a live instance in this harness: the commands match the
// ones operators run by hand, but treat the first SSM run as a bring-up.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// ssmChannel carries one SSM-access machine's commands and transfers.
type ssmChannel struct {
	aws        *AWS
	machine    string
	instanceID string
	bucket     string
	prefix     string
	scratch    string
	sequence   atomic.Int64
	// commandTimeout bounds one RunCommand invocation; the detached run
	// itself is not bound by it.
	commandTimeout time.Duration
}

// ssmPrefix is the per-run, per-machine key prefix inside the bucket.
func ssmPrefix(resourcePrefix, runID, machine string) string {
	if resourcePrefix == "" {
		resourcePrefix = "rarpar-fleet"
	}
	return joinPosix(resourcePrefix, runID, machine)
}

// ssmReadyScript is the only script sent inline: it runs before aws-cli is
// known to exist, so it cannot fetch itself from S3.
const ssmReadyScript = "test -f /var/lib/cloud/instance/BENCH_USERDATA_DONE && command -v aws >/dev/null && echo ready"

func (channel *ssmChannel) key(kind string) string {
	return joinPosix(channel.prefix, fmt.Sprintf("%s-%04d", kind, channel.sequence.Add(1)))
}

func (channel *ssmChannel) url(key string) string { return "s3://" + channel.bucket + "/" + key }

// invoke sends one AWS-RunShellScript command and waits for it to finish.
func (channel *ssmChannel) invoke(ctx context.Context, commands []string) (string, string, error) {
	parameters, err := json.Marshal(map[string][]string{
		"commands":         commands,
		"executionTimeout": {fmt.Sprint(int(channel.commandTimeout.Seconds()))},
	})
	if err != nil {
		return "", "", err
	}
	output, err := channel.aws.run(ctx, "ssm", "send-command",
		"--instance-ids", channel.instanceID,
		"--document-name", "AWS-RunShellScript",
		"--comment", "rarpar-bench fleet "+channel.machine,
		"--parameters", string(parameters),
		"--query", "Command.CommandId", "--output", "text")
	if err != nil {
		return "", "", fmt.Errorf("machine %s: ssm send-command: %w", channel.machine, err)
	}
	commandID := strings.TrimSpace(string(output))
	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		described, err := channel.aws.run(ctx, "ssm", "get-command-invocation",
			"--command-id", commandID, "--instance-id", channel.instanceID)
		if err != nil {
			// The invocation is not queryable for a moment after send-command.
			if strings.Contains(err.Error(), "InvocationDoesNotExist") {
				continue
			}
			return "", "", fmt.Errorf("machine %s: ssm get-command-invocation: %w", channel.machine, err)
		}
		var invocation struct {
			Status                string `json:"Status"`
			ResponseCode          int    `json:"ResponseCode"`
			StandardOutputContent string `json:"StandardOutputContent"`
			StandardErrorContent  string `json:"StandardErrorContent"`
		}
		if err := json.Unmarshal(described, &invocation); err != nil {
			return "", "", fmt.Errorf("machine %s: reading ssm invocation: %w", channel.machine, err)
		}
		switch invocation.Status {
		case "Pending", "InProgress", "Delayed":
			continue
		case "Success":
			return invocation.StandardOutputContent, invocation.StandardErrorContent, nil
		default:
			return invocation.StandardOutputContent, invocation.StandardErrorContent,
				fmt.Errorf("machine %s: ssm command %s %s (rc=%d): %s", channel.machine, commandID,
					invocation.Status, invocation.ResponseCode, strings.TrimSpace(invocation.StandardErrorContent))
		}
	}
}

// run executes a POSIX script on the instance. The script travels as an S3
// object; the RunCommand line only fetches, runs, and deletes it.
func (channel *ssmChannel) run(ctx context.Context, script string) (string, string, error) {
	key := channel.key("cmd")
	local := filepath.Join(channel.scratch, filepath.Base(key)+".sh")
	if err := os.WriteFile(local, []byte(script), 0o600); err != nil {
		return "", "", err
	}
	defer os.Remove(local)
	if _, err := channel.aws.run(ctx, "s3", "cp", "--quiet", local, channel.url(key)); err != nil {
		return "", "", fmt.Errorf("machine %s: staging a command in S3: %w", channel.machine, err)
	}
	fetched := "/tmp/rarpar-fleet-" + filepath.Base(key) + ".sh"
	return channel.invoke(ctx, []string{
		fmt.Sprintf("aws s3 cp --quiet %s %s && aws s3 rm --quiet %s", shellQuote(channel.url(key)), shellQuote(fetched), shellQuote(channel.url(key))),
		fmt.Sprintf("sh %s; rc=$?; rm -f %s; exit $rc", shellQuote(fetched), shellQuote(fetched)),
	})
}

func (channel *ssmChannel) ready(ctx context.Context) (bool, error) {
	stdout, _, err := channel.invoke(ctx, []string{ssmReadyScript})
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(stdout) == "ready", nil
}

func (channel *ssmChannel) uploadDir(ctx context.Context, localDir, remoteDir string) error {
	key := channel.key("up") + ".tar"
	archive := filepath.Join(channel.scratch, filepath.Base(key))
	pack := exec.CommandContext(ctx, "tar", "--no-xattrs", "-cf", archive, "-C", localDir, ".")
	pack.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
	if output, err := pack.CombinedOutput(); err != nil {
		return fmt.Errorf("machine %s: packing %s: %w: %s", channel.machine, localDir, err, strings.TrimSpace(string(output)))
	}
	defer os.Remove(archive)
	if _, err := channel.aws.run(ctx, "s3", "cp", "--quiet", archive, channel.url(key)); err != nil {
		return fmt.Errorf("machine %s: upload of %s to S3: %w", channel.machine, localDir, err)
	}
	_, _, err := channel.run(ctx, fmt.Sprintf("set -e\nmkdir -p %s\naws s3 cp --quiet %s - | tar -xf - -C %s\naws s3 rm --quiet %s\n",
		shellQuote(remoteDir), shellQuote(channel.url(key)), shellQuote(remoteDir), shellQuote(channel.url(key))))
	return err
}

func (channel *ssmChannel) downloadPath(ctx context.Context, remotePath, localDir string) error {
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return err
	}
	key := channel.key("down") + ".tar"
	if _, _, err := channel.run(ctx, fmt.Sprintf("set -e\ntar -cf - -C %s %s | aws s3 cp --quiet - %s\n",
		shellQuote(posixDir(remotePath)), shellQuote(posixBase(remotePath)), shellQuote(channel.url(key)))); err != nil {
		return err
	}
	archive := filepath.Join(channel.scratch, filepath.Base(key))
	defer os.Remove(archive)
	if _, err := channel.aws.run(ctx, "s3", "cp", "--quiet", channel.url(key), archive); err != nil {
		return fmt.Errorf("machine %s: download of %s from S3: %w", channel.machine, remotePath, err)
	}
	_, _ = channel.aws.run(ctx, "s3", "rm", "--quiet", channel.url(key))
	unpack := exec.CommandContext(ctx, "tar", "-xf", archive, "-C", localDir)
	var stderr bytes.Buffer
	unpack.Stderr = &stderr
	if err := unpack.Run(); err != nil {
		return fmt.Errorf("machine %s: unpacking %s: %w: %s", channel.machine, remotePath, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// NewSSMTransport returns a Transport whose every method goes through SSM
// RunCommand and S3 instead of SSH.
func NewSSMTransport(machine Machine, aws *AWS, bucket, prefix, instanceID, runDir string) (*Transport, error) {
	scratch := filepath.Join(runDir, "ssm-"+machine.Name)
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return nil, err
	}
	return &Transport{
		Machine: machine.Name,
		Shell:   "sh",
		ssm: &ssmChannel{
			aws: aws, machine: machine.Name, instanceID: instanceID, bucket: bucket, prefix: prefix,
			scratch: scratch, commandTimeout: 30 * time.Minute,
		},
	}, nil
}

// SSMLaunchArgs are the run-instances arguments that differ from the SSH path:
// the instance profile replaces the key pair and the session security group
// (the VPC default group's egress is all SSM and S3 need), and spot is opt-in.
func SSMLaunchArgs(spec EC2) []string {
	args := []string{"--iam-instance-profile", "Name=" + spec.InstanceProfile}
	if spec.Spot {
		args = append(args, "--instance-market-options",
			`{"MarketType":"spot","SpotOptions":{"SpotInstanceType":"one-time","InstanceInterruptionBehavior":"terminate"}}`)
	}
	return args
}

// WaitSSMOnline polls until the instance's agent reports Online.
func (aws *AWS) WaitSSMOnline(ctx context.Context, instanceID string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		output, err := aws.run(ctx, "ssm", "describe-instance-information",
			"--filters", "Key=InstanceIds,Values="+instanceID,
			"--query", "InstanceInformationList[0].PingStatus", "--output", "text")
		if err == nil && strings.TrimSpace(string(output)) == "Online" {
			return nil
		}
		if time.Now().After(deadline) {
			status := strings.TrimSpace(string(output))
			if err != nil {
				status = err.Error()
			}
			return fmt.Errorf("instance %s never reported SSM Online within %s (last: %s); check the instance profile", instanceID, wait, status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}
