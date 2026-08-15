package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// AWS wraps the AWS CLI. The CLI is used rather than an SDK for the same reason
// the rest of this harness has no module dependencies: the evidence trail has to
// be reproducible from a checkout, and every call here is one an operator can
// paste into a terminal to audit.
type AWS struct {
	CLI     string
	Region  string
	Profile string
	// DryRun exercises every code path except the API mutations. Reads
	// (get-caller-identity, describe-*) still run live so a dry run validates
	// credentials, AMIs, instance types, and quota against the real account.
	DryRun bool
	Log    func(format string, args ...any)
}

type SessionResources struct {
	Prefix          string `json:"prefix"`
	KeyName         string `json:"key_name"`
	KeyPath         string `json:"key_path"`
	SecurityGroupID string `json:"security_group_id"`
	PublicCIDR      string `json:"public_cidr"`
	Region          string `json:"region"`
	CreatedUTC      string `json:"created_utc"`
	DryRun          bool   `json:"dry_run"`
}

type CloudState struct {
	InstanceID   string `json:"instance_id"`
	InstanceType string `json:"instance_type"`
	PublicIP     string `json:"public_ip"`
	VolumeID     string `json:"volume_id"`
	ENIID        string `json:"eni_id"`
	AZ           string `json:"availability_zone"`
	LaunchUTC    string `json:"launch_utc"`
	TerminateUTC string `json:"terminate_utc,omitempty"`
	DryRun       bool   `json:"dry_run"`
}

type TeardownEvidence struct {
	InstanceID     string   `json:"instance_id"`
	RequestedUTC   string   `json:"terminate_requested_utc"`
	InstanceState  string   `json:"instance_state"`
	VolumeState    string   `json:"root_volume_state"`
	AttachedVolume []string `json:"volumes_still_attached"`
	ENIs           []string `json:"network_interfaces_remaining"`
	Verified       bool     `json:"verified"`
	Notes          []string `json:"notes,omitempty"`
}

func (aws *AWS) log(format string, args ...any) {
	if aws.Log != nil {
		aws.Log(format, args...)
	}
}

func (aws *AWS) run(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"--region", aws.Region, "--output", "json"}, args...)
	command := exec.CommandContext(ctx, aws.CLI, full...)
	command.Env = os.Environ()
	if aws.Profile != "" {
		command.Env = append(command.Env, "AWS_PROFILE="+aws.Profile)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", aws.CLI, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// mutate is every call that changes account state. In dry-run it is recorded
// and skipped; the surrounding orchestration still runs.
func (aws *AWS) mutate(ctx context.Context, what string, args ...string) ([]byte, error) {
	if aws.DryRun {
		aws.log("DRY-RUN-AWS would %s: %s %s", what, aws.CLI, strings.Join(args, " "))
		return nil, nil
	}
	aws.log("aws %s", strings.Join(args, " "))
	return aws.run(ctx, args...)
}

// ECRAuthToken mints a registry pull token for the given region. It is a
// read (nothing in the account changes), so dry-run still mints it — the
// corpus-image preflight depends on the token to prove the image exists.
// The region comes from the image ref's registry host, not aws.Region, so a
// corpus image can live in a different region than the fleet if it must.
func (aws *AWS) ECRAuthToken(ctx context.Context, region string) (string, error) {
	command := exec.CommandContext(ctx, aws.CLI, "ecr", "get-authorization-token",
		"--region", region, "--output", "json")
	command.Env = os.Environ()
	if aws.Profile != "" {
		command.Env = append(command.Env, "AWS_PROFILE="+aws.Profile)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("ecr get-authorization-token (%s): %w: %s", region, err, strings.TrimSpace(stderr.String()))
	}
	var payload struct {
		AuthorizationData []struct {
			AuthorizationToken string `json:"authorizationToken"`
		} `json:"authorizationData"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		return "", fmt.Errorf("cannot read the ECR token response: %w", err)
	}
	if len(payload.AuthorizationData) == 0 || payload.AuthorizationData[0].AuthorizationToken == "" {
		return "", fmt.Errorf("ECR returned no authorization token for region %s", region)
	}
	return payload.AuthorizationData[0].AuthorizationToken, nil
}

// CheckCredentials runs first, before anything is launched or built. Expired
// credentials mid-launch are how a fleet ends up with orphaned instances.
func (aws *AWS) CheckCredentials(ctx context.Context, expectedAccount string) (string, error) {
	if _, err := exec.LookPath(aws.CLI); err != nil {
		return "", fmt.Errorf("the AWS CLI (%s) is required for cloud machines: %w", aws.CLI, err)
	}
	output, err := aws.run(ctx, "sts", "get-caller-identity")
	if err != nil {
		return "", fmt.Errorf(`AWS credentials are not usable: %w

Remediation (nothing has been launched):
  1. refresh the session, e.g. "aws sso login --profile <profile>" or renew the
     access keys used by this shell;
  2. confirm with "aws sts get-caller-identity";
  3. re-run the same fleet command — it is safe to repeat, no resources exist yet`, err)
	}
	var identity struct {
		Account string `json:"Account"`
		Arn     string `json:"Arn"`
	}
	if err := json.Unmarshal(output, &identity); err != nil {
		return "", fmt.Errorf("cannot read the AWS identity response: %w", err)
	}
	if expectedAccount != "" && identity.Account != expectedAccount {
		return "", fmt.Errorf("AWS credentials belong to account %s but the fleet config pins account %s; refusing to launch into the wrong account",
			identity.Account, expectedAccount)
	}
	aws.log("aws identity: account=%s arn=%s", identity.Account, identity.Arn)
	return identity.Account, nil
}

// PublicIP discovers this orchestrator's public address so the session security
// group can be scoped to it. DNS-based on purpose: HTTP echo services are
// blocked on this network, and an empty answer must never widen the group.
func PublicIP(ctx context.Context, commands []string) (string, error) {
	var problems []string
	for _, line := range commands {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		command := exec.CommandContext(ctx, fields[0], fields[1:]...)
		output, err := command.Output()
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", line, err))
			continue
		}
		for _, candidate := range strings.Fields(string(output)) {
			candidate = strings.Trim(candidate, "\"")
			parsed := net.ParseIP(candidate)
			if parsed != nil && parsed.To4() != nil {
				return candidate, nil
			}
		}
		problems = append(problems, fmt.Sprintf("%s: no IPv4 in %q", line, strings.TrimSpace(string(output))))
	}
	return "", fmt.Errorf("cannot determine this machine's public IPv4 address; refusing to open a security group without it (%s)", strings.Join(problems, "; "))
}

// CreateSession makes the ephemeral keypair and the session security group that
// every cloud host in this run shares.
func (aws *AWS) CreateSession(ctx context.Context, prefix, publicIP, keyDir string, sshPort int) (SessionResources, error) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	session := SessionResources{
		Prefix:     prefix,
		KeyName:    fmt.Sprintf("%s-%s", prefix, stamp),
		KeyPath:    joinPosix(keyDir, fmt.Sprintf("%s-%s.pem", prefix, stamp)),
		PublicCIDR: publicIP + "/32",
		Region:     aws.Region,
		CreatedUTC: time.Now().UTC().Format(time.RFC3339),
		DryRun:     aws.DryRun,
	}
	output, err := aws.mutate(ctx, "create the ephemeral keypair", "ec2", "create-key-pair",
		"--key-name", session.KeyName, "--query", "KeyMaterial", "--output", "text")
	if err != nil {
		return session, err
	}
	if !aws.DryRun {
		if err := os.WriteFile(session.KeyPath, output, 0o600); err != nil {
			return session, fmt.Errorf("write session key: %w", err)
		}
	}

	groupName := fmt.Sprintf("%s-%s", prefix, stamp)
	output, err = aws.mutate(ctx, "create the session security group", "ec2", "create-security-group",
		"--group-name", groupName,
		"--description", "rarpar fleet bench session (ephemeral)",
		"--query", "GroupId", "--output", "text")
	if err != nil {
		return session, err
	}
	if aws.DryRun {
		session.SecurityGroupID = "sg-dryrun00000000000"
	} else {
		session.SecurityGroupID = strings.TrimSpace(string(output))
	}
	if _, err := aws.mutate(ctx, "scope SSH ingress to this machine only", "ec2", "authorize-security-group-ingress",
		"--group-id", session.SecurityGroupID,
		"--protocol", "tcp", "--port", fmt.Sprint(sshPort), "--cidr", session.PublicCIDR); err != nil {
		return session, err
	}
	aws.log("session resources: keypair=%s sg=%s ingress=%s", session.KeyName, session.SecurityGroupID, session.PublicCIDR)
	return session, nil
}

// UserData is the deadman plus quiet-box hygiene applied to every cloud host.
func UserData(deadmanMinutes int) string {
	return fmt.Sprintf(`#!/bin/bash
# Deadman. instance-initiated-shutdown-behavior=terminate makes this a hard cap:
# if the orchestrator dies, the box still disappears.
shutdown -h +%d
# Quiet-box hygiene: nothing may wake up mid-measurement.
systemctl disable --now unattended-upgrades.service >/dev/null 2>&1
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
systemctl disable --now snapd.service snapd.socket snapd.seeded.service >/dev/null 2>&1
systemctl disable --now motd-news.timer man-db.timer >/dev/null 2>&1
# Unprivileged perf. Stock Ubuntu cloud images ship kernel.perf_event_paranoid=4,
# which makes perf stat/record fail for the bench user and silently costs the run
# its perf evidence -- exactly how fleet round 1 lost perf on four of five boxes.
# Applied live for this boot and dropped in so a reboot cannot take it back.
echo 'kernel.perf_event_paranoid=1' > /etc/sysctl.d/99-bench-perf.conf
sysctl -w kernel.perf_event_paranoid=1 >/dev/null 2>&1
touch /var/lib/cloud/instance/BENCH_USERDATA_DONE
`, deadmanMinutes)
}

func (aws *AWS) Launch(ctx context.Context, machine Machine, session SessionResources, userDataPath string) (*CloudState, error) {
	spec := machine.EC2
	state := &CloudState{
		InstanceType: spec.InstanceType,
		LaunchUTC:    time.Now().UTC().Format(time.RFC3339),
		DryRun:       aws.DryRun,
	}
	blockDevice := fmt.Sprintf(`[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":%d,"VolumeType":"gp3","DeleteOnTermination":true}}]`, spec.VolumeGB)
	args := []string{
		"ec2", "run-instances",
		"--image-id", spec.AMI,
		"--instance-type", spec.InstanceType,
		"--key-name", session.KeyName,
		"--security-group-ids", session.SecurityGroupID,
		"--associate-public-ip-address",
		// Paired with the deadman shutdown in user-data: shutdown means gone,
		// not stopped-and-still-billing-for-storage.
		"--instance-initiated-shutdown-behavior", "terminate",
		"--block-device-mappings", blockDevice,
		"--user-data", "file://" + userDataPath,
		"--metadata-options", "HttpTokens=required,HttpEndpoint=enabled",
		"--tag-specifications", fmt.Sprintf("ResourceType=instance,Tags=[{Key=Name,Value=%s-%s},{Key=purpose,Value=%s}]",
			session.Prefix, machine.Name, session.Prefix),
		"--query", "Instances[0].InstanceId", "--output", "text",
	}
	if spec.Subnet != "" {
		args = append(args, "--subnet-id", spec.Subnet)
	}
	output, err := aws.mutate(ctx, "launch "+machine.Name, args...)
	if err != nil {
		return state, err
	}
	if aws.DryRun {
		state.InstanceID = "i-dryrun" + machine.Name
		state.PublicIP = "203.0.113.1"
		state.VolumeID = "vol-dryrun"
		state.ENIID = "eni-dryrun"
		state.AZ = aws.Region + "a"
		return state, nil
	}
	state.InstanceID = strings.TrimSpace(string(output))
	if _, err := aws.run(ctx, "ec2", "wait", "instance-running", "--instance-ids", state.InstanceID); err != nil {
		return state, err
	}
	described, err := aws.run(ctx, "ec2", "describe-instances", "--instance-ids", state.InstanceID,
		"--query", "Reservations[0].Instances[0].{ip:PublicIpAddress,vol:BlockDeviceMappings[0].Ebs.VolumeId,az:Placement.AvailabilityZone,eni:NetworkInterfaces[0].NetworkInterfaceId}")
	if err != nil {
		return state, err
	}
	var details struct {
		IP  string `json:"ip"`
		Vol string `json:"vol"`
		AZ  string `json:"az"`
		ENI string `json:"eni"`
	}
	if err := json.Unmarshal(described, &details); err != nil {
		return state, fmt.Errorf("cannot read instance description: %w", err)
	}
	state.PublicIP, state.VolumeID, state.AZ, state.ENIID = details.IP, details.Vol, details.AZ, details.ENI
	aws.log("launched %s as %s ip=%s vol=%s az=%s", machine.Name, state.InstanceID, state.PublicIP, state.VolumeID, state.AZ)
	return state, nil
}

// Terminate tears one host down and then proves it, resource by resource.
// Teardown verification is part of a host being DONE, not a best-effort extra.
func (aws *AWS) Terminate(ctx context.Context, state *CloudState) (TeardownEvidence, error) {
	evidence := TeardownEvidence{InstanceID: state.InstanceID, RequestedUTC: time.Now().UTC().Format(time.RFC3339)}
	state.TerminateUTC = evidence.RequestedUTC
	if aws.DryRun {
		evidence.InstanceState = "terminated (dry-run)"
		evidence.VolumeState = "deleted (dry-run)"
		evidence.Verified = true
		evidence.Notes = append(evidence.Notes, "dry-run: no API mutation was issued")
		return evidence, nil
	}
	if _, err := aws.mutate(ctx, "terminate "+state.InstanceID, "ec2", "terminate-instances", "--instance-ids", state.InstanceID); err != nil {
		return evidence, err
	}
	if _, err := aws.run(ctx, "ec2", "wait", "instance-terminated", "--instance-ids", state.InstanceID); err != nil {
		evidence.Notes = append(evidence.Notes, "wait instance-terminated: "+err.Error())
	}
	if output, err := aws.run(ctx, "ec2", "describe-instances", "--instance-ids", state.InstanceID,
		"--query", "Reservations[0].Instances[0].State.Name", "--output", "text"); err == nil {
		evidence.InstanceState = strings.TrimSpace(string(output))
	} else {
		evidence.Notes = append(evidence.Notes, "describe-instances: "+err.Error())
	}
	// A root volume that still exists means DeleteOnTermination did not apply.
	if state.VolumeID != "" {
		output, err := aws.run(ctx, "ec2", "describe-volumes", "--volume-ids", state.VolumeID,
			"--query", "Volumes[0].State", "--output", "text")
		switch {
		case err != nil && strings.Contains(err.Error(), "InvalidVolume.NotFound"):
			evidence.VolumeState = "deleted"
		case err != nil:
			evidence.Notes = append(evidence.Notes, "describe-volumes: "+err.Error())
		default:
			evidence.VolumeState = strings.TrimSpace(string(output))
		}
	}
	if output, err := aws.run(ctx, "ec2", "describe-volumes",
		"--filters", "Name=attachment.instance-id,Values="+state.InstanceID,
		"--query", "Volumes[].VolumeId"); err == nil {
		_ = json.Unmarshal(output, &evidence.AttachedVolume)
	}
	if output, err := aws.run(ctx, "ec2", "describe-network-interfaces",
		"--filters", "Name=attachment.instance-id,Values="+state.InstanceID,
		"--query", "NetworkInterfaces[].NetworkInterfaceId"); err == nil {
		_ = json.Unmarshal(output, &evidence.ENIs)
	}
	evidence.Verified = strings.EqualFold(evidence.InstanceState, "terminated") &&
		(evidence.VolumeState == "deleted" || evidence.VolumeState == "") &&
		len(evidence.AttachedVolume) == 0 && len(evidence.ENIs) == 0
	return evidence, nil
}

// DeleteSession removes the shared keypair and security group once the last
// cloud host is gone, and proves both are NotFound afterwards.
func (aws *AWS) DeleteSession(ctx context.Context, session SessionResources) ([]string, error) {
	var evidence []string
	if aws.DryRun {
		return []string{"dry-run: session security group and keypair were never created"}, nil
	}
	if session.SecurityGroupID != "" {
		if _, err := aws.mutate(ctx, "delete the session security group", "ec2", "delete-security-group", "--group-id", session.SecurityGroupID); err != nil {
			evidence = append(evidence, "delete-security-group: "+err.Error())
		}
		if _, err := aws.run(ctx, "ec2", "describe-security-groups", "--group-ids", session.SecurityGroupID); err != nil {
			evidence = append(evidence, "security group "+session.SecurityGroupID+": NotFound (expected)")
		} else {
			evidence = append(evidence, "security group "+session.SecurityGroupID+": STILL EXISTS")
		}
	}
	if session.KeyName != "" {
		if _, err := aws.mutate(ctx, "delete the ephemeral keypair", "ec2", "delete-key-pair", "--key-name", session.KeyName); err != nil {
			evidence = append(evidence, "delete-key-pair: "+err.Error())
		}
		if _, err := aws.run(ctx, "ec2", "describe-key-pairs", "--key-names", session.KeyName); err != nil {
			evidence = append(evidence, "keypair "+session.KeyName+": NotFound (expected)")
		} else {
			evidence = append(evidence, "keypair "+session.KeyName+": STILL EXISTS")
		}
		if session.KeyPath != "" {
			_ = os.Remove(session.KeyPath)
		}
	}
	return evidence, nil
}

// Sweep lists anything still alive that carries the fleet's resource prefix.
// `fleet teardown` uses it to catch strays from an interrupted run.
func (aws *AWS) Sweep(ctx context.Context, prefix string) ([]string, error) {
	var found []string
	output, err := aws.run(ctx, "ec2", "describe-instances",
		"--filters", "Name=instance-state-name,Values=pending,running,stopping,stopped",
		"Name=tag:purpose,Values="+prefix,
		"--query", "Reservations[].Instances[].[InstanceId,InstanceType,State.Name]")
	if err != nil {
		return nil, err
	}
	var instances [][]string
	_ = json.Unmarshal(output, &instances)
	for _, row := range instances {
		found = append(found, "instance "+strings.Join(row, " "))
	}
	if output, err := aws.run(ctx, "ec2", "describe-security-groups",
		"--filters", "Name=group-name,Values="+prefix+"-*", "--query", "SecurityGroups[].[GroupId,GroupName]"); err == nil {
		var groups [][]string
		_ = json.Unmarshal(output, &groups)
		for _, row := range groups {
			found = append(found, "security-group "+strings.Join(row, " "))
		}
	}
	if output, err := aws.run(ctx, "ec2", "describe-key-pairs",
		"--filters", "Name=key-name,Values="+prefix+"-*", "--query", "KeyPairs[].KeyName"); err == nil {
		var keys []string
		_ = json.Unmarshal(output, &keys)
		for _, key := range keys {
			found = append(found, "keypair "+key)
		}
	}
	return found, nil
}

// DescribeInstanceTypes reads the real vCPU count for each configured instance
// type, so the quota arithmetic is checked against AWS rather than the config's
// own claim. This is a read, so it runs live even under --dry-run-aws.
func (aws *AWS) DescribeInstanceTypes(ctx context.Context, types []string) (map[string]int, error) {
	if len(types) == 0 {
		return map[string]int{}, nil
	}
	args := append([]string{"ec2", "describe-instance-types", "--instance-types"}, types...)
	args = append(args, "--query", "InstanceTypes[].{type:InstanceType,vcpus:VCpuInfo.DefaultVCpus}")
	output, err := aws.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Type  string `json:"type"`
		VCPUs int    `json:"vcpus"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		return nil, fmt.Errorf("cannot read instance type description: %w", err)
	}
	result := make(map[string]int, len(rows))
	for _, row := range rows {
		result[row.Type] = row.VCPUs
	}
	return result, nil
}
