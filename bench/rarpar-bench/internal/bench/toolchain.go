package bench

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func LoadToolchains(path string) (ToolchainLock, error) {
	var lock ToolchainLock
	if err := readJSON(path, &lock); err != nil {
		return ToolchainLock{}, err
	}
	if err := lock.Validate(); err != nil {
		return ToolchainLock{}, err
	}
	return lock, nil
}

func (lock ToolchainLock) Validate() error {
	if lock.SchemaVersion != 1 {
		return fmt.Errorf("unsupported toolchain schema version %d", lock.SchemaVersion)
	}
	if lock.DockerBase == "" || !regexp.MustCompile(`@sha256:[a-f0-9]{64}$`).MatchString(lock.DockerBase) {
		return fmt.Errorf("toolchain docker_base must be digest pinned")
	}
	seen := map[string]bool{}
	formats := map[string]bool{}
	for _, writer := range lock.RARWriters {
		if writer.ID == "" || writer.Image == "" || writer.URL == "" || writer.Binary == "" || seen[writer.ID] {
			return fmt.Errorf("invalid or duplicate RAR writer %q", writer.ID)
		}
		if writer.Platform != "linux/amd64" || !sha256Pattern.MatchString(writer.SHA256) {
			return fmt.Errorf("RAR writer %q is not source locked for linux/amd64", writer.ID)
		}
		seen[writer.ID] = true
		formats[writer.ID] = true
	}
	for _, required := range []string{"rarlab-3.93", "rarlab-4.20", "rarlab-5.00", "rarlab-6.24", "rarlab-7.23"} {
		if !formats[required] {
			return fmt.Errorf("missing required RAR writer %q", required)
		}
	}
	par2 := lock.PAR2Generator
	if par2.ID == "" || par2.Image == "" || par2.URL == "" || par2.Platform != "linux/amd64" || !sha256Pattern.MatchString(par2.SHA256) {
		return fmt.Errorf("PAR2 generator is not source locked for linux/amd64")
	}
	return nil
}

func (lock ToolchainLock) Writer(id string) (RARWriter, bool) {
	for _, writer := range lock.RARWriters {
		if writer.ID == id {
			return writer, true
		}
	}
	return RARWriter{}, false
}

func BuildToolchains(ctx context.Context, docker, root string, lock ToolchainLock) error {
	if err := verifyDockerfiles(root, lock.DockerBase); err != nil {
		return err
	}
	for _, writer := range lock.RARWriters {
		args := []string{"build", "--platform", writer.Platform, "--tag", writer.Image,
			"--file", filepath.Join(root, "docker/rarlab/Dockerfile"),
			"--build-arg", "RAR_URL=" + writer.URL,
			"--build-arg", "RAR_SHA256=" + writer.SHA256,
			"--build-arg", "RAR_BINARY=" + writer.Binary,
			filepath.Join(root, "docker/rarlab")}
		if err := runCommand(ctx, docker, args...); err != nil {
			return fmt.Errorf("build %s: %w", writer.ID, err)
		}
	}
	par2 := lock.PAR2Generator
	args := []string{"build", "--platform", par2.Platform, "--tag", par2.Image,
		"--file", filepath.Join(root, "docker/par2/Dockerfile"),
		"--build-arg", "PAR2_URL=" + par2.URL,
		"--build-arg", "PAR2_SHA256=" + par2.SHA256,
		filepath.Join(root, "docker/par2")}
	if err := runCommand(ctx, docker, args...); err != nil {
		return fmt.Errorf("build %s: %w", par2.ID, err)
	}
	return nil
}

func verifyDockerfiles(root, base string) error {
	for _, relative := range []string{"docker/rarlab/Dockerfile", "docker/par2/Dockerfile"} {
		path := filepath.Join(root, relative)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), "FROM "+base) {
			return fmt.Errorf("%s does not use source-locked Docker base %s", relative, base)
		}
	}
	return nil
}

func runCommand(ctx context.Context, program string, args ...string) error {
	command := exec.CommandContext(ctx, program, args...)
	command.Stdout = nil
	command.Stderr = nil
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w\n%s", program, args, err, output)
	}
	return nil
}

func ToolchainIDs(lock ToolchainLock, caseConfig CaseConfig) []string {
	ids := []string{caseConfig.Writer}
	if caseConfig.PAR2 {
		ids = append(ids, lock.PAR2Generator.ID)
	}
	sort.Strings(ids)
	return ids
}
