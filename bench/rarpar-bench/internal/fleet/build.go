package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BuildInfo travels with every bundle. A benchmark number whose binary cannot be
// identified later is not evidence, and a commit id alone does not identify a
// build made from a dirty tree.
type BuildInfo struct {
	SchemaVersion int               `json:"schema_version"`
	Bundle        string            `json:"bundle"`
	BuiltUTC      string            `json:"built_utc"`
	Machine       string            `json:"machine"`
	PlatformLabel string            `json:"platform_label"`
	BuildTarget   string            `json:"build_target"`
	Source        string            `json:"source"`
	BuildHost     string            `json:"build_host"`
	Image         string            `json:"image,omitempty"`
	CodegenPolicy map[string]string `json:"codegen_policy"`
	Trees         map[string]Tree   `json:"trees"`
	Binaries      map[string]string `json:"binary_sha256"`
	Oracles       map[string]Oracle `json:"oracles,omitempty"`
	Notes         []string          `json:"notes,omitempty"`
}

type Tree struct {
	Path       string `json:"path"`
	GitSHA     string `json:"git_sha,omitempty"`
	Branch     string `json:"branch,omitempty"`
	DirtyFiles int    `json:"dirty_files"`
	Note       string `json:"note,omitempty"`
}

// Bundler assembles one per-target bundle directory on the orchestrator.
type Bundler struct {
	Settings Settings
	RunDir   string
	Log      func(format string, args ...any)
}

func (bundler *Bundler) log(format string, args ...any) {
	if bundler.Log != nil {
		bundler.Log(format, args...)
	}
}

// Build produces (or reuses) the bundle directory for one machine and returns
// its path.
func (bundler *Bundler) Build(ctx context.Context, machine Machine) (string, BuildInfo, error) {
	target := filepath.Join(bundler.bundleRoot(), machine.Name)
	// Assemble into a clean directory. A stale binary left over from an earlier
	// run would be shipped, hashed into BUILDINFO, and silently measured.
	if err := os.RemoveAll(target); err != nil {
		return "", BuildInfo{}, err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", BuildInfo{}, err
	}
	info := BuildInfo{
		SchemaVersion: 1,
		Bundle:        machine.Name,
		BuiltUTC:      time.Now().UTC().Format(time.RFC3339),
		Machine:       machine.Name,
		PlatformLabel: machine.PlatformLabel,
		BuildTarget:   machine.BuildTarget,
		Source:        machine.Bundle.Source,
		BuildHost:     machine.Bundle.BuildHost,
		Image:         machine.Bundle.Image,
		CodegenPolicy: map[string]string{},
		Trees:         map[string]Tree{},
		Binaries:      map[string]string{},
	}

	switch machine.Bundle.Source {
	case BundlePrebuilt:
		if err := copyTree(machine.Bundle.Path, target); err != nil {
			return "", info, fmt.Errorf("machine %s: staging the prebuilt bundle: %w", machine.Name, err)
		}
		info.Notes = append(info.Notes,
			"prebuilt bundle staged from "+machine.Bundle.Path+"; its own BUILDINFO (if any) records the codegen policy")
	case BundleDocker:
		if err := bundler.dockerBuild(ctx, machine, target, &info); err != nil {
			return "", info, err
		}
	}

	required := []string{"rarpar-bench"}
	if machine.needsCorpus() {
		required = append(required, "rarpar")
	}
	if machine.hasSuite(SuiteCRCProbe) {
		required = append(required, "crc_probe")
	}
	for _, name := range required {
		if _, err := os.Stat(filepath.Join(target, name)); err != nil {
			return "", info, fmt.Errorf("machine %s: bundle is missing %s (suites %s need it)",
				machine.Name, name, strings.Join(machine.Suites, ","))
		}
	}

	entries, err := os.ReadDir(target)
	if err != nil {
		return "", info, err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		digest, err := fileSHA256(filepath.Join(target, entry.Name()))
		if err != nil {
			return "", info, err
		}
		info.Binaries[entry.Name()] = digest
	}
	info.Trees["rarpar"] = describeTree(ctx, bundler.rarparPath())
	if bundler.Settings.WeaverPath != "" {
		info.Trees["weaver"] = describeTree(ctx, bundler.Settings.WeaverPath)
	}
	if bundler.Settings.RapidyencPath != "" {
		info.Trees["rapidyenc"] = describeTree(ctx, bundler.Settings.RapidyencPath)
	}
	if len(machine.Oracles) > 0 {
		info.Oracles = machine.Oracles
	}
	if err := writeJSONFile(filepath.Join(target, "BUILDINFO.json"), info); err != nil {
		return "", info, err
	}
	return target, info, nil
}

func (bundler *Bundler) bundleRoot() string {
	if bundler.Settings.BundleCache != "" {
		return bundler.Settings.BundleCache
	}
	return filepath.Join(bundler.RunDir, "bundles")
}

func (bundler *Bundler) rarparPath() string {
	if bundler.Settings.RarparPath != "" {
		return bundler.Settings.RarparPath
	}
	return "."
}

// dockerBuild runs the recorded container recipe. The flags are not incidental:
//   - crt-static via the target-specific RUSTFLAGS variable only, so proc-macros
//     still build for the host;
//   - no -march/-mcpu/-mtune anywhere: tier selection is runtime dispatch, and a
//     target-cpu flag would silently make one platform's numbers incomparable;
//   - aws-lc built in-container against musl (cmake + clang), which is what keeps
//     the native crypto backend rather than falling back to RustCrypto;
//   - Go with CGO off so the harness is a static binary on appliance hosts.
func (bundler *Bundler) dockerBuild(ctx context.Context, machine Machine, target string, info *BuildInfo) error {
	bundle := machine.Bundle
	rustFlagVar := "CARGO_TARGET_" + strings.ToUpper(strings.ReplaceAll(bundle.RustTarget, "-", "_")) + "_RUSTFLAGS"
	rustFlags := ""
	if bundle.CrtStatic {
		rustFlags = "-C target-feature=+crt-static"
	}
	info.CodegenPolicy["target_cpu"] = "NONE (baseline); tier selection is runtime dispatch only"
	info.CodegenPolicy["rust_target"] = bundle.RustTarget
	info.CodegenPolicy["rust_flags"] = rustFlags + " (" + rustFlagVar + ", target-only)"
	info.CodegenPolicy["go_flags"] = fmt.Sprintf("CGO_ENABLED=0 GOOS=%s GOARCH=%s %s -trimpath",
		bundle.GoOS, bundle.GoArch, goamd64Flag(bundle))

	work := filepath.Join(bundler.RunDir, "build", machine.Name)
	if err := os.MkdirAll(filepath.Join(work, "out"), 0o755); err != nil {
		return err
	}
	script := containerBuildScript(machine, rustFlagVar, rustFlags, bundler.Settings.WeaverPath != "")
	scriptPath := filepath.Join(work, "build-in-container.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		return err
	}

	sources := map[string]string{"rarpar": bundler.rarparPath()}
	if bundler.Settings.WeaverPath != "" && (machine.hasSuite(SuiteYencMicro) || machine.hasSuite(SuiteCRCProbe)) {
		sources["weaver"] = bundler.Settings.WeaverPath
		if bundler.Settings.RapidyencPath != "" {
			sources["rapidyenc"] = bundler.Settings.RapidyencPath
		}
	}
	for name, path := range sources {
		if err := snapshotTree(ctx, path, filepath.Join(work, name)); err != nil {
			return fmt.Errorf("machine %s: snapshotting %s: %w", machine.Name, name, err)
		}
	}

	if bundle.BuildHost != "" && bundle.BuildHost != "local" {
		return fmt.Errorf("machine %s: bundle.build_host = %q requires the remote build host to be reachable; run `fleet build --machine %s` from that host or use source = %q",
			machine.Name, bundle.BuildHost, machine.Name, BundlePrebuilt)
	}

	docker := bundler.Settings.Docker
	if docker == "" {
		docker = "docker"
	}
	bundler.log("machine %s: building bundle in %s (%s)", machine.Name, bundle.Image, bundle.RustTarget)
	command := exec.CommandContext(ctx, docker, "run", "--rm",
		"-v", work+":/work", "-w", "/work", bundle.Image, "sh", "/work/build-in-container.sh")
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("machine %s: container build failed: %w", machine.Name, err)
	}

	// The Go harness cross-compiles natively on the orchestrator: CGO is off, so
	// there is nothing a container adds and a lot of container time it saves.
	goBuild := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(work, "out", "rarpar-bench"), "./cmd/rarpar-bench")
	goBuild.Dir = filepath.Join(bundler.rarparPath(), "bench", "rarpar-bench")
	goBuild.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+bundle.GoOS, "GOARCH="+bundle.GoArch)
	if bundle.GOAMD64 != "" {
		goBuild.Env = append(goBuild.Env, "GOAMD64="+bundle.GOAMD64)
	}
	goBuild.Stdout = os.Stderr
	goBuild.Stderr = os.Stderr
	if err := goBuild.Run(); err != nil {
		return fmt.Errorf("machine %s: building the Go harness: %w", machine.Name, err)
	}
	return copyTree(filepath.Join(work, "out"), target)
}

func goamd64Flag(bundle Bundle) string {
	if bundle.GOAMD64 == "" {
		return ""
	}
	return "GOAMD64=" + bundle.GOAMD64
}

func containerBuildScript(machine Machine, rustFlagVar, rustFlags string, weaver bool) string {
	var script strings.Builder
	script.WriteString("#!/bin/sh\nset -eu\n")
	script.WriteString("apk add --no-cache musl-dev g++ make cmake clang clang-dev llvm-dev linux-headers perl pkgconfig git bash file >/dev/null 2>&1\n")
	script.WriteString("export CARGO_HOME=/work/cargo-home\n")
	script.WriteString("export CARGO_TARGET_DIR=/work/build-target\n")
	if rustFlags != "" {
		fmt.Fprintf(&script, "export %s=%q\n", rustFlagVar, rustFlags)
	}
	script.WriteString("mkdir -p /work/out\n")
	script.WriteString("rustc --version; cargo --version; clang --version | head -1; cmake --version | head -1\n")
	fmt.Fprintf(&script, "cd /work/rarpar && cargo build --release --target %s -p rarpar --bin rarpar\n", machine.Bundle.RustTarget)
	fmt.Fprintf(&script, "cp /work/build-target/%s/release/rarpar /work/out/rarpar\n", machine.Bundle.RustTarget)
	if weaver && (machine.hasSuite(SuiteYencMicro) || machine.hasSuite(SuiteCRCProbe)) {
		script.WriteString("if [ -d /work/rapidyenc ]; then export WEAVER_RAPIDYENC_SRC=/work/rapidyenc; fi\n")
		script.WriteString("cd /work/weaver\n")
		if machine.hasSuite(SuiteYencMicro) {
			fmt.Fprintf(&script, "cargo build --release --target %s -p weaver-yenc --example decode_timing --example searchend_timing\n", machine.Bundle.RustTarget)
			fmt.Fprintf(&script, "cp /work/build-target/%s/release/examples/decode_timing /work/out/decode_timing\n", machine.Bundle.RustTarget)
			fmt.Fprintf(&script, "cp /work/build-target/%s/release/examples/searchend_timing /work/out/searchend_timing\n", machine.Bundle.RustTarget)
		}
		if machine.hasSuite(SuiteCRCProbe) {
			fmt.Fprintf(&script, "cargo build --release --target %s -p weaver-yenc --example crc_probe\n", machine.Bundle.RustTarget)
			fmt.Fprintf(&script, "cp /work/build-target/%s/release/examples/crc_probe /work/out/crc_probe\n", machine.Bundle.RustTarget)
		}
	}
	script.WriteString("cd /work/out && sha256sum * && file *\n")
	return script.String()
}

func describeTree(ctx context.Context, path string) Tree {
	tree := Tree{Path: path}
	if path == "" {
		return tree
	}
	if output, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "HEAD").Output(); err == nil {
		tree.GitSHA = strings.TrimSpace(string(output))
	}
	if output, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
		tree.Branch = strings.TrimSpace(string(output))
	}
	if output, err := exec.CommandContext(ctx, "git", "-C", path, "status", "--porcelain").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		tree.DirtyFiles = len(lines)
		if tree.DirtyFiles > 0 {
			tree.Note = "working tree is dirty; the commit id alone does not identify this build"
		}
	}
	return tree
}

// snapshotTree copies a source tree without build output, so a container build
// starts from exactly the tree the operator is measuring.
func snapshotTree(ctx context.Context, source, destination string) error {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	pack := exec.CommandContext(ctx, "tar", "-cf", "-",
		"--exclude", "./target", "--exclude", "./.git", "--exclude", "./build",
		"-C", source, ".")
	pack.Env = append(os.Environ(), "COPYFILE_DISABLE=1")
	pipe, err := pack.StdoutPipe()
	if err != nil {
		return err
	}
	unpack := exec.CommandContext(ctx, "tar", "-xf", "-", "-C", destination)
	unpack.Stdin = pipe
	unpack.Stderr = os.Stderr
	if err := pack.Start(); err != nil {
		return err
	}
	if err := unpack.Start(); err != nil {
		_ = pack.Process.Kill()
		return err
	}
	if err := unpack.Wait(); err != nil {
		return err
	}
	return pack.Wait()
}

func copyTree(source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		from := filepath.Join(source, entry.Name())
		to := filepath.Join(destination, entry.Name())
		if entry.IsDir() {
			if err := copyTree(from, to); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(from, to); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(source, destination string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func readJSONFile(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func sortedKeys[Value any](source map[string]Value) []string {
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
