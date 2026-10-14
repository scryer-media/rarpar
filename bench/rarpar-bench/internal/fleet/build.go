package fleet

import (
	"bytes"
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
// build made from a dirty tree. Schema 2 records the published release a
// release bundle stages and drops the container build's image and build host.
type BuildInfo struct {
	SchemaVersion int               `json:"schema_version"`
	Bundle        string            `json:"bundle"`
	BuiltUTC      string            `json:"built_utc"`
	Machine       string            `json:"machine"`
	PlatformLabel string            `json:"platform_label"`
	BuildTarget   string            `json:"build_target"`
	Source        string            `json:"source"`
	Release       *ReleaseArtifact  `json:"release,omitempty"`
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
	// Releases holds the verified release binaries by releaseKey; release
	// bundles are staged from it and never fetch anything themselves.
	Releases map[string]*ReleaseArtifact
	Log      func(format string, args ...any)
}

func (bundler *Bundler) log(format string, args ...any) {
	if bundler.Log != nil {
		bundler.Log(format, args...)
	}
}

// SharedBuild stages the bundle for one bundle KEY: every machine whose bundle
// configuration and content needs are identical shares one staged bundle.
// Nothing here builds a candidate. A release bundle stages the verified
// release binary, a prebuilt bundle copies the operator's local bundle, and
// only the pure-Go harness is cross-compiled on the orchestrator.
func (bundler *Bundler) SharedBuild(ctx context.Context, sharedName string, rep Machine, machineNames []string) (string, BuildInfo, error) {
	target := filepath.Join(bundler.bundleRoot(), sharedName)
	// Assemble into a clean directory. A stale binary left over from an earlier
	// run would be shipped, hashed into BUILDINFO, and silently measured.
	if err := os.RemoveAll(target); err != nil {
		return "", BuildInfo{}, err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", BuildInfo{}, err
	}
	info := BuildInfo{
		SchemaVersion: 2,
		Bundle:        sharedName,
		BuiltUTC:      time.Now().UTC().Format(time.RFC3339),
		Machine:       strings.Join(machineNames, ","),
		PlatformLabel: BundlePrebuilt,
		BuildTarget:   rep.BuildTarget,
		Source:        rep.Bundle.Source,
		CodegenPolicy: map[string]string{},
		Trees:         map[string]Tree{},
		Binaries:      map[string]string{},
	}

	var release *ReleaseArtifact
	switch rep.Bundle.Source {
	case BundleRelease:
		artifact, err := bundler.release(rep.Bundle)
		if err != nil {
			return "", info, fmt.Errorf("bundle %s: %w", sharedName, err)
		}
		release = artifact
		info.PlatformLabel = artifact.Platform
		info.Release = artifact
		if err := copyFileMode(artifact.binaryPath, filepath.Join(target, artifact.Binary), 0o755); err != nil {
			return "", info, fmt.Errorf("bundle %s: staging %s from %s: %w", sharedName, artifact.Binary, artifact.Asset, err)
		}
		info.CodegenPolicy["rarpar"] = fmt.Sprintf("published release %s, asset %s (%s); sha256 verified against %s, not rebuilt",
			artifact.Tag, artifact.Asset, artifact.RustTarget, releaseSumsName)
		info.CodegenPolicy["go_flags"] = harnessGoFlags(rep.Bundle)
		info.Notes = append(info.Notes,
			fmt.Sprintf("rarpar is the published release binary from %s (%s, sha256 %s)", artifact.ReleaseURL, artifact.Asset, artifact.SHA256),
			"trees.rarpar is the checkout the Go harness was cross-compiled from, not the candidate's source")
		if err := bundler.buildHarness(ctx, sharedName, rep.Bundle, target); err != nil {
			return "", info, err
		}
	case BundlePrebuilt:
		if err := copyTree(rep.Bundle.Path, target); err != nil {
			return "", info, fmt.Errorf("bundle %s: staging the prebuilt bundle: %w", sharedName, err)
		}
		info.Notes = append(info.Notes,
			"prebuilt bundle staged from "+rep.Bundle.Path+" for a dev spot test, not the published release artifacts; its own BUILDINFO (if any) records the codegen policy")
	default:
		return "", info, fmt.Errorf("bundle %s: bundle.source %q is neither %q nor %q", sharedName, rep.Bundle.Source, BundleRelease, BundlePrebuilt)
	}
	if rep.hasTurbo() {
		// The turbo candidates are built on the host from git bundles of
		// their checkouts; see turbo.go.
		info.CodegenPolicy["turbo"] = "lzma-turbo/sevenz-turbo built on host with each checkout's pinned toolchain (rust-toolchain.toml); see turbo.go"
		if err := bundler.stageTurbo(ctx, rep, target, &info); err != nil {
			return "", info, fmt.Errorf("bundle %s: %w", sharedName, err)
		}
	}

	required := []string{"rarpar-bench"}
	if rep.needsCandidate() {
		required = append(required, "rarpar")
	}
	if rep.hasSuite(SuiteCRCProbe) {
		required = append(required, "crc_probe")
	}
	for _, source := range turboSources(bundler.Settings, rep) {
		required = append(required, source[1]+"-bench", source[1]+".bundle", source[1]+".commit")
	}
	for index, name := range required {
		// Windows bundles hold PE binaries; the names carry .exe.
		if rep.isWindows() {
			name += ".exe"
			required[index] = name
		}
		if _, err := os.Stat(filepath.Join(target, name)); err != nil {
			return "", info, fmt.Errorf("bundle %s: bundle is missing %s (suites %s need it)",
				sharedName, name, strings.Join(rep.Suites, ","))
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
	// The staged rarpar must be byte for byte the binary the verified asset
	// unpacked to.
	if release != nil && info.Binaries[release.Binary] != release.BinarySHA256 {
		return "", info, fmt.Errorf("bundle %s: staged %s has sha256 %s, but %s unpacked to %s",
			sharedName, release.Binary, info.Binaries[release.Binary], release.Asset, release.BinarySHA256)
	}
	info.Trees["rarpar"] = describeTree(ctx, bundler.rarparPath())
	// Only the weaver suites, which run from a prebuilt bundle, carry weaver
	// binaries.
	if rep.hasSuite(SuiteYencMicro) || rep.hasSuite(SuiteCRCProbe) {
		if bundler.Settings.WeaverPath != "" {
			info.Trees["weaver"] = describeTree(ctx, bundler.Settings.WeaverPath)
		}
		if bundler.Settings.RapidyencPath != "" {
			info.Trees["rapidyenc"] = describeTree(ctx, bundler.Settings.RapidyencPath)
		}
	}
	if err := writeJSONFile(filepath.Join(target, "BUILDINFO.json"), info); err != nil {
		return "", info, err
	}
	return target, info, nil
}

// Assemble stages one machine's bundle directory from a shared build. The
// binaries are copied (cheap); BUILDINFO identity and oracles stay
// per-machine.
func (bundler *Bundler) Assemble(machine Machine, sharedDir string, sharedInfo BuildInfo) (string, BuildInfo, error) {
	target := filepath.Join(bundler.bundleRoot(), machine.Name)
	if err := os.RemoveAll(target); err != nil {
		return "", BuildInfo{}, err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", BuildInfo{}, err
	}
	if err := copyTree(sharedDir, target); err != nil {
		return "", BuildInfo{}, fmt.Errorf("machine %s: staging from shared bundle %s: %w", machine.Name, sharedDir, err)
	}
	info := sharedInfo
	info.Bundle = machine.Name
	info.Machine = machine.Name
	info.PlatformLabel = machine.PlatformLabel
	info.BuildTarget = machine.BuildTarget
	info.Oracles = nil
	if len(machine.Oracles) > 0 {
		info.Oracles = machine.Oracles
	}
	if machine.hasSuite(SuiteMacroPAR3) {
		// The PAR3 suite reads the par3cmdline pin from the toolchain lock
		// (the on-host reference build resolves and verifies the source with
		// it); ship the orchestrator's copy so host and plan agree.
		lock := filepath.Join(bundler.rarparPath(), "bench", "rarpar-bench", "config", "toolchains.json")
		if err := copyFile(lock, filepath.Join(target, "toolchains.json")); err != nil {
			return "", info, fmt.Errorf("machine %s: staging config/toolchains.json: %w", machine.Name, err)
		}
		digest, err := fileSHA256(filepath.Join(target, "toolchains.json"))
		if err != nil {
			return "", info, err
		}
		info.Notes = append(info.Notes, "toolchains.json sha256 "+digest+" shipped for the PAR3 reference pin")
	}
	if err := writeJSONFile(filepath.Join(target, "BUILDINFO.json"), info); err != nil {
		return "", info, err
	}
	return target, info, nil
}

// buildKey groups machines whose bundles are content-identical: the same
// bundle configuration AND the same suite-driven bundle contents. One staged
// bundle serves the whole group.
func buildKey(machine Machine) string {
	bundle := machine.Bundle
	features := []string{}
	if machine.needsCandidate() {
		features = append(features, "rarpar")
	}
	if machine.hasSuite(SuiteMacroPAR3) {
		features = append(features, "par3")
	}
	if machine.hasSuite(SuiteYencMicro) {
		features = append(features, "yenc-micro")
	}
	if machine.hasSuite(SuiteCRCProbe) {
		features = append(features, "crc-probe")
	}
	if machine.hasSuite(SuiteLzmaTurbo) {
		features = append(features, "lzma-turbo")
	}
	if machine.hasSuite(SuiteSevenzTurbo) {
		features = append(features, "sevenz-turbo")
	}
	return strings.Join([]string{
		bundle.Source, bundle.Path, bundle.releaseTag(), bundlePlatform(bundle),
		bundle.GoOS, bundle.GoArch, bundle.GOAMD64,
		strings.Join(features, "+"),
	}, "|")
}

// bundlePlatform labels a bundle: the release platform a release bundle
// stages, or the bundle source.
func bundlePlatform(bundle Bundle) string {
	if bundle.Source == BundleRelease {
		if platform, err := resolveReleasePlatform(bundle); err == nil {
			return platform.Name
		}
	}
	return bundle.Source
}

// sharedBundleName is the stable directory name for one build key AND one
// harness tree. The tree digest is part of the name on purpose: two runs
// with identical bundle configuration but different checkouts must not
// assemble into the same directory, where one run's clean could delete the
// other's bundle and timing alone could ship the OTHER run's harness while
// BUILDINFO reports its own. Content-addressing the name closes both for
// different trees.
func sharedBundleName(machine Machine, treeID string) string {
	sum := sha256.Sum256([]byte(buildKey(machine) + "|tree=" + treeID))
	return "shared-" + bundlePlatform(machine.Bundle) + "-" + hex.EncodeToString(sum[:4])
}

// bundleTreeID content-digests the checkout the harness is cross-compiled
// from: every regular file's relative path and bytes, in sorted order, with
// VCS and build-output directories skipped. Unlike [`describeTree`] this
// needs no git metadata, so snapshot trees digest the same as checkouts.
func bundleTreeID(root string) (string, error) {
	digest := sha256.New()
	skip := map[string]bool{".git": true, "target": true, "results": true, "bundles": true}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if skip[entry.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("digesting candidate tree %s: %w", root, err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return "", err
		}
		digest.Write([]byte(relative))
		digest.Write([]byte{0})
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			digest.Write([]byte("->" + link))
			digest.Write([]byte{0})
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(digest, file)
		file.Close()
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(digest.Sum(nil)[:8]), nil
}

func (bundler *Bundler) bundleRoot() string {
	if bundler.Settings.BundleCache != "" {
		return bundler.Settings.BundleCache
	}
	return filepath.Join(bundler.RunDir, "bundles")
}

// release returns the verified release binary a release bundle stages. The
// orchestrator resolves every release before preflight; a miss here is a bug,
// never a reason to fetch.
func (bundler *Bundler) release(bundle Bundle) (*ReleaseArtifact, error) {
	platform, err := resolveReleasePlatform(bundle)
	if err != nil {
		return nil, err
	}
	artifact, ok := bundler.Releases[releaseKey(bundle.releaseTag(), platform.Name)]
	if !ok || artifact.binaryPath == "" {
		return nil, fmt.Errorf("release %s (%s) was not downloaded and verified before the build", bundle.releaseTag(), platform.Name)
	}
	return artifact, nil
}

func (bundler *Bundler) rarparPath() string {
	if bundler.Settings.RarparPath != "" {
		return bundler.Settings.RarparPath
	}
	return "."
}

// harnessBinary is the harness's file name in a bundle: a Windows host runs
// rarpar-bench.exe.
func harnessBinary(bundle Bundle) string {
	if bundle.GoOS == "windows" {
		return "rarpar-bench.exe"
	}
	return "rarpar-bench"
}

// harnessGoFlags records how buildHarness cross-compiles the harness.
func harnessGoFlags(bundle Bundle) string {
	flags := "CGO_ENABLED=0 GOOS=" + bundle.GoOS + " GOARCH=" + bundle.GoArch
	if bundle.GOAMD64 != "" {
		flags += " GOAMD64=" + bundle.GOAMD64
	}
	return flags + " -trimpath"
}

// buildHarness cross-compiles the pure-Go harness on the orchestrator. It is
// not a measured binary — CGO is off, output is byte-identical from any build
// host — so there is nothing an on-host build would add.
func (bundler *Bundler) buildHarness(ctx context.Context, bundleName string, bundle Bundle, outDir string) error {
	goBuild := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(outDir, harnessBinary(bundle)), "./cmd/rarpar-bench")
	goBuild.Dir = filepath.Join(bundler.rarparPath(), "bench", "rarpar-bench")
	goBuild.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+bundle.GoOS, "GOARCH="+bundle.GoArch)
	if bundle.GOAMD64 != "" {
		goBuild.Env = append(goBuild.Env, "GOAMD64="+bundle.GOAMD64)
	}
	goBuild.Stdout = os.Stderr
	goBuild.Stderr = os.Stderr
	if err := goBuild.Run(); err != nil {
		return fmt.Errorf("bundle %s: building the Go harness: %w", bundleName, err)
	}
	return nil
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
	// Windows PowerShell 5.1 writes UTF-8 with a BOM, which encoding/json
	// rejects; host evidence may carry one.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
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
