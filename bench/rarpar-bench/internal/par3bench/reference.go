package par3bench

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zeebo/blake3"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// macOSPatch is the bench-only macOS port of the pinned par3cmdline commit.
// See the header of the patch file for what it changes and why.
//
//go:embed patches/par3cmdline-2971702e-macos.patch
var macOSPatch []byte

// macOSPatchCommit is the only par3cmdline commit the patch applies to.
const macOSPatchCommit = "2971702e501f1350b1c7b9d11369af9157d6ed56"

// sse2neon pins the header Leopard's ARM path includes. It is fetched at
// build time and checked against both digests, not vendored.
var sse2neon = struct {
	URL, SHA256, BLAKE3 string
}{
	URL:    "https://raw.githubusercontent.com/DLTcollab/sse2neon/60fc9391e378b58c60899791c0e9ee9cdaf43c08/sse2neon.h",
	SHA256: "0624a1270fc88a67e6b886cd0e33e322d93de4b3a760b3373dc3a66e713bd43f",
	BLAKE3: "94d6cb6973948737957dc2e8bb3e48bb7cf3a0ef710891aec8b348a0ca8ef169",
}

// ReferenceBuildOptions configures `par3 build-reference`.
type ReferenceBuildOptions struct {
	Lock       bench.ToolchainLock
	Out        string
	Cache      string
	MirrorBase string
	CMake      string
	Jobs       int
	Log        io.Writer
}

// ReferenceBuild records how the reference binary was produced.
type ReferenceBuild struct {
	ID             string `json:"id"`
	ArchiveURL     string `json:"archive_url"`
	ArchiveBLAKE3  string `json:"archive_blake3"`
	ArchiveOrigin  string `json:"archive_origin"`
	Patch          string `json:"patch,omitempty"`
	PatchSHA256    string `json:"patch_sha256,omitempty"`
	SSE2NEONURL    string `json:"sse2neon_url,omitempty"`
	SSE2NEONSHA256 string `json:"sse2neon_sha256,omitempty"`
	CMakeVersion   string `json:"cmake_version"`
	Binary         string `json:"binary"`
	BinarySHA256   string `json:"binary_sha256"`
	BuiltUTC       string `json:"built_utc"`
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
}

func (o ReferenceBuildOptions) logf(format string, args ...any) {
	if o.Log != nil {
		fmt.Fprintf(o.Log, "par3 build-reference: "+format+"\n", args...)
	}
}

// BuildReference resolves the pinned par3cmdline archive (mirror first, then
// the official URL, BLAKE3-verified either way), applies the macOS port on
// macOS only, and builds it with CMake in Release mode.
func BuildReference(ctx context.Context, options ReferenceBuildOptions) (ReferenceBuild, error) {
	generator := options.Lock.PAR3Generator
	source, err := bench.PAR3ArchiveSource(generator)
	if err != nil {
		return ReferenceBuild{}, err
	}
	if options.CMake == "" {
		options.CMake = "cmake"
	}
	if options.Jobs <= 0 {
		options.Jobs = runtime.NumCPU()
	}
	out, err := filepath.Abs(options.Out)
	if err != nil {
		return ReferenceBuild{}, err
	}
	cmakeVersion, err := exec.CommandContext(ctx, options.CMake, "--version").Output()
	if err != nil {
		return ReferenceBuild{}, fmt.Errorf("cmake is required to build the reference (%s --version: %v)", options.CMake, err)
	}
	mirror := &bench.SourceMirror{BaseURL: options.MirrorBase, Log: options.Log}
	resolved, err := mirror.Resolve(ctx, source, options.Cache)
	if err != nil {
		return ReferenceBuild{}, fmt.Errorf("resolve %s: %w", source.Name, err)
	}
	options.logf("archive %s from %s", source.Name, resolved.Origin)

	srcRoot := filepath.Join(out, "src")
	buildDir := filepath.Join(out, "build")
	for _, dir := range []string{srcRoot, buildDir} {
		if err := os.RemoveAll(dir); err != nil {
			return ReferenceBuild{}, err
		}
	}
	if err := extractTarGz(resolved.Path, srcRoot, 1); err != nil {
		return ReferenceBuild{}, fmt.Errorf("extract %s: %w", source.Name, err)
	}

	build := ReferenceBuild{
		ID: generator.ID, ArchiveURL: generator.URL, ArchiveBLAKE3: generator.BLAKE3, ArchiveOrigin: resolved.Origin,
		CMakeVersion: firstLine(string(cmakeVersion)), BuiltUTC: time.Now().UTC().Format(time.RFC3339),
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}
	configure := []string{"-D", "CMAKE_BUILD_TYPE=Release", "-S", filepath.Join(srcRoot, "src"), "-B", buildDir}
	// The port patch is also what builds the reference on Linux arm64: it
	// keeps upstream's x86-only SIMD flags off non-x86 CPUs, and its Darwin
	// hunks are guarded, so the Linux code paths are unchanged.
	if portPatchApplies(runtime.GOOS, runtime.GOARCH) {
		if !strings.Contains(generator.URL, macOSPatchCommit) {
			return ReferenceBuild{}, fmt.Errorf("the macOS port patch is for par3cmdline %s; the lock pins %s — refresh the patch with the pin", macOSPatchCommit, generator.URL)
		}
		patchPath := filepath.Join(out, "par3cmdline-2971702e-macos.patch")
		if err := os.WriteFile(patchPath, macOSPatch, 0o644); err != nil {
			return ReferenceBuild{}, err
		}
		if err := runLogged(ctx, options, srcRoot, "patch", "-p1", "-N", "-i", patchPath); err != nil {
			return ReferenceBuild{}, fmt.Errorf("apply the macOS port patch: %w", err)
		}
		sum := sha256.Sum256(macOSPatch)
		build.Patch = filepath.Base(patchPath)
		build.PatchSHA256 = hex.EncodeToString(sum[:])
		options.logf("applied the bench-only port patch (sha256 %s)", build.PatchSHA256)
		if runtime.GOARCH == "arm64" {
			include := filepath.Join(srcRoot, "inc")
			if err := fetchPinned(ctx, sse2neon.URL, sse2neon.SHA256, sse2neon.BLAKE3, filepath.Join(include, "sse2neon", "sse2neon.h")); err != nil {
				return ReferenceBuild{}, fmt.Errorf("fetch sse2neon: %w", err)
			}
			build.SSE2NEONURL, build.SSE2NEONSHA256 = sse2neon.URL, sse2neon.SHA256
			configure = append(configure, "-D", "CMAKE_C_FLAGS=-I"+include, "-D", "CMAKE_CXX_FLAGS=-I"+include)
		}
	}
	if err := runLogged(ctx, options, srcRoot, options.CMake, configure...); err != nil {
		return ReferenceBuild{}, fmt.Errorf("cmake configure: %w", err)
	}
	if err := runLogged(ctx, options, srcRoot, options.CMake, "--build", buildDir, "--config", "Release", "-j", strconv.Itoa(options.Jobs)); err != nil {
		return ReferenceBuild{}, fmt.Errorf("cmake build: %w", err)
	}
	binary, err := findReferenceBinary(buildDir)
	if err != nil {
		return ReferenceBuild{}, err
	}
	digest, _, err := hashFile(binary)
	if err != nil {
		return ReferenceBuild{}, err
	}
	build.Binary, build.BinarySHA256 = binary, digest
	if err := writeJSONFile(filepath.Join(out, "reference.json"), build); err != nil {
		return ReferenceBuild{}, err
	}
	return build, nil
}

// portPatchApplies reports whether the bench-only port patch is applied:
// on macOS, and on Linux arm64, where upstream's x86 compile flags fail.
func portPatchApplies(goos, goarch string) bool {
	return goos == "darwin" || (goos == "linux" && goarch == "arm64")
}

// findReferenceBinary handles single-config generators (build/par3cmd/par3)
// and multi-config ones such as Visual Studio (build/par3cmd/Release/par3.exe).
func findReferenceBinary(buildDir string) (string, error) {
	name := "par3"
	if runtime.GOOS == "windows" {
		name = "par3.exe"
	}
	for _, candidate := range []string{
		filepath.Join(buildDir, "par3cmd", name),
		filepath.Join(buildDir, "par3cmd", "Release", name),
	} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no %s under %s/par3cmd after the build", name, buildDir)
}

func runLogged(ctx context.Context, options ReferenceBuildOptions, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if len(text) > 4000 {
			text = text[len(text)-4000:]
		}
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, text)
	}
	return nil
}

// fetchPinned downloads one file and refuses it unless both digests match.
func fetchPinned(ctx context.Context, url, wantSHA256, wantBLAKE3, destination string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return err
	}
	if err := verifyPinned(data, wantSHA256, wantBLAKE3); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0o644)
}

func verifyPinned(data []byte, wantSHA256, wantBLAKE3 string) error {
	shaSum := sha256.Sum256(data)
	if got := hex.EncodeToString(shaSum[:]); got != wantSHA256 {
		return fmt.Errorf("sha256 %s, want %s", got, wantSHA256)
	}
	b3 := blake3.Sum256(data)
	if got := hex.EncodeToString(b3[:]); got != wantBLAKE3 {
		return fmt.Errorf("blake3 %s, want %s", got, wantBLAKE3)
	}
	return nil
}

// extractTarGz unpacks a gzip tarball under root, dropping the first strip
// path components and refusing anything that would land outside root.
func extractTarGz(archive, root string, strip int) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		parts := strings.Split(strings.Trim(filepath.ToSlash(header.Name), "/"), "/")
		if len(parts) <= strip {
			continue
		}
		relative := filepath.FromSlash(strings.Join(parts[strip:], "/"))
		if !filepath.IsLocal(relative) {
			return fmt.Errorf("archive entry %q escapes the extraction root", header.Name)
		}
		target := filepath.Join(root, relative)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, io.LimitReader(reader, header.Size)); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		default:
			// Links and specials are not needed to build and are not followed.
		}
	}
}
