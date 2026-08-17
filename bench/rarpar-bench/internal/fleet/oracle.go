package fleet

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// OracleResolution is where a machine's oracle binary will live at run time and
// how its identity was established.
type OracleResolution struct {
	Role       string `json:"role"`
	Policy     string `json:"policy"`
	RemotePath string `json:"remote_path"`
	SHA256     string `json:"sha256,omitempty"`
	Origin     string `json:"origin"`
	Note       string `json:"note,omitempty"`
}

// ResolveOracles decides, per machine, where each oracle comes from.
//
// Standing rule: never build an oracle where an official binary exists. The
// official-binary policy fetches a pinned release asset and verifies its digest;
// source-build exists only for platforms with no official binary (linux-arm
// unrar), uses an audited portable-flags recipe, and records why.
func ResolveOracles(ctx context.Context, machine Machine, bundleDir, cacheDir string, layout RemoteLayout, allowFetch bool) (map[string]OracleResolution, error) {
	resolutions := map[string]OracleResolution{}
	for _, role := range sortedKeys(machine.Oracles) {
		oracle := machine.Oracles[role]
		resolution := OracleResolution{Role: role, Policy: oracle.Policy}
		switch oracle.Policy {
		case OracleHostPath:
			// Already on the host: nothing is shipped, and preflight proves the
			// path exists (and matches sha256 when one is pinned) over SSH.
			resolution.RemotePath = oracle.Path
			resolution.SHA256 = oracle.BinarySHA256
			resolution.Origin = "preinstalled on the host: " + oracle.Path
		case OracleOfficialBinary:
			name := oracleBinaryName(role, oracle)
			local := filepath.Join(bundleDir, name)
			digest, err := materializeOfficialBinary(ctx, oracle, cacheDir, local, allowFetch)
			if err != nil {
				return nil, fmt.Errorf("machine %s: oracle %s: %w", machine.Name, role, err)
			}
			resolution.RemotePath = joinPosix(layout.Bin, name)
			resolution.SHA256 = digest
			resolution.Origin = "official release asset " + oracle.URL
		case OracleSourceBuild:
			name := oracleBinaryName(role, oracle)
			local := filepath.Join(bundleDir, name)
			digest, err := buildOracleFromSource(ctx, machine, oracle, cacheDir, local, allowFetch)
			if err != nil {
				return nil, fmt.Errorf("machine %s: oracle %s: %w", machine.Name, role, err)
			}
			resolution.RemotePath = joinPosix(layout.Bin, name)
			resolution.SHA256 = digest
			resolution.Origin = "source build (" + oracle.Recipe + ") from " + oracle.URL
			resolution.Note = oracle.Reason
		}
		resolutions[role] = resolution
	}
	return resolutions, nil
}

func oracleBinaryName(role string, oracle Oracle) string {
	if oracle.ArchiveMember != "" {
		return posixBase(oracle.ArchiveMember)
	}
	if role == "rar" {
		return "unrar"
	}
	return "par2"
}

func materializeOfficialBinary(ctx context.Context, oracle Oracle, cacheDir, destination string, allowFetch bool) (string, error) {
	archive, err := cachedDownload(ctx, oracle.URL, oracle.SHA256, cacheDir, allowFetch)
	if err != nil {
		return "", err
	}
	if err := extractMember(archive, oracle.ArchiveMember, destination); err != nil {
		return "", err
	}
	digest, err := fileSHA256(destination)
	if err != nil {
		return "", err
	}
	if oracle.BinarySHA256 != "" && digest != oracle.BinarySHA256 {
		return "", fmt.Errorf("extracted binary sha256 %s does not match the pinned binary_sha256 %s", digest, oracle.BinarySHA256)
	}
	return digest, nil
}

// cachedDownload returns a local path to a sha256-verified artifact. A cached
// copy is re-verified rather than trusted, and a digest mismatch is fatal.
func cachedDownload(ctx context.Context, url, sha256Hex, cacheDir string, allowFetch bool) (string, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(cacheDir, sha256Hex[:16]+"-"+posixBase(url))
	if _, err := os.Stat(path); err == nil {
		digest, hashErr := fileSHA256(path)
		if hashErr != nil {
			return "", hashErr
		}
		if digest == sha256Hex {
			return path, nil
		}
		return "", fmt.Errorf("cached artifact %s has sha256 %s, expected %s; delete it and re-run", path, digest, sha256Hex)
	}
	if !allowFetch {
		return "", fmt.Errorf("artifact %s is not in the oracle cache and fetching is disabled; pre-populate %s or allow the fetch", url, cacheDir)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %s", url, response.Status)
	}
	temporary := path + ".part"
	file, err := os.Create(temporary)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(file, response.Body); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	digest, err := fileSHA256(temporary)
	if err != nil {
		return "", err
	}
	if digest != sha256Hex {
		_ = os.Remove(temporary)
		return "", fmt.Errorf("downloaded %s has sha256 %s, expected %s", url, digest, sha256Hex)
	}
	return path, os.Rename(temporary, path)
}

func extractMember(archive, member, destination string) error {
	switch {
	case member == "":
		return copyFileMode(archive, destination, 0o755)
	case strings.HasSuffix(archive, ".zip"):
		return extractZipMember(archive, member, destination)
	case strings.HasSuffix(archive, ".tar.gz"), strings.HasSuffix(archive, ".tgz"):
		return extractTarMember(archive, member, destination)
	default:
		return copyFileMode(archive, destination, 0o755)
	}
}

func extractZipMember(archive, member, destination string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, file := range reader.File {
		if file.Name != member && posixBase(file.Name) != member {
			continue
		}
		source, err := file.Open()
		if err != nil {
			return err
		}
		defer source.Close()
		return writeExecutable(destination, source)
	}
	return fmt.Errorf("archive %s has no member %q", archive, member)
}

func extractTarMember(archive, member, destination string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	decompressed, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer decompressed.Close()
	reader := tar.NewReader(decompressed)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return fmt.Errorf("archive %s has no member %q", archive, member)
		}
		if err != nil {
			return err
		}
		if header.Name != member && posixBase(header.Name) != member {
			continue
		}
		return writeExecutable(destination, reader)
	}
}

func writeExecutable(destination string, source io.Reader) error {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, source); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func copyFileMode(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// buildOracleFromSource implements the audited portable-flags recipe. The whole
// point of the amendment that allows it is that the build adds no
// -march/-mcpu/-mtune of its own: an oracle compiled for the host it runs on
// would not be the oracle anyone else can reproduce.
func buildOracleFromSource(ctx context.Context, machine Machine, oracle Oracle, cacheDir, destination string, allowFetch bool) (string, error) {
	if oracle.Recipe != "unrar-portable" {
		return "", fmt.Errorf("unknown oracle recipe %q", oracle.Recipe)
	}
	archive, err := cachedDownload(ctx, oracle.URL, oracle.SHA256, cacheDir, allowFetch)
	if err != nil {
		return "", err
	}
	work, err := os.MkdirTemp(cacheDir, "unrar-src-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	if err := extractTarTree(archive, work); err != nil {
		return "", err
	}
	source := filepath.Join(work, "unrar")
	if _, err := os.Stat(source); err != nil {
		source = work
	}
	script := `#!/bin/sh
set -eu
apk add --no-cache build-base g++ make binutils >/dev/null 2>&1
cd /work/src
# Audit trail: the stock makefile must carry no target-cpu flag of its own.
# Comments are stripped first: unrar 7.2.3's stock makefile explains in a
# comment that upstream REMOVED -march=native, and matching that text made
# the guard refuse a makefile that carries no flag at all.
grep -vE '^[[:space:]]*#' makefile | grep -nE -- '-march|-mcpu|-mtune|native' && { echo "REFUSING: stock makefile carries a target-cpu flag"; exit 1; } || echo "flag audit: no -march/-mcpu/-mtune in the stock makefile (comments ignored)"
make clean >/dev/null 2>&1 || true
# Only CXX and a static link are set. Stock CXXFLAGS are used verbatim.
make CXX=g++ LDFLAGS="-pthread -static"
cp unrar /work/out/unrar
cd /work/out && sha256sum unrar && file unrar
`
	container := filepath.Join(cacheDir, "unrar-build")
	if err := os.RemoveAll(container); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(container, "out"), 0o755); err != nil {
		return "", err
	}
	if err := copyTree(source, filepath.Join(container, "src")); err != nil {
		return "", err
	}
	scriptPath := filepath.Join(container, "build.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		return "", err
	}
	image := machine.Bundle.Image
	if image == "" {
		image = "docker.io/library/rust:1.97-alpine"
	}
	command := exec.CommandContext(ctx, "docker", "run", "--rm", "-v", container+":/work", "-w", "/work", image, "sh", "/work/build.sh")
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("portable source build failed: %w", err)
	}
	if err := copyFileMode(filepath.Join(container, "out", "unrar"), destination, 0o755); err != nil {
		return "", err
	}
	digest, err := fileSHA256(destination)
	if err != nil {
		return "", err
	}
	if oracle.BinarySHA256 != "" && digest != oracle.BinarySHA256 {
		return "", fmt.Errorf("source-built oracle sha256 %s does not match the recorded binary_sha256 %s", digest, oracle.BinarySHA256)
	}
	return digest, nil
}

func extractTarTree(archive, destination string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	decompressed, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer decompressed.Close()
	reader := tar.NewReader(decompressed)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := containedPath(destination, header.Name)
		if err != nil {
			return fmt.Errorf("archive %s: %w", archive, err)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := writeExecutableMode(target, reader, os.FileMode(header.Mode).Perm()); err != nil {
				return err
			}
		}
	}
}

// containedPath resolves an archive entry name under destination and refuses
// anything that would land outside it: absolute names, volume-qualified names,
// NULs, and any `..` that survives cleaning. The containment check is done on
// the joined result with filepath.Rel, not by inspecting the name's prefix, so
// a traversal cannot be smuggled past it by any spelling.
func containedPath(destination, entryName string) (string, error) {
	if strings.ContainsRune(entryName, 0) {
		return "", fmt.Errorf("unsafe path %q: contains NUL", entryName)
	}
	// `..` anywhere in the raw name is refused outright, before any
	// resolution. The archives this extracts are the pinned toolchain
	// tarballs, whose well-formed entry names never contain dotdot in any
	// segment — so a name that does is a corrupt or hostile archive, not a
	// naming style to accommodate, and a refusal the reader can verify at a
	// glance beats a containment proof they have to trace. The resolved-path
	// checks below stay as the second and third proofs.
	if strings.Contains(entryName, "..") {
		return "", fmt.Errorf("unsafe path %q: contains '..'", entryName)
	}
	clean := filepath.Clean(filepath.FromSlash(entryName))
	if filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" {
		return "", fmt.Errorf("unsafe path %q: absolute", entryName)
	}
	root := filepath.Clean(destination)
	target := filepath.Join(root, clean)
	// Containment is checked on the resolved path itself: after Clean and
	// Join it must be the extraction directory or sit strictly under it.
	// The Rel check below proves the same thing a second way; two proofs of
	// containment cost nothing, and this one is the shape a reader (or a
	// static analyser) can confirm without modelling filepath.Rel.
	if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe path %q: escapes the extraction directory", entryName)
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe path %q: escapes the extraction directory", entryName)
	}
	return target, nil
}

func writeExecutableMode(destination string, source io.Reader, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o644
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, source); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
