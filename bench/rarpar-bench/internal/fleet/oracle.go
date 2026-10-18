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
// Standing rule: the benches use what the vendor provides. The official-binary
// policy fetches a pinned release asset and verifies its digest. source-build
// exists only where the vendor publishes no binary for the platform, records
// why, and builds on the host itself at run start, never on the orchestrator
// and never in a container:
//   - unrar-portable-onhost, on Linux arm64 only: RARLAB's download page has
//     no Linux arm64 UnRAR, and the only Linux ARM build on its extras page,
//     unrar-5.5.0-arm.gz, is UnRAR 5.5.0 for 32-bit armhf (dynamically linked
//     against /lib/ld-linux-armhf.so.3). The pinned source tarball ships in the
//     bundle and `rarpar-bench fleet build-unrar` builds it with the audited
//     portable recipe: stock makefile, CXXFLAGS and LDFLAGS, CXX=g++, linked
//     against the host's glibc, and no -march/-mcpu/-mtune.
//   - par3cmdline-onhost: par3cmdline publishes no release and no Linux
//     binary; the tree ships only windows/par3.exe, which Windows hosts use
//     as an official binary.
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
			name := oracleBinaryName(machine, role, oracle)
			local := filepath.Join(bundleDir, name)
			digest, err := materializeOfficialBinary(ctx, oracle, cacheDir, local, allowFetch)
			if err != nil {
				return nil, fmt.Errorf("machine %s: oracle %s: %w", machine.Name, role, err)
			}
			resolution.RemotePath = hostJoin(machine, layout.Bin, name)
			resolution.SHA256 = digest
			resolution.Origin = "official release asset " + oracle.URL
		case OracleSourceBuild:
			// Built on the host by the run script itself. The UnRAR recipe
			// ships its sha256-verified source tarball in the bundle; the
			// par3cmdline one ships only the toolchain lock that pins its
			// source.
			if oracle.Recipe == RecipeUnrarHost {
				archive, err := cachedDownload(ctx, oracle.URL, oracle.SHA256, cacheDir, allowFetch)
				if err != nil {
					return nil, fmt.Errorf("machine %s: oracle %s: %w", machine.Name, role, err)
				}
				if err := copyFileMode(archive, filepath.Join(bundleDir, unrarSourceName), 0o644); err != nil {
					return nil, fmt.Errorf("machine %s: oracle %s: staging the UnRAR source: %w", machine.Name, role, err)
				}
			}
			resolution = sourceBuildResolution(machine, role, oracle, layout)
		}
		resolutions[role] = resolution
	}
	return resolutions, nil
}

func oracleBinaryName(machine Machine, role string, oracle Oracle) string {
	if oracle.ArchiveMember != "" {
		return posixBase(oracle.ArchiveMember)
	}
	name := map[string]string{"rar": "unrar", "par2": "par2", "par3": "par3"}[role]
	if machine.isWindows() {
		name += ".exe"
	}
	return name
}

// sourceBuildResolution describes a source-built oracle without building it.
// Both recipes build on the host during the run, at the path their builder
// produces: `rarpar-bench par3 build-reference` for par3cmdline-onhost,
// `rarpar-bench fleet build-unrar` for unrar-portable-onhost.
func sourceBuildResolution(machine Machine, role string, oracle Oracle, layout RemoteLayout) OracleResolution {
	resolution := OracleResolution{Role: role, Policy: oracle.Policy, Note: oracle.Reason}
	switch oracle.Recipe {
	case RecipePAR3CmdlineHost:
		resolution.RemotePath = hostJoin(machine, par3ReferenceDir(machine, layout), "build", "par3cmd", oracleBinaryName(machine, role, oracle))
		resolution.Origin = "on-host source build (" + oracle.Recipe + ") of the par3cmdline commit rarpar-bench pins (internal/par3bench/reference.go)"
	case RecipeUnrarHost:
		resolution.RemotePath = hostJoin(machine, unrarReferenceDir(machine, layout), unrarBinaryName)
		resolution.SHA256 = oracle.BinarySHA256
		resolution.Origin = "on-host audited portable source build (" + oracle.Recipe + ") of " + oracle.URL + ", source sha256 " + oracle.SHA256
	}
	return resolution
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
