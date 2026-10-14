package fleet

// Release bundles. The rarpar a measured round runs is the published release
// artifact for each host's platform, never a binary built for the round. The
// orchestrator downloads the asset and the release's SHA256SUMS from GitHub,
// checks the asset's sha256 against it, unpacks the binary and stages it where
// the bundle layout expects rarpar. All of that happens before preflight, so
// a release that lacks the asset or its SHA256SUMS, or whose bytes do not
// match, stops the round before any credential check, host probe or launch.
//
// SHA256SUMS is fetched fresh on every run. Each (tag, platform) asset is
// downloaded once into the run's release cache, however many machines share
// it, and a cached copy is re-hashed against SHA256SUMS before it is reused.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Linux release flavors. Darwin and Windows publish one build per
// architecture.
const (
	FlavorMuslDirect = "musl-direct"
	FlavorGNUDirect  = "gnu-direct"
)

const (
	releaseRepository = "scryer-media/rarpar"
	releaseSumsName   = "SHA256SUMS"
	releaseCacheDir   = "release-cache"

	// Ceilings on what one download or one unpacked member may write. The
	// published assets are a few megabytes; these only stop a broken or
	// hostile response from filling the disk.
	maxReleaseAssetBytes  = 512 << 20
	maxReleaseSumsBytes   = 1 << 20
	maxReleaseBinaryBytes = 512 << 20
)

// releaseBaseURL is where release assets download from. Tests point it at a
// local server; nothing else changes it.
var releaseBaseURL = "https://github.com/" + releaseRepository + "/releases"

// releaseTagPattern is the shape of a rarpar release tag. The tag becomes a
// URL path segment and a cache directory name, so nothing else is accepted.
var releaseTagPattern = regexp.MustCompile(`^rarpar-v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

// releasePlatform is one published build: the platform part of the asset
// name, the Rust target it was built for, its archive format and the binary
// it carries.
type releasePlatform struct {
	Name       string
	RustTarget string
	Archive    string
	Binary     string
}

// resolveReleasePlatform maps a bundle's go_os, go_arch and flavor onto the
// build the rarpar release workflow publishes for that platform.
func resolveReleasePlatform(bundle Bundle) (releasePlatform, error) {
	var arch, rustArch string
	switch bundle.GoArch {
	case "amd64":
		arch, rustArch = "x86_64", "x86_64"
	case "arm64":
		arch, rustArch = "arm64", "aarch64"
	case "":
		return releasePlatform{}, errors.New("bundle.go_arch is required to pick the release asset (amd64 or arm64)")
	default:
		return releasePlatform{}, fmt.Errorf("bundle.go_arch = %q has no rarpar release asset; releases are published for amd64 and arm64", bundle.GoArch)
	}
	switch bundle.GoOS {
	case "linux":
		flavor := bundle.Flavor
		if flavor == "" {
			flavor = FlavorMuslDirect
		}
		var libc string
		switch flavor {
		case FlavorMuslDirect:
			libc = "musl"
		case FlavorGNUDirect:
			libc = "gnu"
		default:
			return releasePlatform{}, fmt.Errorf("bundle.flavor must be %q (the default) or %q, got %q", FlavorMuslDirect, FlavorGNUDirect, flavor)
		}
		return releasePlatform{
			Name:       "linux-" + arch + "-" + flavor,
			RustTarget: rustArch + "-unknown-linux-" + libc,
			Archive:    "tar.gz",
			Binary:     "rarpar",
		}, nil
	case "darwin", "windows":
		if bundle.Flavor != "" {
			return releasePlatform{}, fmt.Errorf("bundle.flavor only applies to linux release assets; %s publishes one build per architecture", bundle.GoOS)
		}
		if bundle.GoOS == "darwin" {
			return releasePlatform{Name: "darwin-" + arch, RustTarget: rustArch + "-apple-darwin", Archive: "tar.gz", Binary: "rarpar"}, nil
		}
		return releasePlatform{Name: "windows-" + arch, RustTarget: rustArch + "-pc-windows-msvc", Archive: "zip", Binary: "rarpar.exe"}, nil
	default:
		return releasePlatform{}, fmt.Errorf("bundle.go_os = %q has no rarpar release asset; releases are published for linux, darwin and windows", bundle.GoOS)
	}
}

// releaseAssetName is the file the release workflow uploads for a platform.
func releaseAssetName(tag string, platform releasePlatform) string {
	return "rarpar-" + tag + "-" + platform.Name + "." + platform.Archive
}

// releaseKey identifies one staged release binary.
func releaseKey(tag, platformName string) string {
	return tag + "/" + platformName
}

func releaseAssetURL(tag, asset string) string {
	return releaseBaseURL + "/download/" + tag + "/" + asset
}

func releasePageURL(tag string) string {
	return releaseBaseURL + "/tag/" + tag
}

// ReleaseArtifact is the provenance of one staged release binary, recorded in
// the run state and in BUILDINFO.json: which release and asset, the digests
// that were checked, and the binary that came out of the asset.
type ReleaseArtifact struct {
	Repository   string `json:"repository"`
	Tag          string `json:"tag"`
	ReleaseURL   string `json:"release_url"`
	Platform     string `json:"platform"`
	RustTarget   string `json:"rust_target"`
	Asset        string `json:"asset"`
	AssetURL     string `json:"asset_url"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	SumsURL      string `json:"sha256sums_url"`
	SumsSHA256   string `json:"sha256sums_sha256"`
	Binary       string `json:"binary"`
	BinarySHA256 string `json:"binary_sha256"`
	BinarySize   int64  `json:"binary_size"`

	// binaryPath is the unpacked binary in the release cache.
	binaryPath string
}

// parseSHA256Sums reads a sha256sum manifest: one "<sha256>  <file>" line per
// asset ("<sha256> *<file>" in binary mode). A line in any other shape is an
// error rather than skipped, so a damaged manifest cannot quietly drop the
// asset being checked.
func parseSHA256Sums(data []byte) (map[string]string, error) {
	digests := map[string]string{}
	for index, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		digest, rest, found := strings.Cut(line, " ")
		if !found || len(digest) != sha256.Size*2 || !(strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "*")) {
			return nil, fmt.Errorf("line %d is not a \"<sha256>  <file>\" entry", index+1)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("line %d: %q is not a hex sha256", index+1, digest)
		}
		name := rest[1:]
		if name == "" || strings.TrimSpace(name) != name || strings.ContainsAny(name, `/\`) {
			return nil, fmt.Errorf("line %d: %q is not a release asset name", index+1, name)
		}
		if _, duplicate := digests[name]; duplicate {
			return nil, fmt.Errorf("line %d lists %s a second time", index+1, name)
		}
		digests[name] = strings.ToLower(digest)
	}
	if len(digests) == 0 {
		return nil, errors.New("the manifest lists no assets")
	}
	return digests, nil
}

// githubOnlyRedirect keeps a download on GitHub. Release downloads redirect
// from github.com to GitHub's own asset host; any other destination is
// refused. Only the scheme and host are reported: the redirect URL carries a
// signed query string.
func githubOnlyRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	host := request.URL.Hostname()
	if request.URL.Scheme != "https" || (host != "github.com" && !strings.HasSuffix(host, ".githubusercontent.com")) {
		return fmt.Errorf("refusing a redirect off GitHub to %s://%s", request.URL.Scheme, request.URL.Host)
	}
	return nil
}

// releaseResolver downloads and verifies release assets for one run.
type releaseResolver struct {
	cacheDir string
	client   *http.Client
	log      func(format string, args ...any)
	sums     map[string]*releaseSums
	resolved map[string]*ReleaseArtifact
}

// releaseSums is one release's parsed SHA256SUMS.
type releaseSums struct {
	url     string
	sha256  string
	digests map[string]string
}

func newReleaseResolver(cacheDir string, log func(format string, args ...any)) *releaseResolver {
	return &releaseResolver{
		cacheDir: cacheDir,
		client:   &http.Client{Timeout: 10 * time.Minute, CheckRedirect: githubOnlyRedirect},
		log:      log,
		sums:     map[string]*releaseSums{},
		resolved: map[string]*ReleaseArtifact{},
	}
}

func (resolver *releaseResolver) logf(format string, args ...any) {
	if resolver.log != nil {
		resolver.log(format, args...)
	}
}

// resolve returns the verified, unpacked release binary for a bundle.
func (resolver *releaseResolver) resolve(ctx context.Context, bundle Bundle) (*ReleaseArtifact, error) {
	tag := bundle.releaseTag()
	if !releaseTagPattern.MatchString(tag) {
		return nil, fmt.Errorf("%q is not a rarpar release tag (rarpar-vMAJOR.MINOR.PATCH)", tag)
	}
	platform, err := resolveReleasePlatform(bundle)
	if err != nil {
		return nil, err
	}
	key := releaseKey(tag, platform.Name)
	if artifact, ok := resolver.resolved[key]; ok {
		return artifact, nil
	}
	sums, err := resolver.loadSums(ctx, tag)
	if err != nil {
		return nil, err
	}
	asset := releaseAssetName(tag, platform)
	want, ok := sums.digests[asset]
	if !ok {
		return nil, fmt.Errorf("release %s: %s does not list %s; the release has no %s build", tag, sums.url, asset, platform.Name)
	}
	dir := filepath.Join(resolver.cacheDir, tag, platform.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	assetURL := releaseAssetURL(tag, asset)
	archive := filepath.Join(dir, asset)
	size, err := resolver.fetchAsset(ctx, assetURL, archive, want)
	if err != nil {
		return nil, fmt.Errorf("release %s: %w", tag, err)
	}
	binary := filepath.Join(dir, platform.Binary)
	if err := extractReleaseBinary(archive, platform, binary); err != nil {
		return nil, fmt.Errorf("release %s: unpacking %s: %w", tag, asset, err)
	}
	binaryDigest, binarySize, err := fileDigestAndSize(binary)
	if err != nil {
		return nil, err
	}
	artifact := &ReleaseArtifact{
		Repository:   releaseRepository,
		Tag:          tag,
		ReleaseURL:   releasePageURL(tag),
		Platform:     platform.Name,
		RustTarget:   platform.RustTarget,
		Asset:        asset,
		AssetURL:     assetURL,
		Size:         size,
		SHA256:       want,
		SumsURL:      sums.url,
		SumsSHA256:   sums.sha256,
		Binary:       platform.Binary,
		BinarySHA256: binaryDigest,
		BinarySize:   binarySize,
		binaryPath:   binary,
	}
	resolver.resolved[key] = artifact
	resolver.logf("release: %s verified against %s (sha256 %s, %d bytes); %s unpacked (sha256 %s, %d bytes)",
		asset, releaseSumsName, want, size, platform.Binary, binaryDigest, binarySize)
	return artifact, nil
}

// loadSums fetches and parses a release's SHA256SUMS once per run, and keeps
// a copy next to the assets it vouches for.
func (resolver *releaseResolver) loadSums(ctx context.Context, tag string) (*releaseSums, error) {
	if sums, ok := resolver.sums[tag]; ok {
		return sums, nil
	}
	address := releaseAssetURL(tag, releaseSumsName)
	body, err := resolver.open(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("release %s: %w", tag, err)
	}
	data, err := io.ReadAll(io.LimitReader(body, maxReleaseSumsBytes+1))
	body.Close()
	if err != nil {
		return nil, fmt.Errorf("release %s: reading %s: %w", tag, address, err)
	}
	if len(data) > maxReleaseSumsBytes {
		return nil, fmt.Errorf("release %s: %s is larger than %d bytes", tag, address, maxReleaseSumsBytes)
	}
	digests, err := parseSHA256Sums(data)
	if err != nil {
		return nil, fmt.Errorf("release %s: %s: %w", tag, address, err)
	}
	sum := sha256.Sum256(data)
	sums := &releaseSums{url: address, sha256: hex.EncodeToString(sum[:]), digests: digests}
	dir := filepath.Join(resolver.cacheDir, tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, releaseSumsName), data, 0o644); err != nil {
		return nil, err
	}
	resolver.sums[tag] = sums
	resolver.logf("release: %s fetched from %s (%d assets, sha256 %s)", releaseSumsName, address, len(digests), sums.sha256)
	return sums, nil
}

func (resolver *releaseResolver) open(ctx context.Context, address string) (io.ReadCloser, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	response, err := resolver.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", address, err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("fetch %s: HTTP %s", address, response.Status)
	}
	return response.Body, nil
}

// fetchAsset makes path hold the asset whose sha256 SHA256SUMS lists. A cached
// copy is re-hashed rather than trusted. A download is hashed as it streams
// and only renamed into place once it matches.
func (resolver *releaseResolver) fetchAsset(ctx context.Context, address, path, want string) (int64, error) {
	name := filepath.Base(path)
	if _, err := os.Stat(path); err == nil {
		got, size, err := fileDigestAndSize(path)
		if err != nil {
			return 0, err
		}
		if got != want {
			return 0, fmt.Errorf("cached %s has sha256 %s but %s lists %s; delete it and re-run", path, got, releaseSumsName, want)
		}
		resolver.logf("release: %s reused from the release cache (sha256 matches %s)", name, releaseSumsName)
		return size, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	body, err := resolver.open(ctx, address)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	partial := path + ".part"
	file, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	digest := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(body, maxReleaseAssetBytes+1))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil && size > maxReleaseAssetBytes {
		err = fmt.Errorf("larger than %d bytes", maxReleaseAssetBytes)
	}
	if err != nil {
		_ = os.Remove(partial)
		return 0, fmt.Errorf("downloading %s: %w", address, err)
	}
	if got := hex.EncodeToString(digest.Sum(nil)); got != want {
		_ = os.Remove(partial)
		return 0, fmt.Errorf("downloaded %s has sha256 %s but %s lists %s; refusing it", name, got, releaseSumsName, want)
	}
	if err := os.Rename(partial, path); err != nil {
		_ = os.Remove(partial)
		return 0, err
	}
	return size, nil
}

// extractReleaseBinary writes the release binary from a verified archive to
// destination. Only the binary at the archive root is taken: the tarballs
// also carry share/bash-completion/completions/rarpar, which must not be
// mistaken for it. Every member name is still checked to stay inside the
// destination directory, and a root binary that is a link, or that appears
// twice, is refused.
func extractReleaseBinary(archive string, platform releasePlatform, destination string) error {
	partial := destination + ".part"
	defer os.Remove(partial)
	var err error
	switch platform.Archive {
	case "tar.gz":
		err = extractReleaseTar(archive, platform.Binary, partial)
	case "zip":
		err = extractReleaseZip(archive, platform.Binary, partial)
	default:
		err = fmt.Errorf("unknown archive format %q", platform.Archive)
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(partial, 0o755); err != nil {
		return err
	}
	return os.Rename(partial, destination)
}

// releaseEntryName is an archive member's name relative to the archive root,
// with "./" prefixes and Windows separators normalised away.
func releaseEntryName(raw string) string {
	name := strings.ReplaceAll(raw, `\`, "/")
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	return name
}

func extractReleaseTar(archive, binary, destination string) error {
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
	root := filepath.Dir(destination)
	found := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if _, err := containedPath(root, header.Name); err != nil {
			return err
		}
		if releaseEntryName(header.Name) != binary {
			continue
		}
		if found {
			return fmt.Errorf("the archive carries %s more than once", binary)
		}
		found = true
		if header.Typeflag != tar.TypeReg {
			return fmt.Errorf("%s in the archive is not a regular file", binary)
		}
		if header.Size > maxReleaseBinaryBytes {
			return fmt.Errorf("%s in the archive is %d bytes, over the %d-byte ceiling", binary, header.Size, maxReleaseBinaryBytes)
		}
		if err := writeReleaseMember(destination, reader, header.Size); err != nil {
			return fmt.Errorf("%s: %w", binary, err)
		}
	}
	if !found {
		return fmt.Errorf("the archive has no %s at its root", binary)
	}
	return nil
}

func extractReleaseZip(archive, binary, destination string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer reader.Close()
	root := filepath.Dir(destination)
	var member *zip.File
	for _, file := range reader.File {
		if _, err := containedPath(root, file.Name); err != nil {
			return err
		}
		if releaseEntryName(file.Name) != binary {
			continue
		}
		if member != nil {
			return fmt.Errorf("the archive carries %s more than once", binary)
		}
		member = file
	}
	if member == nil {
		return fmt.Errorf("the archive has no %s at its root", binary)
	}
	if !member.Mode().IsRegular() {
		return fmt.Errorf("%s in the archive is not a regular file", binary)
	}
	if member.UncompressedSize64 > maxReleaseBinaryBytes {
		return fmt.Errorf("%s in the archive is %d bytes, over the %d-byte ceiling", binary, member.UncompressedSize64, maxReleaseBinaryBytes)
	}
	source, err := member.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	// Reading the member to its end is what makes archive/zip check its
	// CRC-32 and size.
	if err := writeReleaseMember(destination, source, int64(member.UncompressedSize64)); err != nil {
		return fmt.Errorf("%s: %w", binary, err)
	}
	return nil
}

// writeReleaseMember copies one archive member to destination and refuses a
// member that is shorter or longer than its header says.
func writeReleaseMember(destination string, source io.Reader, size int64) error {
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	written, err := io.Copy(file, io.LimitReader(source, maxReleaseBinaryBytes+1))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if written != size {
		return fmt.Errorf("member holds %d bytes but its header says %d", written, size)
	}
	return nil
}

func fileDigestAndSize(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

// resolveReleases downloads, verifies and unpacks the release asset of every
// release-bundle machine. It runs on the orchestrator before preflight, so a
// release that lacks the asset or its SHA256SUMS, or whose bytes do not
// match, stops the round before any credential check, host probe or launch.
func (orch *orchestrator) resolveReleases(ctx context.Context) error {
	resolver := newReleaseResolver(filepath.Join(orch.runDir, releaseCacheDir), orch.log)
	orch.releases = map[string]*ReleaseArtifact{}
	for _, machine := range orch.options.Machines {
		if machine.Bundle.Source != BundleRelease {
			continue
		}
		artifact, err := resolver.resolve(ctx, machine.Bundle)
		if err != nil {
			return fmt.Errorf("machine %s: %w", machine.Name, err)
		}
		orch.releases[releaseKey(artifact.Tag, artifact.Platform)] = artifact
		hostState := orch.state.Machine(machine.Name)
		hostState.Release = artifact
		orch.state.Record(hostState, "release", "%s %s (%d bytes) sha256 %s verified against %s",
			artifact.Tag, artifact.Asset, artifact.Size, artifact.SHA256, artifact.SumsURL)
	}
	return nil
}
