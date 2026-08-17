package bench

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// digestPattern is the lowercase 32-byte hex every archive digest in the lock
// has: BLAKE3 for the source archives, and the same shape the OCI `@sha256:`
// references below happen to use.
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// RequiredRARWriters is the complete shared writer set: the benchmark's
// historical writers (3.93, 4.20, 5.00), the writers the test corpus was
// generated with (6.24 for RAR4 and PPMd, 7.20 for the RAR5 sets), and the
// current benchmark RAR5 writer (7.23). Both corpus systems resolve their
// writers through this one lock, so every entry has to be present and pinned.
var RequiredRARWriters = []string{"rarlab-3.93", "rarlab-4.20", "rarlab-5.00", "rarlab-6.24", "rarlab-7.20", "rarlab-7.23"}

// rarWriterIDPattern is the writer id shape: the RARLAB release the archive
// really is, so the id can be checked against the source URL.
var rarWriterIDPattern = regexp.MustCompile(`^rarlab-([0-9]+)\.([0-9]{2})$`)

// rarWriterURLPattern is the only place a writer may come from: an https URL
// on RARLAB's own host, naming a tarball.
var rarWriterURLPattern = regexp.MustCompile(`^https://www\.rarlab\.com/rar/([A-Za-z0-9._-]+\.tar\.gz)$`)

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
	// Schema 2 is the BLAKE3 field set. Schema 1 pinned each archive by
	// SHA-256 under a `sha256` key, so it is a different contract, not an
	// older spelling of this one.
	if lock.SchemaVersion != 2 {
		return fmt.Errorf("unsupported toolchain schema version %d", lock.SchemaVersion)
	}
	// SHA-256 by specification: `@sha256:` is how an OCI reference pins an
	// image manifest, which is the registry's digest, not this lock's.
	if lock.DockerBase == "" || !regexp.MustCompile(`@sha256:[a-f0-9]{64}$`).MatchString(lock.DockerBase) {
		return fmt.Errorf("toolchain docker_base must be digest pinned")
	}
	seen := map[string]bool{}
	seenURL := map[string]bool{}
	seenDigest := map[string]bool{}
	seenImage := map[string]bool{}
	for _, writer := range lock.RARWriters {
		if writer.ID == "" || writer.Image == "" || writer.URL == "" || writer.Binary == "" || seen[writer.ID] {
			return fmt.Errorf("invalid or duplicate RAR writer %q", writer.ID)
		}
		if writer.Platform != "linux/amd64" || !digestPattern.MatchString(writer.BLAKE3) {
			return fmt.Errorf("RAR writer %q is not source locked for linux/amd64", writer.ID)
		}
		if err := writer.validateSource(); err != nil {
			return err
		}
		// Two writers sharing a URL, digest, or image tag would be one writer
		// under two names: the second could never be the release its id claims.
		if seenURL[writer.URL] || seenDigest[writer.BLAKE3] || seenImage[writer.Image] {
			return fmt.Errorf("RAR writer %q duplicates another writer's source or image", writer.ID)
		}
		seen[writer.ID] = true
		seenURL[writer.URL] = true
		seenDigest[writer.BLAKE3] = true
		seenImage[writer.Image] = true
	}
	for _, required := range RequiredRARWriters {
		if !seen[required] {
			return fmt.Errorf("missing required RAR writer %q", required)
		}
	}
	par2 := lock.PAR2Generator
	if par2.ID == "" || par2.Image == "" || par2.URL == "" || par2.Platform != "linux/amd64" || !digestPattern.MatchString(par2.BLAKE3) {
		return fmt.Errorf("PAR2 generator is not source locked for linux/amd64")
	}
	if encoder := lock.VideoEncoder; encoder.ID != "" || encoder.Image != "" {
		// The encoder is consumed as a published image, so the digest is the
		// only thing that makes its output reproducible; a floating tag would
		// silently re-encode the media payloads on some later pull.
		if encoder.ID == "" || encoder.Platform != "linux/amd64" || !digestPinnedImage(encoder.Image) {
			return fmt.Errorf("video encoder is not digest pinned for linux/amd64")
		}
	}
	return nil
}

// digestPinnedImage checks the OCI `@sha256:` reference form the registry
// specifies for a pulled image; the lock's own archive digests are BLAKE3.
func digestPinnedImage(image string) bool {
	return regexp.MustCompile(`@sha256:[a-f0-9]{64}$`).MatchString(image)
}

// validateSource rejects a floating writer: the id names a RARLAB release, and
// the URL has to be the versioned tarball for that very release on RARLAB's
// host, so a lock entry can never quietly point at "whatever RARLAB serves
// today". The digest pin catches a moved file after the fact; this catches an
// entry that was never pinned to a release to begin with.
func (writer RARWriter) validateSource() error {
	id := rarWriterIDPattern.FindStringSubmatch(writer.ID)
	if id == nil {
		return fmt.Errorf("RAR writer %q is not named rarlab-<major>.<minor>", writer.ID)
	}
	url := rarWriterURLPattern.FindStringSubmatch(writer.URL)
	if url == nil {
		return fmt.Errorf("RAR writer %q must be sourced from a versioned https://www.rarlab.com/rar/ tarball", writer.ID)
	}
	// RARLAB names its tarballs either "rarlinux-<major>.<minor>.<patch>" or
	// "rarlinux-x64-<major><minor>", so the release digits of the id must
	// appear, in order, in the file name with the dots removed: 3.93 in
	// rarlinux-3.9.3.tar.gz, 7.20 in rarlinux-x64-720.tar.gz.
	release := id[1] + id[2]
	name := strings.ReplaceAll(url[1], ".", "")
	if !strings.Contains(name, release) {
		return fmt.Errorf("RAR writer %q URL %s does not name release %s.%s", writer.ID, writer.URL, id[1], id[2])
	}
	return nil
}

// ArchiveName is the file name of the writer's original distribution archive.
func (writer RARWriter) ArchiveName() string {
	url := rarWriterURLPattern.FindStringSubmatch(writer.URL)
	if url == nil {
		return ""
	}
	return url[1]
}

func (lock ToolchainLock) Writer(id string) (RARWriter, bool) {
	for _, writer := range lock.RARWriters {
		if writer.ID == id {
			return writer, true
		}
	}
	return RARWriter{}, false
}

// BuildToolchains builds every generator image from archives that are already
// verified locally. Each archive is resolved — mirror first, official URL as
// the fallback — and checked against the reviewed digest before Docker is
// started, and the build context holds nothing but the checked-in Dockerfile
// and that archive, so no image build ever reaches upstream for its tool.
//
// `only`, when non-empty, restricts the build to those toolchain lock ids: one
// runner per generator has no use for the six writers and the par2 compile
// when its recipe drives one of them. An id the lock does not declare is an
// error, so a typo cannot quietly build nothing.
func BuildToolchains(ctx context.Context, docker, root string, lock ToolchainLock, mirror *SourceMirror, only []string) error {
	if err := verifyDockerfiles(root, lock.DockerBase); err != nil {
		return err
	}
	wanted, err := selectedToolchains(lock, only)
	if err != nil {
		return err
	}
	cacheDir := mirror.cacheDir()
	for _, writer := range lock.RARWriters {
		if wanted != nil && !wanted[writer.ID] {
			continue
		}
		source, err := WriterArchiveSource(writer)
		if err != nil {
			return err
		}
		resolved, err := mirror.Resolve(ctx, source, cacheDir)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", writer.ID, err)
		}
		args := []string{"--platform", writer.Platform, "--tag", writer.Image,
			"--build-arg", "RAR_BINARY=" + writer.Binary}
		if err := buildFromArchive(ctx, docker, filepath.Join(root, "docker/rarlab/Dockerfile"), resolved.Path, "rar.tar.gz", args); err != nil {
			return fmt.Errorf("build %s: %w", writer.ID, err)
		}
	}
	par2 := lock.PAR2Generator
	if wanted != nil && !wanted[par2.ID] {
		return nil
	}
	source, err := PAR2ArchiveSource(par2)
	if err != nil {
		return err
	}
	resolved, err := mirror.Resolve(ctx, source, cacheDir)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", par2.ID, err)
	}
	args := []string{"--platform", par2.Platform, "--tag", par2.Image}
	if err := buildFromArchive(ctx, docker, filepath.Join(root, "docker/par2/Dockerfile"), resolved.Path, "par2.tar.gz", args); err != nil {
		return fmt.Errorf("build %s: %w", par2.ID, err)
	}
	return nil
}

// selectedToolchains turns the requested lock ids into a membership set, or
// nil for "everything". The video encoder is a legal request and simply builds
// nothing: it is pulled by digest rather than built from a source archive.
func selectedToolchains(lock ToolchainLock, only []string) (map[string]bool, error) {
	if len(only) == 0 {
		return nil, nil
	}
	known := map[string]bool{lock.PAR2Generator.ID: true}
	if lock.VideoEncoder.ID != "" {
		known[lock.VideoEncoder.ID] = true
	}
	for _, writer := range lock.RARWriters {
		known[writer.ID] = true
	}
	wanted := map[string]bool{}
	for _, id := range only {
		if !known[id] {
			return nil, fmt.Errorf("toolchain %q is not in the lock", id)
		}
		wanted[id] = true
	}
	return wanted, nil
}

// buildFromArchive stages a throwaway build context — the checked-in Dockerfile
// and the verified archive under the name the Dockerfile copies — and builds it.
// Nothing else is in the context, so nothing else can end up in the image.
func buildFromArchive(ctx context.Context, docker, dockerfile, archive, archiveName string, args []string) error {
	stage, err := os.MkdirTemp("", "rarpar-bench-context-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	staged := filepath.Join(stage, "Dockerfile")
	if err := copyStagedFile(dockerfile, staged, 0o644); err != nil {
		return err
	}
	if err := copyStagedFile(archive, filepath.Join(stage, archiveName), 0o644); err != nil {
		return err
	}
	build := append([]string{"build"}, args...)
	build = append(build, "--file", staged, stage)
	return runCommand(ctx, docker, build...)
}

// dockerfileContract is what each generator Dockerfile has to say — and what it
// may no longer say. The archive arrives through the staged build context, so a
// Dockerfile that still fetches its own tool would bypass every digest and
// signature check the resolver performs.
var dockerfileContract = []struct{ path, staged string }{
	{"docker/rarlab/Dockerfile", "COPY rar.tar.gz"},
	{"docker/par2/Dockerfile", "COPY par2.tar.gz"},
}

var dockerfileForbidden = []string{"curl ", "wget ", "RAR_URL", "PAR2_URL", "RAR_SHA256", "PAR2_SHA256", "RAR_BLAKE3", "PAR2_BLAKE3"}

func verifyDockerfiles(root, base string) error {
	for _, contract := range dockerfileContract {
		relative, required := contract.path, contract.staged
		path := filepath.Join(root, relative)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		if !strings.Contains(text, "FROM "+base) {
			return fmt.Errorf("%s does not use source-locked Docker base %s", relative, base)
		}
		if !strings.Contains(text, required) {
			return fmt.Errorf("%s does not build from the staged archive (%s)", relative, required)
		}
		for _, forbidden := range dockerfileForbidden {
			if strings.Contains(text, forbidden) {
				return fmt.Errorf("%s downloads its own source (%q); the archive is staged into the build context instead", relative, strings.TrimSpace(forbidden))
			}
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

// runCommandStdout runs a command that streams payload bytes on stdout. Stderr
// is captured separately so diagnostics can never contaminate the byte stream.
func runCommandStdout(ctx context.Context, program string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, program, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w\n%s", program, args, err, stderr.Bytes())
	}
	return stdout.Bytes(), nil
}

func ToolchainIDs(lock ToolchainLock, caseConfig CaseConfig) []string {
	ids := []string{caseConfig.Writer}
	if caseConfig.PAR2 {
		ids = append(ids, lock.PAR2Generator.ID)
	}
	// A video payload's bytes come from the encoder, so the encoder belongs in
	// the case's recorded provenance alongside the archive writer.
	if videoProfiles[caseConfig.PayloadProfile] {
		ids = append(ids, lock.VideoEncoder.ID)
	}
	sort.Strings(ids)
	return ids
}
