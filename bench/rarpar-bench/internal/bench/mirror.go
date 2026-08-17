package bench

// The tool-source mirror.
//
// Every original distribution archive the toolchain lock pins — the six RARLAB
// tarballs and the par2cmdline-turbo source tarball — is resolved to a verified
// local file before anything is built from it. The mirror is a public,
// content-addressed object set on R2 whose keys are derived from the reviewed
// BLAKE3 digest, and it fails closed: an object that is present but does not
// verify is an error, never a cache miss. Only absence (HTTP 404) or
// retry-exhausted unavailability may fall back to the official URL, and that
// download must still match the reviewed digest before it is used.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultMirrorIdentity is the exact Sigstore identity every mirrored
	// object must carry: the protected publish workflow on main. It is matched
	// literally, never by regexp, so a fork or a workflow on another branch can
	// never satisfy it.
	DefaultMirrorIdentity = "https://github.com/scryer-media/rarpar/.github/workflows/test-corpus-publish.yml@refs/heads/main"
	// DefaultMirrorIssuer is the OIDC issuer that keyless GitHub signing uses.
	DefaultMirrorIssuer = "https://token.actions.githubusercontent.com"
)

// Archive kinds. The kind is a key segment, so it is a closed set rather than
// free text: an unknown kind would publish into a namespace nothing verifies.
const (
	ArchiveKindRARLAB = "rarlab"
	ArchiveKindPAR2   = "par2cmdline-turbo"
)

// Where a resolved archive came from.
const (
	OriginMirror   = "mirror"
	OriginOfficial = "official"
	OriginMirrored = "official+mirrored"
)

const (
	mirrorProvenanceSchemaVersion = 1
	// mirrorAttempts is the total number of tries a transient failure gets.
	mirrorAttempts    = 3
	mirrorBackoff     = 200 * time.Millisecond
	mirrorHTTPTimeout = 10 * time.Minute
	archiveMediaType  = "application/gzip"
	jsonMediaType     = "application/json"
	// defaultUserAgent is what mirror reads present.
	//
	// The mirror is served from a domain behind this project's own bot
	// defence, which refuses Go's default `Go-http-client/…` — and a refusal
	// is indistinguishable from the object being absent, so the mirror silently
	// stops being usable. A browser user agent is what that defence admits.
	//
	// RARPAR_CORPUS_USER_AGENT overrides it, so the value can follow whatever
	// the far end accepts without waiting for a release. `xtask test-corpus`
	// reads the same variable for the curl transport that hydrates the corpus.
	defaultUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	userAgentEnv = "RARPAR_CORPUS_USER_AGENT"
)

// userAgent is the override when it is set and not empty, the browser default
// otherwise.
func userAgent() string {
	if value := strings.TrimSpace(os.Getenv(userAgentEnv)); value != "" {
		return value
	}
	return defaultUserAgent
}

var (
	// errMirrorAbsent is the one condition that may fall back to the official
	// URL: the mirror simply does not hold this key yet.
	errMirrorAbsent = errors.New("the mirror does not hold this object")
	// errSourceUnavailable means the endpoint answered nothing usable within
	// the retry budget. On the mirror that also falls back; on the official URL
	// it is the end of the road.
	errSourceUnavailable = errors.New("source is unavailable")
)

// SourceMirror describes the public, content-addressed tool mirror on R2 and
// how to verify what it serves. The zero value (and a nil *SourceMirror) is a
// disabled mirror: archives then come from their official URLs only.
type SourceMirror struct {
	// BaseURL is the public read base, e.g. https://corpus.example.net, with
	// no trailing slash. Empty disables the mirror.
	BaseURL string
	// Identity is the exact cosign --certificate-identity every bundle must
	// carry (default DefaultMirrorIdentity).
	Identity string
	// Issuer is the exact cosign --certificate-oidc-issuer (default
	// DefaultMirrorIssuer).
	Issuer string
	// Cosign is the cosign executable (default "cosign").
	Cosign string
	// Curl is the curl executable, used only for SigV4 uploads (default
	// "curl"). Reads go through Client.
	Curl string
	// Client performs the GETs (default: http.DefaultTransport with a timeout).
	Client *http.Client
	// Publish is nil unless the protected publish workflow is mirroring.
	Publish *MirrorPublisher
	// CacheDir is where resolved archives are written when a caller does not
	// name a directory of its own. Empty means a rarpar-bench directory under
	// the system temp dir.
	CacheDir string
	// AllowInsecure permits plain-http endpoints. It exists so the tests can
	// drive loopback httptest servers; production callers leave it false so a
	// mirror, an upload endpoint, or an upstream can never be downgraded.
	AllowInsecure bool
	// Sleep replaces the retry backoff (nil = wait for real).
	Sleep func(time.Duration)
	// Log receives one-line notices (nil = os.Stderr).
	Log io.Writer
}

// MirrorPublisher holds the write side: the S3 endpoint, the credentials, and
// the build identity recorded in every provenance document. The secret never
// reaches a command line or a log; it travels to curl on stdin.
type MirrorPublisher struct {
	// WriteBase is the S3 endpoint plus bucket, e.g.
	// https://<account>.r2.cloudflarestorage.com/<bucket>.
	WriteBase       string
	AccessKeyID     string
	SecretAccessKey string
	Repository      string
	Commit          string
	WorkflowRef     string
	RunURL          string
}

// ArchiveSource is one original distribution archive as the reviewed toolchain
// lock pins it.
type ArchiveSource struct {
	Kind   string
	Name   string
	URL    string
	BLAKE3 string
}

// ResolvedArchive is a verified local copy of an ArchiveSource.
type ResolvedArchive struct {
	Path   string
	Origin string
}

// ArchiveProvenance is the small document published beside every mirrored
// archive: what the bytes are, where they officially came from, and which run
// mirrored them.
type ArchiveProvenance struct {
	SchemaVersion int              `json:"schema_version"`
	Kind          string           `json:"kind"`
	Name          string           `json:"name"`
	URL           string           `json:"url"`
	BLAKE3        string           `json:"blake3"`
	Size          int64            `json:"size"`
	MirroredAt    string           `json:"mirrored_at"`
	Source        ProvenanceSource `json:"source"`
}

// ProvenanceSource identifies the workflow run that mirrored an archive.
type ProvenanceSource struct {
	Repository  string `json:"repository"`
	Commit      string `json:"commit"`
	WorkflowRef string `json:"workflow_ref"`
	RunURL      string `json:"run_url"`
}

// mirrorKeys is the complete object set for one archive. Every key is derived
// from the reviewed digest, so a key can hold exactly one byte sequence.
type mirrorKeys struct {
	archive          string
	archiveBundle    string
	provenance       string
	provenanceBundle string
}

func (source ArchiveSource) keys() mirrorKeys {
	prefix := path.Join("tools", source.Kind, "blake3", source.BLAKE3)
	return mirrorKeys{
		archive:          path.Join(prefix, source.Name),
		archiveBundle:    path.Join(prefix, source.Name+".sigstore.json"),
		provenance:       path.Join(prefix, "provenance.json"),
		provenanceBundle: path.Join(prefix, "provenance.json.sigstore.json"),
	}
}

func (source ArchiveSource) validate(allowInsecure bool) error {
	switch source.Kind {
	case ArchiveKindRARLAB, ArchiveKindPAR2:
	default:
		return fmt.Errorf("unknown archive kind %q", source.Kind)
	}
	if source.Name == "" || source.Name == "." || source.Name == ".." || strings.ContainsAny(source.Name, `/\`) {
		return fmt.Errorf("archive name %q is not a plain file name", source.Name)
	}
	if !digestPattern.MatchString(source.BLAKE3) {
		return fmt.Errorf("archive %s is not pinned to a lowercase blake3", source.Name)
	}
	return checkTransport("archive URL", source.URL, allowInsecure)
}

// WriterArchiveSource is the RARLAB distribution archive a locked writer is
// built from.
func WriterArchiveSource(writer RARWriter) (ArchiveSource, error) {
	name := writer.ArchiveName()
	if name == "" {
		return ArchiveSource{}, fmt.Errorf("RAR writer %q does not name a distribution archive", writer.ID)
	}
	return ArchiveSource{Kind: ArchiveKindRARLAB, Name: name, URL: writer.URL, BLAKE3: writer.BLAKE3}, nil
}

// PAR2ArchiveSource is the par2cmdline-turbo source tarball the generator image
// is compiled from.
func PAR2ArchiveSource(generator PAR2Generator) (ArchiveSource, error) {
	parsed, err := url.Parse(generator.URL)
	if err != nil {
		return ArchiveSource{}, fmt.Errorf("PAR2 generator URL %q is not a URL: %w", generator.URL, err)
	}
	name := path.Base(parsed.Path)
	if name == "" || name == "." || name == "/" {
		return ArchiveSource{}, fmt.Errorf("PAR2 generator URL %q does not name an archive", generator.URL)
	}
	return ArchiveSource{Kind: ArchiveKindPAR2, Name: name, URL: generator.URL, BLAKE3: generator.BLAKE3}, nil
}

// ToolchainSources is every original distribution archive the lock pins, in
// build order: the writers, then the PAR2 generator.
func ToolchainSources(lock ToolchainLock) ([]ArchiveSource, error) {
	sources := make([]ArchiveSource, 0, len(lock.RARWriters)+1)
	for _, writer := range lock.RARWriters {
		source, err := WriterArchiveSource(writer)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	source, err := PAR2ArchiveSource(lock.PAR2Generator)
	if err != nil {
		return nil, err
	}
	return append(sources, source), nil
}

// ResolveToolchainSources resolves — and, when the mirror publishes, mirrors —
// every archive the lock pins without building anything, printing one line per
// archive: kind, name, digest, origin.
func ResolveToolchainSources(ctx context.Context, lock ToolchainLock, mirror *SourceMirror, out io.Writer) error {
	sources, err := ToolchainSources(lock)
	if err != nil {
		return err
	}
	cacheDir := mirror.cacheDir()
	for _, source := range sources {
		resolved, err := mirror.Resolve(ctx, source, cacheDir)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", source.Name, err)
		}
		// One line per archive: kind, name, blake3 digest, origin.
		if _, err := fmt.Fprintf(out, "%s %s blake3:%s %s\n", source.Kind, source.Name, source.BLAKE3, resolved.Origin); err != nil {
			return err
		}
	}
	return nil
}

func (m *SourceMirror) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return &http.Client{Timeout: mirrorHTTPTimeout}
}

func (m *SourceMirror) cosign() string {
	if m.Cosign != "" {
		return m.Cosign
	}
	return "cosign"
}

func (m *SourceMirror) curl() string {
	if m.Curl != "" {
		return m.Curl
	}
	return "curl"
}

func (m *SourceMirror) identity() string {
	if m.Identity != "" {
		return m.Identity
	}
	return DefaultMirrorIdentity
}

func (m *SourceMirror) issuer() string {
	if m.Issuer != "" {
		return m.Issuer
	}
	return DefaultMirrorIssuer
}

// cacheDir is the directory resolved archives land in. It is nil-safe: a
// disabled mirror still caches its official downloads somewhere.
func (m *SourceMirror) cacheDir() string {
	if m != nil && m.CacheDir != "" {
		return m.CacheDir
	}
	return filepath.Join(os.TempDir(), "rarpar-bench-tools")
}

func (m *SourceMirror) notice(format string, args ...any) {
	writer := m.Log
	if writer == nil {
		writer = os.Stderr
	}
	fmt.Fprintf(writer, "rarpar-bench: "+format+"\n", args...)
}

func (m *SourceMirror) validate() error {
	if m.BaseURL != "" {
		if err := checkTransport("mirror base URL", m.BaseURL, m.AllowInsecure); err != nil {
			return err
		}
	}
	publisher := m.Publish
	if publisher == nil {
		return nil
	}
	if m.BaseURL == "" {
		// Publishing without a public read base could not read back what it
		// stored, so it could never prove the stored copy is what was signed.
		return fmt.Errorf("publishing to the tool mirror requires a public read base URL")
	}
	if err := checkTransport("mirror write base URL", publisher.WriteBase, m.AllowInsecure); err != nil {
		return err
	}
	if publisher.AccessKeyID == "" || publisher.SecretAccessKey == "" {
		return fmt.Errorf("publishing to the tool mirror requires S3 credentials")
	}
	return nil
}

// checkTransport keeps every endpoint on TLS. Plain http is only reachable
// through AllowInsecure, which production callers never set.
func checkTransport(what, raw string, allowInsecure bool) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q is not a URL: %w", what, raw, err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s %q has no host", what, raw)
	}
	if parsed.Scheme == "https" || (parsed.Scheme == "http" && allowInsecure) {
		return nil
	}
	return fmt.Errorf("%s must be https, got %q", what, raw)
}

func (m *SourceMirror) readURL(key string) string {
	return strings.TrimSuffix(m.BaseURL, "/") + "/" + key
}

// How a read treats an intermediate cache. Reading a *published* object is a
// plain read: the key is a digest, so a hit is the object by construction.
// Reading back an object this process just wrote is not, and cachedRead would
// answer it wrong.
const (
	cachedRead = false
	freshRead  = true
)

// freshURL is readURL with a token no cache has seen.
//
// A publication reads its own writes, and the same URL was fetched moments
// earlier to decide whether to publish at all — when the answer was "absent",
// which is a response a CDN may cache like any other. The read-back would then
// be served that stale miss and conclude the upload never landed. (It is what
// broke the first publication: the object was in the bucket and public, and
// the read-back still saw 404.)
//
// A cache key includes the query string, so a token that has never been
// requested cannot have a stored answer, and object storage ignores a query it
// was not asked about. Nothing else changes: the bytes are still held to the
// reviewed digest, and consumers still read the clean URL.
func (m *SourceMirror) freshURL(key string) string {
	return fmt.Sprintf("%s?rarpar-read-back=%d", m.readURL(key), time.Now().UnixNano())
}

// url picks between the two for one read.
func (m *SourceMirror) url(key string, fresh bool) string {
	if fresh {
		return m.freshURL(key)
	}
	return m.readURL(key)
}

func (m *SourceMirror) writeURL(key string) string {
	return strings.TrimSuffix(m.Publish.WriteBase, "/") + "/" + key
}

// Resolve returns a verified local copy of source, mirror-first.
//
//  1. When a mirror base is configured the object set is fetched from it and
//     fully verified. Absence or unavailability falls back; anything else fails.
//  2. Otherwise the official URL is downloaded and checked against the reviewed
//     digest.
//  3. When a publisher is configured the freshly downloaded archive is signed,
//     given provenance, conditionally uploaded, and read back before it is used.
func (m *SourceMirror) Resolve(ctx context.Context, source ArchiveSource, cacheDir string) (ResolvedArchive, error) {
	if m == nil {
		m = &SourceMirror{}
	}
	if err := source.validate(m.AllowInsecure); err != nil {
		return ResolvedArchive{}, err
	}
	if err := m.validate(); err != nil {
		return ResolvedArchive{}, err
	}
	if cacheDir == "" {
		cacheDir = m.cacheDir()
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return ResolvedArchive{}, err
	}
	// The staging area holds the blobs cosign has to see. It lives outside the
	// cache directory so a rejected archive leaves nothing behind at all.
	work, err := os.MkdirTemp("", "rarpar-tool-mirror-")
	if err != nil {
		return ResolvedArchive{}, err
	}
	defer os.RemoveAll(work)

	if m.BaseURL != "" {
		data, err := m.fetchVerified(ctx, source, filepath.Join(work, "mirror"), cachedRead)
		switch {
		case err == nil:
			stored, err := writeVerifiedArchive(cacheDir, source.Name, data)
			if err != nil {
				return ResolvedArchive{}, err
			}
			return ResolvedArchive{Path: stored, Origin: OriginMirror}, nil
		case errors.Is(err, errMirrorAbsent):
			// Not mirrored yet: the official URL is the fallback.
		case errors.Is(err, errSourceUnavailable):
			m.notice("tool mirror unavailable for %s (%v); falling back to %s", source.Name, err, source.URL)
		default:
			return ResolvedArchive{}, err
		}
	}

	data, err := m.download(ctx, source.URL)
	if err != nil {
		return ResolvedArchive{}, fmt.Errorf("download %s: %w", source.URL, err)
	}
	// A digest that does not match the reviewed lock is never stored and never
	// executed, whatever served it.
	if digest := bytesBLAKE3(data); digest != source.BLAKE3 {
		return ResolvedArchive{}, fmt.Errorf("%s served blake3 %s, the lock pins %s", source.URL, digest, source.BLAKE3)
	}

	origin := OriginOfficial
	if m.Publish != nil {
		if err := m.publish(ctx, source, data, filepath.Join(work, "publish")); err != nil {
			return ResolvedArchive{}, err
		}
		origin = OriginMirrored
	}
	stored, err := writeVerifiedArchive(cacheDir, source.Name, data)
	if err != nil {
		return ResolvedArchive{}, err
	}
	return ResolvedArchive{Path: stored, Origin: origin}, nil
}

// fetchVerified retrieves the whole published object set for source and proves
// it: the archive hashes to the reviewed digest, both bundles verify under the
// pinned identity and issuer, and the provenance describes this very archive.
// It returns errMirrorAbsent only when the archive key itself is a 404; once the
// archive exists, every companion is mandatory.
func (m *SourceMirror) fetchVerified(ctx context.Context, source ArchiveSource, work string, fresh bool) ([]byte, error) {
	keys := source.keys()
	target := m.url(keys.archive, fresh)
	status, data, header, err := m.get(ctx, target)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", errMirrorAbsent, keys.archive)
	case refusedStatus(status):
		// The mirror refused to serve rather than serving something wrong: an
		// unauthenticated read of a private bucket, or an edge rule that will
		// not answer this client. No bytes came back, so there is nothing to
		// mistake for the object, and the official archive that replaces it is
		// held to the same reviewed digest — the fallback cannot lower the bar.
		// Failing hard here would instead make the *first* publication
		// impossible, when by definition nothing is mirrored yet.
		return nil, fmt.Errorf("%w: mirror %s", errSourceUnavailable, describeResponse(target, status, header, data))
	case status != http.StatusOK:
		// Neither absence nor unavailability: something answered for this key
		// that is not the object, so nothing may be assumed about it.
		return nil, fmt.Errorf("mirror %s", describeResponse(target, status, header, data))
	}
	if digest := bytesBLAKE3(data); digest != source.BLAKE3 {
		return nil, fmt.Errorf("the mirror holds a different object under this digest key %s: blake3 %s", keys.archive, digest)
	}
	archiveBundle, err := m.companion(ctx, keys.archiveBundle, fresh)
	if err != nil {
		return nil, err
	}
	provenanceData, err := m.companion(ctx, keys.provenance, fresh)
	if err != nil {
		return nil, err
	}
	provenanceBundle, err := m.companion(ctx, keys.provenanceBundle, fresh)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	archivePath := filepath.Join(work, source.Name)
	provenancePath := filepath.Join(work, "provenance.json")
	for _, staged := range []struct {
		file string
		blob []byte
	}{
		{archivePath, data},
		{archivePath + ".sigstore.json", archiveBundle},
		{provenancePath, provenanceData},
		{provenancePath + ".sigstore.json", provenanceBundle},
	} {
		if err := os.WriteFile(staged.file, staged.blob, 0o644); err != nil {
			return nil, err
		}
	}
	if err := m.verifyBundle(ctx, archivePath, archivePath+".sigstore.json"); err != nil {
		return nil, fmt.Errorf("mirrored %s is not signed by the publish workflow: %w", keys.archive, err)
	}
	if err := m.verifyBundle(ctx, provenancePath, provenancePath+".sigstore.json"); err != nil {
		return nil, fmt.Errorf("mirrored %s is not signed by the publish workflow: %w", keys.provenance, err)
	}
	var provenance ArchiveProvenance
	if err := json.Unmarshal(provenanceData, &provenance); err != nil {
		return nil, fmt.Errorf("decode %s: %w", keys.provenance, err)
	}
	if err := provenance.check(source, int64(len(data))); err != nil {
		return nil, fmt.Errorf("%s: %w", keys.provenance, err)
	}
	return data, nil
}

// companion fetches an object that must exist: the archive it belongs to is
// already published, so a companion that is *missing* is a broken publication,
// not an invitation to fall back. An endpoint that answers nothing usable
// within the retry budget is the same retry-exhausted unavailability the
// archive key itself gets, and it wraps errSourceUnavailable so Resolve may
// fall back to the official URL — which is still digest-checked.
func (m *SourceMirror) companion(ctx context.Context, key string, fresh bool) ([]byte, error) {
	target := m.url(key, fresh)
	status, data, header, err := m.get(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("mirror GET %s: %w", key, err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("mirror is missing companion object %s: %s",
			key, describeResponse(target, status, header, data))
	}
	return data, nil
}

// check requires the published provenance to describe exactly the archive the
// reviewed lock asks for.
func (provenance ArchiveProvenance) check(source ArchiveSource, size int64) error {
	if provenance.SchemaVersion != mirrorProvenanceSchemaVersion {
		return fmt.Errorf("provenance schema version is %d, this harness reads %d", provenance.SchemaVersion, mirrorProvenanceSchemaVersion)
	}
	if provenance.Size != size {
		return fmt.Errorf("provenance size is %d, the object is %d bytes", provenance.Size, size)
	}
	for _, field := range []struct{ name, published, expected string }{
		{"kind", provenance.Kind, source.Kind},
		{"name", provenance.Name, source.Name},
		{"url", provenance.URL, source.URL},
		{"blake3", provenance.BLAKE3, source.BLAKE3},
	} {
		if field.published != field.expected {
			return fmt.Errorf("provenance %s is %q, the lock pins %q", field.name, field.published, field.expected)
		}
	}
	return nil
}

// publish signs the freshly downloaded archive, writes and signs its
// provenance, uploads all four objects conditionally, and reads the stored copy
// back before the archive is used for anything.
func (m *SourceMirror) publish(ctx context.Context, source ArchiveSource, data []byte, work string) error {
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	archivePath := filepath.Join(work, source.Name)
	if err := os.WriteFile(archivePath, data, 0o644); err != nil {
		return err
	}
	archiveBundle := archivePath + ".sigstore.json"
	if err := m.signBlob(ctx, archivePath, archiveBundle); err != nil {
		return fmt.Errorf("sign %s: %w", source.Name, err)
	}
	provenance := ArchiveProvenance{
		SchemaVersion: mirrorProvenanceSchemaVersion,
		Kind:          source.Kind,
		Name:          source.Name,
		URL:           source.URL,
		BLAKE3:        source.BLAKE3,
		Size:          int64(len(data)),
		MirroredAt:    time.Now().UTC().Format(time.RFC3339),
		Source: ProvenanceSource{
			Repository:  m.Publish.Repository,
			Commit:      m.Publish.Commit,
			WorkflowRef: m.Publish.WorkflowRef,
			RunURL:      m.Publish.RunURL,
		},
	}
	document, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return err
	}
	document = append(document, '\n')
	provenancePath := filepath.Join(work, "provenance.json")
	if err := os.WriteFile(provenancePath, document, 0o644); err != nil {
		return err
	}
	provenanceBundle := provenancePath + ".sigstore.json"
	if err := m.signBlob(ctx, provenancePath, provenanceBundle); err != nil {
		return fmt.Errorf("sign provenance for %s: %w", source.Name, err)
	}
	keys := source.keys()
	// Order matters: the archive appears first, so a reader can never see a
	// signature or a provenance document for bytes that are not there yet.
	for _, upload := range []struct{ key, file, mediaType string }{
		{keys.archive, archivePath, archiveMediaType},
		{keys.archiveBundle, archiveBundle, jsonMediaType},
		{keys.provenance, provenancePath, jsonMediaType},
		{keys.provenanceBundle, provenanceBundle, jsonMediaType},
	} {
		if err := m.put(ctx, upload.key, upload.file, upload.mediaType); err != nil {
			return err
		}
	}
	stored, err := m.fetchVerified(ctx, source, filepath.Join(work, "readback"), freshRead)
	if err != nil {
		return fmt.Errorf("read back %s: stored copy is not what was published: %w", keys.archive, err)
	}
	if !bytes.Equal(stored, data) {
		return fmt.Errorf("read back %s: stored copy is not what was published", keys.archive)
	}
	return nil
}

func (m *SourceMirror) verifyBundle(ctx context.Context, blob, bundle string) error {
	return runCommand(ctx, m.cosign(), "verify-blob", "--bundle", bundle,
		"--certificate-identity", m.identity(),
		"--certificate-oidc-issuer", m.issuer(), blob)
}

func (m *SourceMirror) signBlob(ctx context.Context, blob, bundle string) error {
	if err := runCommand(ctx, m.cosign(), "sign-blob", "--yes", "--bundle", bundle, blob); err != nil {
		return err
	}
	if _, err := os.Stat(bundle); err != nil {
		return fmt.Errorf("cosign produced no bundle for %s: %w", blob, err)
	}
	return nil
}

// put stores one object with a conditional PUT. The key space is immutable and
// content-addressed, so If-None-Match: * is the whole concurrency story: either
// this writer created the key, or another writer already did and the read-back
// has to agree with what this one would have written.
//
// `--aws-sigv4` signs the request with SHA-256 because AWS Signature Version 4
// specifies that hash; it is curl's business and says nothing about how the
// object itself is addressed or verified.
func (m *SourceMirror) put(ctx context.Context, key, file, mediaType string) error {
	args := []string{
		"--silent", "--show-error",
		"--proto", "=https",
		"--tlsv1.2",
		"--retry", "3",
		"--aws-sigv4", "aws:amz:auto:s3",
		"--upload-file", file,
		"--header", "If-None-Match: *",
		"--header", "Content-Type: " + mediaType,
		"--output", os.DevNull,
		"--write-out", "%{http_code}",
		"--config", "-",
		"--", m.writeURL(key),
	}
	command := exec.CommandContext(ctx, m.curl(), args...)
	// The secret only ever travels on stdin: never an argument, never a log
	// line, never part of an error.
	command.Stdin = strings.NewReader(curlCredentialConfig(m.Publish.AccessKeyID, m.Publish.SecretAccessKey))
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("upload %s: %s: %w\n%s", key, m.curl(), err, strings.TrimSpace(stderr.String()))
	}
	status, err := strconv.Atoi(strings.TrimSpace(stdout.String()))
	if err != nil {
		return fmt.Errorf("upload %s: curl reported no HTTP status (%q)", key, strings.TrimSpace(stdout.String()))
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusPreconditionFailed:
		m.notice("%s was already published by another writer; verifying the stored copy", key)
		return nil
	default:
		return fmt.Errorf("upload %s: HTTP %d", key, status)
	}
}

// curlCredentialConfig renders the one config line curl reads from stdin.
// Values are double quoted with curl's own escaping.
func curlCredentialConfig(accessKeyID, secretAccessKey string) string {
	return "user = " + quoteCurlConfigValue(accessKeyID+":"+secretAccessKey) + "\n"
}

func quoteCurlConfigValue(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

// download fetches an object that must be there: the official upstream.
func (m *SourceMirror) download(ctx context.Context, target string) ([]byte, error) {
	status, data, header, err := m.get(ctx, target)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s", describeResponse(target, status, header, data))
	}
	return data, nil
}

// get performs a GET, retrying transient failures — a network error, a 5xx, or
// a 429 — a bounded number of times. A non-transient response is returned with
// its status so the caller can act on 404; an exhausted budget is reported as
// errSourceUnavailable.
func (m *SourceMirror) get(ctx context.Context, target string) (int, []byte, http.Header, error) {
	var last error
	for attempt := 1; attempt <= mirrorAttempts; attempt++ {
		if attempt > 1 {
			if err := m.backoff(ctx, attempt); err != nil {
				return 0, nil, nil, err
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return 0, nil, nil, err
		}
		request.Header.Set("User-Agent", userAgent())
		response, err := m.client().Do(request)
		if err != nil {
			last = err
			continue
		}
		data, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			last = readErr
			continue
		}
		if closeErr != nil {
			last = closeErr
			continue
		}
		if transientStatus(response.StatusCode) {
			last = fmt.Errorf("HTTP %d", response.StatusCode)
			continue
		}
		return response.StatusCode, data, response.Header, nil
	}
	return 0, nil, nil, fmt.Errorf("%w: %s: %v", errSourceUnavailable, target, last)
}

// describeResponse says who answered and what they said, for a response that
// carried no object.
//
// A bare "HTTP 403" cannot be diagnosed: the mirror key alone does not even
// name the host it was requested from, and an intermediary that refuses the
// request looks exactly like a bucket that refuses it. The identifying detail
// is all in the response — an edge network names itself in `server` and stamps
// a request id that its own event log can be searched by, while object storage
// answers with its own error document. Everything here is a public response to
// a public URL: no credential is ever sent to a read base, so nothing that
// could be echoed back is sensitive.
func describeResponse(target string, status int, header http.Header, body []byte) string {
	description := fmt.Sprintf("GET %s: HTTP %d", target, status)
	var marks []string
	for _, name := range []string{"Server", "Cf-Ray", "Cf-Mitigated", "X-Amz-Request-Id"} {
		if value := header.Get(name); value != "" {
			marks = append(marks, fmt.Sprintf("%s=%s", strings.ToLower(name), value))
		}
	}
	if len(marks) > 0 {
		description += " [" + strings.Join(marks, ", ") + "]"
	}
	if excerpt := bodyExcerpt(body); excerpt != "" {
		description += ": " + excerpt
	}
	return description
}

// bodyExcerpt flattens an error document to one short line: tags dropped,
// runs of whitespace collapsed, truncated. Enough to tell a CDN block page
// from a storage error, and not enough to bury the log in HTML.
func bodyExcerpt(body []byte) string {
	const limit = 200
	var text strings.Builder
	inTag := false
	for _, r := range string(body) {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			text.WriteRune(' ')
		case !inTag:
			text.WriteRune(r)
		}
	}
	flattened := strings.Join(strings.Fields(text.String()), " ")
	if flattened == "" {
		return ""
	}
	if len(flattened) > limit {
		flattened = flattened[:limit] + "…"
	}
	return strconv.Quote(flattened)
}

func transientStatus(status int) bool {
	return status >= 500 || status == http.StatusTooManyRequests
}

// refusedStatus is the mirror declining to serve this client at all, as
// opposed to answering for the key. A bucket that is not public yet answers
// 401/403 for every key including ones it holds; a CDN rule that blocks the
// runner's network answers 403 before the bucket is consulted; 410 is a key
// deliberately retired. None of them hand back an object, so each is treated
// as the mirror being unavailable for this archive rather than as a mirror
// that lies about it.
func refusedStatus(status int) bool {
	return status == http.StatusUnauthorized ||
		status == http.StatusForbidden ||
		status == http.StatusGone
}

func (m *SourceMirror) backoff(ctx context.Context, attempt int) error {
	delay := mirrorBackoff << (attempt - 2)
	if m.Sleep != nil {
		m.Sleep(delay)
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// writeVerifiedArchive publishes the verified bytes into the cache directory
// atomically, so a reader never sees a half-written archive and a failed
// resolve never leaves one behind.
func writeVerifiedArchive(cacheDir, name string, data []byte) (string, error) {
	// A fixed pattern, not the archive name: os.CreateTemp reads "*" in the
	// pattern, and the name comes from a URL.
	temporary, err := os.CreateTemp(cacheDir, ".archive-*")
	if err != nil {
		return "", err
	}
	staged := temporary.Name()
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		os.Remove(staged)
		return "", err
	}
	if err := temporary.Close(); err != nil {
		os.Remove(staged)
		return "", err
	}
	if err := os.Chmod(staged, 0o644); err != nil {
		os.Remove(staged)
		return "", err
	}
	destination := filepath.Join(cacheDir, name)
	if err := os.Rename(staged, destination); err != nil {
		os.Remove(staged)
		return "", err
	}
	return destination, nil
}
