package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const testBucket = "corpus-bucket"

// recordedUpload is one PUT the S3 stand-in saw.
type recordedUpload struct {
	Method      string
	Key         string
	IfNoneMatch string
	ContentType string
	Body        []byte
}

// mirrorFixture is a hermetic stand-in for the whole publication chain: the
// public read base, the official upstream, the S3 write endpoint, and stub
// cosign/curl executables. No test touches the network, cosign, or Docker.
type mirrorFixture struct {
	t *testing.T

	mu               sync.Mutex
	objects          map[string][]byte
	readStatus       map[string][]int
	reads            map[string]int
	uploads          []recordedUpload
	uploadStatus     int
	official         map[string][]byte
	officialStatus   []int
	officialRequests int

	root      string
	cacheDir  string
	readBase  string
	writeBase string
	cosignLog string
	curlLog   string

	mirror  *SourceMirror
	source  ArchiveSource
	archive []byte
}

func newMirrorFixture(t *testing.T) *mirrorFixture {
	t.Helper()
	root := t.TempDir()
	fixture := &mirrorFixture{
		t:          t,
		objects:    map[string][]byte{},
		readStatus: map[string][]int{},
		reads:      map[string]int{},
		official:   map[string][]byte{},
		root:       root,
		cacheDir:   filepath.Join(root, "cache"),
		cosignLog:  filepath.Join(root, "cosign.log"),
		curlLog:    filepath.Join(root, "curl.log"),
	}
	if err := os.MkdirAll(fixture.cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	read := httptest.NewServer(http.HandlerFunc(fixture.serveRead))
	t.Cleanup(read.Close)
	official := httptest.NewServer(http.HandlerFunc(fixture.serveOfficial))
	t.Cleanup(official.Close)
	write := httptest.NewServer(http.HandlerFunc(fixture.serveWrite))
	t.Cleanup(write.Close)
	fixture.readBase = read.URL
	fixture.writeBase = write.URL + "/" + testBucket

	fixture.archive = []byte("rarlinux distribution archive bytes")
	fixture.source = ArchiveSource{
		Kind:   ArchiveKindRARLAB,
		Name:   "rarlinux-x64-720.tar.gz",
		URL:    official.URL + "/rar/rarlinux-x64-720.tar.gz",
		BLAKE3: bytesBLAKE3(fixture.archive),
	}
	fixture.official["/rar/rarlinux-x64-720.tar.gz"] = fixture.archive

	fixture.mirror = &SourceMirror{
		BaseURL:       fixture.readBase,
		Cosign:        writeCosignStub(t, root, "cosign", DefaultMirrorIdentity, false, fixture.cosignLog),
		Curl:          writeCurlStub(t, root, fixture.curlLog),
		Client:        &http.Client{Timeout: 30 * time.Second},
		CacheDir:      fixture.cacheDir,
		AllowInsecure: true,
		Sleep:         func(time.Duration) {},
		Log:           io.Discard,
	}
	return fixture
}

func (f *mirrorFixture) serveRead(writer http.ResponseWriter, request *http.Request) {
	key := strings.TrimPrefix(request.URL.Path, "/")
	f.mu.Lock()
	f.reads[key]++
	if queue := f.readStatus[key]; len(queue) > 0 {
		status := queue[0]
		f.readStatus[key] = queue[1:]
		if status != http.StatusOK {
			f.mu.Unlock()
			writer.WriteHeader(status)
			return
		}
	}
	body, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		http.NotFound(writer, request)
		return
	}
	_, _ = writer.Write(body)
}

func (f *mirrorFixture) serveOfficial(writer http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	f.officialRequests++
	if len(f.officialStatus) > 0 {
		status := f.officialStatus[0]
		f.officialStatus = f.officialStatus[1:]
		if status != http.StatusOK {
			f.mu.Unlock()
			writer.WriteHeader(status)
			return
		}
	}
	body, ok := f.official[request.URL.Path]
	f.mu.Unlock()
	if !ok {
		http.NotFound(writer, request)
		return
	}
	_, _ = writer.Write(body)
}

func (f *mirrorFixture) serveWrite(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	key := strings.TrimPrefix(strings.TrimPrefix(request.URL.Path, "/"+testBucket), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploads = append(f.uploads, recordedUpload{
		Method:      request.Method,
		Key:         key,
		IfNoneMatch: request.Header.Get("If-None-Match"),
		ContentType: request.Header.Get("Content-Type"),
		Body:        body,
	})
	if f.uploadStatus != 0 && f.uploadStatus != http.StatusOK {
		writer.WriteHeader(f.uploadStatus)
		return
	}
	// A created key is immediately readable on the public base, which is what
	// the read-back then proves.
	f.objects[key] = body
	writer.WriteHeader(http.StatusOK)
}

// store publishes one object on the public read base without going through the
// write endpoint: what an earlier, successful publication left behind.
func (f *mirrorFixture) store(key string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = body
}

func (f *mirrorFixture) remove(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
}

func (f *mirrorFixture) queueReadStatus(key string, statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readStatus[key] = append(f.readStatus[key], statuses...)
}

func (f *mirrorFixture) officialHits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.officialRequests
}

func (f *mirrorFixture) queueOfficialStatus(statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.officialStatus = append(f.officialStatus, statuses...)
}

func (f *mirrorFixture) readHits(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads[key]
}

func (f *mirrorFixture) recordedUploads() []recordedUpload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedUpload(nil), f.uploads...)
}

func (f *mirrorFixture) objectAt(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, ok := f.objects[key]
	return body, ok
}

// mirrorObjects publishes a complete, valid object set for a source.
func (f *mirrorFixture) mirrorObjects(source ArchiveSource, archive []byte, mutate func(*ArchiveProvenance)) {
	keys := source.keys()
	f.store(keys.archive, archive)
	f.store(keys.archiveBundle, []byte(`{"stub":"sigstore-bundle"}`))
	f.store(keys.provenance, f.provenanceFor(source, archive, mutate))
	f.store(keys.provenanceBundle, []byte(`{"stub":"sigstore-bundle"}`))
}

func (f *mirrorFixture) provenanceFor(source ArchiveSource, archive []byte, mutate func(*ArchiveProvenance)) []byte {
	f.t.Helper()
	provenance := ArchiveProvenance{
		SchemaVersion: 1,
		Kind:          source.Kind,
		Name:          source.Name,
		URL:           source.URL,
		BLAKE3:        bytesBLAKE3(archive),
		Size:          int64(len(archive)),
		MirroredAt:    "2026-08-16T00:00:00Z",
		Source:        ProvenanceSource{Repository: "scryer-media/rarpar", Commit: strings.Repeat("a", 40)},
	}
	if mutate != nil {
		mutate(&provenance)
	}
	document, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		f.t.Fatal(err)
	}
	return append(document, '\n')
}

func (f *mirrorFixture) publisher() *MirrorPublisher {
	return &MirrorPublisher{
		WriteBase:       f.writeBase,
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		Repository:      "scryer-media/rarpar",
		Commit:          strings.Repeat("b", 40),
		WorkflowRef:     "scryer-media/rarpar/.github/workflows/test-corpus-publish.yml@refs/heads/main",
		RunURL:          "https://github.com/scryer-media/rarpar/actions/runs/1",
	}
}

func (f *mirrorFixture) cosignInvocations() []string {
	f.t.Helper()
	data, err := os.ReadFile(f.cosignLog)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func (f *mirrorFixture) cacheEntries() []string {
	f.t.Helper()
	entries, err := os.ReadDir(f.cacheDir)
	if err != nil {
		f.t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

// The cosign stub records every invocation, refuses any identity but the one it
// was told to expect — so a wrong signer is distinguishable from a bad
// signature — and materializes the bundle when it signs.
func writeCosignStub(t *testing.T, dir, name, identity string, failVerify bool, record string) string {
	t.Helper()
	failure := ""
	if failVerify {
		failure = `echo "cosign: signature does not verify" >&2; exit 1`
	}
	script := fmt.Sprintf(`#!/bin/sh
set -eu
printf '%%s\n' "$*" >> %q
mode="$1"
shift
bundle=""
identity=""
previous=""
for argument in "$@"; do
	case "$previous" in
		--bundle) bundle="$argument" ;;
		--certificate-identity) identity="$argument" ;;
	esac
	previous="$argument"
done
case "$mode" in
verify-blob)
	if [ "$identity" != %q ]; then
		echo "cosign: $identity is not the publish workflow" >&2
		exit 1
	fi
	%s
	exit 0
	;;
sign-blob)
	printf '{"stub":"sigstore-bundle"}\n' > "$bundle"
	exit 0
	;;
esac
echo "cosign: unsupported mode $mode" >&2
exit 2
`, record, identity, failure)
	return writeStub(t, dir, name, script)
}

// The curl stub records its argv, drops the transport hardening the loopback
// stand-in cannot satisfy, and hands everything else — including the
// credentials curl reads from stdin — to the real curl.
func writeCurlStub(t *testing.T, dir, record string) string {
	t.Helper()
	real, err := exec.LookPath("curl")
	if err != nil {
		t.Skipf("curl is not installed: %v", err)
	}
	script := fmt.Sprintf(`#!/bin/sh
set -eu
printf '%%s\n' "$*" >> %q
total=$#
index=0
skip=0
while [ $index -lt $total ]; do
	argument="$1"
	shift
	index=$((index + 1))
	if [ $skip -eq 1 ]; then
		skip=0
		continue
	fi
	case "$argument" in
		--proto|--aws-sigv4)
			skip=1
			continue
			;;
		--tlsv1.2)
			continue
			;;
	esac
	set -- "$@" "$argument"
done
exec %q "$@"
`, record, real)
	return writeStub(t, dir, "curl", script)
}

func writeStub(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// A published object that verifies end to end is used as it stands, and the
// official upstream is never contacted.
func TestResolveUsesTheVerifiedMirrorObject(t *testing.T) {
	fixture := newMirrorFixture(t)
	fixture.mirrorObjects(fixture.source, fixture.archive, nil)

	resolved, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Origin != OriginMirror {
		t.Fatalf("origin = %q, want %q", resolved.Origin, OriginMirror)
	}
	digest, err := fileBLAKE3(resolved.Path)
	if err != nil {
		t.Fatal(err)
	}
	if digest != fixture.source.BLAKE3 {
		t.Fatalf("resolved archive blake3 = %s, want %s", digest, fixture.source.BLAKE3)
	}
	if got := fixture.officialHits(); got != 0 {
		t.Fatalf("official upstream was contacted %d times for a mirrored archive", got)
	}
	invocations := fixture.cosignInvocations()
	if len(invocations) != 2 {
		t.Fatalf("cosign invocations = %v, want one per bundle", invocations)
	}
	for _, invocation := range invocations {
		if !strings.Contains(invocation, "verify-blob") ||
			!strings.Contains(invocation, "--certificate-identity "+DefaultMirrorIdentity) ||
			!strings.Contains(invocation, "--certificate-oidc-issuer "+DefaultMirrorIssuer) {
			t.Fatalf("cosign was not asked to pin the publish identity: %q", invocation)
		}
	}
	if entries := fixture.cacheEntries(); len(entries) != 1 || entries[0] != fixture.source.Name {
		t.Fatalf("cache holds %v, want just the archive", entries)
	}
}

// Absence is the one condition that falls back, and the fallback still has to
// match the reviewed digest.
func TestResolveFallsBackToTheOfficialURLWhenTheMirrorIsAbsent(t *testing.T) {
	fixture := newMirrorFixture(t)

	resolved, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Origin != OriginOfficial {
		t.Fatalf("origin = %q, want %q", resolved.Origin, OriginOfficial)
	}
	if got := fixture.officialHits(); got != 1 {
		t.Fatalf("official requests = %d, want exactly one", got)
	}
	if fixture.cosignInvocations() != nil {
		t.Fatal("nothing was published, so nothing should have been signed or verified")
	}
}

// With a publisher configured the fallback is mirrored: signed, given
// provenance, conditionally uploaded in order, and read back before use.
func TestResolvePublishesTheOfficialDownload(t *testing.T) {
	fixture := newMirrorFixture(t)
	fixture.mirror.Publish = fixture.publisher()

	resolved, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Origin != OriginMirrored {
		t.Fatalf("origin = %q, want %q", resolved.Origin, OriginMirrored)
	}
	keys := fixture.source.keys()
	uploads := fixture.recordedUploads()
	want := []struct{ key, mediaType string }{
		{keys.archive, "application/gzip"},
		{keys.archiveBundle, "application/json"},
		{keys.provenance, "application/json"},
		{keys.provenanceBundle, "application/json"},
	}
	if len(uploads) != len(want) {
		t.Fatalf("uploaded %d objects, want %d: %+v", len(uploads), len(want), uploads)
	}
	for index, expected := range want {
		upload := uploads[index]
		if upload.Method != http.MethodPut {
			t.Errorf("upload %d used %s, want PUT", index, upload.Method)
		}
		if upload.Key != expected.key {
			t.Errorf("upload %d stored %q, want %q", index, upload.Key, expected.key)
		}
		if upload.IfNoneMatch != "*" {
			t.Errorf("upload %d sent If-None-Match %q, want the conditional create", index, upload.IfNoneMatch)
		}
		if upload.ContentType != expected.mediaType {
			t.Errorf("upload %d sent Content-Type %q, want %q", index, upload.ContentType, expected.mediaType)
		}
	}
	if string(uploads[0].Body) != string(fixture.archive) {
		t.Fatal("the uploaded archive is not the archive that was downloaded and verified")
	}
	// The read-back must see exactly the uploaded bytes.
	stored, ok := fixture.objectAt(keys.archive)
	if !ok || string(stored) != string(fixture.archive) {
		t.Fatal("the stored archive is not the archive that was uploaded")
	}
	var provenance ArchiveProvenance
	published, _ := fixture.objectAt(keys.provenance)
	if err := json.Unmarshal(published, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.SchemaVersion != 1 || provenance.Kind != fixture.source.Kind || provenance.Name != fixture.source.Name ||
		provenance.URL != fixture.source.URL || provenance.BLAKE3 != fixture.source.BLAKE3 ||
		provenance.Size != int64(len(fixture.archive)) {
		t.Fatalf("published provenance does not describe the archive: %+v", provenance)
	}
	if provenance.Source.Repository != "scryer-media/rarpar" || provenance.Source.RunURL == "" {
		t.Fatalf("published provenance does not record the run: %+v", provenance.Source)
	}
	if _, err := time.Parse(time.RFC3339, provenance.MirroredAt); err != nil {
		t.Fatalf("mirrored_at %q is not RFC3339: %v", provenance.MirroredAt, err)
	}
	// Two signatures produced, then four verifications on read-back.
	invocations := fixture.cosignInvocations()
	signed, verified := 0, 0
	for _, invocation := range invocations {
		if strings.HasPrefix(invocation, "sign-blob") {
			signed++
		}
		if strings.HasPrefix(invocation, "verify-blob") {
			verified++
		}
	}
	if signed != 2 || verified != 2 {
		t.Fatalf("cosign usage = %d signatures, %d verifications; want 2 and 2: %v", signed, verified, invocations)
	}
	// The credentials must never appear on a command line.
	log, err := os.ReadFile(fixture.curlLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "test-secret-key") {
		t.Fatal("the secret access key reached curl's argv")
	}
}

// A mirror that answers nothing usable within the retry budget is unavailable,
// not authoritative: the official URL is the fallback.
func TestResolveFallsBackWhenTheMirrorIsUnavailable(t *testing.T) {
	fixture := newMirrorFixture(t)
	keys := fixture.source.keys()
	fixture.mirrorObjects(fixture.source, fixture.archive, nil)
	fixture.queueReadStatus(keys.archive, http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable)

	resolved, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Origin != OriginOfficial {
		t.Fatalf("origin = %q, want %q", resolved.Origin, OriginOfficial)
	}
	if got := fixture.officialHits(); got != 1 {
		t.Fatalf("official requests = %d, want exactly one", got)
	}
	// The whole retry budget is spent before the mirror is called unavailable.
	if got := fixture.readHits(keys.archive); got != mirrorAttempts {
		t.Fatalf("mirror was read %d times, want the full budget of %d", got, mirrorAttempts)
	}
}

// A transient failure inside the budget is retried, and the mirror still wins.
func TestResolveRetriesATransientMirrorFailure(t *testing.T) {
	fixture := newMirrorFixture(t)
	keys := fixture.source.keys()
	fixture.mirrorObjects(fixture.source, fixture.archive, nil)
	fixture.queueReadStatus(keys.archive, http.StatusServiceUnavailable)

	resolved, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Origin != OriginMirror {
		t.Fatalf("origin = %q, want %q", resolved.Origin, OriginMirror)
	}
	if got := fixture.readHits(keys.archive); got != 2 {
		t.Fatalf("mirror was read %d times, want one failure and one success", got)
	}
	if got := fixture.officialHits(); got != 0 {
		t.Fatalf("official upstream was contacted %d times after a retry succeeded", got)
	}
}

// The official upstream gets the same retry budget as the mirror.
func TestResolveRetriesATransientOfficialFailure(t *testing.T) {
	fixture := newMirrorFixture(t)
	fixture.queueOfficialStatus(http.StatusServiceUnavailable)

	resolved, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Origin != OriginOfficial {
		t.Fatalf("origin = %q, want %q", resolved.Origin, OriginOfficial)
	}
	if got := fixture.officialHits(); got != 2 {
		t.Fatalf("official requests = %d, want one failure and one success", got)
	}
}

// The reviewed digest is the fixed point: bytes that do not match it are never
// stored, whoever served them.
func TestResolveRejectsBytesThatDoNotMatchTheLock(t *testing.T) {
	t.Run("official", func(t *testing.T) {
		fixture := newMirrorFixture(t)
		fixture.official["/rar/rarlinux-x64-720.tar.gz"] = []byte("substituted upstream bytes")

		if _, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir); err == nil {
			t.Fatal("a mismatched official download was accepted")
		} else if !strings.Contains(err.Error(), fixture.source.BLAKE3) {
			t.Fatalf("error does not name the pinned digest: %v", err)
		}
		if entries := fixture.cacheEntries(); len(entries) != 0 {
			t.Fatalf("a rejected download left %v in the cache", entries)
		}
	})
	t.Run("mirror", func(t *testing.T) {
		fixture := newMirrorFixture(t)
		fixture.mirrorObjects(fixture.source, fixture.archive, nil)
		fixture.store(fixture.source.keys().archive, []byte("a different object under the digest key"))

		_, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
		if err == nil {
			t.Fatal("a mirror object that is not its own digest was accepted")
		}
		if !strings.Contains(err.Error(), "different object") {
			t.Fatalf("error does not explain the mismatch: %v", err)
		}
		if got := fixture.officialHits(); got != 0 {
			t.Fatalf("a corrupt mirror object fell back to the official URL (%d requests)", got)
		}
		if entries := fixture.cacheEntries(); len(entries) != 0 {
			t.Fatalf("a rejected object left %v in the cache", entries)
		}
	})
}

// A present object whose signature does not verify is an error, not a cache
// miss: falling back would let a tampered mirror choose the code path.
func TestResolveRejectsAnInvalidSignature(t *testing.T) {
	fixture := newMirrorFixture(t)
	fixture.mirror.Cosign = writeCosignStub(t, fixture.root, "cosign-invalid", DefaultMirrorIdentity, true, fixture.cosignLog)
	fixture.mirrorObjects(fixture.source, fixture.archive, nil)

	_, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err == nil {
		t.Fatal("an unverifiable bundle was accepted")
	}
	if !strings.Contains(err.Error(), "publish workflow") {
		t.Fatalf("error does not name the signature failure: %v", err)
	}
	if got := fixture.officialHits(); got != 0 {
		t.Fatalf("an invalid signature fell back to the official URL (%d requests)", got)
	}
}

// The identity is pinned exactly: a bundle signed by anything else fails.
func TestResolveRejectsASignerOtherThanThePublishWorkflow(t *testing.T) {
	fixture := newMirrorFixture(t)
	fixture.mirror.Identity = "https://github.com/attacker/rarpar/.github/workflows/publish.yml@refs/heads/main"
	fixture.mirrorObjects(fixture.source, fixture.archive, nil)

	_, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err == nil {
		t.Fatal("a bundle from another identity was accepted")
	}
	if !strings.Contains(err.Error(), "publish workflow") {
		t.Fatalf("error does not name the identity failure: %v", err)
	}
	// The pinned identity is what cosign was asked for, verbatim.
	for _, invocation := range fixture.cosignInvocations() {
		if !strings.Contains(invocation, "--certificate-identity "+fixture.mirror.Identity) {
			t.Fatalf("cosign was not asked for the configured identity: %q", invocation)
		}
	}
}

// Once the archive key exists, every companion is mandatory.
func TestResolveRejectsAMissingCompanionObject(t *testing.T) {
	for name, companion := range map[string]func(mirrorKeys) string{
		"signature":            func(k mirrorKeys) string { return k.archiveBundle },
		"provenance":           func(k mirrorKeys) string { return k.provenance },
		"provenance signature": func(k mirrorKeys) string { return k.provenanceBundle },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newMirrorFixture(t)
			fixture.mirrorObjects(fixture.source, fixture.archive, nil)
			fixture.remove(companion(fixture.source.keys()))

			_, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
			if err == nil {
				t.Fatalf("a publication without its %s was accepted", name)
			}
			if got := fixture.officialHits(); got != 0 {
				t.Fatalf("a broken publication fell back to the official URL (%d requests)", got)
			}
		})
	}
}

// Provenance that disagrees with the reviewed lock means the object is not the
// archive the lock asks for.
func TestResolveRejectsProvenanceThatDisagreesWithTheLock(t *testing.T) {
	for name, mutate := range map[string]func(*ArchiveProvenance){
		"url":    func(p *ArchiveProvenance) { p.URL = "https://mirror.example.test/rarlinux-x64-720.tar.gz" },
		"blake3": func(p *ArchiveProvenance) { p.BLAKE3 = strings.Repeat("c", 64) },
		"name":   func(p *ArchiveProvenance) { p.Name = "rarlinux-x64-723.tar.gz" },
		"kind":   func(p *ArchiveProvenance) { p.Kind = ArchiveKindPAR2 },
		"size":   func(p *ArchiveProvenance) { p.Size = 1 },
		"schema version": func(p *ArchiveProvenance) {
			p.SchemaVersion = 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newMirrorFixture(t)
			fixture.mirrorObjects(fixture.source, fixture.archive, mutate)

			_, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
			if err == nil {
				t.Fatalf("provenance with a wrong %s was accepted", name)
			}
			if !strings.Contains(err.Error(), "provenance "+name) {
				t.Fatalf("error does not name the disagreeing field: %v", err)
			}
			if got := fixture.officialHits(); got != 0 {
				t.Fatalf("disagreeing provenance fell back to the official URL (%d requests)", got)
			}
		})
	}
}

// Two publishers can race on an immutable key. 412 means the other writer won,
// which is harmless exactly when the stored copy verifies.
func TestPublishSurvivesAConditionalWriteRace(t *testing.T) {
	fixture := newMirrorFixture(t)
	fixture.mirror.Publish = fixture.publisher()
	fixture.uploadStatus = http.StatusPreconditionFailed
	keys := fixture.source.keys()
	// The object appears between this publisher's first read and its write.
	fixture.queueReadStatus(keys.archive, http.StatusNotFound)
	fixture.mirrorObjects(fixture.source, fixture.archive, nil)

	resolved, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Origin != OriginMirrored {
		t.Fatalf("origin = %q, want %q", resolved.Origin, OriginMirrored)
	}
	if uploads := fixture.recordedUploads(); len(uploads) != 4 {
		t.Fatalf("uploaded %d objects, want all four attempted", len(uploads))
	}
}

// A race is only harmless when the winner stored the same bytes. If the
// read-back disagrees, the publication aborts.
func TestPublishRejectsAStoredCopyThatIsNotWhatWasPublished(t *testing.T) {
	fixture := newMirrorFixture(t)
	fixture.mirror.Publish = fixture.publisher()
	fixture.uploadStatus = http.StatusPreconditionFailed
	keys := fixture.source.keys()
	fixture.queueReadStatus(keys.archive, http.StatusNotFound)
	fixture.mirrorObjects(fixture.source, fixture.archive, nil)
	fixture.store(keys.archive, []byte("bytes the winning writer stored"))

	_, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err == nil {
		t.Fatal("a stored copy that is not what was published was accepted")
	}
	if !strings.Contains(err.Error(), "stored copy is not what was published") {
		t.Fatalf("error does not name the read-back failure: %v", err)
	}
	if entries := fixture.cacheEntries(); len(entries) != 0 {
		t.Fatalf("a failed publication left %v in the cache", entries)
	}
}

// A non-2xx, non-412 upload is an error: nothing may be assumed about the key.
func TestPublishRejectsAFailedUpload(t *testing.T) {
	fixture := newMirrorFixture(t)
	fixture.mirror.Publish = fixture.publisher()
	fixture.uploadStatus = http.StatusForbidden

	_, err := fixture.mirror.Resolve(context.Background(), fixture.source, fixture.cacheDir)
	if err == nil {
		t.Fatal("a rejected upload was treated as a publication")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error does not report the upload status: %v", err)
	}
}

// Production endpoints are https, always. Plain http is reachable only through
// the switch the tests set.
func TestSourceMirrorRejectsPlainHTTPEndpoints(t *testing.T) {
	ctx := context.Background()
	cacheDir := t.TempDir()
	source := ArchiveSource{
		Kind:   ArchiveKindRARLAB,
		Name:   "rarlinux-x64-720.tar.gz",
		URL:    "https://www.rarlab.com/rar/rarlinux-x64-720.tar.gz",
		BLAKE3: strings.Repeat("d", 64),
	}
	insecureSource := source
	insecureSource.URL = "http://www.rarlab.com/rar/rarlinux-x64-720.tar.gz"

	for name, testCase := range map[string]struct {
		mirror *SourceMirror
		source ArchiveSource
		want   string
	}{
		"read base": {&SourceMirror{BaseURL: "http://corpus.example.test"}, source, "mirror base URL must be https"},
		"write base": {&SourceMirror{BaseURL: "https://corpus.example.test", Publish: &MirrorPublisher{
			WriteBase: "http://account.r2.cloudflarestorage.com/bucket", AccessKeyID: "id", SecretAccessKey: "secret",
		}}, source, "mirror write base URL must be https"},
		"archive url": {&SourceMirror{}, insecureSource, "archive URL must be https"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := testCase.mirror.Resolve(ctx, testCase.source, cacheDir)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("err = %v, want %q", err, testCase.want)
			}
		})
	}
}

// Publishing without a public read base could never prove what it stored.
func TestPublishingRequiresAPublicReadBase(t *testing.T) {
	mirror := &SourceMirror{Publish: &MirrorPublisher{WriteBase: "https://account.r2.cloudflarestorage.com/bucket", AccessKeyID: "id", SecretAccessKey: "secret"}}
	source := ArchiveSource{Kind: ArchiveKindRARLAB, Name: "rarlinux-x64-720.tar.gz", URL: "https://www.rarlab.com/rar/rarlinux-x64-720.tar.gz", BLAKE3: strings.Repeat("d", 64)}
	_, err := mirror.Resolve(context.Background(), source, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "public read base") {
		t.Fatalf("err = %v, want the missing read base", err)
	}
}

// The object layout is the published contract; it is derived from the reviewed
// digest so one key can hold exactly one byte sequence.
func TestMirrorKeysAreContentAddressed(t *testing.T) {
	source := ArchiveSource{Kind: ArchiveKindRARLAB, Name: "rarlinux-x64-720.tar.gz", URL: "https://www.rarlab.com/rar/rarlinux-x64-720.tar.gz", BLAKE3: strings.Repeat("e", 64)}
	keys := source.keys()
	prefix := "tools/rarlab/blake3/" + source.BLAKE3 + "/"
	for got, want := range map[string]string{
		keys.archive:          prefix + "rarlinux-x64-720.tar.gz",
		keys.archiveBundle:    prefix + "rarlinux-x64-720.tar.gz.sigstore.json",
		keys.provenance:       prefix + "provenance.json",
		keys.provenanceBundle: prefix + "provenance.json.sigstore.json",
	} {
		if got != want {
			t.Errorf("key = %q, want %q", got, want)
		}
	}
}

// Every archive the lock pins is resolvable, and the resolver names all seven.
func TestResolveToolchainSourcesCoversTheWholeLock(t *testing.T) {
	fixture := newMirrorFixture(t)
	lock := mirroredToolchainLock(t, fixture)

	var out strings.Builder
	if err := ResolveToolchainSources(context.Background(), lock, fixture.mirror, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(lock.RARWriters)+1 {
		t.Fatalf("resolved %d archives, want %d", len(lines), len(lock.RARWriters)+1)
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[3] != OriginMirror {
			t.Fatalf("line %q does not report kind, name, digest and origin", line)
		}
	}
	if !strings.Contains(out.String(), ArchiveKindPAR2) {
		t.Fatalf("the PAR2 generator source is missing from %q", out.String())
	}
	if got := fixture.officialHits(); got != 0 {
		t.Fatalf("official upstreams were contacted %d times for a fully mirrored lock", got)
	}
}

// mirroredToolchainLock rewrites the checked-in lock so every archive is a
// small, mirrored blob, leaving the writer identities and URLs intact.
func mirroredToolchainLock(t *testing.T, fixture *mirrorFixture) ToolchainLock {
	t.Helper()
	lock, err := LoadToolchains(filepath.Join("..", "..", "config", "toolchains.json"))
	if err != nil {
		t.Fatal(err)
	}
	for index := range lock.RARWriters {
		archive := []byte("archive for " + lock.RARWriters[index].ID)
		lock.RARWriters[index].BLAKE3 = bytesBLAKE3(archive)
		source, err := WriterArchiveSource(lock.RARWriters[index])
		if err != nil {
			t.Fatal(err)
		}
		fixture.mirrorObjects(source, archive, nil)
	}
	archive := []byte("archive for " + lock.PAR2Generator.ID)
	lock.PAR2Generator.BLAKE3 = bytesBLAKE3(archive)
	source, err := PAR2ArchiveSource(lock.PAR2Generator)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mirrorObjects(source, archive, nil)
	return lock
}

// Docker builds from what the harness verified: a context holding the staged
// archive and the checked-in Dockerfile, with no URL or digest arguments left
// for the image to fetch anything itself.
func TestBuildToolchainsBuildsFromVerifiedLocalArchives(t *testing.T) {
	fixture := newMirrorFixture(t)
	lock := mirroredToolchainLock(t, fixture)
	record := filepath.Join(fixture.root, "docker-builds")
	if err := os.MkdirAll(record, 0o755); err != nil {
		t.Fatal(err)
	}
	docker := writeStub(t, fixture.root, "docker", fmt.Sprintf(`#!/bin/sh
set -eu
count=$(ls %q | wc -l | tr -d ' ')
directory=%q/build-$count
mkdir -p "$directory"
printf '%%s\n' "$@" > "$directory/argv"
context=""
for argument in "$@"; do context="$argument"; done
cp -R "$context" "$directory/context"
`, record, record))

	if err := BuildToolchains(context.Background(), docker, filepath.Join("..", ".."), lock, fixture.mirror, nil); err != nil {
		t.Fatal(err)
	}
	builds, err := os.ReadDir(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(builds) != len(lock.RARWriters)+1 {
		t.Fatalf("%d builds recorded, want one per locked tool", len(builds))
	}
	for index, writer := range lock.RARWriters {
		directory := filepath.Join(record, fmt.Sprintf("build-%d", index))
		argv := readArgv(t, filepath.Join(directory, "argv"))
		assertNoUpstreamArguments(t, writer.ID, argv)
		if !argvHasPair(argv, "--build-arg", "RAR_BINARY="+writer.Binary) {
			t.Errorf("%s: build does not pass RAR_BINARY=%s: %v", writer.ID, writer.Binary, argv)
		}
		assertStagedContext(t, writer.ID, filepath.Join(directory, "context"), "rar.tar.gz", writer.BLAKE3)
	}
	par2Directory := filepath.Join(record, fmt.Sprintf("build-%d", len(lock.RARWriters)))
	argv := readArgv(t, filepath.Join(par2Directory, "argv"))
	assertNoUpstreamArguments(t, lock.PAR2Generator.ID, argv)
	assertStagedContext(t, lock.PAR2Generator.ID, filepath.Join(par2Directory, "context"), "par2.tar.gz", lock.PAR2Generator.BLAKE3)
}

// One runner per generator builds one generator's images. The subset is the
// lock ids `toolchains build --only-images-for` resolves to; the video encoder
// is a legal member that builds nothing, and an id the lock does not declare
// is an error rather than a build of nothing at all.
func TestBuildToolchainsBuildsOnlyTheRequestedToolchains(t *testing.T) {
	fixture := newMirrorFixture(t)
	lock := mirroredToolchainLock(t, fixture)
	record := filepath.Join(fixture.root, "subset-builds")
	if err := os.MkdirAll(record, 0o755); err != nil {
		t.Fatal(err)
	}
	docker := writeStub(t, fixture.root, "docker-subset", fmt.Sprintf(`#!/bin/sh
set -eu
count=$(ls %q | wc -l | tr -d ' ')
directory=%q/build-$count
mkdir -p "$directory"
printf '%%s\n' "$@" > "$directory/argv"
`, record, record))

	writer := lock.RARWriters[len(lock.RARWriters)-1]
	only := []string{writer.ID, lock.VideoEncoder.ID}
	if err := BuildToolchains(context.Background(), docker, filepath.Join("..", ".."), lock, fixture.mirror, only); err != nil {
		t.Fatal(err)
	}
	builds, err := os.ReadDir(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(builds) != 1 {
		t.Fatalf("%d builds recorded, want exactly the one requested writer", len(builds))
	}
	argv := readArgv(t, filepath.Join(record, "build-0", "argv"))
	if !argvHasPair(argv, "--tag", writer.Image) {
		t.Fatalf("the build is not tagged %s: %v", writer.Image, argv)
	}
	if err := BuildToolchains(context.Background(), docker, filepath.Join("..", ".."), lock, fixture.mirror, []string{"rarlab-0.0"}); err == nil {
		t.Fatal("an id the lock does not declare must be an error")
	}
}

func readArgv(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func argvHasPair(argv []string, flag, value string) bool {
	for index := 0; index+1 < len(argv); index++ {
		if argv[index] == flag && argv[index+1] == value {
			return true
		}
	}
	return false
}

func assertNoUpstreamArguments(t *testing.T, id string, argv []string) {
	t.Helper()
	for _, argument := range argv {
		for _, forbidden := range []string{"RAR_URL", "RAR_SHA256", "PAR2_URL", "PAR2_SHA256", "RAR_BLAKE3", "PAR2_BLAKE3"} {
			if strings.Contains(argument, forbidden) {
				t.Errorf("%s: build still passes %s (%q)", id, forbidden, argument)
			}
		}
	}
}

func assertStagedContext(t *testing.T, id, context, archiveName, digest string) {
	t.Helper()
	entries, err := os.ReadDir(context)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	want := []string{"Dockerfile", archiveName}
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("%s: build context holds %v, want exactly %v", id, names, want)
	}
	staged, err := fileBLAKE3(filepath.Join(context, archiveName))
	if err != nil {
		t.Fatal(err)
	}
	if staged != digest {
		t.Fatalf("%s: staged %s hashes to %s, the lock pins %s", id, archiveName, staged, digest)
	}
}

// The checked-in Dockerfiles have to build from the staged archive and must not
// be able to fetch anything themselves.
func TestVerifyDockerfilesRequiresStagedArchives(t *testing.T) {
	lock, err := LoadToolchains(filepath.Join("..", "..", "config", "toolchains.json"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("..", "..")
	if err := verifyDockerfiles(root, lock.DockerBase); err != nil {
		t.Fatalf("the checked-in Dockerfiles do not satisfy the contract: %v", err)
	}
	original, err := os.ReadFile(filepath.Join(root, "docker/rarlab/Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for name, injected := range map[string]string{
		"curl":          "RUN curl --fail --location --output /tmp/rar.tar.gz \"$RAR_URL\"\n",
		"url build-arg": "ARG RAR_URL\n",
	} {
		t.Run(name, func(t *testing.T) {
			staged := t.TempDir()
			if err := os.MkdirAll(filepath.Join(staged, "docker/rarlab"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(staged, "docker/par2"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := copyStagedFile(filepath.Join(root, "docker/par2/Dockerfile"), filepath.Join(staged, "docker/par2/Dockerfile"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(staged, "docker/rarlab/Dockerfile"), append(original, []byte(injected)...), 0o644); err != nil {
				t.Fatal(err)
			}
			err := verifyDockerfiles(staged, lock.DockerBase)
			if err == nil {
				t.Fatalf("a Dockerfile that downloads its own source (%s) was accepted", name)
			}
			if !strings.Contains(err.Error(), "downloads its own source") {
				t.Fatalf("error does not explain the rejection: %v", err)
			}
		})
	}
}

// curl reads the credentials from stdin; the rendering has to survive quoting.
func TestCurlCredentialConfigEscapes(t *testing.T) {
	if got, want := curlCredentialConfig("id", "secret"), "user = \"id:secret\"\n"; got != want {
		t.Fatalf("config = %q, want %q", got, want)
	}
	got := curlCredentialConfig(`i"d`, `se\cret`)
	if want := "user = \"i\\\"d:se\\\\cret\"\n"; got != want {
		t.Fatalf("config = %q, want %q", got, want)
	}
}
