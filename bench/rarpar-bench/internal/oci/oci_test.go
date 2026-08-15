package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeRegistry implements just enough of the distribution API for the client:
// blob HEAD/GET, the POST+PUT upload flow, and manifest HEAD/GET/PUT.
type fakeRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte
	requests  []string
	// corrupt, when set, swaps the payload served for GET blob so digest
	// verification can be exercised.
	corrupt map[string][]byte
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		blobs:     map[string][]byte{},
		manifests: map[string][]byte{},
		corrupt:   map[string][]byte{},
	}
}

func (f *fakeRegistry) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/"), "/")
		// repo names may contain slashes; the last two segments carry the verb.
		if len(parts) < 2 {
			http.NotFound(w, r)
			return
		}
		kind, arg := parts[len(parts)-2], parts[len(parts)-1]
		switch {
		case kind == "manifests":
			f.serveManifest(w, r, arg)
		case kind == "blobs" && arg != "":
			f.serveBlob(w, r, arg)
		case kind == "uploads" || (len(parts) >= 3 && parts[len(parts)-3] == "blobs" && kind == "uploads"):
			f.serveUpload(w, r)
		case strings.HasPrefix(r.URL.Path, "/upload-session/"):
			f.serveUpload(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *fakeRegistry) serveManifest(w http.ResponseWriter, r *http.Request, tag string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		m, ok := f.manifests[tag]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", manifestMediaType)
		if r.Method == http.MethodGet {
			w.Write(m)
		}
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		f.manifests[tag] = body
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
	}
}

func (f *fakeRegistry) serveBlob(w http.ResponseWriter, r *http.Request, digest string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	payload, ok := f.blobs[digest]
	if alt, corrupted := f.corrupt[digest]; corrupted {
		payload, ok = alt, true
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodHead:
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
	case http.MethodGet:
		w.Write(payload)
	default:
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
	}
}

func (f *fakeRegistry) serveUpload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		// Hand back a relative session URL, like ECR does.
		w.Header().Set("Location", "/upload-session/1")
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		digest := r.URL.Query().Get("digest")
		if digest == "" {
			http.Error(w, "missing digest", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		if digest != "sha256:"+hex.EncodeToString(sum[:]) {
			http.Error(w, "digest mismatch", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.blobs[digest] = body
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
	}
}

func (f *fakeRegistry) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func testClient(t *testing.T, reg *fakeRegistry) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(reg.handler(t))
	t.Cleanup(srv.Close)
	ref, err := ParseImageRef("123.dkr.ecr.us-east-1.amazonaws.com/rarpar-corpus:dca3e362")
	if err != nil {
		t.Fatal(err)
	}
	return &Client{Ref: ref, BaseURL: srv.URL, Token: "dGVzdA=="}, srv
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	got := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(rel)] = string(body)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestPushFetchRoundTrip(t *testing.T) {
	reg := newFakeRegistry()
	client, _ := testClient(t, reg)
	src := t.TempDir()
	files := map[string]string{
		"corpus.json":        `{"generation":"dca3e362"}`,
		"cases/a/input.bin":  strings.Repeat("x", 4096),
		"cases/b/nested.bin": "payload-b",
	}
	writeTree(t, src, files)

	digest, err := client.PushDir(context.Background(), src, t.Logf)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("push returned digest %q", digest)
	}

	out := filepath.Join(t.TempDir(), "corpus")
	if err := client.FetchDir(context.Background(), out, t.Logf); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	got := readTree(t, out)
	for name, want := range files {
		if got[name] != want {
			t.Fatalf("file %s: got %q want %q", name, got[name], want)
		}
	}
	if len(got) != len(files) {
		t.Fatalf("fetched %d files, want %d", len(got), len(files))
	}
	if _, err := os.Stat(out + ".partial"); !os.IsNotExist(err) {
		t.Fatalf("partial dir survived a successful fetch: %v", err)
	}
}

func TestPushIsIdempotent(t *testing.T) {
	reg := newFakeRegistry()
	client, _ := testClient(t, reg)
	src := t.TempDir()
	writeTree(t, src, map[string]string{"corpus.json": "{}"})
	if _, err := client.PushDir(context.Background(), src, nil); err != nil {
		t.Fatal(err)
	}
	before := reg.requestCount()
	if _, err := client.PushDir(context.Background(), src, nil); err != nil {
		t.Fatal(err)
	}
	// Second push must stop at the manifest HEAD: no uploads, no tar work.
	if reg.requestCount() != before+1 {
		t.Fatalf("idempotent push issued %d extra requests, want 1 (HEAD manifest)", reg.requestCount()-before)
	}
}

func TestDeterministicTarDigest(t *testing.T) {
	build := func(order []string) string {
		dir := t.TempDir()
		for _, name := range order {
			writeTree(t, dir, map[string]string{name: "content-" + name})
		}
		var buf bytes.Buffer
		digest, _, err := writeDeterministicTar(&buf, dir)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	a := build([]string{"z.bin", "a/b.bin", "m.json"})
	b := build([]string{"m.json", "z.bin", "a/b.bin"})
	if a != b {
		t.Fatalf("same tree hashed differently: %s vs %s", a, b)
	}
	c := build([]string{"z.bin", "a/b.bin", "m.json", "extra.bin"})
	if a == c {
		t.Fatal("different trees produced the same digest")
	}
}

func TestFetchRejectsCorruptedLayer(t *testing.T) {
	reg := newFakeRegistry()
	client, _ := testClient(t, reg)
	src := t.TempDir()
	writeTree(t, src, map[string]string{"corpus.json": "{}", "cases/x.bin": "real"})
	digest, err := client.PushDir(context.Background(), src, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Serve a different (still well-formed) tar for the layer digest.
	var evil bytes.Buffer
	tw := tar.NewWriter(&evil)
	body := []byte("tampered")
	tw.WriteHeader(&tar.Header{Name: "corpus.json", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	reg.mu.Lock()
	reg.corrupt[digest] = evil.Bytes()
	reg.mu.Unlock()

	out := filepath.Join(t.TempDir(), "corpus")
	err = client.FetchDir(context.Background(), out, nil)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("fetch of tampered layer returned %v; want digest mismatch", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("tampered fetch left an output directory behind")
	}
}

func TestExtractRejectsEscapingPaths(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("owned")
	tw.WriteHeader(&tar.Header{Name: "../escape.bin", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	err := extractTar(&buf, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("path traversal extract returned %v", err)
	}
}

func TestExtractRejectsSymlinks(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	tw.Close()
	err := extractTar(&buf, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("symlink extract returned %v", err)
	}
}

func TestParseImageRef(t *testing.T) {
	good, err := ParseImageRef("123.dkr.ecr.us-east-1.amazonaws.com/rarpar/corpus:dca3e362")
	if err != nil {
		t.Fatal(err)
	}
	if good.Registry != "123.dkr.ecr.us-east-1.amazonaws.com" || good.Repo != "rarpar/corpus" || good.Tag != "dca3e362" {
		t.Fatalf("parsed %+v", good)
	}
	for _, bad := range []string{"", "no-slash:tag", "host.com/repo", "host.com/repo:", "plainname/repo:tag"} {
		if _, err := ParseImageRef(bad); err == nil {
			t.Fatalf("ref %q parsed but should not", bad)
		}
	}
}

func TestECRRegion(t *testing.T) {
	region, err := ECRRegion("561234.dkr.ecr.us-east-1.amazonaws.com")
	if err != nil || region != "us-east-1" {
		t.Fatalf("got %q, %v", region, err)
	}
	if _, err := ECRRegion("ghcr.io"); err == nil {
		t.Fatal("non-ECR host produced a region")
	}
}
