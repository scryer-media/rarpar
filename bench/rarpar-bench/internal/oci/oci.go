// Package oci moves a benchmark corpus through an OCI registry (ECR in
// practice) so EC2 instances pull it in-region instead of receiving it over
// the orchestrator's home uplink. The uplink pays the corpus cost exactly
// once, at push time; every instance pull after that is registry->EC2.
//
// The "image" is deliberately minimal: one uncompressed tar layer holding the
// corpus tree, plus the smallest config blob registries accept. Uncompressed
// because the corpus is dominated by high-entropy archive bodies that do not
// compress, and because a plain tar keeps both sides pure stdlib. The layer
// digest doubles as an end-to-end integrity check: the fetch side refuses to
// expose an extraction whose bytes do not hash to the manifest's digest.
//
// Everything here speaks the registry HTTP API directly. No docker daemon is
// required on either side; instances authenticate with a short-lived ECR
// token the orchestrator passes out-of-band (never baked into run scripts,
// which get archived with results).
package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ImageRef is a fully pinned image location: host, repository, and tag. Tags
// are expected to be corpus-generation digests, so a ref names exactly one
// corpus tree and re-pushing the same tree is a no-op.
type ImageRef struct {
	Registry string
	Repo     string
	Tag      string
}

func (r ImageRef) String() string {
	return r.Registry + "/" + r.Repo + ":" + r.Tag
}

// ParseImageRef splits "<registry-host>/<repo>:<tag>". The registry host is
// whatever precedes the first slash and must look like a host (contain a dot
// or a port), matching how docker distinguishes registries from repo paths.
func ParseImageRef(ref string) (ImageRef, error) {
	slash := strings.Index(ref, "/")
	if slash <= 0 {
		return ImageRef{}, fmt.Errorf("image ref %q needs <registry>/<repo>:<tag>", ref)
	}
	host := ref[:slash]
	if !strings.ContainsAny(host, ".:") {
		return ImageRef{}, fmt.Errorf("image ref %q does not start with a registry host", ref)
	}
	rest := ref[slash+1:]
	colon := strings.LastIndex(rest, ":")
	if colon <= 0 || colon == len(rest)-1 {
		return ImageRef{}, fmt.Errorf("image ref %q is missing an explicit :tag", ref)
	}
	repo, tag := rest[:colon], rest[colon+1:]
	if strings.Contains(repo, ":") {
		return ImageRef{}, fmt.Errorf("image ref %q has a malformed repository", ref)
	}
	return ImageRef{Registry: host, Repo: repo, Tag: tag}, nil
}

// ECRRegion extracts the region from an ECR registry host
// (<account>.dkr.ecr.<region>.amazonaws.com). The orchestrator needs it to
// mint an authorization token; non-ECR registries return an error so callers
// fail at preflight rather than mid-run.
func ECRRegion(registry string) (string, error) {
	parts := strings.Split(registry, ".")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "ecr" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("registry %q is not an ECR host; cannot derive a token region", registry)
}

const (
	manifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	configMediaType   = "application/vnd.oci.image.config.v1+json"
	layerMediaType    = "application/vnd.oci.image.layer.v1.tar"
)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

// Client talks to one repository on one registry. BaseURL exists so tests can
// point it at an httptest server; production callers leave it empty and get
// https://<registry>.
type Client struct {
	Ref     ImageRef
	Token   string // base64 basic-auth payload (ECR authorizationToken); empty for anonymous registries
	BaseURL string
	HTTP    *http.Client
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return "https://" + c.Ref.Registry
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	// No overall timeout: layer transfers are GB-scale and governed by the
	// caller's context instead.
	return &http.Client{}
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Basic "+c.Token)
	}
	return c.http().Do(req)
}

func (c *Client) url(parts ...string) string {
	return c.base() + "/v2/" + c.Ref.Repo + "/" + strings.Join(parts, "/")
}

func closeDiscard(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
}

func httpError(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("%s: registry returned %s: %s", op, resp.Status, strings.TrimSpace(string(body)))
}

// ManifestExists reports whether the pinned tag is already present. Push uses
// it for idempotence; fleet preflight uses it to fail before any EC2 spend.
func (c *Client) ManifestExists(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.url("manifests", c.Ref.Tag), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", manifestMediaType)
	resp, err := c.do(req)
	if err != nil {
		return false, err
	}
	defer closeDiscard(resp)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, httpError("head manifest", resp)
	}
}

func (c *Client) blobExists(ctx context.Context, digest string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.url("blobs", digest), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.do(req)
	if err != nil {
		return false, err
	}
	defer closeDiscard(resp)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, httpError("head blob", resp)
	}
}

// uploadBlob pushes one blob via the two-step upload flow (POST for a session
// URL, then a monolithic PUT with the digest). content must be an
// io.ReadSeeker so the PUT can carry an exact Content-Length and be replayed
// by net/http if the connection drops mid-handshake.
func (c *Client) uploadBlob(ctx context.Context, digest string, size int64, content io.ReadSeeker) error {
	exists, err := c.blobExists(ctx, digest)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("blobs", "uploads")+"/", nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusAccepted || location == "" {
		defer closeDiscard(resp)
		return httpError("start blob upload", resp)
	}
	closeDiscard(resp)
	if strings.HasPrefix(location, "/") {
		location = c.base() + location
	}
	sep := "?"
	if strings.Contains(location, "?") {
		sep = "&"
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return err
	}
	put, err := http.NewRequestWithContext(ctx, http.MethodPut, location+sep+"digest="+digest, io.NopCloser(content))
	if err != nil {
		return err
	}
	put.ContentLength = size
	put.Header.Set("Content-Type", "application/octet-stream")
	resp, err = c.do(put)
	if err != nil {
		return err
	}
	defer closeDiscard(resp)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return httpError("put blob "+digest, resp)
	}
	return nil
}

// PushDir publishes root as a single-layer image at the client's ref and
// returns the layer digest. Re-pushing an identical tree is a cheap no-op:
// the tag's manifest already exists and is left untouched.
func (c *Client) PushDir(ctx context.Context, root string, logf func(string, ...any)) (string, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	exists, err := c.ManifestExists(ctx)
	if err != nil {
		return "", err
	}
	if exists {
		logf("oci: %s already present; nothing to push", c.Ref)
		return "", nil
	}

	tarFile, err := os.CreateTemp("", "corpus-oci-*.tar")
	if err != nil {
		return "", err
	}
	defer os.Remove(tarFile.Name())
	defer tarFile.Close()
	layerDigest, layerSize, err := writeDeterministicTar(tarFile, root)
	if err != nil {
		return "", fmt.Errorf("tar %s: %w", root, err)
	}
	logf("oci: layer %s (%d bytes) from %s", layerDigest, layerSize, root)

	configBytes, err := json.Marshal(map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config":       map[string]any{},
		"rootfs": map[string]any{
			"type": "layers",
			// Uncompressed layer: diff_id and layer digest are the same bytes.
			"diff_ids": []string{layerDigest},
		},
	})
	if err != nil {
		return "", err
	}
	configDigest := digestOf(configBytes)

	if err := c.uploadBlob(ctx, layerDigest, layerSize, tarFile); err != nil {
		return "", fmt.Errorf("upload layer: %w", err)
	}
	if err := c.uploadBlob(ctx, configDigest, int64(len(configBytes)), bytes.NewReader(configBytes)); err != nil {
		return "", fmt.Errorf("upload config: %w", err)
	}

	manifestBytes, err := json.Marshal(manifest{
		SchemaVersion: 2,
		MediaType:     manifestMediaType,
		Config:        descriptor{MediaType: configMediaType, Digest: configDigest, Size: int64(len(configBytes))},
		Layers:        []descriptor{{MediaType: layerMediaType, Digest: layerDigest, Size: layerSize}},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.url("manifests", c.Ref.Tag), bytes.NewReader(manifestBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", manifestMediaType)
	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer closeDiscard(resp)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", httpError("put manifest", resp)
	}
	logf("oci: pushed %s", c.Ref)
	return layerDigest, nil
}

// FetchDir pulls the image into outDir. Extraction happens next to outDir in
// a ".partial" tree that is renamed into place only after the layer bytes
// hash to the manifest's digest, so a truncated or corrupted transfer can
// never masquerade as a corpus (the later `corpus verify` gate then checks
// semantic integrity on top).
func (c *Client) FetchDir(ctx context.Context, outDir string, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("manifests", c.Ref.Tag), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", manifestMediaType+", application/vnd.docker.distribution.manifest.v2+json")
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		defer closeDiscard(resp)
		return httpError("get manifest", resp)
	}
	var m manifest
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m)
	closeDiscard(resp)
	if err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if len(m.Layers) != 1 {
		return fmt.Errorf("corpus image must have exactly one layer, got %d", len(m.Layers))
	}
	layer := m.Layers[0]
	if layer.MediaType != layerMediaType {
		return fmt.Errorf("corpus layer has media type %q; expected an uncompressed tar (%s)", layer.MediaType, layerMediaType)
	}

	partial := outDir + ".partial"
	if err := os.RemoveAll(partial); err != nil {
		return err
	}
	if err := os.MkdirAll(partial, 0o755); err != nil {
		return err
	}

	const attempts = 3
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		lastErr = c.fetchLayer(ctx, layer, partial, logf)
		if lastErr == nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
		logf("oci: fetch attempt %d/%d failed: %v", attempt, attempts, lastErr)
		if err := os.RemoveAll(partial); err != nil {
			return err
		}
		if err := os.MkdirAll(partial, 0o755); err != nil {
			return err
		}
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	if lastErr != nil {
		os.RemoveAll(partial)
		return lastErr
	}
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	if err := os.Rename(partial, outDir); err != nil {
		return err
	}
	logf("oci: fetched %s into %s", c.Ref, outDir)
	return nil
}

func (c *Client) fetchLayer(ctx context.Context, layer descriptor, dest string, logf func(string, ...any)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("blobs", layer.Digest), nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer closeDiscard(resp)
	if resp.StatusCode != http.StatusOK {
		return httpError("get layer", resp)
	}
	hasher := sha256.New()
	counted := &countingReader{r: io.TeeReader(resp.Body, hasher)}
	if err := extractTar(counted, dest); err != nil {
		return err
	}
	// Drain trailing tar padding so the hash covers the full blob.
	if _, err := io.Copy(io.Discard, counted); err != nil {
		return err
	}
	got := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if got != layer.Digest {
		return fmt.Errorf("layer digest mismatch: manifest says %s, transfer hashed to %s (%d bytes)", layer.Digest, got, counted.n)
	}
	logf("oci: layer verified: %s (%d bytes)", got, counted.n)
	return nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// extractTar unpacks regular files and directories only, refusing entry names
// that would escape dest. The corpus contains nothing else; anything else in
// the stream means the image is not one of ours.
func extractTar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.FromSlash(hdr.Name)
		if filepath.IsAbs(name) || strings.Contains(name, "..") {
			return fmt.Errorf("tar entry %q escapes the extraction root", hdr.Name)
		}
		target := filepath.Join(dest, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("tar entry %q has unsupported type %d; corpus images hold only files and directories", hdr.Name, hdr.Typeflag)
		}
	}
}

// writeDeterministicTar streams root into w as a byte-stable tar: sorted
// walk order, zeroed times and ownership, normalized modes, USTAR format.
// Identical trees therefore produce identical layer digests, which is what
// makes push idempotence and digest-tags trustworthy.
func writeDeterministicTar(w io.Writer, root string) (digest string, size int64, err error) {
	var entries []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; corpus trees must be plain files", rel)
		}
		entries = append(entries, rel)
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(entries)

	hasher := sha256.New()
	counter := &countingWriter{w: io.MultiWriter(w, hasher)}
	tw := tar.NewWriter(counter)
	for _, rel := range entries {
		full := filepath.Join(root, rel)
		info, err := os.Lstat(full)
		if err != nil {
			return "", 0, err
		}
		hdr := &tar.Header{
			Name:    filepath.ToSlash(rel),
			ModTime: time.Unix(0, 0),
			Format:  tar.FormatUSTAR,
		}
		switch {
		case info.IsDir():
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
			hdr.Mode = 0o755
		case info.Mode().IsRegular():
			hdr.Typeflag = tar.TypeReg
			hdr.Size = info.Size()
			hdr.Mode = 0o644
			if info.Mode()&0o100 != 0 {
				hdr.Mode = 0o755
			}
		default:
			return "", 0, fmt.Errorf("%s has unsupported file type %v", rel, info.Mode().Type())
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", 0, err
		}
		if hdr.Typeflag == tar.TypeReg {
			f, err := os.Open(full)
			if err != nil {
				return "", 0, err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			if err != nil {
				return "", 0, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), counter.n, nil
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
