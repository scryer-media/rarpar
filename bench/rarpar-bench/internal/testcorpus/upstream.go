package testcorpus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zeebo/blake3"
)

// LedgerFile is the provenance ledger, relative to the repository root.
const LedgerFile = "test-corpus/sources.json"

// Ledger is the part of test-corpus/sources.json this package reads: the
// upstream table, the generator table (which its own test holds the unit list
// to), and the files.
type Ledger struct {
	Generators map[string]LedgerGenerator `json:"generators"`
	Upstreams  map[string]LedgerUpstream  `json:"upstreams"`
	Files      []LedgerFileEntry          `json:"files"`
}

type LedgerGenerator struct {
	Path       string   `json:"path"`
	Toolchains []string `json:"toolchains"`
}

type LedgerUpstream struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Encoding   string `json:"encoding"`
	Private    bool   `json:"private"`
}

type LedgerFileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	BLAKE3 string `json:"blake3"`
	Source struct {
		Kind      string `json:"kind"`
		Generator string `json:"generator"`
		Upstream  string `json:"upstream"`
		Path      string `json:"path"`
	} `json:"source"`
}

// LoadLedger reads the provenance ledger.
func LoadLedger(path string) (Ledger, error) {
	var ledger Ledger
	raw, err := os.ReadFile(path)
	if err != nil {
		return ledger, err
	}
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return ledger, fmt.Errorf("decode %s: %w", path, err)
	}
	return ledger, nil
}

// fetchUpstreams places every upstream import in the tree, from its pinned
// commit.
//
// This is what makes an upstream a *source* rather than a check: the bytes come
// from the commit the ledger pins, not from whatever was already on disk. They
// still have to hash to what the ledger records — an upstream pinned by commit
// is immutable, so a mismatch is a broken pin, never a new revision.
func fetchUpstreams(ctx context.Context, e *env, jobs int) (int, error) {
	ledger, err := LoadLedger(filepath.Join(e.repoRoot, filepath.FromSlash(LedgerFile)))
	if err != nil {
		return 0, err
	}
	type job struct {
		entry    LedgerFileEntry
		upstream LedgerUpstream
	}
	var pending []job
	for _, entry := range ledger.Files {
		if entry.Source.Kind != "upstream" {
			continue
		}
		upstream, declared := ledger.Upstreams[entry.Source.Upstream]
		if !declared {
			return 0, fmt.Errorf("%s: upstream %q is not declared", entry.Path, entry.Source.Upstream)
		}
		if upstream.Private {
			return 0, fmt.Errorf(
				"%s: upstream %q is private, so the corpus cannot be generated from it; give the fixture a recipe or make the upstream public",
				entry.Path, entry.Source.Upstream)
		}
		pending = append(pending, job{entry: entry, upstream: upstream})
	}
	if len(pending) == 0 {
		return 0, nil
	}

	client := &http.Client{Timeout: 2 * time.Minute}
	if jobs < 1 {
		jobs = 1
	}
	if jobs > 8 {
		jobs = 8
	}
	queue := make(chan job)
	problems := make(chan string, len(pending))
	var workers sync.WaitGroup
	for range jobs {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range queue {
				if err := fetchOne(ctx, client, e, item.entry, item.upstream); err != nil {
					problems <- fmt.Sprintf("%s: %v", item.entry.Path, err)
				}
			}
		}()
	}
	for _, item := range pending {
		queue <- item
	}
	close(queue)
	workers.Wait()
	close(problems)
	var collected []string
	for problem := range problems {
		collected = append(collected, problem)
	}
	if len(collected) > 0 {
		sort.Strings(collected)
		return 0, fmt.Errorf("%d upstream import(s) could not be fetched\n  %s",
			len(collected), strings.Join(collected, "\n  "))
	}
	return len(pending), nil
}

func fetchOne(ctx context.Context, client *http.Client, e *env, entry LedgerFileEntry, upstream LedgerUpstream) error {
	url, err := rawURL(upstream, entry.Source.Path)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d for %s", response.StatusCode, url)
	}
	fetched, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	var data []byte
	switch upstream.Encoding {
	case "raw":
		data = fetched
	case "uuencode":
		data, err = uudecode(fetched)
		if err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
	default:
		return fmt.Errorf("cannot decode upstream encoding %q", upstream.Encoding)
	}
	digest := blake3.Sum256(data)
	if hex.EncodeToString(digest[:]) != entry.BLAKE3 || int64(len(data)) != entry.Size {
		return fmt.Errorf(
			"bytes at %s hash to %s (%d bytes); the ledger pins %s (%d bytes). An upstream pinned by commit is immutable: fix the pin, never the digest",
			url, hex.EncodeToString(digest[:]), len(data), entry.BLAKE3, entry.Size)
	}
	return writeFile(filepath.Join(e.repoRoot, filepath.FromSlash(entry.Path)), data)
}

// rawURL is the raw-content URL for a file at a pinned commit of a GitHub
// repository.
func rawURL(upstream LedgerUpstream, path string) (string, error) {
	repository := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(upstream.Repository, "/"), ".git"), "/")
	slug, found := strings.CutPrefix(repository, "https://github.com/")
	if !found {
		return "", fmt.Errorf("upstream %s is not a github.com repository; add a fetcher before generating from it", upstream.Repository)
	}
	if strings.Count(slug, "/") != 1 {
		return "", fmt.Errorf("upstream repository %q is not owner/repo", upstream.Repository)
	}
	return "https://raw.githubusercontent.com/" + slug + "/" + upstream.Commit + "/" + path, nil
}

// uudecode decodes one uuencoded file — the classic `begin <mode> <name>` … `end`
// form libarchive stores its test archives in. Only the first member is decoded.
func uudecode(text []byte) ([]byte, error) {
	lines := strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n")
	start := -1
	for index, line := range lines {
		if strings.HasPrefix(line, "begin ") {
			start = index + 1
			break
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("uuencoded input has no begin line")
	}
	var out []byte
	for _, line := range lines[start:] {
		if line == "end" {
			return out, nil
		}
		if line == "" {
			continue
		}
		length := int((line[0] - 32) & 0x3f)
		if length == 0 {
			// A "`" line marks the end of data.
			continue
		}
		body := []byte(line[1:])
		decoded := make([]byte, 0, len(body)/4*3+3)
		for offset := 0; offset < len(body); offset += 4 {
			var quad [4]byte
			for index := range 4 {
				if offset+index < len(body) {
					quad[index] = (body[offset+index] - 32) & 0x3f
				}
			}
			decoded = append(decoded,
				quad[0]<<2|quad[1]>>4,
				quad[1]<<4|quad[2]>>2,
				quad[2]<<6|quad[3])
		}
		if len(decoded) < length {
			return nil, fmt.Errorf("uuencoded line is shorter than its declared length")
		}
		out = append(out, decoded[:length]...)
	}
	return nil, fmt.Errorf("uuencoded input has no end line")
}
