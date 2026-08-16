package testcorpus

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// --------------------------------------------------------------- payloads ---

// deterministicBytes is the corpus's incompressible filler: SHA-256 in counter
// mode over a label. It replaces the `/dev/urandom` and Python `random` draws
// the shell recipes used, so a member's bytes are a function of its name and
// nothing else — same on every machine, same on every run, and still opaque
// enough that `-m0` stays the interesting case for a stored member.
//
// This is a keystream, not a digest, and it stays SHA-256 while the corpus's
// digests are BLAKE3. Its output *is* the checked-in fixture content — the
// ledger records BLAKE3 digests **of these bytes**, and tests/integration.rs
// pins payload prefixes drawn from it. Changing the hash here would rewrite
// every generated fixture on the next `test-corpus generate` and silently
// invalidate those assertions, which is a corpus revision, not a digest
// migration.
func deterministicBytes(label string, size int) []byte {
	out := make([]byte, 0, size+sha256.Size)
	seed := []byte(label)
	for counter := uint64(0); len(out) < size; counter++ {
		var suffix [8]byte
		binary.LittleEndian.PutUint64(suffix[:], counter)
		block := sha256.Sum256(append(seed, suffix[:]...))
		out = append(out, block[:]...)
	}
	return out[:size]
}

// splitmix64 is the corpus's choice PRNG: a fixed, fully specified algorithm,
// so "which word comes next" cannot drift with a standard-library change the
// way `math/rand`'s stream can.
type splitmix64 uint64

func (state *splitmix64) next() uint64 {
	*state += 0x9E3779B97F4A7C15
	value := uint64(*state)
	value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9
	value = (value ^ (value >> 27)) * 0x94D049BB133111EB
	return value ^ (value >> 31)
}

func (state *splitmix64) intn(n int) int { return int(state.next() % uint64(n)) }

// mosaic builds `size` bytes out of `pool` fixed chunks drawn from a
// deterministic stream, so LZ has real long-range matches to find: the first
// occurrence of each chunk is incompressible and every later one is a match.
// A sixteen-chunk pool of 4 KiB is what gives the solid LZ members their ~4.6:1
// ratio.
func mosaic(label string, size, chunk, pool int, prefix []byte) []byte {
	chunks := make([][]byte, pool)
	for index := range chunks {
		chunks[index] = deterministicBytes(fmt.Sprintf("%s/chunk/%d", label, index), chunk)
	}
	random := splitmix64(0x15D00 + uint64(len(label)))
	out := make([]byte, 0, size+chunk)
	out = append(out, prefix...)
	for len(out) < size {
		out = append(out, chunks[random.intn(pool)]...)
	}
	return out[:size]
}

// wordSalad is text PPMd models well: space-separated words from a fixed
// vocabulary, opened with a fixed phrase and cut to an exact length. Both are
// load-bearing — tests/integration.rs pins each PPMd member's first 24 bytes and
// its exact size.
func wordSalad(label string, size int, opening []string) []byte {
	vocabulary := []string{
		"archive", "block", "boundary", "checksum", "content", "decode", "escape",
		"extract", "header", "member", "model", "order", "parity", "range",
		"repair", "restart", "solid", "stream", "symbol", "usenet", "volume",
		"weaver", "window",
	}
	random := splitmix64(0x9A11D + uint64(len(label)))
	out := make([]byte, 0, size+16)
	for _, word := range opening {
		out = append(out, word...)
		out = append(out, ' ')
	}
	for len(out) < size {
		out = append(out, vocabulary[random.intn(len(vocabulary))]...)
		out = append(out, ' ')
	}
	return out[:size]
}

// ramp is the arithmetic input the multi-volume stored sets are built from.
func ramp(size int, step, offset byte) []byte {
	out := make([]byte, size)
	for index := range out {
		out[index] = byte(index)*step + offset
	}
	return out
}

// ------------------------------------------------------------- file system ---

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Replace rather than truncate in place: a hydrated checkout marks the .rar
	// fixtures lockable, and Git LFS makes lockable files read-only.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func copyFile(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return writeFile(destination, data)
}

// removeGlob deletes exactly the files a recipe owns before it writes them, so
// re-running one is a replacement and never a merge into a stale archive.
func removeGlob(patterns ...string) error {
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return err
		}
		for _, match := range matches {
			if err := os.Remove(match); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

// collect copies every file in `from` whose name starts with one of `prefixes`
// into `to`, replacing what is there.
func collect(from, to string, prefixes ...string) ([]string, error) {
	entries, err := os.ReadDir(from)
	if err != nil {
		return nil, err
	}
	var written []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matched := len(prefixes) == 0
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry.Name(), prefix) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if err := copyFile(filepath.Join(from, entry.Name()), filepath.Join(to, entry.Name())); err != nil {
			return nil, err
		}
		written = append(written, entry.Name())
	}
	sort.Strings(written)
	return written, nil
}

// countMatching is how a recipe asserts its own volume count: a set that stops
// splitting the way the ledger and the suites expect has to fail here, not two
// steps later in a path-set diff.
func countMatching(dir, prefix, suffix string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			count++
		}
	}
	return count, nil
}

func expectVolumes(dir, stem string, want int) error {
	got, err := countMatching(dir, stem+".part", ".rar")
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s: produced %d volume(s), expected %d", stem, got, want)
	}
	return nil
}

func workDir(name string) (string, func(), error) {
	// Absolute, because Docker mounts it: a relative path is not a bind source
	// Docker Desktop can resolve.
	dir, err := os.MkdirTemp("", "rarpar-testcorpus-"+name+"-")
	if err != nil {
		return "", nil, err
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return absolute, func() { os.RemoveAll(dir) }, nil
}

// ----------------------------------------------------------------- writers ---

// rarWriter is one pinned RARLAB image bound to one host directory.
//
// Every fixture in the corpus that is a RAR archive comes out of one of these:
// RARLAB's own writer, given inputs, with no post-processing of the produced
// bytes anywhere. Nothing here reads or links unrar.
type rarWriter struct {
	environment *env
	image       string
	host        string
	sub         string
}

func (e *env) rar(image, host, sub string) rarWriter {
	return rarWriter{environment: e, image: image, host: host, sub: sub}
}

// add runs `rar a …` inside the image. The host directory is mounted at /work
// and `sub` is the working directory under it, so every argument is a bare name
// and no host path ever reaches the command line.
func (w rarWriter) add(ctx context.Context, args ...string) error {
	work := "/work"
	if w.sub != "" {
		work = "/work/" + w.sub
	}
	command := []string{
		"run", "--rm", "--platform", "linux/amd64",
		"-v", w.host + ":/work", "-w", work, w.image, "a", "-idq",
	}
	command = append(command, args...)
	return runDocker(ctx, w.environment, command...)
}

// par2 runs the pinned par2cmdline-turbo image, whose ENTRYPOINT is `par2`.
func (e *env) par2Run(ctx context.Context, host, sub string, args ...string) error {
	work := "/work"
	if sub != "" {
		work = "/work/" + sub
	}
	command := []string{
		"run", "--rm", "--platform", "linux/amd64",
		"-v", host + ":/work", "-w", work, e.par2Image,
	}
	command = append(command, args...)
	return runDocker(ctx, e, command...)
}

func runDocker(ctx context.Context, e *env, args ...string) error {
	command := exec.CommandContext(ctx, e.docker, args...)
	command.Stdout = io.Discard
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", e.docker, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// video encodes one MKV member through the pinned FFmpeg encoder, in process.
func (e *env) video(ctx context.Context, targetBytes int64, out string) error {
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	// EncodeVideoPayload refuses to overwrite, which is the behaviour we want
	// everywhere else; here the destination is scratch we own.
	if err := os.Remove(out); err != nil && !os.IsNotExist(err) {
		return err
	}
	_, err := bench.EncodeVideoPayload(ctx, e.docker, e.harnessRoot(), e.lock, "ffmpeg-video", targetBytes, out)
	return err
}

func (e *env) harnessRoot() string {
	return filepath.Join(e.repoRoot, filepath.FromSlash("bench/rarpar-bench"))
}
