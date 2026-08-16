package testcorpus

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

// generatePPMdSolid writes the two RAR4 PPMd correctness fixtures.
//
//   - rar4_ppm_solid_restart.rar — one 1 600 000-byte member compressed with a
//     deliberately small PPMd heap, so the sub-allocator restarts several times
//     mid-stream. tests/integration.rs pins the member's length, that it is all
//     ASCII, and its first sixteen bytes.
//   - rar4_ppm_solid_mv.rar — three solid PPMd members, so the range coder's
//     registers have to survive a member boundary.
//     test_rar4_ppmd_solid_multi_member_boundaries pins each member's exact
//     length and its first 24 bytes, which is why the word salad starts from a
//     fixed opening phrase and is cut to an exact length.
//
// Both are also imported by config/corpus.json (rar4-ppmd-restart,
// rar4-ppmd-solid-multi-member) under a pinned digest, so regenerating them
// moves those pins: `test-corpus bench-pins` prints the new values.
//
// The writer is rarlab-6.24 — the newest RARLAB release that still writes RAR4.
// ppmd_perf writes the *performance* PPMd corpora; this recipe writes the
// correctness ones.
func generatePPMdSolid(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("ppmd")
	if err != nil {
		return err
	}
	defer cleanup()
	src := filepath.Join(work, "src")
	out := filepath.Join(work, "out")
	for _, dir := range []string{src, out} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	restart := base64Stream("ppmd/restart", 1_600_000)
	if err := writeFile(filepath.Join(src, "ppm_restart_src.txt"), restart); err != nil {
		return err
	}

	members := []struct {
		name    string
		size    int
		opening []string
	}{
		{"ppm_part0.txt", 2_881_486, []string{"usenet", "weaver", "stream", "solid"}},
		{"ppm_part1.txt", 2_880_210, []string{"solid", "archive", "boundary", "window"}},
		{"ppm_part2.txt", 2_881_867, []string{"window", "boundary", "solid", "decode"}},
	}
	for _, member := range members {
		text := wordSalad("ppmd/"+member.name, member.size, member.opening)
		if len(text) != member.size {
			return fmt.Errorf("%s: produced %d bytes, expected %d", member.name, len(text), member.size)
		}
		if err := writeFile(filepath.Join(src, member.name), text); err != nil {
			return err
		}
	}

	rar4 := e.rar(e.rar4.Image, work, "src")
	if err := rar4.add(ctx, "-ma4", "-m5", "-mc16:1t+", "-md4m", "-ep",
		"../out/rar4_ppm_solid_restart.rar", "ppm_restart_src.txt"); err != nil {
		return err
	}
	if err := rar4.add(ctx, "-ma4", "-m5", "-mc16:1t+", "-md4m", "-s", "-ep",
		"../out/rar4_ppm_solid_mv.rar",
		"ppm_part0.txt", "ppm_part1.txt", "ppm_part2.txt"); err != nil {
		return err
	}

	rar4Dir := e.unrarPath("rar4")
	if err := removeGlob(
		filepath.Join(rar4Dir, "rar4_ppm_solid_restart.rar"),
		filepath.Join(rar4Dir, "rar4_ppm_solid_mv.rar"),
	); err != nil {
		return err
	}
	_, err = collect(out, rar4Dir, "rar4_ppm_solid_")
	return err
}

// base64Stream is the restart member's payload: base64 over a deterministic
// byte stream, so every byte is printable ASCII (which tests/integration.rs
// asserts) and the text is only as compressible as base64 of high-entropy input
// — which is what keeps the PPMd model working hard enough to exhaust a small
// heap.
//
// SHA-256 here is a keystream, not a digest: tests/integration.rs pins this
// member's first sixteen characters, so the hash is part of the fixture's
// content and does not move with the corpus's digests (see deterministicBytes
// in payload.go).
func base64Stream(label string, size int) []byte {
	// 3 raw bytes encode to 4 characters, so ask for exactly the raw length the
	// target implies and the result lands on it without padding.
	raw := make([]byte, 0, size/4*3+sha256.Size)
	seed := []byte(label)
	for counter := uint64(0); len(raw) < size/4*3; counter++ {
		var suffix [8]byte
		binary.LittleEndian.PutUint64(suffix[:], counter)
		block := sha256.Sum256(append(seed, suffix[:]...))
		raw = append(raw, block[:]...)
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(size/4*3))
	base64.StdEncoding.Encode(encoded, raw[:size/4*3])
	return encoded[:size]
}
