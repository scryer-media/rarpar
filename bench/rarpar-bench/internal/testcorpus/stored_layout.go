package testcorpus

import (
	"context"
	"os"
	"path/filepath"
)

// generateStoredLayout writes the stored-layout sets consumed by
// tests/stored_layout_fixtures.rs, plus the multi-member multi-volume sets
// tests/integration.rs uses for volume addressing.
//
// These sets exist because the rest of the corpus does not reach them: a chain
// longer than twenty volumes, a recovery record on every volume of a stored set,
// the -htb BLAKE2 switch, a -p encrypted stored set holding more than one
// member, and its plain and solid twins — the only sets here whose second member
// starts past the set's first volume.
//
// The writer is rarlab-7.20 throughout. 7.20 dropped -ma4 and -vn, so it cannot
// write RAR4 archives or old-style (.r00) volume names; the RAR4 sets come from
// rarlab-6.24 elsewhere.
//
// The payloads are incompressible fixed streams. Stored members must not be
// shrinkable, or -m0 stops being the interesting case, and fixed bytes keep the
// member sizes and split boundaries stable across regenerations. The sizes are
// what the suite pins: 48 KiB over 2 KiB volumes is 27 parts, 20 001 B is
// fifteen bytes short of an AES block and 12 288 B is exactly on one, and the two
// together over 4 KiB volumes put the second member's start in the set's sixth
// volume.
func generateStoredLayout(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("layout")
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

	blobs := []struct {
		name string
		size int
	}{
		{"Silver.Horizon.S01E04.mkv", 48 * 1024},
		{"Silver.Horizon.S01E05.mkv", 16 * 1024},
		{"Silver.Horizon.S01E06.mkv", 4 * 1024},
		{"Silver.Horizon.S01E07.mkv", 3 * 1024},
		// AES-CBC pads a member's plaintext up to a whole block, so these two
		// sit on opposite sides of that boundary: 20 001 is fifteen bytes short
		// and 12 288 is exactly on one. A set holding both proves `align16` in
		// the same archive as the case where it is a no-op.
		{"Silver.Horizon.S02E01.mkv", 20_001},
		{"Silver.Horizon.S02E02.mkv", 12 * 1024},
	}
	for _, blob := range blobs {
		if err := writeFile(filepath.Join(src, blob.name),
			deterministicBytes("stored_layout/"+blob.name, blob.size)); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(src, "Silver.Horizon.S01E07.nfo"),
		[]byte("Silver Horizon season one, episode seven.\n")); err != nil {
		return err
	}

	rar5 := e.rar(e.rar5.Image, work, "src")
	sets := [][]string{
		// [1/9] Long chain: 48 KiB across 2 KiB volumes -> 27 parts. The first
		// part is one byte larger than the middle ones and the last is much
		// smaller, so a prefix sum over the chain cannot be mistaken for
		// `index * part_size`.
		{"-m0", "-v2k", "../out/rar5_mv_store_long.rar", "Silver.Horizon.S01E04.mkv"},
		// [2/9] Recovery record on every volume of a stored multi-volume set:
		// RR service data that must land in the envelope without disturbing the
		// member mapping. 16 KiB across 4 KiB volumes -> 6 parts.
		{"-m0", "-rr5p", "-v4k", "../out/rar5_mv_store_rr.rar", "Silver.Horizon.S01E05.mkv"},
		// [3/9] BLAKE2 across a split chain: non-final parts state a packed
		// BLAKE2sp and no packed CRC32. 4 KiB across 1 KiB volumes -> 6 parts.
		{"-m0", "-htb", "-v1k", "../out/rar5_mv_store_blake2.rar", "Silver.Horizon.S01E06.mkv"},
		// [4/9] and [5/9] The BLAKE2 pair: identical members and layout,
		// differing only in the hash switch. Together they establish that -htb
		// replaces the CRC32 rather than adding to it.
		{"-m0", "-htb", "../out/rar5_store_blake2.rar", "Silver.Horizon.S01E07.mkv", "Silver.Horizon.S01E07.nfo"},
		{"-m0", "../out/rar5_store_crc32_control.rar", "Silver.Horizon.S01E07.mkv", "Silver.Horizon.S01E07.nfo"},
		// [6/9] and [7/9] Encrypted (-p) stored sets — file data encrypted,
		// headers plain — holding the same two members, once split across
		// volumes and once in a single volume. Two members mean two independent
		// CBC chains (RAR states a per-member IV) and a volume that carries the
		// tail of one member and the head of the next.
		{"-m0", "-p" + testPassword, "-v4k", "../out/rar5_enc_mv_store_pair.rar", "Silver.Horizon.S02E01.mkv", "Silver.Horizon.S02E02.mkv"},
		{"-m0", "-p" + testPassword, "../out/rar5_enc_store_pair.rar", "Silver.Horizon.S02E01.mkv", "Silver.Horizon.S02E02.mkv"},
		// [8/9] and [9/9] The plain and solid twins of that pair: the same two
		// members and the same 4 KiB volumes, so the second member again begins
		// in the set's sixth volume. -s adds the case where reaching the second
		// member has to decode the first, addressing its volumes too.
		{"-m0", "-v4k", "../out/rar5_mv_store_pair.rar", "Silver.Horizon.S02E01.mkv", "Silver.Horizon.S02E02.mkv"},
		{"-m5", "-s", "-v4k", "../out/rar5_mv_solid_pair.rar", "Silver.Horizon.S02E01.mkv", "Silver.Horizon.S02E02.mkv"},
	}
	for _, args := range sets {
		if err := rar5.add(ctx, args...); err != nil {
			return err
		}
	}
	for _, want := range []struct {
		stem  string
		count int
	}{
		{"rar5_mv_store_long", 27},
		{"rar5_mv_store_rr", 6},
		{"rar5_mv_store_blake2", 6},
		{"rar5_enc_mv_store_pair", 9},
		{"rar5_mv_store_pair", 9},
		{"rar5_mv_solid_pair", 9},
	} {
		if err := expectVolumes(out, want.stem, want.count); err != nil {
			return err
		}
	}

	rar5Dir := e.unrarPath("rar5")
	if err := removeGlob(
		filepath.Join(rar5Dir, "rar5_mv_store_long.part*.rar"),
		filepath.Join(rar5Dir, "rar5_mv_store_rr.part*.rar"),
		filepath.Join(rar5Dir, "rar5_mv_store_blake2.part*.rar"),
		filepath.Join(rar5Dir, "rar5_store_blake2.rar"),
		filepath.Join(rar5Dir, "rar5_store_crc32_control.rar"),
		filepath.Join(rar5Dir, "rar5_enc_mv_store_pair.part*.rar"),
		filepath.Join(rar5Dir, "rar5_enc_store_pair.rar"),
		filepath.Join(rar5Dir, "rar5_mv_store_pair.part*.rar"),
		filepath.Join(rar5Dir, "rar5_mv_solid_pair.part*.rar"),
	); err != nil {
		return err
	}
	_, err = collect(out, rar5Dir, "rar5_")
	return err
}
