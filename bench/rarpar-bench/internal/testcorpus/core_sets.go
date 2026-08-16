package testcorpus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// hpPassword is the corpus-wide header-encryption password (`HP_PASSWORD` in
// the suites).
const hpPassword = "secretpass"

// generateCoreSets writes the plain and header-encrypted base sets, the stored
// multi-volume sets, and the RAR4 solid multi-member LZ set — the fixtures the
// fast integration, api-parity, failure-path, stored-layout and CLI suites open
// first.
//
// Shapes the suites pin, and where:
//   - rar4_store / rar5_store: one stored small.txt; extraction is compared
//     against originals/small.txt (tests/integration.rs), and the CLI smoke lane
//     asserts the member is named small.txt (tools/rarpar/tests/cli.rs).
//   - rar4_lz / rar5_lz: one -m3 compressible.txt, compared against
//     originals/compressible.txt.
//   - the four _hp_ sets: header encryption under the corpus HP password over
//     one 48-byte member whose exact bytes tests/integration.rs asserts.
//   - rar4_mv_store / rar5_mv_store: originals/binary.bin over five 64 KiB
//     volumes. tests/stored_layout_fixtures.rs asserts the whole-member CRC32
//     0xc790bff6 — a property of the ramp, not of this run.
//   - rar4_mv_video / rar5_mv_video: originals/test_clip.mkv over five 256 KiB
//     volumes (the volume size read back from the sets they replace).
//   - rar4_lz_solid_mv: three 307 200-byte solid -m3 members. Despite the name
//     it is a single-volume, multi-member archive. tests/integration.rs pins
//     each member's length and its first eight bytes, so those eight bytes are
//     written literally below.
func generateCoreSets(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("core")
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

	originals := e.unrarPath("originals")
	for _, name := range []string{"small.txt", "compressible.txt", "binary.bin", "test_clip.mkv"} {
		source := filepath.Join(originals, name)
		if _, err := os.Stat(source); err != nil {
			return fmt.Errorf("missing input originals/%s (the inputs recipe writes it): %w", name, err)
		}
		if err := copyFile(source, filepath.Join(src, name)); err != nil {
			return err
		}
	}

	// The member every `_hp_` set holds: named small.txt, because the CLI's
	// password-file test extracts it by that name (tools/rarpar/tests/cli.rs),
	// but carrying the 48-byte string tests/integration.rs compares the
	// extracted bytes to — for RAR4 and RAR5 alike. It is deliberately not the
	// same content as originals/small.txt, which the plain stored sets carry.
	if err := os.MkdirAll(filepath.Join(src, "hp"), 0o755); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(src, "hp", "small.txt"),
		[]byte("This is a test file for RAR4 header encryption.\n")); err != nil {
		return err
	}

	// The three solid LZ members: a mosaic of sixteen fixed 4 KiB chunks, so
	// -m3 has real long-range matches to find, each opening with the eight bytes
	// tests/integration.rs pins.
	prefixes := [][]byte{
		{0xA5, 0x4D, 0xCA, 0x18, 0x25, 0x30, 0xBB, 0x1D},
		{0x15, 0xA0, 0x84, 0x44, 0x1E, 0x46, 0xD2, 0xF9},
		{0x27, 0xB6, 0x16, 0xE8, 0xC4, 0xF9, 0x86, 0x30},
	}
	for index, prefix := range prefixes {
		name := fmt.Sprintf("lz_part%d.bin", index)
		label := fmt.Sprintf("core/lz_solid/%d", index)
		if err := writeFile(filepath.Join(src, name), mosaic(label, 307_200, 4096, 16, prefix)); err != nil {
			return err
		}
	}

	rar5 := e.rar(e.rar5.Image, work, "src")
	rar4 := e.rar(e.rar4.Image, work, "src")

	rar5Sets := [][]string{
		{"-m0", "../out/rar5_store.rar", "small.txt"},
		{"-m3", "../out/rar5_lz.rar", "compressible.txt"},
		{"-m0", "-ep1", "-hp" + hpPassword, "../out/rar5_hp_store.rar", "hp/small.txt"},
		{"-m3", "-ep1", "-hp" + hpPassword, "../out/rar5_hp_lz.rar", "hp/small.txt"},
		{"-m0", "-v64k", "../out/rar5_mv_store.rar", "binary.bin"},
		{"-m0", "-v256k", "../out/rar5_mv_video.rar", "test_clip.mkv"},
	}
	for _, args := range rar5Sets {
		if err := rar5.add(ctx, args...); err != nil {
			return err
		}
	}
	rar4Sets := [][]string{
		{"-ma4", "-m0", "../out/rar4_store.rar", "small.txt"},
		{"-ma4", "-m3", "../out/rar4_lz.rar", "compressible.txt"},
		{"-ma4", "-m0", "-ep1", "-hp" + hpPassword, "../out/rar4_hp_store.rar", "hp/small.txt"},
		{"-ma4", "-m3", "-ep1", "-hp" + hpPassword, "../out/rar4_hp_lz.rar", "hp/small.txt"},
		{"-ma4", "-m0", "-v64k", "../out/rar4_mv_store.rar", "binary.bin"},
		{"-ma4", "-m0", "-v256k", "../out/rar4_mv_video.rar", "test_clip.mkv"},
		{"-ma4", "-m3", "-s", "../out/rar4_lz_solid_mv.rar", "lz_part0.bin", "lz_part1.bin", "lz_part2.bin"},
	}
	for _, args := range rar4Sets {
		if err := rar4.add(ctx, args...); err != nil {
			return err
		}
	}
	for _, stem := range []string{"rar5_mv_store", "rar5_mv_video", "rar4_mv_store", "rar4_mv_video"} {
		if err := expectVolumes(out, stem, 5); err != nil {
			return err
		}
	}

	rar4Dir, rar5Dir := e.unrarPath("rar4"), e.unrarPath("rar5")
	if err := removeGlob(
		filepath.Join(rar4Dir, "rar4_store.rar"),
		filepath.Join(rar4Dir, "rar4_lz.rar"),
		filepath.Join(rar4Dir, "rar4_hp_store.rar"),
		filepath.Join(rar4Dir, "rar4_hp_lz.rar"),
		filepath.Join(rar4Dir, "rar4_mv_store.part*.rar"),
		filepath.Join(rar4Dir, "rar4_mv_video.part*.rar"),
		filepath.Join(rar4Dir, "rar4_lz_solid_mv.rar"),
		filepath.Join(rar5Dir, "rar5_store.rar"),
		filepath.Join(rar5Dir, "rar5_lz.rar"),
		filepath.Join(rar5Dir, "rar5_hp_store.rar"),
		filepath.Join(rar5Dir, "rar5_hp_lz.rar"),
		filepath.Join(rar5Dir, "rar5_mv_store.part*.rar"),
		filepath.Join(rar5Dir, "rar5_mv_video.part*.rar"),
	); err != nil {
		return err
	}
	if _, err := collect(out, rar4Dir, "rar4_"); err != nil {
		return err
	}
	_, err = collect(out, rar5Dir, "rar5_")
	return err
}
