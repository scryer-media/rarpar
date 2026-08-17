package testcorpus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// generateRecoveryVolumes writes the three standalone `.rev` recovery-volume
// sets driven by tests/integration.rs, src/recovery.rs and the CLI's repair lane.
//
// All are `rar a … -rv2`, which writes the data volumes and two recovery
// volumes in one pass — RARLAB's writer produces the `.rev` files, exactly as it
// produces the `.rar` ones. The `.rev` format follows the *archive* format,
// which is what makes the RAR4 set the interesting one:
//
//   - rar3_recovery_volumes comes from the rarlab-6.24 image with -ma4, so the
//     archive is RAR 2.9-format and rar writes RAR 3.x-style recovery volumes:
//     no RAR signature at all, the parity followed by a three-byte
//     (data_count-1, rec_count-1, rec_position-1) footer and a CRC32. That is
//     the "new-style footer" branch in src/recovery.rs, reached because the
//     volume names carry no _<data>_<rec>_<pos> suffix. 6.24 rather than the
//     3.93/4.20 images because it writes the same format and is the RAR4 writer
//     the rest of the corpus already uses.
//
//   - rar5_recovery_volumes comes from rarlab-7.20, so the .rev files carry the
//     RAR5 `Rar!\x1aRev` signature and a proper header.
//
//   - rar3_recovery_volumes_large is the same RAR4-format shape at a size that
//     matters: 1 MiB volumes, so one reconstruction pass decodes about a
//     million byte columns and the RS decode runs at real depth through
//     rayon's split recursion, with the coder reused across a split's columns.
//     The 1 KiB set cannot reach that path; it decodes 1024 columns and is
//     done. This is the shape whose restore aborted an embedder with a stack
//     overflow under fat LTO before unrar-rs 0.5.3, and the size at which the
//     0.5.1 build still reproduces it — 512 KiB volumes do too, so 1 MiB is
//     comfortably past the threshold rather than on it.
//
// rar names recovery volumes from the first archive name onwards, so two of them
// are .part1.rev and .part2.rev (.part01/.part02 for the ten-volume RAR5 set).
//
// The small payloads are the exact arithmetic ramps the sets they replace hold,
// verified byte for byte against them; the large one is another ramp with its
// own step and offset so no two sets share bytes.
func generateRecoveryVolumes(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("rev")
	if err != nil {
		return err
	}
	defer cleanup()
	rar4Work := filepath.Join(work, "rar4")
	rar4LargeWork := filepath.Join(work, "rar4-large")
	rar5Work := filepath.Join(work, "rar5")
	for _, dir := range []string{rar4Work, rar4LargeWork, rar5Work} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	// RAR4 set: 4096 bytes of (i * 17 + 23) mod 256.
	if err := writeFile(filepath.Join(rar4Work, "payload.bin"), ramp(4096, 17, 23)); err != nil {
		return err
	}
	// RAR5 set: 8192 bytes of (17 + 51*(i/8) + 37*(i%8)) mod 256 — an eight-byte
	// inner ramp whose per-group base advances by 51.
	payload5 := make([]byte, 8192)
	for index := range payload5 {
		payload5[index] = byte(17 + 51*(index/8) + 37*(index%8))
	}
	if err := writeFile(filepath.Join(rar5Work, "payload.bin"), payload5); err != nil {
		return err
	}

	// RAR4 large set: 3.5 MiB of (i * 29 + 7) mod 256, in 1 MiB volumes — four
	// data volumes (the last one half full) and two recovery volumes.
	if err := writeFile(filepath.Join(rar4LargeWork, "payload.bin"), ramp(7*512*1024, 29, 7)); err != nil {
		return err
	}

	if err := e.rar(e.rar4.Image, work, "rar4").add(ctx,
		"-ma4", "-m0", "-v1k", "-rv2", "rar3_recovery_volumes.rar", "payload.bin"); err != nil {
		return err
	}
	if err := e.rar(e.rar4.Image, work, "rar4-large").add(ctx,
		"-ma4", "-m0", "-v1m", "-rv2", "rar3_recovery_volumes_large.rar", "payload.bin"); err != nil {
		return err
	}
	if err := e.rar(e.rar5.Image, work, "rar5").add(ctx,
		"-m0", "-v1k", "-rv2", "rar5_recovery_volumes.rar", "payload.bin"); err != nil {
		return err
	}

	for _, want := range []struct {
		dir, stem, suffix string
		count             int
	}{
		{rar4Work, "rar3_recovery_volumes.part", ".rar", 5},
		{rar4Work, "rar3_recovery_volumes.part", ".rev", 2},
		{rar4LargeWork, "rar3_recovery_volumes_large.part", ".rar", 4},
		{rar4LargeWork, "rar3_recovery_volumes_large.part", ".rev", 2},
		{rar5Work, "rar5_recovery_volumes.part", ".rar", 10},
		{rar5Work, "rar5_recovery_volumes.part", ".rev", 2},
	} {
		got, err := countMatching(want.dir, want.stem, want.suffix)
		if err != nil {
			return err
		}
		if got != want.count {
			return fmt.Errorf("%s*%s: produced %d file(s), expected %d", want.stem, want.suffix, got, want.count)
		}
	}

	rar4Dir, rar5Dir := e.unrarPath("rar4"), e.unrarPath("rar5")
	if err := removeGlob(
		filepath.Join(rar4Dir, "rar3_recovery_volumes.part*.rar"),
		filepath.Join(rar4Dir, "rar3_recovery_volumes.part*.rev"),
		filepath.Join(rar4Dir, "rar3_recovery_volumes_large.part*.rar"),
		filepath.Join(rar4Dir, "rar3_recovery_volumes_large.part*.rev"),
		filepath.Join(rar5Dir, "rar5_recovery_volumes.part*.rar"),
		filepath.Join(rar5Dir, "rar5_recovery_volumes.part*.rev"),
	); err != nil {
		return err
	}
	if _, err := collect(rar4Work, rar4Dir, "rar3_recovery_volumes."); err != nil {
		return err
	}
	if _, err := collect(rar4LargeWork, rar4Dir, "rar3_recovery_volumes_large."); err != nil {
		return err
	}
	_, err = collect(rar5Work, rar5Dir, "rar5_recovery_volumes.")
	return err
}
