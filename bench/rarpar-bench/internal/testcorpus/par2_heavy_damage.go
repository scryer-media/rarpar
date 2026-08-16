package testcorpus

import (
	"context"
	"os"
	"path/filepath"
)

// heavyDamageTargetBytes aims the clip at 80 MiB so the archive holds ~1,200
// slices at 64 KiB and up to 500 damaged slices are recoverable.
const heavyDamageTargetBytes = 80 * 1024 * 1024

// generateHeavyDamage writes the rar5_heavy_damage set: an ~80 MB RAR5 archive
// with a 64 KiB-slice PAR2 set carrying 500 recovery blocks, which is what
// pushes PAR2 repair to its limits.
//
// The set is also imported by config/corpus.json under a pinned digest
// (par2-heavy-damage-28 / -250), so regenerating it moves those pins.
func generateHeavyDamage(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("heavy")
	if err != nil {
		return err
	}
	defer cleanup()
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	if err := e.video(ctx, heavyDamageTargetBytes, filepath.Join(work, "heavy_damage_clip.mkv")); err != nil {
		return err
	}
	if err := e.rar(e.rar5.Image, work, "").add(ctx,
		"-m5", "-ep1", "fixture_rar5_heavy_damage.rar", "heavy_damage_clip.mkv"); err != nil {
		return err
	}
	if err := e.par2Run(ctx, work, "",
		"create", "-q", "-s65536", "-c500", "-n10",
		"fixture_rar5_heavy_damage_repair.par2",
		"fixture_rar5_heavy_damage.rar"); err != nil {
		return err
	}

	out := e.par2Path("rar5_heavy_damage")
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	_, err = collect(work, out, "fixture_rar5_heavy_damage")
	return err
}
