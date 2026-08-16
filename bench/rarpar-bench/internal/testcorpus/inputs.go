package testcorpus

import (
	"context"
	"path/filepath"
)

// clipTargetBytes is the target every ~1.1 MB corpus clip is encoded at.
//
// `payload video` turns a target into whole seconds of encode, so anything
// below two seconds' worth produces the same one-second clip; the number only
// has to stay under that. The resulting size is load-bearing, because it decides
// how the sets that carry it split: it has to land above four and at or below
// five volumes' worth for both -v256k (core_sets, ~261 966 B of payload per
// volume) and -v240k (encrypted, ~245 582 B) — between 1 047 865 and 1 227 910
// bytes.
const clipTargetBytes = 1_100_000

// generateInputs writes the two binary inputs the rest of the corpus is built
// from.
//
// `binary.bin` is exactly the (i mod 256) ramp over 262 144 bytes — verified
// byte for byte against the bytes it replaces, so this input really is
// reproducible and needs no pinned tool at all. `test_clip.mkv` comes from the
// pinned FFmpeg encoder, in process. It is the same encode generated_matrix
// uses for its clip, so the two inputs share their bytes and therefore their
// content-addressed object.
func generateInputs(ctx context.Context, e *env) error {
	originals := e.unrarPath("originals")
	if err := writeFile(filepath.Join(originals, "binary.bin"), ramp(262_144, 1, 0)); err != nil {
		return err
	}

	work, cleanup, err := workDir("inputs")
	if err != nil {
		return err
	}
	defer cleanup()
	clip := filepath.Join(work, "test_clip.mkv")
	if err := e.video(ctx, clipTargetBytes, clip); err != nil {
		return err
	}
	return copyFile(clip, filepath.Join(originals, "test_clip.mkv"))
}
