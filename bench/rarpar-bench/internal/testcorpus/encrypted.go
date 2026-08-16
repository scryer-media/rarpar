package testcorpus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// testPassword is the corpus-wide `-p` password (`TEST_PASSWORD` in the suites).
const testPassword = "testpass123"

// generateEncrypted writes the four `-p` sets per format: data-only encryption,
// so the headers parse without a password and the layout classifies the set
// before anything is decrypted.
//
// Every run draws a fresh KDF salt and IV, so these are shape-identical and
// never byte-identical across revisions.
func generateEncrypted(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("enc")
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

	rar5 := e.rar(e.rar5.Image, work, "src")
	rar4 := e.rar(e.rar4.Image, work, "src")

	rar5Sets := [][]string{
		{"-m0", "-p" + testPassword, "../out/rar5_enc_store.rar", "small.txt"},
		{"-m3", "-p" + testPassword, "../out/rar5_enc_lz.rar", "compressible.txt"},
		{"-m0", "-v55k", "-p" + testPassword, "../out/rar5_enc_mv_store.rar", "binary.bin"},
		{"-m0", "-v240k", "-p" + testPassword, "../out/rar5_enc_mv_video.rar", "test_clip.mkv"},
	}
	for _, args := range rar5Sets {
		if err := rar5.add(ctx, args...); err != nil {
			return err
		}
	}
	rar4Sets := [][]string{
		{"-ma4", "-m0", "-p" + testPassword, "../out/rar4_enc_store.rar", "small.txt"},
		{"-ma4", "-m3", "-p" + testPassword, "../out/rar4_enc_lz.rar", "compressible.txt"},
		{"-ma4", "-m0", "-v55k", "-p" + testPassword, "../out/rar4_enc_mv_store.rar", "binary.bin"},
		{"-ma4", "-m0", "-v240k", "-p" + testPassword, "../out/rar4_enc_mv_video.rar", "test_clip.mkv"},
	}
	for _, args := range rar4Sets {
		if err := rar4.add(ctx, args...); err != nil {
			return err
		}
	}
	for _, stem := range []string{
		"rar5_enc_mv_store", "rar5_enc_mv_video", "rar4_enc_mv_store", "rar4_enc_mv_video",
	} {
		if err := expectVolumes(out, stem, 5); err != nil {
			return err
		}
	}

	rar4Dir, rar5Dir := e.unrarPath("rar4"), e.unrarPath("rar5")
	// Not `rar5_enc_*`: that glob would also take stored_layout's
	// rar5_enc_mv_store_pair and rar5_enc_store_pair sets.
	if err := removeGlob(
		filepath.Join(rar5Dir, "rar5_enc_store.rar"),
		filepath.Join(rar5Dir, "rar5_enc_lz.rar"),
		filepath.Join(rar5Dir, "rar5_enc_mv_store.part*.rar"),
		filepath.Join(rar5Dir, "rar5_enc_mv_video.part*.rar"),
		filepath.Join(rar4Dir, "rar4_enc_store.rar"),
		filepath.Join(rar4Dir, "rar4_enc_lz.rar"),
		filepath.Join(rar4Dir, "rar4_enc_mv_store.part*.rar"),
		filepath.Join(rar4Dir, "rar4_enc_mv_video.part*.rar"),
	); err != nil {
		return err
	}
	if _, err := collect(out, rar4Dir, "rar4_"); err != nil {
		return err
	}
	_, err = collect(out, rar5Dir, "rar5_")
	return err
}
