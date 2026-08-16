package testcorpus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// generateRealWorld writes the PAR2 repair fixtures consumed by
// tests/real_world_generated.rs: one plain RAR5 LZ set and one encrypted RAR4
// stored set, each with a PAR2 recovery set over its volumes.
//
// The MKV member comes from the pinned encoder, the RAR sets from the pinned
// RARLAB images, and the PAR2 sets from the pinned par2cmdline-turbo image.
func generateRealWorld(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("realworld")
	if err != nil {
		return err
	}
	defer cleanup()
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	clip := filepath.Join(work, "generated_sample_clip.mkv")
	if err := e.video(ctx, clipTargetBytes, clip); err != nil {
		return err
	}
	if err := copyFile(clip, e.par2Path("source", "generated_sample_clip.mkv")); err != nil {
		return err
	}

	// The member name is per set, not a shared scratch name: the CLI's
	// rediscover-after-repair test extracts `rar5_lz_plain_clip.mkv` by name
	// (tools/rarpar/tests/cli.rs).
	sets := []struct {
		writer   rarWriter
		prefix   []string
		modeFlag string
		password string
		stem     string
		member   string
		outDir   string
		volumes  int
	}{
		{e.rar(e.rar5.Image, work, ""), nil, "-m5", "", "fixture_rar5_lz_plain", "rar5_lz_plain_clip.mkv", e.par2Path("rar5_lz_plain"), 6},
		{e.rar(e.rar4.Image, work, ""), []string{"-ma4"}, "-m0", testPassword, "fixture_rar4_store_enc", "rar4_store_enc_clip.mkv", e.par2Path("rar4_store_enc"), 6},
	}
	for _, set := range sets {
		if err := copyFile(clip, filepath.Join(work, set.member)); err != nil {
			return err
		}
		args := append([]string{}, set.prefix...)
		args = append(args, set.modeFlag, "-ep1", "-v192k")
		if set.password != "" {
			args = append(args, "-p"+set.password)
		}
		args = append(args, set.stem+".rar", set.member)
		if err := set.writer.add(ctx, args...); err != nil {
			return err
		}
		if err := expectVolumes(work, set.stem, set.volumes); err != nil {
			return err
		}
		volumes, err := collectNames(work, set.stem)
		if err != nil {
			return err
		}
		par2Args := append([]string{"create", "-q", "-s65536", "-c12", "-n6", set.stem + "_repair.par2"}, volumes...)
		if err := e.par2Run(ctx, work, "", par2Args...); err != nil {
			return err
		}
		if err := os.RemoveAll(set.outDir); err != nil {
			return err
		}
		if err := os.MkdirAll(set.outDir, 0o755); err != nil {
			return err
		}
		if _, err := collect(work, set.outDir, set.stem); err != nil {
			return err
		}
		if err := removeGlob(
			filepath.Join(work, set.stem+"*.rar"),
			filepath.Join(work, set.stem+"_repair*.par2"),
			filepath.Join(work, set.member),
		); err != nil {
			return err
		}
	}
	return nil
}

// collectNames lists, in sorted order, the archive volumes a set produced — the
// argument list the PAR2 create step protects.
func collectNames(dir, stem string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, stem+"*.rar"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%s: no volumes to protect", stem)
	}
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, filepath.Base(match))
	}
	return names, nil
}
