package testcorpus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// Volume size chosen so the clip splits into exactly seven volumes, which is
	// the number of parts every consumer of these sets names. Seven 176 KiB
	// volumes hold about 1.26 MB and six hold about 1.08 MB, so the clip sits in
	// the middle of the window rather than on its edge. (The sets this replaces
	// used 160 KiB against a smaller clip from an earlier encoder recipe; at
	// that size this clip needs eight.)
	matrixVolumeSize = "176k"
	matrixVolumes    = 7
)

// generateGeneratedMatrix writes the eight-way multi-volume matrix consumed by
// tests/generated_multivolume_matrix.rs: two formats x two modes x plain and
// encrypted, over one clip.
func generateGeneratedMatrix(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("matrix")
	if err != nil {
		return err
	}
	defer cleanup()
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	clip := filepath.Join(work, "generated_matrix_clip.mkv")
	if err := e.video(ctx, clipTargetBytes, clip); err != nil {
		return err
	}
	if err := copyFile(clip, e.unrarPath("originals", "generated_matrix_clip.mkv")); err != nil {
		return err
	}

	for _, flavor := range []string{"rar5", "rar4"} {
		writer := e.rar(e.rar5.Image, work, "")
		var prefix []string
		if flavor == "rar4" {
			writer = e.rar(e.rar4.Image, work, "")
			prefix = []string{"-ma4"}
		}
		for _, mode := range []string{"store", "lz"} {
			modeFlag := "-m0"
			if mode == "lz" {
				modeFlag = "-m5"
			}
			for _, encryption := range []string{"plain", "enc"} {
				base := fmt.Sprintf("generated_matrix_%s_%s_%s", flavor, mode, encryption)
				args := append([]string{}, prefix...)
				args = append(args, modeFlag, "-ep1", "-v"+matrixVolumeSize)
				if encryption == "enc" {
					args = append(args, "-p"+testPassword)
				}
				args = append(args, base+".rar", "generated_matrix_clip.mkv")
				if err := writer.add(ctx, args...); err != nil {
					return err
				}
				// Fail here, not at the ledger diff, if the clip ever drifts far
				// enough that the volume size stops producing seven parts.
				if err := expectVolumes(work, base, matrixVolumes); err != nil {
					return err
				}
				destination := e.unrarPath(flavor)
				if err := removeGlob(filepath.Join(destination, base+"*.rar")); err != nil {
					return err
				}
				if _, err := collect(work, destination, base); err != nil {
					return err
				}
				if err := removeGlob(filepath.Join(work, base+"*.rar")); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
