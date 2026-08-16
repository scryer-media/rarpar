package testcorpus

import (
	"context"
	"os"
	"path/filepath"
)

// e2ePassword is the password the large sets were imported under; the suites
// hard-code it.
const e2ePassword = "e2e-test-password"

const (
	// ~85 MB main member and a ~26 MB companion for the solid encrypted set.
	sampleTargetBytes  = 85 * 1000 * 1000
	episodeTargetBytes = 26 * 1000 * 1000
)

// generateLargeSets writes the large single-volume sets: the solid archives, the
// two header-encrypted ~85 MB archives, the solid encrypted set, the CJK-named
// set and the three nested RAR-in-RAR chains.
//
// These were imported from the Scryer e2e release gate and had no recipe; this
// is that recipe, on the pinned toolchain. Shapes the suites pin:
//
//   - rar4_solid / rar5_solid: solid, members sample.mkv, file1.txt, file2.txt
//     in that order (tests/integration.rs asserts the exact list and that the
//     archive reports itself solid).
//   - rar4_hp_large / rar5_hp_large: header-encrypted under e2ePassword, one
//     member large enough that its unpacked size exceeds the RAR5 dictionary
//     (tests/rar5_controller_invariants.rs asserts exactly that), which is why
//     the RAR5 archive pins -md32m.
//   - rar5_solid_encrypted: -p (file data encrypted, headers readable), solid,
//     exactly two members — tests/integration.rs opens it *without* a password
//     and still reads the member list.
//   - rar5_unicode_cjk: exactly one member whose name contains 映画テスト
//     (tests/integration.rs). RAR5 only: the RAR4 image's locale mangles
//     non-ASCII names.
//   - the nested chains: a RAR holding a RAR, two, three and five deep, with a
//     video at the bottom. No suite opens them today. The depths and inner
//     member names follow the sets they replace, except that the imported
//     three-deep chain's innermost container was a 7-Zip archive — this one is
//     RAR all the way down, because 7-Zip is not in the pinned toolchain.
func generateLargeSets(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("large")
	if err != nil {
		return err
	}
	defer cleanup()
	src := filepath.Join(work, "src")
	out := filepath.Join(work, "out")
	nest := filepath.Join(work, "nest")
	for _, dir := range []string{src, out, nest} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	sample := filepath.Join(src, "sample.mkv")
	if err := e.video(ctx, sampleTargetBytes, sample); err != nil {
		return err
	}
	if err := e.video(ctx, episodeTargetBytes, filepath.Join(src, "ep1.mkv")); err != nil {
		return err
	}
	// The two small solid companions. They differ in one digit, so the second
	// compresses to almost nothing against the first — which is the solid
	// continuation the suites walk.
	if err := writeFile(filepath.Join(src, "file1.txt"), []byte("Silver Horizon, episode 001.\n")); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(src, "file2.txt"), []byte("Silver Horizon, episode 002.\n")); err != nil {
		return err
	}
	if err := copyFile(sample, filepath.Join(src, "映画テスト.mkv")); err != nil {
		return err
	}

	rar5 := e.rar(e.rar5.Image, work, "src")
	rar4 := e.rar(e.rar4.Image, work, "src")
	nested := e.rar(e.rar5.Image, work, "nest")

	sets := []struct {
		writer rarWriter
		args   []string
	}{
		{rar5, []string{"-m1", "-s", "../out/rar5_solid.rar", "sample.mkv", "file1.txt", "file2.txt"}},
		{rar4, []string{"-ma4", "-m1", "-s", "../out/rar4_solid.rar", "sample.mkv", "file1.txt", "file2.txt"}},
		{rar5, []string{"-m1", "-md32m", "-hp" + e2ePassword, "../out/rar5_hp_large.rar", "sample.mkv"}},
		{rar4, []string{"-ma4", "-m1", "-hp" + e2ePassword, "../out/rar4_hp_large.rar", "sample.mkv"}},
		{rar5, []string{"-m1", "-s", "-p" + e2ePassword, "../out/rar5_solid_encrypted.rar", "ep1.mkv", "sample.mkv"}},
		{rar5, []string{"-m1", "../out/rar5_unicode_cjk.rar", "映画テスト.mkv"}},
	}
	for _, set := range sets {
		if err := set.writer.add(ctx, set.args...); err != nil {
			return err
		}
	}

	// The nested chains, built innermost first and pruned as they go so no more
	// than a few copies of the clip are on disk at once.
	if err := copyFile(sample, filepath.Join(nest, "sample.mkv")); err != nil {
		return err
	}
	chains := []struct {
		steps [][]string
		prune []string
	}{
		// Two deep: outer(store) -> inner.rar(compressed) -> sample.mkv
		{[][]string{
			{"-m1", "inner.rar", "sample.mkv"},
			{"-m0", "../out/rar5_nested_2deep.rar", "inner.rar"},
		}, []string{"inner.rar"}},
		// Three deep: outer(store) -> middle.rar -> inner.rar -> sample.mkv
		{[][]string{
			{"-m0", "inner.rar", "sample.mkv"},
			{"-m0", "middle.rar", "inner.rar"},
		}, []string{"inner.rar"}},
		{[][]string{
			{"-m0", "../out/rar5_nested_3deep.rar", "middle.rar"},
		}, []string{"middle.rar"}},
		// Five deep: outer(store) -> level4 -> level3 -> level2 -> level1 -> clip
		{[][]string{{"-m0", "level1.rar", "sample.mkv"}}, nil},
		{[][]string{{"-m0", "level2.rar", "level1.rar"}}, []string{"level1.rar"}},
		{[][]string{{"-m0", "level3.rar", "level2.rar"}}, []string{"level2.rar"}},
		{[][]string{{"-m0", "level4.rar", "level3.rar"}}, []string{"level3.rar"}},
		{[][]string{{"-m0", "../out/rar5_nested_5deep.rar", "level4.rar"}}, []string{"level4.rar"}},
	}
	for _, chain := range chains {
		for _, args := range chain.steps {
			if err := nested.add(ctx, args...); err != nil {
				return err
			}
		}
		for _, name := range chain.prune {
			if err := os.Remove(filepath.Join(nest, name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}

	rar4Dir, rar5Dir := e.unrarPath("rar4"), e.unrarPath("rar5")
	if err := removeGlob(
		filepath.Join(rar4Dir, "rar4_solid.rar"),
		filepath.Join(rar4Dir, "rar4_hp_large.rar"),
		filepath.Join(rar5Dir, "rar5_solid.rar"),
		filepath.Join(rar5Dir, "rar5_hp_large.rar"),
		filepath.Join(rar5Dir, "rar5_solid_encrypted.rar"),
		filepath.Join(rar5Dir, "rar5_unicode_cjk.rar"),
		filepath.Join(rar5Dir, "rar5_nested_2deep.rar"),
		filepath.Join(rar5Dir, "rar5_nested_3deep.rar"),
		filepath.Join(rar5Dir, "rar5_nested_5deep.rar"),
	); err != nil {
		return err
	}
	if _, err := collect(out, rar4Dir, "rar4_"); err != nil {
		return err
	}
	_, err = collect(out, rar5Dir, "rar5_")
	return err
}
