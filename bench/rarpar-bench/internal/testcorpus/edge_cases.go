package testcorpus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// longFixtureName is the 200-character member name the long-name sets carry.
var longFixtureName = strings.Repeat("a", 200) + ".txt"

// generateEdgeCases writes the edge-case sets — multi-file, directories, empty
// members, unicode names, recovery records, comments, tiny volumes, the
// best-compression set, long names and the symlink set — and the `originals/`
// inputs the sibling recipes read.
//
// It is stage 0 for that second reason: random_4k.bin, random_512.bin and
// zeros_64k.bin are inputs elsewhere.
//
// Every archive here is written by a pinned RARLAB image; only the plain inputs
// are produced in Go.
func generateEdgeCases(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("edge")
	if err != nil {
		return err
	}
	defer cleanup()
	src := filepath.Join(work, "src")
	out := filepath.Join(work, "out")
	for _, dir := range []string{filepath.Join(src, "subdir", "nested"), out} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	// --- inputs -------------------------------------------------------------
	// Deterministic where the shell recipes drew from /dev/urandom: the sizes
	// are what the suites pin (a 4 KiB member over 1 KiB volumes is five parts),
	// and high-entropy bytes keep `-m0` the interesting case.
	files := map[string][]byte{
		"hello.txt":              []byte("Hello, world!\n"),
		"second.txt":             []byte("Second file content here\n"),
		"empty.txt":              {},
		"日本語ファイル.txt":            []byte("日本語テスト\n"),
		"café-résumé.txt":        []byte("Emoji content 🎉\n"),
		"subdir/a.txt":           []byte("Nested file A\n"),
		"subdir/nested/b.txt":    []byte("Deeply nested B\n"),
		"zeros_64k.bin":          make([]byte, 64*1024),
		"random_512.bin":         deterministicBytes("edge/random_512", 512),
		"random_4k.bin":          deterministicBytes("edge/random_4k", 4096),
		"_comment.txt":           []byte("This is a test comment for the archive\n"),
		longFixtureName:          []byte("long filename test\n"),
		"rar4_long_password.txt": []byte("RAR4 long password KDF fixture\n"),
	}
	for name, data := range files {
		if err := writeFile(filepath.Join(src, filepath.FromSlash(name)), data); err != nil {
			return err
		}
	}
	// The symlink set needs a real symlink. On Windows that requires developer
	// mode or the privilege; say so rather than writing a copy and calling it a
	// symlink fixture.
	link := filepath.Join(src, "link_to_hello.txt")
	if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink("hello.txt", link); err != nil {
		return fmt.Errorf("rar5_symlink.rar needs a real symlink: %w", err)
	}

	rar5 := e.rar(e.rar5.Image, work, "src")
	rar4 := e.rar(e.rar4.Image, work, "src")

	rar5Sets := []struct {
		name string
		args []string
	}{
		{"rar5_multifile_store", []string{"-m0", "../out/rar5_multifile_store.rar", "hello.txt", "second.txt", "random_512.bin"}},
		{"rar5_multifile_lz", []string{"-m3", "../out/rar5_multifile_lz.rar", "hello.txt", "second.txt", "zeros_64k.bin"}},
		{"rar5_dirs", []string{"-m0", "-r", "../out/rar5_dirs.rar", "subdir"}},
		{"rar5_empty_member", []string{"-m0", "../out/rar5_empty_member.rar", "empty.txt", "hello.txt"}},
		{"rar5_unicode", []string{"-m0", "../out/rar5_unicode.rar", "日本語ファイル.txt", "café-résumé.txt"}},
		{"rar5_recovery", []string{"-m0", "-rr5p", "../out/rar5_recovery.rar", "hello.txt", "second.txt"}},
		{"rar5_comment", []string{"-m0", "-z_comment.txt", "../out/rar5_comment.rar", "hello.txt"}},
		{"rar5_tiny_volumes", []string{"-m0", "-v1k", "../out/rar5_tiny_volumes.rar", "random_4k.bin"}},
		{"rar5_best", []string{"-m5", "../out/rar5_best.rar", "zeros_64k.bin"}},
		{"rar5_longname", []string{"-m0", "../out/rar5_longname.rar", longFixtureName}},
		{"rar5_symlink", []string{"-m0", "-ol", "../out/rar5_symlink.rar", "link_to_hello.txt", "hello.txt"}},
	}
	for _, set := range rar5Sets {
		if err := rar5.add(ctx, set.args...); err != nil {
			return fmt.Errorf("%s: %w", set.name, err)
		}
	}
	if err := expectVolumes(out, "rar5_tiny_volumes", 5); err != nil {
		return err
	}

	// rar5_solid.rar and rar4_solid.rar belong to large_sets, which holds every
	// ~85 MB video-member set; they are deliberately not written here.
	rar4Sets := []struct {
		name string
		args []string
	}{
		{"rar4_multifile_store", []string{"-ma4", "-m0", "../out/rar4_multifile_store.rar", "hello.txt", "second.txt", "random_512.bin"}},
		{"rar4_multifile_lz", []string{"-ma4", "-m3", "../out/rar4_multifile_lz.rar", "hello.txt", "second.txt", "zeros_64k.bin"}},
		{"rar4_dirs", []string{"-ma4", "-m0", "-r", "../out/rar4_dirs.rar", "subdir"}},
		{"rar4_empty_member", []string{"-ma4", "-m0", "../out/rar4_empty_member.rar", "empty.txt", "hello.txt"}},
		{"rar4_recovery", []string{"-ma4", "-m0", "-rr5p", "../out/rar4_recovery.rar", "hello.txt", "second.txt"}},
		{"rar4_comment", []string{"-ma4", "-m0", "-z_comment.txt", "../out/rar4_comment.rar", "hello.txt"}},
		{"rar4_longname", []string{"-ma4", "-m0", "../out/rar4_longname.rar", longFixtureName}},
		// The RAR4 twin of the RAR5 tiny-volume set: same 4 KiB input, same
		// 1 KiB volumes, so the two formats' volume chains are comparable.
		// tools/rarpar/tests/cli.rs drives the compat extractor across it.
		{"rar4_tiny_volumes", []string{"-ma4", "-m0", "-v1k", "../out/rar4_tiny_volumes.rar", "random_4k.bin"}},
	}
	for _, set := range rar4Sets {
		if err := rar4.add(ctx, set.args...); err != nil {
			return fmt.Errorf("%s: %w", set.name, err)
		}
	}
	if err := expectVolumes(out, "rar4_tiny_volumes", 5); err != nil {
		return err
	}

	// The long-password KDF set is deliberately NOT corpus content: it has no
	// ledger entry and the test that reads it is #[ignore]d, so writing it
	// unconditionally would put a file in the tree no manifest describes.
	if os.Getenv("RARPAR_FIXTURES_LONG_PASSWORD") == "1" {
		if err := rar4.add(ctx, "-ma4", "-m0", "-hpabcdefghijklmnopqrstuvwxyzabcdef",
			"../out/rar4_hp_long_password.rar", "rar4_long_password.txt"); err != nil {
			return err
		}
	}

	if err := removeGlob(
		filepath.Join(e.unrarPath("rar5"), "rar5_multifile_store.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_multifile_lz.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_dirs.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_empty_member.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_unicode.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_recovery.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_comment.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_tiny_volumes.part*.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_best.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_longname.rar"),
		filepath.Join(e.unrarPath("rar5"), "rar5_symlink.rar"),
		filepath.Join(e.unrarPath("rar4"), "rar4_multifile_store.rar"),
		filepath.Join(e.unrarPath("rar4"), "rar4_multifile_lz.rar"),
		filepath.Join(e.unrarPath("rar4"), "rar4_dirs.rar"),
		filepath.Join(e.unrarPath("rar4"), "rar4_empty_member.rar"),
		filepath.Join(e.unrarPath("rar4"), "rar4_recovery.rar"),
		filepath.Join(e.unrarPath("rar4"), "rar4_comment.rar"),
		filepath.Join(e.unrarPath("rar4"), "rar4_longname.rar"),
		filepath.Join(e.unrarPath("rar4"), "rar4_tiny_volumes.part*.rar"),
	); err != nil {
		return err
	}
	if _, err := collect(out, e.unrarPath("rar5"), "rar5_"); err != nil {
		return err
	}
	if _, err := collect(out, e.unrarPath("rar4"), "rar4_"); err != nil {
		return err
	}

	// The originals the sibling recipes and the extraction comparisons read.
	originals := e.unrarPath("originals")
	for _, name := range []string{
		"hello.txt", "second.txt", "empty.txt", "zeros_64k.bin", "random_512.bin",
		"random_4k.bin", "rar4_long_password.txt", "日本語ファイル.txt", "café-résumé.txt",
		longFixtureName,
	} {
		if err := copyFile(filepath.Join(src, name), filepath.Join(originals, name)); err != nil {
			return err
		}
	}
	if err := copyFile(filepath.Join(src, "subdir", "a.txt"), filepath.Join(originals, "subdir_a.txt")); err != nil {
		return err
	}
	return copyFile(filepath.Join(src, "subdir", "nested", "b.txt"), filepath.Join(originals, "subdir_nested_b.txt"))
}
