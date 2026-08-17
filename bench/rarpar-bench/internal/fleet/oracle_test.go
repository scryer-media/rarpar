package fleet

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// The oracle source tarball is untrusted input; an entry that would land
// outside the extraction directory aborts the extraction and writes nothing.
func TestExtractTarTreeRefusesEscapingEntries(t *testing.T) {
	root := t.TempDir()
	for _, evil := range []string{"../escape.txt", "sub/../../escape.txt", "/abs.txt"} {
		archive := filepath.Join(root, "evil.tar.gz")
		file, err := os.Create(archive)
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(file)
		tw := tar.NewWriter(gz)
		for _, name := range []string{"ok/inside.txt", evil} {
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 2}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte("hi")); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(root, "out")
		if err := os.MkdirAll(destination, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := extractTarTree(archive, destination); err == nil {
			t.Fatalf("%q was extracted", evil)
		}
		if _, err := os.Stat(filepath.Join(root, "escape.txt")); !os.IsNotExist(err) {
			t.Fatalf("%q escaped the destination", evil)
		}
	}
	// Any `..` in the raw name is refused before resolution — even spellings
	// that would resolve harmlessly. The pinned toolchain tarballs this
	// extracts never carry dotdot in a well-formed name, so the blunt refusal
	// costs nothing real and is checkable at a glance; the trade is deliberate
	// (an in-tree `a/b/../c.txt` is refused too, not resolved).
	for _, name := range []string{"..hidden/file", "a/b/../c.txt", "a/..", ".."} {
		if _, err := containedPath(root, name); err == nil {
			t.Fatalf("%q was accepted despite containing dotdot", name)
		}
	}
	// Ordinary nested names still resolve where they should.
	if got, err := containedPath(root, "a/b/c.txt"); err != nil || got != filepath.Join(root, "a", "b", "c.txt") {
		t.Fatalf("plain nested name: %q, %v", got, err)
	}
	if got, err := containedPath(root, "./a/.hidden"); err != nil || got != filepath.Join(root, "a", ".hidden") {
		t.Fatalf("dot-prefixed segments that are not dotdot: %q, %v", got, err)
	}
}
