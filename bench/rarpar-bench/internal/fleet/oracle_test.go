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
	// A benign tarball still extracts, and containment is judged on the
	// resolved path rather than a name prefix.
	if _, err := containedPath(root, "..hidden/file"); err != nil {
		t.Fatalf("a name that merely starts with dots was refused: %v", err)
	}
	if got, err := containedPath(root, "a/b/../c.txt"); err != nil || got != filepath.Join(root, "a", "c.txt") {
		t.Fatalf("clean in-tree traversal: %q, %v", got, err)
	}
}
