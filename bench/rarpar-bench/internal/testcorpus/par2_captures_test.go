package testcorpus

import (
	"path/filepath"
	"strings"
	"testing"
)

// The upstream data tarballs are extracted flat, and an entry that is not a
// plain file name — a traversal, a directory, an absolute path — is refused
// rather than written anywhere.
func TestFlatEntryPathRefusesTraversalAndKeepsOnlyTheBaseName(t *testing.T) {
	destination := t.TempDir()
	for _, entry := range []string{"file.dat", "sub/dir/file.dat", "./file.dat"} {
		target, err := flatEntryPath(destination, entry)
		if err != nil {
			t.Fatalf("%q: %v", entry, err)
		}
		if target != filepath.Join(destination, "file.dat") {
			t.Fatalf("%q -> %q", entry, target)
		}
	}
	for _, entry := range []string{"..", "sub/..", "/", ".", "", "a/../../evil/.."} {
		if _, err := flatEntryPath(destination, entry); err == nil {
			t.Fatalf("%q was accepted", entry)
		} else if !strings.Contains(err.Error(), "refusing tar entry") {
			t.Fatalf("%q: unexpected error %v", entry, err)
		}
	}
	// A traversal that ends in a plain name is flattened to that name, which
	// is inside destination by construction — never the traversed location.
	target, err := flatEntryPath(destination, "../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join(destination, "passwd") {
		t.Fatalf("traversal flattened to %q", target)
	}
}
