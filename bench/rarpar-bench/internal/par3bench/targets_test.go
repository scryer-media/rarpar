package par3bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetsNamingOneDirectoryAreRefused(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "volume")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	same := [][2]string{
		{filepath.Join(real, "w"), filepath.Join(real, "w")},
		// Neither exists yet: the alias is resolved through its parent.
		{filepath.Join(real, "w"), filepath.Join(alias, "w")},
		{real, alias},
	}
	for _, pair := range same {
		targets := []Target{{Name: "local", Work: pair[0]}, {Name: "nfs-sync", Work: pair[1]}}
		err := distinctTargets(targets)
		if err == nil || !strings.Contains(err.Error(), "same work directory") {
			t.Errorf("%q: want a refusal, got %v", pair, err)
		}
	}
	if err := distinctTargets([]Target{{Name: "local", Work: filepath.Join(real, "a")}, {Name: "nfs-sync", Work: filepath.Join(alias, "b")}}); err != nil {
		t.Errorf("distinct targets refused: %v", err)
	}
	// The run refuses before it creates anything.
	options := Options{Reference: "/opt/ref/par3", Candidate: "/opt/cand/rarpar", Out: filepath.Join(root, "out"), Repeats: 1,
		Targets: []Target{{Name: "local", Work: filepath.Join(real, "w")}, {Name: "nfs-sync", Work: filepath.Join(alias, "w")}}}
	if err := validateOptions(&options); err == nil || !strings.Contains(err.Error(), "same work directory") {
		t.Fatalf("validateOptions: %v", err)
	}
	if _, err := os.Stat(filepath.Join(real, "w")); !os.IsNotExist(err) {
		t.Fatalf("a refused run created its work directory: %v", err)
	}
}
