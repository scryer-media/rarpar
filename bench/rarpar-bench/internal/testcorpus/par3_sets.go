package testcorpus

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// par3Input is one protected file: its path under the case's in/ directory,
// forward slashes, and its size. Its bytes are deterministicBytes over the
// case and path, so the set is a function of this table alone.
type par3Input struct {
	path string
	size int
}

// par3Case is one PAR3 set the reference writes: the inputs, the create
// options (everything between `create -B<base>` and the output name), and
// the names handed to the reference after the output, relative to in/.
type par3Case struct {
	name    string
	inputs  []par3Input
	options []string
	targets []string
}

// par3Cases are the sets crates/par3-rs is held to. Each one exists to pin a
// distinct decision the reference makes at its default settings, so that a
// create in par3-rs can be compared byte for byte and a verify or repair can
// be run against files the reference itself protected:
//
//	gf8_packed        four files with tails of every kind (inline, packed,
//	                  none) and a subdirectory; 76 blocks of 4 KiB, 20 %
//	                  recovery, GF(2^8), five power-of-two volumes, comment
//	gf16_blocks       more than 128 input blocks, which is what moves the
//	                  reference to GF(2^16) on block count alone
//	gf16_by_recovery  100 input blocks and 200 recovery blocks: GF(2^16)
//	                  chosen because input + recovery exceeds 256, not
//	                  because of the input count
//	index_only        no recovery blocks at all: an index file, no volumes,
//	                  no Matrix packet
//	tree              nested directories reached through -R, a pair of
//	                  identical files in different directories, and an
//	                  empty file
//	tiny_inline       files around the 40-byte tail threshold with the
//	                  block size left to the reference
//	auto_block        mixed sizes with the block size left to the
//	                  reference, which pins its suggestion rule
//	large_stream      a 16 MiB file at 64 KiB blocks: the streaming verify
//	                  and repair paths at a size that is not a toy
//
// Nothing here is damaged. The tests damage copies of these inputs in
// memory; the fixture tree holds only what the reference saw and wrote.
var par3Cases = []par3Case{
	{
		name: "gf8_packed",
		inputs: []par3Input{
			{"big.bin", 300_000},
			{"sub/mid.bin", 5_000},
			{"tiny.bin", 37},
			{"odd.bin", 4_131},
		},
		options: []string{"-s4096", "-r20", "-Ccorpus gf8_packed"},
		targets: []string{"big.bin", "sub/mid.bin", "tiny.bin", "odd.bin"},
	},
	{
		name: "gf16_blocks",
		inputs: []par3Input{
			{"long.bin", 700_000},
			{"a.bin", 1_000},
			{"b.bin", 2_000},
		},
		options: []string{"-s1024", "-r10"},
		targets: []string{"long.bin", "a.bin", "b.bin"},
	},
	{
		name: "gf16_by_recovery",
		inputs: []par3Input{
			{"exact.bin", 409_600},
		},
		options: []string{"-s4096", "-c200"},
		targets: []string{"exact.bin"},
	},
	{
		name: "index_only",
		inputs: []par3Input{
			{"one.bin", 10_000},
			{"two.bin", 20_000},
			{"three.bin", 300},
		},
		options: []string{"-s4096", "-c0"},
		targets: []string{"one.bin", "two.bin", "three.bin"},
	},
	{
		name: "tree",
		inputs: []par3Input{
			{"top.bin", 5_000},
			{"a/b/c/deep.bin", 9_000},
			{"a/twin.bin", 4_200},
			{"a/b/twin.bin", 4_200},
			{"a/empty.bin", 0},
		},
		options: []string{"-R", "-s4096", "-r10"},
		targets: []string{"top.bin", "a"},
	},
	{
		name: "tiny_inline",
		inputs: []par3Input{
			{"t05.bin", 5},
			{"t39.bin", 39},
			{"t40.bin", 40},
			{"t41.bin", 41},
			{"t100.bin", 100},
		},
		options: []string{"-r50"},
		targets: []string{"t05.bin", "t39.bin", "t40.bin", "t41.bin", "t100.bin"},
	},
	{
		name: "auto_block",
		inputs: []par3Input{
			{"clip.bin", 150_000},
			{"meta.bin", 20_000},
			{"note.bin", 999},
		},
		options: []string{"-r15"},
		targets: []string{"clip.bin", "meta.bin", "note.bin"},
	},
	{
		name: "large_stream",
		inputs: []par3Input{
			{"stream.bin", 16*1024*1024 + 12_345},
		},
		options: []string{"-s65536", "-r5"},
		targets: []string{"stream.bin"},
	},
}

// generatePar3Sets writes every case under crates/par3-rs/tests/fixtures:
// <case>/in/... holds the inputs exactly as the reference read them, and
// <case>/set.par3 plus <case>/set.vol*.par3 are what it wrote. The reference
// runs once per case with -B pointing at in/, so every path it records is
// relative to that directory.
func generatePar3Sets(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("par3")
	if err != nil {
		return err
	}
	defer cleanup()

	for _, set := range par3Cases {
		dir := filepath.Join(work, set.name)
		in := filepath.Join(dir, "in")
		if err := os.MkdirAll(in, 0o755); err != nil {
			return err
		}
		for _, input := range set.inputs {
			payload := deterministicBytes("par3/"+set.name+"/"+input.path, input.size)
			if err := writeFile(filepath.Join(in, filepath.FromSlash(input.path)), payload); err != nil {
				return err
			}
		}

		// Container paths only: the host directory is mounted at /work.
		args := []string{"create", "-B/work/" + set.name + "/in"}
		args = append(args, set.options...)
		args = append(args, "/work/"+set.name+"/set.par3")
		args = append(args, set.targets...)
		if err := e.par3Run(ctx, work, "", args...); err != nil {
			return fmt.Errorf("%s: %w", set.name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "set.par3")); err != nil {
			return fmt.Errorf("%s: the reference wrote no index file: %w", set.name, err)
		}

		out := e.par3Path(set.name)
		if err := os.RemoveAll(out); err != nil {
			return err
		}
		written, err := copyTree(dir, out)
		if err != nil {
			return fmt.Errorf("%s: %w", set.name, err)
		}
		e.logf("testcorpus: par3_sets %s: %d file(s)", set.name, written)
	}
	return nil
}

// copyTree copies every regular file under source to the same relative path
// under destination and reports how many it copied. The reference leaves
// nothing but regular files behind, so anything else is an error rather than
// a skip.
func copyTree(source, destination string) (int, error) {
	written := 0
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(relative, "..") {
			return fmt.Errorf("%s resolves outside %s", path, source)
		}
		if err := copyFile(path, filepath.Join(destination, relative)); err != nil {
			return err
		}
		written++
		return nil
	})
	return written, err
}
