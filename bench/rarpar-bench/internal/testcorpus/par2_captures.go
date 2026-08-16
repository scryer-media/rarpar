package testcorpus

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// generatePar2Captures rebuilds the five testNN-generated.tar.gz captures.
//
// Five of par2cmdline-turbo's shell tests build their working directory at run
// time — they invoke the par2 binary, and one of them draws from /dev/urandom —
// so no upstream file holds those bytes and they cannot be imported. This is
// their recipe: replay what each upstream script does, against the same upstream
// data tarballs (which *are* byte-identical imports sitting beside the captures)
// and the pinned par2cmdline-turbo image, and capture the result.
//
// Upstream scripts mirrored, at the commit test-corpus/sources.json pins for the
// par2cmdline-turbo upstream:
//
//	test13  tests/test13  flatdata + `par2 c testdata.par2 *.data`, then
//	                      test-1.data truncated at the end to 177 173 B with the
//	                      untruncated copy kept as test-1.data-correct
//	test14  tests/test14  the same set, truncated at the *beginning* instead
//	test18  tests/test18  flatdata.tar.gz itself protected by `par2 c recovery`
//	test20  tests/test20  `par2 c -s1000 -c0 recovery myfile.dat` over a 2 000-byte
//	                      file, then that file split into .001/.002 and removed
//	test29  tests/test29  bug190's 9 MB pair, `par2 c -m500 -r30 -n1 -v` over the
//	                      good copy, then the bit-flipped copy left in place
//
// Two deliberate differences from upstream:
//   - test18 keeps flatdata.tar.gz-correct where upstream keeps (and then
//     deletes) flatdata.tar.gz-orig, because the Rust test compares the repaired
//     file against it. Upstream's 1 983-byte truncation cannot shorten a
//     1 925-byte file, so the two copies are identical, exactly as in the
//     captures this replaces.
//   - test20 starts from a fixed deterministic 2 000-byte blob rather than
//     /dev/urandom, so the capture is reproducible. Upstream only needs "some
//     file"; nothing about the case depends on the bytes being unpredictable.
func generatePar2Captures(ctx context.Context, e *env) error {
	work, cleanup, err := workDir("captures")
	if err != nil {
		return err
	}
	defer cleanup()
	captures := e.par2Path("par2cmdline-turbo")

	// --- test13 / test14: flatdata with one truncated member ----------------
	for _, name := range []string{"test13", "test14"} {
		dir := filepath.Join(work, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := extractTarGz(filepath.Join(captures, "flatdata.tar.gz"), dir); err != nil {
			return err
		}
		data, err := filepath.Glob(filepath.Join(dir, "*.data"))
		if err != nil {
			return err
		}
		sort.Strings(data)
		args := []string{"c", "testdata.par2"}
		for _, path := range data {
			args = append(args, filepath.Base(path))
		}
		if err := e.par2Run(ctx, work, name, args...); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(dir, "test-1.data"), filepath.Join(dir, "test-1.data-correct")); err != nil {
			return err
		}
		correct, err := os.ReadFile(filepath.Join(dir, "test-1.data-correct"))
		if err != nil {
			return err
		}
		const kept = 177_173
		if len(correct) <= kept {
			return fmt.Errorf("%s: test-1.data-correct is %d bytes, expected more than %d", name, len(correct), kept)
		}
		damaged := correct[:kept] // test13 loses the last byte
		if name == "test14" {
			damaged = correct[len(correct)-kept:] // test14 loses the first
		}
		if err := writeFile(filepath.Join(dir, "test-1.data"), damaged); err != nil {
			return err
		}
		if err := packCapture(dir, filepath.Join(captures, name+"-generated.tar.gz")); err != nil {
			return err
		}
	}

	// --- test18: the data tarball protected as a single file ----------------
	test18 := filepath.Join(work, "test18")
	if err := os.MkdirAll(test18, 0o755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(captures, "flatdata.tar.gz"), filepath.Join(test18, "flatdata.tar.gz")); err != nil {
		return err
	}
	if err := e.par2Run(ctx, work, "test18", "c", "recovery", "flatdata.tar.gz"); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(test18, "flatdata.tar.gz"), filepath.Join(test18, "flatdata.tar.gz-correct")); err != nil {
		return err
	}
	if err := packCapture(test18, filepath.Join(captures, "test18-generated.tar.gz")); err != nil {
		return err
	}

	// --- test20: repair from two split fragments ----------------------------
	test20 := filepath.Join(work, "test20")
	if err := os.MkdirAll(test20, 0o755); err != nil {
		return err
	}
	payload := deterministicBytes("par2/test20/myfile.dat", 2000)
	if err := writeFile(filepath.Join(test20, "myfile.dat"), payload); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(test20, "myfile.dat-correct"), payload); err != nil {
		return err
	}
	if err := e.par2Run(ctx, work, "test20", "c", "-s1000", "-c0", "recovery", "myfile.dat"); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(test20, "myfile.dat.001"), payload[:1000]); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(test20, "myfile.dat.002"), payload[1000:]); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(test20, "myfile.dat")); err != nil {
		return err
	}
	if err := packCapture(test20, filepath.Join(captures, "test20-generated.tar.gz")); err != nil {
		return err
	}

	// --- test29: issue 190, a single bit flip in 9 MB -----------------------
	test29 := filepath.Join(work, "test29")
	if err := os.MkdirAll(test29, 0o755); err != nil {
		return err
	}
	if err := extractTarGz(filepath.Join(captures, "bug190.tar.gz"), test29); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(test29, "9MBones_crc_ok_orig"), filepath.Join(test29, "9MBones_crc_ok")); err != nil {
		return err
	}
	if err := e.par2Run(ctx, work, "test29", "c", "-m500", "-r30", "-n1", "-v", "9MBones_crc_ok"); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(test29, "9MBones_crc_ok_bad"), filepath.Join(test29, "9MBones_crc_ok")); err != nil {
		return err
	}
	return packCapture(test29, filepath.Join(captures, "test29-generated.tar.gz"))
}

// extractTarGz unpacks a gzipped tar into `destination`, flat regular files
// only — which is all the upstream data tarballs hold.
func extractTarGz(archive, destination string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	decompressed, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer decompressed.Close()
	reader := tar.NewReader(decompressed)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Base(filepath.Clean(filepath.FromSlash(header.Name)))
		if name == "." || name == string(filepath.Separator) {
			continue
		}
		data := make([]byte, header.Size)
		if _, err := io.ReadFull(reader, data); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(destination, name), data); err != nil {
			return err
		}
	}
}

// packCapture writes one case directory as a deterministic tarball: regular
// files only, sorted, no owner names, no timestamps, and gzip without its own
// name/mtime header — so a capture's bytes depend on the case and nothing else.
func packCapture(dir, out string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("%s: nothing to capture", dir)
	}

	// A zero ModTime and an empty Name are what `gzip -n` produces: no
	// timestamp and no original filename in the member header.
	var buffer bytes.Buffer
	compressed, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return err
	}
	archive := tar.NewWriter(compressed)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if err := archive.WriteHeader(&tar.Header{
			Name:     "./" + name,
			Mode:     0o644,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}); err != nil {
			return err
		}
		if _, err := archive.Write(data); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if err := compressed.Close(); err != nil {
		return err
	}
	return writeFile(out, buffer.Bytes())
}
