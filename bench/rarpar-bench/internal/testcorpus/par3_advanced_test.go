package testcorpus

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPar3InsideZipInputs(t *testing.T) {
	payload := par3AdvancedInput()
	inputs, err := par3InsideInputs(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inside.zip", "inside64.zip"} {
		data := inputs[name]
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		if name == "inside64.zip" {
			if len(archive.File) != 65536 {
				t.Fatal("ZIP64 entry count")
			}
			continue
		}
		reader, err := archive.File[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		actual, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("ZIP payload: %v", err)
		}
	}
}

// Explicit export supports independent archive tools and the pinned reference.
// The destination must be absent, so this cannot replace unrelated fixtures.
func TestExportPar3InsideInputs(t *testing.T) {
	dir := os.Getenv("PAR3_INSIDE_ORACLE_INPUTS")
	if dir == "" {
		t.Skip("set PAR3_INSIDE_ORACLE_INPUTS to a new directory")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute destination required")
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	inputs, err := par3InsideInputs(par3AdvancedInput())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range inputs {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
