package testcorpus

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Advanced fixtures always take their PAR3 bytes from the pinned executable.
// The archive writers below create only original ZIP/7z inputs, before PAR3
// exists; no code in this recipe assembles or modifies a PAR3 packet.
func generatePar3Advanced(ctx context.Context, e *env, work string) error {
	dir := filepath.Join(work, "advanced")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	payload := par3AdvancedInput()
	if err := writeFile(filepath.Join(dir, "input.bin"), payload); err != nil {
		return err
	}
	for _, recipe := range []struct {
		name    string
		options []string
	}{
		{"fft", []string{"-s1024", "-e8", "-c8", "-cm16"}},
		{"fft16", []string{"-s64", "-e8", "-c16", "-cm64"}},
		{"interleaved", []string{"-s1024", "-e8", "-i2", "-c9", "-cm24"}},
	} {
		args := append([]string{"c", "-B/work/advanced"}, recipe.options...)
		args = append(args, "/work/advanced/"+recipe.name+".par3", "input.bin")
		if err := e.par3Run(ctx, work, "", args...); err != nil {
			return err
		}
	}
	dataDir := filepath.Join(work, "data-input")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	dataInput := make([]byte, 3300)
	for i := range dataInput {
		dataInput[i] = byte(i*29 + i/31)
	}
	for _, name := range []string{"input.bin", "copy.bin"} {
		if err := writeFile(filepath.Join(dataDir, name), dataInput); err != nil {
			return err
		}
	}
	// The pinned reference returns an error with -c0 after writing Data volumes.
	// Generate one recovery block and omit it in Data-only consumer tests.
	if err := e.par3Run(ctx, work, "", "c", "-B/work/data-input", "-s1024", "-e8", "-c1", "-D", "-d1", "/work/advanced/data-dedup.par3", "input.bin", "copy.bin"); err != nil {
		return err
	}
	archives, err := par3InsideInputs(payload)
	if err != nil {
		return err
	}
	for name, data := range archives {
		ext := filepath.Ext(name)
		original := strings.TrimSuffix(name, ext) + "-original" + ext
		if err := writeFile(filepath.Join(dir, original), data); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(dir, name), data); err != nil {
			return err
		}
		if err := e.par3Run(ctx, work, "", "i", "/work/advanced/"+name); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "input.bin" {
			continue
		} // Reconstructed in Rust tests.
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected advanced fixture %s", entry.Name())
		}
		if err := copyFile(filepath.Join(dir, entry.Name()), e.par3Path("advanced/"+entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func par3AdvancedInput() []byte {
	data := make([]byte, 14000)
	for i := range data {
		data[i] = byte(i*73 + i/29)
	}
	return data
}

func par3InsideInputs(payload []byte) (map[string][]byte, error) {
	result := make(map[string][]byte)
	for _, wide := range []bool{false, true} {
		var out bytes.Buffer
		writer := zip.NewWriter(&out)
		count := 1
		if wide {
			count = 65536
		}
		for i := 0; i < count; i++ {
			name, method, data := "input.bin", uint16(zip.Deflate), payload
			if wide {
				name, method, data = strconv.Itoa(i), zip.Store, nil
			}
			member, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: method})
			if err != nil {
				return nil, err
			}
			if _, err := member.Write(data); err != nil {
				return nil, err
			}
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		name := "inside.zip"
		if wide {
			name = "inside64.zip"
			// The reference detector requires size/offset sentinels even when
			// only the member count requires ZIP64. The real values remain in
			// the ZIP64 end record. This touches original ZIP bytes only.
			data := out.Bytes()
			binary.LittleEndian.PutUint32(data[len(data)-10:], 0xffffffff)
			binary.LittleEndian.PutUint32(data[len(data)-6:], 0xffffffff)
		}
		result[name] = out.Bytes()
	}
	result["inside.7z"] = par3Stored7z(payload)
	return result, nil
}

// 7z's Copy coder permits a deterministic archive without another dependency.
// Header fields follow the public 7z format, not an archive implementation.
func par3Stored7z(payload []byte) []byte {
	number := func(value uint64) []byte {
		for extra := 0; extra < 8; extra++ {
			if value < uint64(1)<<(7+7*extra) {
				encoded := make([]byte, extra+1)
				encoded[0] = byte(0xff<<(8-extra)) | byte(value>>(8*extra))
				for i := 0; i < extra; i++ {
					encoded[i+1] = byte(value >> (8 * i))
				}
				return encoded
			}
		}
		encoded := make([]byte, 9)
		encoded[0] = 0xff
		binary.LittleEndian.PutUint64(encoded[1:], value)
		return encoded
	}
	header := []byte{1, 4, 6, 0, 1, 9} // Header, MainStreams, PackInfo, one stream.
	header = append(header, number(uint64(len(payload)))...)
	header = append(header, 0, 7, 11, 1, 0, 1, 1, 0, 12) // One Copy folder.
	header = append(header, number(uint64(len(payload)))...)
	header = append(header, 0, 0, 5, 1, 17) // FilesInfo, one name property.
	name := []byte{0}                       // Names stored here, followed by UTF-16LE and terminator.
	for _, ch := range "input.bin" {
		name = append(name, byte(ch), 0)
	}
	name = append(name, 0, 0)
	header = append(header, number(uint64(len(name)))...)
	header = append(header, name...)
	header = append(header, 0, 0)
	out := make([]byte, 32, 32+len(payload)+len(header))
	copy(out, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4})
	binary.LittleEndian.PutUint64(out[12:], uint64(len(payload)))
	binary.LittleEndian.PutUint64(out[20:], uint64(len(header)))
	binary.LittleEndian.PutUint32(out[28:], crc32.ChecksumIEEE(header))
	binary.LittleEndian.PutUint32(out[8:], crc32.ChecksumIEEE(out[12:]))
	out = append(out, payload...)
	return append(out, header...)
}
