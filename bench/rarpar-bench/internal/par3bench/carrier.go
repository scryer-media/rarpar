package par3bench

// PAR-inside carriers. The harness writes only the original ZIP (members
// stored, deterministic headers) before any PAR3 bytes exist; the PAR3
// packets inside a carrier come from the reference's own insert. Nothing here
// assembles or edits a PAR3 packet: scanEmbedded only reads headers.

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

// BuildCarrierZIP writes the dataset's files, in order and stored (no
// compression), into a ZIP at path. Every header field is fixed (no
// timestamps, no data descriptors), so the ZIP bytes are a pure function of
// the dataset. It returns the ZIP's size.
func BuildCarrierZIP(path, dataDir string, dataset Dataset) (int64, error) {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	buffered := bufio.NewWriterSize(out, 1<<20)
	writer := zip.NewWriter(buffered)
	for _, spec := range dataset.Files {
		source := filepath.Join(dataDir, spec.Name)
		crc, err := fileCRC32(source)
		if err != nil {
			out.Close()
			return 0, err
		}
		header := &zip.FileHeader{
			Name:               spec.Name,
			Method:             zip.Store,
			CRC32:              crc,
			CompressedSize64:   uint64(spec.Size),
			UncompressedSize64: uint64(spec.Size),
		}
		member, err := writer.CreateRaw(header)
		if err != nil {
			out.Close()
			return 0, err
		}
		in, err := os.Open(source)
		if err != nil {
			out.Close()
			return 0, err
		}
		_, err = io.Copy(member, in)
		in.Close()
		if err != nil {
			out.Close()
			return 0, err
		}
	}
	if err := writer.Close(); err != nil {
		out.Close()
		return 0, err
	}
	if err := buffered.Flush(); err != nil {
		out.Close()
		return 0, err
	}
	info, err := out.Stat()
	if err != nil {
		out.Close()
		return 0, err
	}
	return info.Size(), out.Close()
}

func fileCRC32(path string) (uint32, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	hasher := crc32.NewIEEE()
	if _, err := io.Copy(hasher, file); err != nil {
		return 0, err
	}
	return hasher.Sum32(), nil
}

// EmbeddedSet is what a carrier's embedded PAR3 packets declare.
type EmbeddedSet struct {
	// FirstPacket is the offset of the first PAR3 packet: the reference
	// appends its region after the original ZIP bytes.
	FirstPacket int64
	BlockSize   int64
	// Recovery counts distinct recovery block indices.
	Recovery int64
	Field    string
}

// scanEmbedded reads the PAR3 packet headers inside a carrier file: every
// position carrying the packet magic and a plausible length is read as a
// header. It only parses.
func scanEmbedded(path string) (EmbeddedSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EmbeddedSet{}, err
	}
	set := EmbeddedSet{FirstPacket: -1}
	recovery := map[uint64]bool{}
	for offset := 0; offset+48 <= len(data); {
		next := bytes.Index(data[offset:], packetMagic)
		if next < 0 {
			break
		}
		offset += next
		if offset+48 > len(data) {
			break
		}
		length := binary.LittleEndian.Uint64(data[offset+24 : offset+32])
		if length < 48 || length > uint64(len(data)-offset) {
			offset++
			continue
		}
		if set.FirstPacket < 0 {
			set.FirstPacket = int64(offset)
		}
		typ := string(bytes.TrimRight(data[offset+40:offset+48], "\x00"))
		body := data[offset+48 : offset+int(length)]
		switch typ {
		case "PAR STA":
			if len(body) > 32 {
				set.BlockSize = int64(binary.LittleEndian.Uint64(body[24:32]))
				set.Field = fieldName(body[32])
			}
		case "PAR REC":
			if len(body) >= 40 {
				recovery[binary.LittleEndian.Uint64(body[32:40])] = true
			}
		}
		offset += int(length)
	}
	set.Recovery = int64(len(recovery))
	if set.FirstPacket < 0 || set.BlockSize <= 0 {
		return set, fmt.Errorf("%s: no embedded PAR3 Start packet found", filepath.Base(path))
	}
	if set.Recovery == 0 {
		return set, fmt.Errorf("%s: the embedded set carries no recovery blocks", filepath.Base(path))
	}
	return set, nil
}

// carrierDamageDataset is the view ApplyDamage uses for a carrier: one file,
// the carrier, as long as the original ZIP bytes minus the tail guard, so
// every damaged block lies in member data and none in the PAR3 region.
func carrierDamageDataset(originalSize int64) Dataset {
	size := originalSize - carrierDamageGuard
	if size < 0 {
		size = 0
	}
	return Dataset{ID: "carrier", Files: []FileSpec{{Name: carrierZIPName, Size: size}}}
}
