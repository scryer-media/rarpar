package par3bench

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// generatorVersion is folded into every seed. Changing how bytes are produced
// must change it, so a cached dataset from an older generator is regenerated
// rather than silently reused.
const generatorVersion = "rarpar-par3-bench-data-v1"

// DatasetManifest records what a generated dataset directory holds.
type DatasetManifest struct {
	Generator string       `json:"generator"`
	Dataset   Dataset      `json:"dataset"`
	SHA256    []FileDigest `json:"sha256"`
}

// FileDigest is one file's SHA-256.
type FileDigest struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func fileSeed(datasetID, name string) [32]byte {
	return sha256.Sum256([]byte(generatorVersion + "\x00" + datasetID + "\x00" + name))
}

// writeGenerated writes size pseudo-random bytes from a ChaCha8 stream keyed by
// the dataset and file name, hashing them on the way out.
func writeGenerated(path, datasetID string, spec FileSpec) (string, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	stream := rand.NewChaCha8(fileSeed(datasetID, spec.Name))
	hasher := sha256.New()
	writer := bufio.NewWriterSize(io.MultiWriter(file, hasher), 1<<20)
	buffer := make([]byte, 1<<20)
	remaining := spec.Size
	for remaining > 0 {
		chunk := buffer
		if remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		if _, err := stream.Read(chunk); err != nil {
			file.Close()
			return "", err
		}
		if _, err := writer.Write(chunk); err != nil {
			file.Close()
			return "", err
		}
		remaining -= int64(len(chunk))
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// EnsureDataset generates the dataset under dir unless a manifest for the same
// generator and file list is already there and every file still hashes to it.
func EnsureDataset(dir string, dataset Dataset, log func(string, ...any)) (DatasetManifest, error) {
	manifestPath := filepath.Join(dir, "dataset.json")
	var existing DatasetManifest
	if data, err := os.ReadFile(manifestPath); err == nil && json.Unmarshal(data, &existing) == nil &&
		existing.Generator == generatorVersion && sameFiles(existing.Dataset, dataset) {
		if err := checkDigests(dir, existing.SHA256); err == nil {
			return existing, nil
		} else if log != nil {
			log("dataset %s: cached copy rejected (%v); regenerating", dataset.ID, err)
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return DatasetManifest{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return DatasetManifest{}, err
	}
	manifest := DatasetManifest{Generator: generatorVersion, Dataset: dataset}
	for _, spec := range dataset.Files {
		if log != nil {
			log("dataset %s: generating %s (%d bytes)", dataset.ID, spec.Name, spec.Size)
		}
		digest, err := writeGenerated(filepath.Join(dir, spec.Name), dataset.ID, spec)
		if err != nil {
			return DatasetManifest{}, err
		}
		manifest.SHA256 = append(manifest.SHA256, FileDigest{Name: spec.Name, Size: spec.Size, SHA256: digest})
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return DatasetManifest{}, err
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o644); err != nil {
		return DatasetManifest{}, err
	}
	return manifest, nil
}

func sameFiles(a, b Dataset) bool {
	if a.ID != b.ID || len(a.Files) != len(b.Files) {
		return false
	}
	for i := range a.Files {
		if a.Files[i] != b.Files[i] {
			return false
		}
	}
	return true
}

// checkDigests confirms every listed file in dir has its recorded size and hash.
func checkDigests(dir string, digests []FileDigest) error {
	for _, want := range digests {
		got, size, err := hashFile(filepath.Join(dir, want.Name))
		if err != nil {
			return err
		}
		if size != want.Size || got != want.SHA256 {
			return fmt.Errorf("%s: sha256 %s size %d, want %s size %d", want.Name, got, size, want.SHA256, want.Size)
		}
	}
	return nil
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// DamageOffsets lists the byte offsets of the blocks a target destroys: n block
// indices spread evenly over the file, b_i = i*blocks/n.
func DamageOffsets(fileSize, blockSize int64, n int) []int64 {
	blocks := (fileSize + blockSize - 1) / blockSize
	if n <= 0 || blocks == 0 {
		return nil
	}
	offsets := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		index := int64(i) * blocks / int64(n)
		offsets = append(offsets, index*blockSize)
	}
	return offsets
}

// ApplyDamage zeroes the profile's blocks in a staged copy of the dataset.
func ApplyDamage(dir string, dataset Dataset, blockSize int64, damage Damage) error {
	zeros := make([]byte, blockSize)
	for _, target := range damage.Targets {
		spec := dataset.Files[target.File]
		file, err := os.OpenFile(filepath.Join(dir, spec.Name), os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		for _, offset := range DamageOffsets(spec.Size, blockSize, target.Blocks) {
			length := blockSize
			if offset+length > spec.Size {
				length = spec.Size - offset
			}
			if _, err := file.WriteAt(zeros[:length], offset); err != nil {
				file.Close()
				return err
			}
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

// CarrierFile is one PAR3 file a create produced.
type CarrierFile struct {
	Name   string         `json:"name"`
	Size   int64          `json:"size"`
	SHA256 string         `json:"sha256"`
	Types  map[string]int `json:"packet_types,omitempty"`
}

// CarrierSet is the identity summary of a create's output directory.
type CarrierSet struct {
	Files []CarrierFile `json:"files"`
	// Digest is the SHA-256 of the sorted "name sha256" lines: equal digests
	// mean byte-identical carrier sets under identical names.
	Digest string `json:"digest"`
	// InputSetIDs are the distinct InputSetIDs in the packet headers.
	InputSetIDs []string `json:"input_set_ids"`
	// Creators are the distinct Creator packet texts.
	Creators []string `json:"creators"`
	// Fields are the distinct Galois field sizes the Start packets declare
	// ("gf8", "gf16", or "gf-N" for anything else).
	Fields []string `json:"fields"`
	// bodies maps packet type to the set of body digests (unexported: used for
	// the comparison, not recorded).
	bodies map[string]map[string]bool
	// recovery maps recovery block index to the SHA-256 of its payload.
	recovery map[uint64]string
}

var packetMagic = []byte("PAR3\x00PKT")

// ReadCarrierSet hashes every *.par3 file in dir and walks its packets.
func ReadCarrierSet(dir string) (CarrierSet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return CarrierSet{}, err
	}
	set := CarrierSet{bodies: map[string]map[string]bool{}, recovery: map[uint64]string{}}
	ids := map[string]bool{}
	creators := map[string]bool{}
	fields := map[string]bool{}
	var lines []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".par3") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return CarrierSet{}, err
		}
		sum := sha256.Sum256(data)
		file := CarrierFile{Name: entry.Name(), Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Types: map[string]int{}}
		if err := walkPackets(data, func(setID []byte, typ string, body []byte) {
			file.Types[typ]++
			ids[hex.EncodeToString(setID)] = true
			bodySum := sha256.Sum256(body)
			if set.bodies[typ] == nil {
				set.bodies[typ] = map[string]bool{}
			}
			set.bodies[typ][hex.EncodeToString(bodySum[:])] = true
			switch typ {
			case "PAR CRE":
				creators[string(body)] = true
			case "PAR STA":
				// Parent InputSetID (8), parent Root hash (16), block size (8),
				// then the Galois field size byte.
				if len(body) > 32 {
					fields[fieldName(body[32])] = true
				}
			case "PAR REC":
				// Root hash (16), Matrix hash (16), recovery index (8), payload.
				if len(body) >= 40 {
					index := binary.LittleEndian.Uint64(body[32:40])
					payload := sha256.Sum256(trimZeros(body[40:]))
					set.recovery[index] = hex.EncodeToString(payload[:])
				}
			}
		}); err != nil {
			return CarrierSet{}, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		set.Files = append(set.Files, file)
		lines = append(lines, file.Name+" "+file.SHA256)
	}
	sort.Slice(set.Files, func(i, j int) bool { return set.Files[i].Name < set.Files[j].Name })
	sort.Strings(lines)
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	set.Digest = hex.EncodeToString(digest[:])
	set.InputSetIDs = sortedKeys(ids)
	set.Creators = sortedKeys(creators)
	set.Fields = sortedKeys(fields)
	return set, nil
}

// walkPackets reads the 48-byte PAR3 packet headers in order. It only parses;
// nothing here assembles or edits a packet.
func walkPackets(data []byte, visit func(setID []byte, typ string, body []byte)) error {
	for offset := 0; offset < len(data); {
		if len(data)-offset < 48 {
			return fmt.Errorf("%d trailing bytes after the last packet", len(data)-offset)
		}
		header := data[offset : offset+48]
		if string(header[:8]) != string(packetMagic) {
			return fmt.Errorf("no packet magic at offset %d", offset)
		}
		length := binary.LittleEndian.Uint64(header[24:32])
		if length < 48 || length > uint64(len(data)-offset) {
			return fmt.Errorf("packet at offset %d has length %d", offset, length)
		}
		typ := strings.TrimRight(string(header[40:48]), "\x00")
		visit(header[32:40], typ, data[offset+48:offset+int(length)])
		offset += int(length)
	}
	return nil
}

func fieldName(size byte) string {
	switch size {
	case 1:
		return "gf8"
	case 2:
		return "gf16"
	default:
		return fmt.Sprintf("gf-%d", size)
	}
}

func trimZeros(data []byte) []byte {
	end := len(data)
	for end > 0 && data[end-1] == 0 {
		end--
	}
	return data[:end]
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Identity is the comparison of a candidate's carrier set with the
// reference's, from strictest to loosest.
type Identity struct {
	// Bytes: every carrier file has the same name and the same bytes.
	Bytes bool `json:"bytes"`
	// Layout: the same file names with the same sizes.
	Layout bool `json:"layout"`
	// SameInputSetID: the packet headers carry the same InputSetID.
	SameInputSetID bool `json:"same_input_set_id"`
	// RecoveryPayloads: every recovery block index carries the same payload,
	// which isolates the coding math from metadata differences.
	RecoveryPayloads bool `json:"recovery_payloads"`
	// RecoveryBlocks is the count of matching recovery payloads out of Total.
	RecoveryMatched int `json:"recovery_matched"`
	RecoveryTotal   int `json:"recovery_total"`
	// DifferingTypes lists packet types whose distinct bodies differ.
	DifferingTypes []string `json:"differing_packet_types,omitempty"`
	// CountDifferences lists per-file packet-type count differences
	// ("file:type ref=N ours=M"), which explain size differences.
	CountDifferences []string `json:"packet_count_differences,omitempty"`
	ReferenceDigest  string   `json:"reference_digest"`
	CandidateDigest  string   `json:"candidate_digest"`
	ReferenceFields  []string `json:"reference_fields,omitempty"`
	CandidateFields  []string `json:"candidate_fields,omitempty"`
	ReferenceCreator []string `json:"reference_creator,omitempty"`
	CandidateCreator []string `json:"candidate_creator,omitempty"`
}

// Verdict is the one-word summary used in tables.
func (i Identity) Verdict() string {
	switch {
	case i.Bytes:
		return "identical"
	case i.RecoveryPayloads:
		return "payloads-only"
	default:
		return "DIFFERENT"
	}
}

// CompareCarriers compares a candidate's carrier set with the reference's.
func CompareCarriers(reference, candidate CarrierSet) Identity {
	identity := Identity{
		Bytes:            reference.Digest == candidate.Digest,
		ReferenceDigest:  reference.Digest,
		CandidateDigest:  candidate.Digest,
		ReferenceFields:  reference.Fields,
		CandidateFields:  candidate.Fields,
		ReferenceCreator: reference.Creators,
		CandidateCreator: candidate.Creators,
		SameInputSetID:   strings.Join(reference.InputSetIDs, ",") == strings.Join(candidate.InputSetIDs, ","),
	}
	refFiles := map[string]CarrierFile{}
	for _, file := range reference.Files {
		refFiles[file.Name] = file
	}
	identity.Layout = len(reference.Files) == len(candidate.Files)
	for _, file := range candidate.Files {
		ref, ok := refFiles[file.Name]
		if !ok || ref.Size != file.Size {
			identity.Layout = false
		}
		if ok {
			for _, typ := range unionKeys(ref.Types, file.Types) {
				if ref.Types[typ] != file.Types[typ] {
					identity.CountDifferences = append(identity.CountDifferences,
						fmt.Sprintf("%s:%s ref=%d ours=%d", file.Name, typ, ref.Types[typ], file.Types[typ]))
				}
			}
		}
	}
	for _, typ := range unionKeys(countMap(reference.bodies), countMap(candidate.bodies)) {
		if !sameSet(reference.bodies[typ], candidate.bodies[typ]) {
			identity.DifferingTypes = append(identity.DifferingTypes, typ)
		}
	}
	identity.RecoveryTotal = len(reference.recovery)
	for index, digest := range reference.recovery {
		if candidate.recovery[index] == digest {
			identity.RecoveryMatched++
		}
	}
	identity.RecoveryPayloads = identity.RecoveryTotal > 0 && identity.RecoveryMatched == identity.RecoveryTotal &&
		len(candidate.recovery) == identity.RecoveryTotal
	return identity
}

func countMap(bodies map[string]map[string]bool) map[string]int {
	out := map[string]int{}
	for key, value := range bodies {
		out[key] = len(value)
	}
	return out
}

func unionKeys(a, b map[string]int) []string {
	set := map[string]bool{}
	for key := range a {
		set[key] = true
	}
	for key := range b {
		set[key] = true
	}
	return sortedKeys(set)
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if !b[key] {
			return false
		}
	}
	return true
}

// copyFile copies a regular file (used to stage inputs; never timed).
func copyFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// linkOrCopy hard-links when it can and copies otherwise. Only read-only
// stages (verify) use it; a repair stage always gets private copies, because
// repairing a hard link would damage the cached dataset.
func linkOrCopy(source, destination string) error {
	if err := os.Link(source, destination); err == nil {
		return nil
	} else if errors.Is(err, os.ErrExist) {
		return err
	}
	return copyFile(source, destination)
}
