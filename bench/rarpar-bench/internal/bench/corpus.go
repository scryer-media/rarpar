package bench

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const benchmarkPassword = "rarpar-benchmark-only-password"

func LoadCorpusConfig(path string) (CorpusConfig, error) {
	var config CorpusConfig
	if err := readJSON(path, &config); err != nil {
		return CorpusConfig{}, err
	}
	if err := config.Validate(); err != nil {
		return CorpusConfig{}, err
	}
	return config, nil
}

func (config CorpusConfig) Validate() error {
	if config.SchemaVersion != 1 || config.ID == "" || config.Seed == "" || config.PayloadBytes <= 0 || config.VolumeSize == "" {
		return fmt.Errorf("invalid corpus configuration")
	}
	if config.PAR2RedundancyPercent <= 0 || config.PAR2RedundancyPercent > 100 {
		return fmt.Errorf("PAR2 redundancy must be in 1..100")
	}
	seen := map[string]bool{}
	for _, item := range config.Cases {
		if item.ID == "" || item.Workload == "" || seen[item.ID] {
			return fmt.Errorf("corpus contains invalid or duplicate case %q", item.ID)
		}
		if item.Family != "rar" && item.Family != "par2" {
			return fmt.Errorf("case %q has unsupported family %q", item.ID, item.Family)
		}
		if item.Format < 3 || item.Format > 5 || item.Writer == "" {
			return fmt.Errorf("case %q has unsupported RAR writer configuration", item.ID)
		}
		if item.PPMd && item.Format != 4 {
			return fmt.Errorf("case %q requests PPMd outside RAR4", item.ID)
		}
		profile := item.PayloadProfile
		if profile == "" {
			profile = "binary"
		}
		if profile != "binary" && profile != "text" {
			return fmt.Errorf("case %q has unsupported payload profile %q", item.ID, item.PayloadProfile)
		}
		if item.PPMd && profile != "text" {
			return fmt.Errorf("PPMd case %q must use the text payload profile", item.ID)
		}
		if item.HeaderEncrypted && !item.Encrypted {
			return fmt.Errorf("case %q encrypts headers without enabling encryption", item.ID)
		}
		if item.PayloadBytes < 0 {
			return fmt.Errorf("case %q has a negative payload size", item.ID)
		}
		if item.Mutation != "none" && item.Mutation != "damage" && item.Mutation != "heavy-damage" && item.Mutation != "remove-volume" {
			return fmt.Errorf("case %q has unsupported mutation %q", item.ID, item.Mutation)
		}
		if item.PAR2Operation != "" && item.PAR2Operation != "create" {
			return fmt.Errorf("case %q has unsupported PAR2 operation %q", item.ID, item.PAR2Operation)
		}
		if item.PAR2Operation != "" && item.Family != "par2" {
			return fmt.Errorf("non-PAR2 case %q has a PAR2 operation", item.ID)
		}
		if item.PAR2Operation == "create" && (item.PAR2 || item.Mutation != "none") {
			return fmt.Errorf("PAR2 generation case %q must start from clean source files without parity", item.ID)
		}
		if item.PAR2Operation == "create" && item.PAR2RecoveryPercent == 0 {
			return fmt.Errorf("PAR2 generation case %q requires an explicit recovery percent", item.ID)
		}
		if item.Mutation == "heavy-damage" && (item.DamageCount < 1 || item.DamageBytesPerSite < 1 || item.PAR2SliceSize < 1) {
			return fmt.Errorf("heavy-damage case %q requires damage count, bytes per site, and PAR2 slice size", item.ID)
		}
		if item.Mutation != "heavy-damage" && (item.DamageCount != 0 || item.DamageBytesPerSite != 0) {
			return fmt.Errorf("case %q has heavy-damage settings without the heavy-damage mutation", item.ID)
		}
		if item.PAR2SliceSize < 0 || (item.PAR2SliceSize != 0 && item.Family != "par2") {
			return fmt.Errorf("case %q has invalid PAR2 slice size", item.ID)
		}
		if item.PAR2RecoveryPercent < 0 || item.PAR2RecoveryPercent > 100 || (item.PAR2RecoveryPercent != 0 && item.Family != "par2") {
			return fmt.Errorf("case %q has invalid PAR2 recovery percent", item.ID)
		}
		if item.FixtureDir != "" {
			if item.FixturePrefix == "" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(item.FixtureSHA256) {
				return fmt.Errorf("fixture case %q requires a prefix and pinned SHA-256", item.ID)
			}
		} else if item.FixturePrefix != "" || item.FixtureSHA256 != "" {
			return fmt.Errorf("case %q has incomplete fixture provenance", item.ID)
		}
		if item.Family == "par2" && !item.PAR2 && item.PAR2Operation != "create" {
			return fmt.Errorf("PAR2 case %q must generate parity", item.ID)
		}
		if item.Mutation != "none" && !item.PAR2 && !item.RecoveryVolumes {
			return fmt.Errorf("mutated case %q has no recovery material", item.ID)
		}
		seen[item.ID] = true
	}
	return nil
}

func GenerateCorpus(ctx context.Context, docker, harnessRoot, out string, lock ToolchainLock, config CorpusConfig) error {
	if err := ensureEmptyDir(out); err != nil {
		return err
	}
	configBytes, err := canonicalJSON(config)
	if err != nil {
		return err
	}
	toolchainBytes, err := canonicalJSON(lock)
	if err != nil {
		return err
	}
	generationDigest := bytesSHA256(append(configBytes, toolchainBytes...))
	for _, caseConfig := range config.Cases {
		writer, found := lock.Writer(caseConfig.Writer)
		if !found {
			return fmt.Errorf("case %q references unavailable writer %q", caseConfig.ID, caseConfig.Writer)
		}
		if err := generateCase(ctx, docker, harnessRoot, out, config, generationDigest, lock, writer, caseConfig); err != nil {
			return err
		}
	}
	manifests := make([]CorpusCaseManifest, 0, len(config.Cases))
	for _, caseConfig := range config.Cases {
		var manifest CorpusCaseManifest
		if err := readJSON(filepath.Join(out, caseConfig.ID, "manifest.json"), &manifest); err != nil {
			return err
		}
		manifests = append(manifests, manifest)
	}
	corpusDigest, err := corpusContentDigest(manifests)
	if err != nil {
		return err
	}
	for index := range manifests {
		manifests[index].CorpusDigest = corpusDigest
		if err := writeJSON(filepath.Join(out, manifests[index].ID, "manifest.json"), manifests[index]); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(out, "corpus.json"), map[string]any{
		"schema_version":    CorpusSchemaVersion,
		"id":                config.ID,
		"digest":            corpusDigest,
		"generation_digest": generationDigest,
		"case_count":        len(config.Cases),
		"harness_root":      filepath.Base(harnessRoot),
	})
}

func generateCase(ctx context.Context, docker, harnessRoot, corpusRoot string, config CorpusConfig, generationDigest string, lock ToolchainLock, writer RARWriter, item CaseConfig) error {
	caseRoot := filepath.Join(corpusRoot, item.ID)
	workRoot, err := os.MkdirTemp("", "rarpar-bench-corpus-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workRoot)
	var expected []ExpectedFile
	if item.FixtureDir != "" {
		if err := importFixture(workRoot, harnessRoot, item); err != nil {
			return err
		}
		expected, err = expectedFromWriter(ctx, docker, writer, workRoot, item.Encrypted)
		if err != nil {
			return fmt.Errorf("extract expected output for fixture %s: %w", item.ID, err)
		}
	} else {
		payloadRoot := filepath.Join(workRoot, "payload")
		if err := os.MkdirAll(payloadRoot, 0o755); err != nil {
			return err
		}
		expected, err = writeDeterministicPayload(payloadRoot, config.Seed, item.ID, payloadBytesForCase(config, item), item.PayloadProfile)
		if err != nil {
			return fmt.Errorf("write payload for %s: %w", item.ID, err)
		}
		volumeSize := config.VolumeSize
		if item.VolumeSize != "" {
			volumeSize = item.VolumeSize
		}
		archiveArgs := []string{"run", "--rm", "--platform", writer.Platform, "-v", workRoot + ":/work", "-w", "/work", writer.Image, "a", "-idq", "-tsm-", "-v" + volumeSize}
		// The legacy writers naturally emit their own format; RAR 3.93 does not
		// understand -ma3. RAR 5 is the only case that needs an explicit selector.
		if item.Format == 5 {
			archiveArgs = append(archiveArgs, "-ma5")
		}
		if item.Store {
			archiveArgs = append(archiveArgs, "-m0")
		}
		if item.PPMd {
			// RAR4's text module is its PPMd decoder path. Force it and pin its
			// order and memory so this corpus case has stable codec provenance.
			archiveArgs = append(archiveArgs, "-mc10:32t+")
		}
		if !item.Solid {
			archiveArgs = append(archiveArgs, "-s-")
		}
		if item.Encrypted {
			passwordSwitch := "-p"
			if item.HeaderEncrypted {
				passwordSwitch = "-hp"
			}
			archiveArgs = append(archiveArgs, passwordSwitch+benchmarkPassword)
		}
		if item.RecoveryVolumes {
			archiveArgs = append(archiveArgs, "-rv2")
		}
		archiveArgs = append(archiveArgs, "release.rar", "payload")
		if err := runCommand(ctx, docker, archiveArgs...); err != nil {
			return fmt.Errorf("build archive for %s: %w", item.ID, err)
		}
	}
	if item.PAR2 && item.FixtureDir == "" {
		par2 := lock.PAR2Generator
		par2Args := []string{"run", "--rm", "--platform", par2.Platform, "-v", workRoot + ":/work", "-w", "/work", par2.Image,
			"c", "-q", fmt.Sprintf("-r%d", par2RecoveryPercent(config, item)), fmt.Sprintf("-s%d", par2SliceSize(item)), "release.par2"}
		archiveFiles, err := archiveFilesIn(workRoot)
		if err != nil {
			return err
		}
		par2Args = append(par2Args, archiveFiles...)
		if err := runCommand(ctx, docker, par2Args...); err != nil {
			return fmt.Errorf("create parity for %s: %w", item.ID, err)
		}
	}
	if err := verifyWithWriter(ctx, docker, writer, workRoot, item.Encrypted, expected); err != nil {
		return fmt.Errorf("verify generated archive %s: %w", item.ID, err)
	}
	if err := os.RemoveAll(filepath.Join(workRoot, "payload")); err != nil {
		return err
	}
	sourceRoot := filepath.Join(caseRoot, "source")
	if err := os.MkdirAll(sourceRoot, 0o755); err != nil {
		return err
	}
	files, err := archiveFilesIn(workRoot)
	if err != nil {
		return err
	}
	for _, name := range files {
		if err := copyTreeFile(filepath.Join(workRoot, name), filepath.Join(sourceRoot, name)); err != nil {
			return err
		}
	}
	sources, err := sourceManifest(sourceRoot)
	if err != nil {
		return err
	}
	manifest := CorpusCaseManifest{
		SchemaVersion:    "rarpar-bench-case-v1",
		ID:               item.ID,
		Config:           item,
		CorpusID:         config.ID,
		GenerationDigest: generationDigest,
		Seed:             config.Seed,
		Toolchains:       ToolchainIDs(lock, item),
		Expected:         expected,
		Sources:          sources,
	}
	return writeJSON(filepath.Join(caseRoot, "manifest.json"), manifest)
}

func payloadBytesForCase(config CorpusConfig, item CaseConfig) int64 {
	if item.PayloadBytes > 0 {
		return item.PayloadBytes
	}
	return config.PayloadBytes
}

func par2SliceSize(item CaseConfig) int64 {
	if item.PAR2SliceSize > 0 {
		return item.PAR2SliceSize
	}
	return 64 * 1024
}

func par2RecoveryPercent(config CorpusConfig, item CaseConfig) int {
	if item.PAR2RecoveryPercent > 0 {
		return item.PAR2RecoveryPercent
	}
	return config.PAR2RedundancyPercent
}

func writeDeterministicPayload(root, seed, caseID string, total int64, profile string) ([]ExpectedFile, error) {
	if profile == "" {
		profile = "binary"
	}
	parts := payloadPartSizes(total)
	var expected []ExpectedFile
	extension := "bin"
	if profile == "text" {
		extension = "txt"
	}
	for index, bytes := range parts {
		relative := filepath.Join("payload", fmt.Sprintf("part-%02d.%s", index+1, extension))
		path := filepath.Join(filepath.Dir(root), relative)
		digest, err := writePayloadFileWithProfile(path, seed, caseID, relative, bytes, profile)
		if err != nil {
			return nil, err
		}
		expected = append(expected, ExpectedFile{Path: filepath.ToSlash(relative), Bytes: bytes, SHA256: digest})
	}
	return expected, nil
}

func payloadPartSizes(total int64) []int64 {
	first := total/4*3 + total%4*3/4
	second := total / 8
	return []int64{first, second, total - first - second}
}

func writePayloadFile(path, seed, caseID, fileID string, bytes int64) (string, error) {
	return writePayloadFileWithProfile(path, seed, caseID, fileID, bytes, "binary")
}

func writePayloadFileWithProfile(path, seed, caseID, fileID string, bytes int64, profile string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	block := uint64(0)
	remaining := bytes
	buffer := make([]byte, 32*1024)
	for remaining > 0 {
		switch profile {
		case "binary":
			fillBinaryPayloadBlock(buffer, seed, caseID, fileID, block)
		case "text":
			fillTextPayloadBlock(buffer, seed, caseID, fileID, block)
		default:
			return "", fmt.Errorf("unsupported payload profile %q", profile)
		}
		count := int64(len(buffer))
		if count > remaining {
			count = remaining
		}
		if _, err := file.Write(buffer[:count]); err != nil {
			return "", err
		}
		if _, err := hash.Write(buffer[:count]); err != nil {
			return "", err
		}
		remaining -= count
		block++
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	deterministicTime := time.Unix(946684800, 0).UTC()
	if err := os.Chtimes(path, deterministicTime, deterministicTime); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func corpusContentDigest(manifests []CorpusCaseManifest) (string, error) {
	normalized := append([]CorpusCaseManifest(nil), manifests...)
	sort.Slice(normalized, func(left, right int) bool { return normalized[left].ID < normalized[right].ID })
	for index := range normalized {
		normalized[index].CorpusDigest = ""
	}
	encoded, err := canonicalJSON(normalized)
	if err != nil {
		return "", err
	}
	return bytesSHA256(encoded), nil
}

func fillBinaryPayloadBlock(buffer []byte, seed, caseID, fileID string, block uint64) {
	for offset := 0; offset < len(buffer); offset += sha256.Size {
		input := []byte(seed + "\x00" + caseID + "\x00" + fileID)
		var counter [16]byte
		binary.LittleEndian.PutUint64(counter[:8], block)
		binary.LittleEndian.PutUint64(counter[8:], uint64(offset/sha256.Size))
		input = append(input, counter[:]...)
		digest := sha256.Sum256(input)
		copy(buffer[offset:], digest[:])
	}
}

func fillTextPayloadBlock(buffer []byte, seed, caseID, fileID string, block uint64) {
	words := [...]string{"archive", "block", "checksum", "content", "extract", "header", "member", "parity", "repair", "volume"}
	input := []byte(seed + "\x00" + caseID + "\x00" + fileID)
	for offset, word := 0, uint64(0); offset < len(buffer); word++ {
		var counter [16]byte
		binary.LittleEndian.PutUint64(counter[:8], block)
		binary.LittleEndian.PutUint64(counter[8:], word)
		digest := sha256.Sum256(append(input, counter[:]...))
		token := words[int(digest[0])%len(words)] + " "
		offset += copy(buffer[offset:], token)
	}
}

func importFixture(workRoot, harnessRoot string, item CaseConfig) error {
	fixtureRoot := filepath.Clean(filepath.Join(harnessRoot, item.FixtureDir))
	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		return fmt.Errorf("read fixture for %s: %w", item.ID, err)
	}
	matched := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), item.FixturePrefix) {
			continue
		}
		if err := copyTreeFile(filepath.Join(fixtureRoot, entry.Name()), filepath.Join(workRoot, entry.Name())); err != nil {
			return err
		}
		matched++
	}
	if matched == 0 {
		return fmt.Errorf("fixture case %q matched no files", item.ID)
	}
	manifest, err := sourceManifest(workRoot)
	if err != nil {
		return err
	}
	encoded, err := canonicalJSON(manifest)
	if err != nil {
		return err
	}
	digest := bytesSHA256(encoded)
	if digest != item.FixtureSHA256 {
		return fmt.Errorf("fixture case %q digest mismatch: got %s, want %s", item.ID, digest, item.FixtureSHA256)
	}
	return nil
}

func expectedFromWriter(ctx context.Context, docker string, writer RARWriter, root string, encrypted bool) ([]ExpectedFile, error) {
	verifyRoot := filepath.Join(root, "verify")
	defer os.RemoveAll(verifyRoot)
	archive, err := firstRARVolume(root)
	if err != nil {
		return nil, err
	}
	args := []string{"run", "--rm", "--platform", writer.Platform, "-v", root + ":/work", "-w", "/work", writer.Image, "x", "-idq", "-y"}
	if encrypted {
		args = append(args, "-p"+benchmarkPassword)
	}
	args = append(args, archive, "verify/")
	if err := runCommand(ctx, docker, args...); err != nil {
		return nil, err
	}
	files, err := sourceManifest(verifyRoot)
	if err != nil {
		return nil, err
	}
	expected := make([]ExpectedFile, len(files))
	for index, file := range files {
		expected[index] = ExpectedFile{Path: file.Path, Bytes: file.Bytes, SHA256: file.SHA256}
	}
	return expected, nil
}

func verifyWithWriter(ctx context.Context, docker string, writer RARWriter, root string, encrypted bool, expected []ExpectedFile) error {
	verifyRoot := filepath.Join(root, "verify")
	archive, err := firstRARVolume(root)
	if err != nil {
		return err
	}
	args := []string{"run", "--rm", "--platform", writer.Platform, "-v", root + ":/work", "-w", "/work", writer.Image, "x", "-idq", "-y"}
	if encrypted {
		args = append(args, "-p"+benchmarkPassword)
	}
	args = append(args, archive, "verify/")
	if err := runCommand(ctx, docker, args...); err != nil {
		return err
	}
	return validateExpected(verifyRoot, expected)
}

func archiveFilesIn(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if entry.Type().IsRegular() && (strings.HasSuffix(name, ".rar") || strings.HasSuffix(name, ".rev") || strings.HasSuffix(name, ".par2") || regexp.MustCompile(`\.r\d\d$`).MatchString(name)) {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no archive files generated in %s", root)
	}
	return files, nil
}

func firstRARVolume(root string) (string, error) {
	files, err := archiveFilesIn(root)
	if err != nil {
		return "", err
	}
	for _, name := range files {
		lower := strings.ToLower(name)
		if strings.Contains(lower, ".part1.") || strings.Contains(lower, ".part01.") {
			return name, nil
		}
	}
	for _, name := range files {
		if strings.HasSuffix(strings.ToLower(name), ".rar") {
			return name, nil
		}
	}
	return "", fmt.Errorf("no first RAR volume generated in %s", root)
}

func sourceManifest(root string) ([]SourceFile, error) {
	files, err := sortedFiles(root)
	if err != nil {
		return nil, err
	}
	result := make([]SourceFile, 0, len(files))
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		digest, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		relative, _ := filepath.Rel(root, path)
		result = append(result, SourceFile{Path: filepath.ToSlash(relative), Bytes: info.Size(), SHA256: digest})
	}
	return result, nil
}

func VerifyCorpus(root string) error {
	indexPath := filepath.Join(root, "corpus.json")
	var index struct {
		Digest    string `json:"digest"`
		CaseCount int    `json:"case_count"`
	}
	if err := readJSON(indexPath, &index); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	count := 0
	var manifests []CorpusCaseManifest
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(root, entry.Name(), "manifest.json")
		var manifest CorpusCaseManifest
		if err := readJSON(manifestPath, &manifest); err != nil {
			return err
		}
		if manifest.CorpusDigest != index.Digest {
			return fmt.Errorf("case %q belongs to a different corpus", manifest.ID)
		}
		for _, source := range manifest.Sources {
			relative, err := cleanRelative(source.Path)
			if err != nil {
				return err
			}
			path := filepath.Join(root, entry.Name(), "source", relative)
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() != source.Bytes {
				return fmt.Errorf("source verification failed for %s", path)
			}
			digest, err := fileSHA256(path)
			if err != nil || digest != source.SHA256 {
				return fmt.Errorf("source checksum verification failed for %s", path)
			}
		}
		manifests = append(manifests, manifest)
		count++
	}
	if count == 0 {
		return fmt.Errorf("corpus contains no cases")
	}
	if index.CaseCount != count {
		return fmt.Errorf("corpus index declares %d cases, found %d", index.CaseCount, count)
	}
	digest, err := corpusContentDigest(manifests)
	if err != nil {
		return err
	}
	if digest != index.Digest {
		return fmt.Errorf("corpus content digest mismatch")
	}
	return nil
}

func validateExpected(root string, expected []ExpectedFile) error {
	for _, file := range expected {
		relative, err := cleanRelative(file.Path)
		if err != nil {
			return err
		}
		path := filepath.Join(root, relative)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != file.Bytes {
			return fmt.Errorf("expected output missing or wrong size: %s", file.Path)
		}
		digest, err := fileSHA256(path)
		if err != nil || digest != file.SHA256 {
			return fmt.Errorf("expected output checksum mismatch: %s", file.Path)
		}
	}
	return nil
}

func copyTreeFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func canonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}
