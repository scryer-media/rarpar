package bench

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Realistic payload profiles.
//
// The synthetic "binary" and "text" profiles model the two extremes of an LZ
// stream (incompressible noise, uniform word soup) but neither matches how real
// archived data behaves: measured against real archives their match-length
// distribution is far too long-tailed. These profiles instead build payloads out
// of bytes that really exist:
//
//   - source-text  : this repository's own tracked sources, read from a pinned
//     git revision so the bytes never move with the working tree.
//   - machine-code : real ELF images taken from the digest-pinned Docker base
//     already trusted by config/toolchains.json.
//   - ffmpeg-video : a real muxed A/V file — lavfi sources encoded with libx264
//     and AAC into Matroska by the pinned encoder image. This is
//     literally what rides inside a scene RAR, so it is the media
//     class default.
//   - ffmpeg-video-hevc : the same idea through a second codec and container
//     (libx265 into MP4), so the class is not one encoder's
//     bitstream shape.
//   - media        : the older synthesized stand-in, kept as the generic
//     high-entropy fallback and used where a payload member has to
//     land on an exact byte count (an encoder cannot). Structured
//     like a muxed container rather than like a CSPRNG:
//     incompressible payload in fixed-stride clusters with a
//     repeating signature plus periodic mux padding.
//   - mixed        : one release-shaped directory blending the classes.
//
// Every profile is a pure function of pinned inputs (git revision, image digest,
// corpus seed), so regeneration is reproducible. Unlike the legacy profiles the
// realistic ones deliberately do NOT derive from the case ID: all cases of one
// class share byte-identical payloads so that writer, mode, and checksum
// variants can be compared against each other with the data held constant.

const (
	profileBinary          = "binary"
	profileText            = "text"
	profileSourceText      = "source-text"
	profileMachineCode     = "machine-code"
	profileMedia           = "media"
	profileMixed           = "mixed"
	profileFFmpegVideo     = "ffmpeg-video"
	profileFFmpegVideoHEVC = "ffmpeg-video-hevc"
)

// realisticProfiles are the payload profiles that need PayloadAssets.
var realisticProfiles = map[string]bool{
	profileSourceText:      true,
	profileMachineCode:     true,
	profileMedia:           true,
	profileMixed:           true,
	profileFFmpegVideo:     true,
	profileFFmpegVideoHEVC: true,
}

// videoProfiles are the payload profiles produced by the pinned encoder.
var videoProfiles = map[string]bool{
	profileFFmpegVideo:     true,
	profileFFmpegVideoHEVC: true,
}

func supportedPayloadProfile(profile string) bool {
	return profile == profileBinary || profile == profileText || realisticProfiles[profile]
}

// profileNeedsSourceRev reports whether a profile reads the pinned git revision.
func profileNeedsSourceRev(profile string) bool {
	return profile == profileSourceText || profile == profileMixed
}

// sourceTextExtensions is the allowlist of tracked file suffixes that count as
// real source text. Everything else in the tree (archives, images, recorded
// fixtures) is excluded so the class stays what it claims to be.
var sourceTextExtensions = []string{
	".rs", ".toml", ".md", ".go", ".json", ".yml", ".yaml", ".sh", ".lock", ".txt", ".sql", ".c", ".h", ".cpp",
}

// realAsset is one real, externally pinned file used as benchmark payload input.
type realAsset struct {
	Path string
	Data []byte
}

// PayloadAssets lazily loads and caches the real byte sources the realistic
// payload profiles draw from. One instance is built per corpus generation and
// shared by every case, so the pinned git revision is read once and the pinned
// Docker base is entered once.
type PayloadAssets struct {
	ctx        context.Context
	docker     string
	repoRoot   string
	dockerBase string
	sourceRev  string
	encoder    VideoEncoder
	cache      map[string][]byte
	// videos maps an encode request to the file the encoder already produced,
	// so one video is encoded once and shared by every case that asks for it.
	videos   map[string]string
	videoDir string
}

func newPayloadAssets(ctx context.Context, docker, harnessRoot, dockerBase, sourceRev string, encoder VideoEncoder) *PayloadAssets {
	return &PayloadAssets{
		ctx:        ctx,
		docker:     docker,
		repoRoot:   filepath.Clean(filepath.Join(harnessRoot, "..", "..")),
		dockerBase: dockerBase,
		sourceRev:  sourceRev,
		encoder:    encoder,
		cache:      map[string][]byte{},
		videos:     map[string]string{},
	}
}

// Close releases the encoder scratch directory.
func (assets *PayloadAssets) Close() {
	if assets.videoDir != "" {
		_ = os.RemoveAll(assets.videoDir)
		assets.videoDir = ""
	}
}

// realBytes returns the full deterministic concatenation for a real-content
// profile, loading and caching it on first use.
func (assets *PayloadAssets) realBytes(profile string) ([]byte, error) {
	if cached, found := assets.cache[profile]; found {
		return cached, nil
	}
	var (
		files []realAsset
		err   error
	)
	switch profile {
	case profileSourceText:
		files, err = assets.sourceTextAssets()
	case profileMachineCode:
		files, err = assets.machineCodeAssets()
	default:
		return nil, fmt.Errorf("profile %q has no real byte source", profile)
	}
	if err != nil {
		return nil, err
	}
	stream := concatenateAssets(files, profile == profileSourceText)
	if len(stream) == 0 {
		return nil, fmt.Errorf("payload profile %q resolved to no bytes", profile)
	}
	assets.cache[profile] = stream
	return stream, nil
}

// sourceTextAssets reads this repository's tracked text at the pinned revision.
// Reading through `git archive` rather than the working tree is what makes the
// class reproducible: a revision's tree is immutable, an editable checkout is
// not.
func (assets *PayloadAssets) sourceTextAssets() ([]realAsset, error) {
	if assets.sourceRev == "" {
		return nil, fmt.Errorf("payload profile %q requires corpus source_rev", profileSourceText)
	}
	stream, err := runCommandStdout(assets.ctx, "git", "-C", assets.repoRoot, "archive", "--format=tar", assets.sourceRev)
	if err != nil {
		return nil, fmt.Errorf("read pinned source revision %s: %w", assets.sourceRev, err)
	}
	return collectTarAssets(stream, func(path string, data []byte) bool {
		if strings.Contains(path, "/fixtures/") || strings.Contains(path, "/testdata/") {
			return false
		}
		lower := strings.ToLower(path)
		for _, extension := range sourceTextExtensions {
			if strings.HasSuffix(lower, extension) {
				return true
			}
		}
		return false
	})
}

// machineCodeAssets reads real ELF images out of the digest-pinned Docker base.
// The digest pin is the same trust anchor config/toolchains.json already uses
// for the writers, so the bytes are fixed forever without vendoring a binary
// into the repository or depending on an unreproducible local build.
func (assets *PayloadAssets) machineCodeAssets() ([]realAsset, error) {
	if assets.dockerBase == "" {
		return nil, fmt.Errorf("payload profile %q requires a digest-pinned docker base", profileMachineCode)
	}
	stream, err := runCommandStdout(assets.ctx, assets.docker, "run", "--rm", "--platform", "linux/amd64",
		"--entrypoint", "tar", assets.dockerBase, "-cf", "-", "-C", "/", "usr/bin", "usr/sbin", "usr/lib/x86_64-linux-gnu")
	if err != nil {
		return nil, fmt.Errorf("read machine code from %s: %w", assets.dockerBase, err)
	}
	return collectTarAssets(stream, func(path string, data []byte) bool {
		return len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'
	})
}

// videoRecipe is a fully pinned encode. Every knob that could move the output
// bitstream is fixed here rather than left to an ffmpeg default, and the
// encoders are held to a single thread: x264 and x265 both make rate-control
// decisions that depend on how work was split across threads, so a
// multi-threaded encode is not reproducible even from identical input.
type videoRecipe struct {
	Extension    string
	VideoSource  string
	AudioSource  string
	VideoCodec   string
	CodecParams  string
	Width        int
	Height       int
	FrameRate    int
	VideoBitrate string
	AudioBitrate string
	// BytesPerSecond is the measured steady-state muxed output rate. It only
	// turns a requested payload size into an encode duration; the size that
	// actually lands is whatever the encoder produced and is what the manifest
	// records. An encoder cannot be asked for an exact byte count.
	BytesPerSecond int64
}

var videoRecipes = map[string]videoRecipe{
	profileFFmpegVideo: {
		Extension:      "mkv",
		VideoSource:    "testsrc2=size=1920x1080:rate=24",
		AudioSource:    "anoisesrc=sample_rate=48000:amplitude=0.5:seed=20260813:color=pink",
		VideoCodec:     "libx264",
		CodecParams:    "threads=1:sliced-threads=0:deterministic=1:log-level=none",
		Width:          1920,
		Height:         1080,
		FrameRate:      24,
		VideoBitrate:   "8000k",
		AudioBitrate:   "128k",
		BytesPerSecond: 1_050_000,
	},
	profileFFmpegVideoHEVC: {
		Extension:      "mp4",
		VideoSource:    "mandelbrot=size=1280x720:rate=24",
		AudioSource:    "anoisesrc=sample_rate=48000:amplitude=0.5:seed=20260814:color=brown",
		VideoCodec:     "libx265",
		CodecParams:    "pools=none:frame-threads=1:wpp=0:log-level=none",
		Width:          1280,
		Height:         720,
		FrameRate:      24,
		VideoBitrate:   "8000k",
		AudioBitrate:   "128k",
		BytesPerSecond: 1_040_000,
	},
}

func codecParamsFlag(codec string) string {
	if codec == "libx265" {
		return "-x265-params"
	}
	return "-x264-params"
}

// videoFile encodes (or reuses) one real video sized near a target and returns
// its path on disk.
func (assets *PayloadAssets) videoFile(profile string, target int64) (string, error) {
	recipe, found := videoRecipes[profile]
	if !found {
		return "", fmt.Errorf("payload profile %q has no video recipe", profile)
	}
	if assets.encoder.Image == "" {
		return "", fmt.Errorf("payload profile %q requires a pinned video encoder in the toolchain lock", profile)
	}
	key := fmt.Sprintf("%s/%d", profile, target)
	if path, cached := assets.videos[key]; cached {
		return path, nil
	}
	if assets.videoDir == "" {
		directory, err := os.MkdirTemp("", "rarpar-bench-video-")
		if err != nil {
			return "", err
		}
		assets.videoDir = directory
	}
	seconds := target / recipe.BytesPerSecond
	if seconds < 1 {
		seconds = 1
	}
	name := fmt.Sprintf("%s-%d.%s", profile, target, recipe.Extension)
	duration := strconv.FormatInt(seconds, 10)
	args := []string{
		"run", "--rm", "--platform", assets.encoder.Platform,
		"-v", assets.videoDir + ":/work", "-w", "/work",
		"--entrypoint", "ffmpeg", assets.encoder.Image,
		"-hide_banner", "-nostdin", "-y", "-loglevel", "error",
		// On the input side this keeps the lavfi sources off any
		// wall-clock-seeded behavior.
		"-fflags", "+bitexact",
		// Length is bounded with an input-level -t rather than a filter
		// duration= option: the lavfi sources do not agree on that option
		// (mandelbrot has no duration), but -t bounds all of them the same way.
		"-f", "lavfi", "-t", duration, "-i", recipe.VideoSource,
		"-f", "lavfi", "-t", duration, "-i", recipe.AudioSource,
		"-c:v", recipe.VideoCodec, "-preset", "veryfast", "-threads", "1",
		codecParamsFlag(recipe.VideoCodec), recipe.CodecParams,
		"-b:v", recipe.VideoBitrate, "-minrate", recipe.VideoBitrate,
		"-maxrate", recipe.VideoBitrate, "-bufsize", recipe.VideoBitrate,
		"-pix_fmt", "yuv420p", "-g", "48",
		"-c:a", "aac", "-b:a", recipe.AudioBitrate, "-ac", "2", "-ar", "48000",
		// Without bitexact on the encoders and the muxer the output carries an
		// encoder version SEI, a random Matroska SegmentUID, and a wall-clock
		// DateUTC/creation_time - measured: 60 bytes differ between two
		// otherwise identical encodes.
		"-flags:v", "+bitexact", "-flags:a", "+bitexact", "-fflags", "+bitexact",
		"-map_metadata", "-1",
		name,
	}
	if err := runCommand(assets.ctx, assets.docker, args...); err != nil {
		return "", fmt.Errorf("encode %s payload: %w", profile, err)
	}
	path := filepath.Join(assets.videoDir, name)
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("encoder produced no %s payload: %w", profile, err)
	}
	assets.videos[key] = path
	return path, nil
}

// collectTarAssets keeps the regular files a predicate accepts, in tar order
// normalized to sorted path order so the concatenation never depends on how the
// producer walked the tree.
func collectTarAssets(stream []byte, keep func(path string, data []byte) bool) ([]realAsset, error) {
	reader := tar.NewReader(bytes.NewReader(stream))
	var files []realAsset
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		path := filepath.ToSlash(filepath.Clean(header.Name))
		if len(data) == 0 || seen[path] || !keep(path, data) {
			continue
		}
		seen[path] = true
		files = append(files, realAsset{Path: path, Data: data})
	}
	sortAssets(files)
	return files, nil
}

func sortAssets(files []realAsset) {
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
}

// concatenateAssets joins real files into one stream. Source text keeps a path
// banner in front of each file the way a concatenated source dump or tar stream
// would; machine code is joined raw so no synthetic text dilutes the class.
func concatenateAssets(files []realAsset, banner bool) []byte {
	var stream bytes.Buffer
	for _, file := range files {
		if banner {
			stream.WriteString("\n===== " + file.Path + " =====\n")
		}
		stream.Write(file.Data)
	}
	return stream.Bytes()
}

// payloadPart describes one member of a realistic payload directory.
type payloadPart struct {
	Name    string
	Bytes   int64
	Profile string
	// Offset is the read position inside the class stream for real-content
	// parts, so the members of one payload never repeat each other's bytes.
	Offset int64
	// SizeIsTarget marks a member whose size the generator can only aim at.
	// An encoder is handed a duration, not a byte count, so a real video member
	// lands near its target and the manifest records what it actually got.
	SizeIsTarget bool
}

// realisticPayloadLayout resolves a profile and total size into the concrete
// member list. Layouts are deliberately release-shaped rather than uniform: a
// media payload is one large member plus a small text sidecar, the way a real
// posted release is.
func realisticPayloadLayout(profile string, total int64) ([]payloadPart, error) {
	if total <= 0 {
		return nil, fmt.Errorf("payload profile %q needs a positive size", profile)
	}
	switch profile {
	case profileSourceText, profileMachineCode:
		extension := "txt"
		if profile == profileMachineCode {
			extension = "bin"
		}
		var parts []payloadPart
		offset := int64(0)
		for index, size := range payloadPartSizes(total) {
			parts = append(parts, payloadPart{
				Name:    fmt.Sprintf("part-%02d.%s", index+1, extension),
				Bytes:   size,
				Profile: profile,
				Offset:  offset,
			})
			offset += size
		}
		return parts, nil
	case profileMedia:
		sidecar := mediaSidecarBytes(total)
		return []payloadPart{
			{Name: "part-01.mkv", Bytes: total - sidecar, Profile: profileMedia},
			{Name: "part-02.nfo", Bytes: sidecar, Profile: profileText},
		}, nil
	case profileFFmpegVideo, profileFFmpegVideoHEVC:
		// A posted release is one large video plus a small text sidecar, so
		// that is the shape here too.
		sidecar := mediaSidecarBytes(total)
		return []payloadPart{
			{
				Name:         "part-01." + videoRecipes[profile].Extension,
				Bytes:        total - sidecar,
				Profile:      profile,
				SizeIsTarget: true,
			},
			{Name: "part-02.nfo", Bytes: sidecar, Profile: profileText},
		}, nil
	case profileMixed:
		// The source share is capped well under the size of this repository's
		// tracked text so the class never has to repeat itself to fill a member.
		media := total / 100 * 65
		source := total / 100 * 15
		code := total / 100 * 15
		sidecar := total - media - source - code
		return []payloadPart{
			{Name: "part-01.mkv", Bytes: media, Profile: profileMedia},
			{Name: "part-02.txt", Bytes: source, Profile: profileSourceText},
			{Name: "part-03.bin", Bytes: code, Profile: profileMachineCode},
			{Name: "part-04.nfo", Bytes: sidecar, Profile: profileText},
		}, nil
	}
	return nil, fmt.Errorf("profile %q has no realistic layout", profile)
}

func mediaSidecarBytes(total int64) int64 {
	sidecar := int64(64 * 1024)
	if sidecar > total/16 {
		sidecar = total / 16
	}
	if sidecar < 1 {
		sidecar = 1
	}
	return sidecar
}

// writeRealisticPayload materializes one realistic payload directory. The
// returned expectations are in the same shape the synthetic profiles produce, so
// nothing downstream of the generator has to know which profile built a case.
func writeRealisticPayload(assets *PayloadAssets, root, seed, profile string, total int64) ([]ExpectedFile, error) {
	parts, err := realisticPayloadLayout(profile, total)
	if err != nil {
		return nil, err
	}
	var expected []ExpectedFile
	for _, part := range parts {
		if part.Bytes <= 0 {
			return nil, fmt.Errorf("payload profile %q produced an empty member %q", profile, part.Name)
		}
		relative := filepath.Join("payload", part.Name)
		path := filepath.Join(filepath.Dir(root), relative)
		digest, err := writeRealisticPayloadFile(assets, path, seed, part)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		expected = append(expected, ExpectedFile{Path: filepath.ToSlash(relative), Bytes: info.Size(), SHA256: digest})
	}
	return expected, nil
}

func writeRealisticPayloadFile(assets *PayloadAssets, path, seed string, part payloadPart) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if videoProfiles[part.Profile] {
		source, err := assets.videoFile(part.Profile, part.Bytes)
		if err != nil {
			return "", err
		}
		if err := copyTreeFile(source, path); err != nil {
			return "", err
		}
		if err := stampDeterministicTime(path); err != nil {
			return "", err
		}
		return fileSHA256(path)
	}
	var content []byte
	switch part.Profile {
	case profileSourceText, profileMachineCode:
		stream, err := assets.realBytes(part.Profile)
		if err != nil {
			return "", err
		}
		end := part.Offset + part.Bytes
		if end > int64(len(stream)) {
			return "", fmt.Errorf("payload profile %q needs %d bytes but only %d are available; lower the case payload size",
				part.Profile, end, len(stream))
		}
		content = stream[part.Offset:end]
	case profileMedia:
		content = buildMediaStream(seed, part.Name, part.Bytes)
	case profileText:
		content = buildTextStream(seed, part.Name, part.Bytes)
	default:
		return "", fmt.Errorf("unsupported realistic member profile %q", part.Profile)
	}
	if int64(len(content)) != part.Bytes {
		return "", fmt.Errorf("payload member %q produced %d bytes, want %d", part.Name, len(content), part.Bytes)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", err
	}
	if err := stampDeterministicTime(path); err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return fmt.Sprintf("%x", digest[:]), nil
}

// mediaClusterBytes is the fixed stride the synthesized container writes its
// headers at, mirroring how a muxer emits clusters.
const mediaClusterBytes = 32 * 1024

// mediaPadClusters is how many clusters pass between mux padding runs.
const mediaPadClusters = 32

// mediaPadBytes is the size of one mux padding run.
const mediaPadBytes = 2048

// mediaSignature is the constant container magic repeated at every cluster
// boundary. It is what makes the class compressible at all: a handful of exact
// short matches at a long, regular distance, exactly like a real container's
// repeated element IDs.
var mediaSignature = [16]byte{0x1a, 0x45, 0xdf, 0xa3, 0x42, 0x86, 0x81, 0x01, 0x53, 0x80, 0x67, 0x88, 0x1f, 0x43, 0xb6, 0x75}

// buildMediaStream synthesizes container-shaped high-entropy data: an
// incompressible body carried in fixed-stride clusters, each opened by a
// repeating signature and per-cluster counters, with a periodic zero padding run
// standing in for mux padding. Real posted media is stored, not compressed, so
// what this class has to get right is entropy and structure, not literal
// content.
func buildMediaStream(seed, fileID string, total int64) []byte {
	stream := make([]byte, total)
	key := []byte(seed + "\x00" + profileMedia + "\x00" + fileID)
	for offset := int64(0); offset < total; offset += mediaClusterBytes {
		end := offset + mediaClusterBytes
		if end > total {
			end = total
		}
		cluster := stream[offset:end]
		block := uint64(offset / mediaClusterBytes)
		fillEntropyBlock(cluster, key, block)
		if len(cluster) >= 64 {
			copy(cluster[0:16], mediaSignature[:])
			binary.LittleEndian.PutUint64(cluster[16:24], block)
			binary.LittleEndian.PutUint64(cluster[56:64], block/mediaPadClusters)
		}
		if block%mediaPadClusters == mediaPadClusters-1 && len(cluster) >= mediaPadBytes {
			padding := cluster[len(cluster)-mediaPadBytes:]
			for index := range padding {
				padding[index] = 0
			}
		}
	}
	return stream
}

func buildTextStream(seed, fileID string, total int64) []byte {
	stream := make([]byte, 0, total)
	buffer := make([]byte, 32*1024)
	for block := uint64(0); int64(len(stream)) < total; block++ {
		fillTextPayloadBlock(buffer, seed, profileText, fileID, block)
		remaining := total - int64(len(stream))
		if remaining > int64(len(buffer)) {
			remaining = int64(len(buffer))
		}
		stream = append(stream, buffer[:remaining]...)
	}
	return stream
}

// fillEntropyBlock writes incompressible bytes derived from a keyed counter.
func fillEntropyBlock(buffer, key []byte, block uint64) {
	for offset := 0; offset < len(buffer); offset += sha256.Size {
		var counter [16]byte
		binary.LittleEndian.PutUint64(counter[:8], block)
		binary.LittleEndian.PutUint64(counter[8:], uint64(offset/sha256.Size))
		digest := sha256.Sum256(append(append([]byte(nil), key...), counter[:]...))
		copy(buffer[offset:], digest[:])
	}
}
