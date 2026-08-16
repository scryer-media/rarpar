package bench

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRealisticPayloadLayoutsFillTheRequestedSize(t *testing.T) {
	sizes := []int64{5 * 1024 * 1024, 32 * 1024 * 1024, 256 * 1024 * 1024}
	for _, profile := range []string{profileSourceText, profileMachineCode, profileMedia, profileMixed,
		profileFFmpegVideo, profileFFmpegVideoHEVC} {
		for _, total := range sizes {
			parts, err := realisticPayloadLayout(profile, total)
			if err != nil {
				t.Fatalf("layout %s/%d: %v", profile, total, err)
			}
			var sum int64
			for _, part := range parts {
				if part.Bytes <= 0 {
					t.Fatalf("layout %s/%d produced empty member %q", profile, total, part.Name)
				}
				sum += part.Bytes
			}
			if sum != total {
				t.Fatalf("layout %s/%d covers %d bytes, want %d", profile, total, sum, total)
			}
		}
	}
}

// The encoder is handed a duration, never a byte count, so the video member is
// the one member whose configured size is a target rather than a promise.
func TestOnlyVideoMembersTreatTheirSizeAsATarget(t *testing.T) {
	for profile := range realisticProfiles {
		parts, err := realisticPayloadLayout(profile, 32*1024*1024)
		if err != nil {
			t.Fatalf("layout %s: %v", profile, err)
		}
		for _, part := range parts {
			if part.SizeIsTarget != videoProfiles[part.Profile] {
				t.Errorf("%s member %q: SizeIsTarget=%v, video profile=%v",
					profile, part.Name, part.SizeIsTarget, videoProfiles[part.Profile])
			}
		}
	}
}

// Every knob that moves an encoder's output bitstream has to be pinned in the
// recipe, single-threaded included: x264 and x265 rate control depends on how
// work was split across threads.
func TestVideoRecipesArePinnedAndSingleThreaded(t *testing.T) {
	for profile := range videoProfiles {
		recipe, found := videoRecipes[profile]
		if !found {
			t.Fatalf("video profile %q has no recipe", profile)
		}
		if recipe.BytesPerSecond <= 0 || recipe.Extension == "" || recipe.VideoBitrate == "" || recipe.AudioBitrate == "" {
			t.Errorf("recipe %q is not fully pinned: %#v", profile, recipe)
		}
		single := strings.Contains(recipe.CodecParams, "threads=1") ||
			strings.Contains(recipe.CodecParams, "pools=none")
		if !single {
			t.Errorf("recipe %q does not pin the encoder to one thread: %q", profile, recipe.CodecParams)
		}
		// A lavfi noise source seeded off the wall clock would re-encode
		// differently on every generation.
		if strings.Contains(recipe.AudioSource, "anoisesrc") && !strings.Contains(recipe.AudioSource, "seed=") {
			t.Errorf("recipe %q uses an unseeded noise source: %q", profile, recipe.AudioSource)
		}
	}
	if got := codecParamsFlag("libx265"); got != "-x265-params" {
		t.Errorf("codecParamsFlag(libx265) = %q", got)
	}
	if got := codecParamsFlag("libx264"); got != "-x264-params" {
		t.Errorf("codecParamsFlag(libx264) = %q", got)
	}
}

// The shared `payload video` command and the corpus generator build the same
// encode: one digest-pinned image, one thread, bitexact on inputs, encoders and
// muxer, no metadata, and a duration derived from the target size. Asserted on
// the argument vector so the invariants hold without running Docker.
func TestVideoEncodeArgsPinEveryDeterminismControl(t *testing.T) {
	lock, err := LoadToolchains(filepath.Join("..", "..", "config", "toolchains.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range VideoPayloadProfiles() {
		recipe := videoRecipes[profile]
		first := videoEncodeArgs(lock.VideoEncoder, recipe, "/work", 8*1024*1024, "clip."+recipe.Extension)
		second := videoEncodeArgs(lock.VideoEncoder, recipe, "/work", 8*1024*1024, "clip."+recipe.Extension)
		if strings.Join(first, " ") != strings.Join(second, " ") {
			t.Fatalf("%s: encode arguments are not a pure function of their inputs", profile)
		}
		joined := " " + strings.Join(first, " ") + " "
		for _, required := range []string{
			" --platform linux/amd64 ",
			" " + lock.VideoEncoder.Image + " ",
			" -nostdin ",
			" -threads 1 ",
			" -flags:v +bitexact ",
			" -flags:a +bitexact ",
			" -map_metadata -1 ",
			" " + codecParamsFlag(recipe.VideoCodec) + " " + recipe.CodecParams + " ",
			" -b:v " + recipe.VideoBitrate + " -minrate " + recipe.VideoBitrate + " -maxrate " + recipe.VideoBitrate + " -bufsize " + recipe.VideoBitrate + " ",
		} {
			if !strings.Contains(joined, required) {
				t.Errorf("%s: encode arguments lack %q: %s", profile, strings.TrimSpace(required), joined)
			}
		}
		// bitexact has to be requested on the input side (before the lavfi
		// sources) and again on the output side (for the muxer).
		if strings.Count(joined, " -fflags +bitexact ") != 2 {
			t.Errorf("%s: -fflags +bitexact must be applied to inputs and muxer: %s", profile, joined)
		}
		if !digestPinnedImage(first[10]) {
			t.Errorf("%s: encoder image is not digest pinned in the argument vector: %q", profile, first[10])
		}
		duration := strconv.FormatInt(videoEncodeSeconds(recipe, 8*1024*1024), 10)
		if strings.Count(joined, " -t "+duration+" -i ") != 2 {
			t.Errorf("%s: both lavfi inputs must be bounded to %s seconds: %s", profile, duration, joined)
		}
		if first[len(first)-1] != "clip."+recipe.Extension {
			t.Errorf("%s: output name must be the last argument: %v", profile, first)
		}
	}
	// A request smaller than one second of output still encodes one second:
	// the encoder cannot produce less, and the manifest records what landed.
	if got := videoEncodeSeconds(videoRecipes[profileFFmpegVideo], 1); got != 1 {
		t.Fatalf("minimum encode duration = %d, want 1", got)
	}
	if got := videoEncodeSeconds(videoRecipes[profileFFmpegVideo], 4*videoRecipes[profileFFmpegVideo].BytesPerSecond); got != 4 {
		t.Fatalf("encode duration = %d, want 4", got)
	}
}

// Everything the command rejects, it rejects before Docker is ever invoked.
func TestEncodeVideoPayloadRejectsBadRequestsBeforeEncoding(t *testing.T) {
	lock, err := LoadToolchains(filepath.Join("..", "..", "config", "toolchains.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "clip.mkv")
	// A Docker executable that cannot exist: any attempt to encode fails loudly
	// instead of producing a file, so a passing test proves validation ran first.
	docker := filepath.Join(t.TempDir(), "no-such-docker")
	if _, err := EncodeVideoPayload(ctx, docker, filepath.Join("..", ".."), lock, profileText, 1024, out); err == nil {
		t.Fatal("a non-video profile was accepted")
	}
	if _, err := EncodeVideoPayload(ctx, docker, filepath.Join("..", ".."), lock, "ffmpeg-video-av1", 1024, out); err == nil {
		t.Fatal("an unknown video profile was accepted")
	}
	if _, err := EncodeVideoPayload(ctx, docker, filepath.Join("..", ".."), lock, profileFFmpegVideo, 0, out); err == nil {
		t.Fatal("a zero target size was accepted")
	}
	if _, err := EncodeVideoPayload(ctx, docker, filepath.Join("..", ".."), lock, profileFFmpegVideo, 1024, ""); err == nil {
		t.Fatal("an empty output path was accepted")
	}
	floating := lock
	floating.VideoEncoder.Image = "jrottenberg/ffmpeg:7.1-ubuntu2404"
	if _, err := EncodeVideoPayload(ctx, docker, filepath.Join("..", ".."), floating, profileFFmpegVideo, 1024, out); err == nil {
		t.Fatal("a floating encoder image was accepted")
	}
	if err := os.WriteFile(out, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeVideoPayload(ctx, docker, filepath.Join("..", ".."), lock, profileFFmpegVideo, 1024, out); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("an existing output was not refused: %v", err)
	}
	if got, err := os.ReadFile(out); err != nil || string(got) != "existing" {
		t.Fatalf("existing output was disturbed: %q, %v", got, err)
	}
	// Once every check passes, the only thing left is Docker itself; with a
	// missing executable that fails at the encode step, and nothing is written.
	missing := filepath.Join(t.TempDir(), "fresh.mkv")
	if _, err := EncodeVideoPayload(ctx, docker, filepath.Join("..", ".."), lock, profileFFmpegVideo, 1024, missing); err == nil || !strings.Contains(err.Error(), "encode ffmpeg-video payload") {
		t.Fatalf("encode without docker: err = %v", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("a failed encode left output behind: %v", err)
	}
	if profiles := VideoPayloadProfiles(); len(profiles) != 2 || profiles[0] != profileFFmpegVideo || profiles[1] != profileFFmpegVideoHEVC {
		t.Fatalf("video payload profiles = %v", profiles)
	}
}

func TestVideoEncoderMustBeDigestPinned(t *testing.T) {
	lock, err := LoadToolchains(filepath.Join("..", "..", "config", "toolchains.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !digestPinnedImage(lock.VideoEncoder.Image) {
		t.Fatalf("video encoder image %q is not digest pinned", lock.VideoEncoder.Image)
	}
	if lock.VideoEncoder.Platform != "linux/amd64" || lock.VideoEncoder.ID == "" {
		t.Fatalf("video encoder is not fully pinned: %#v", lock.VideoEncoder)
	}
	lock.VideoEncoder.Image = "jrottenberg/ffmpeg:7.1-ubuntu2404"
	if err := lock.Validate(); err == nil {
		t.Fatal("a floating encoder tag was accepted")
	}
}

// A video case's bytes come from the encoder, so the encoder has to appear in
// the case's recorded provenance.
func TestVideoCasesRecordTheEncoderAsAToolchain(t *testing.T) {
	lock, err := LoadToolchains(filepath.Join("..", "..", "config", "toolchains.json"))
	if err != nil {
		t.Fatal(err)
	}
	ids := ToolchainIDs(lock, CaseConfig{Writer: "rarlab-7.23", PayloadProfile: profileFFmpegVideo})
	found := false
	for _, id := range ids {
		if id == lock.VideoEncoder.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("video case toolchains = %v, missing encoder %q", ids, lock.VideoEncoder.ID)
	}
	plain := ToolchainIDs(lock, CaseConfig{Writer: "rarlab-7.23", PayloadProfile: profileText})
	for _, id := range plain {
		if id == lock.VideoEncoder.ID {
			t.Fatalf("non-video case recorded the encoder: %v", plain)
		}
	}
}

// The realistic classes are only useful as evidence if regenerating the corpus
// reproduces them byte for byte.
func TestSynthesizedMediaStreamIsReproducible(t *testing.T) {
	first := buildMediaStream("seed", "part-01.mkv", 3*mediaClusterBytes+7)
	second := buildMediaStream("seed", "part-01.mkv", 3*mediaClusterBytes+7)
	if !bytes.Equal(first, second) {
		t.Fatal("media stream is not reproducible")
	}
	if other := buildMediaStream("seed", "part-02.mkv", 3*mediaClusterBytes+7); bytes.Equal(first, other) {
		t.Fatal("media stream does not vary per member")
	}
	if !bytes.Equal(first[:16], mediaSignature[:]) {
		t.Fatal("media stream is missing its container signature")
	}
	padding := first[mediaClusterBytes-mediaPadBytes : mediaClusterBytes]
	if bytes.Equal(padding, make([]byte, mediaPadBytes)) {
		t.Fatal("mux padding landed in the wrong cluster")
	}
}

// The source-text class is pinned to a revision rather than to the working tree.
// This is the property that keeps the class reproducible while other agents edit
// crates/ underneath the benchmark harness.
func TestSourceTextAssetsComeFromThePinnedRevisionNotTheWorkingTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	config, err := LoadCorpusConfig(filepath.Join("..", "..", "config", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	if config.SourceRev == "" {
		t.Fatal("default corpus pins no source_rev")
	}
	assets := newPayloadAssets(context.Background(), "docker", filepath.Join("..", ".."), "", config.SourceRev, VideoEncoder{})
	first, err := assets.sourceTextAssets()
	if err != nil {
		t.Skipf("pinned revision %s is unavailable here: %v", config.SourceRev, err)
	}
	if len(first) == 0 {
		t.Fatal("pinned revision produced no source text")
	}
	stream := concatenateAssets(first, true)

	second := newPayloadAssets(context.Background(), "docker", filepath.Join("..", ".."), "", config.SourceRev, VideoEncoder{})
	repeat, err := second.sourceTextAssets()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream, concatenateAssets(repeat, true)) {
		t.Fatal("pinned source text is not reproducible")
	}

	// Every case that draws on the class must fit inside it; repeating the
	// stream to fill a member would fabricate long-range matches.
	var largest int64
	for _, item := range config.Cases {
		if item.PayloadProfile != profileSourceText {
			continue
		}
		if size := payloadBytesForCase(config, item); size > largest {
			largest = size
		}
	}
	if largest > int64(len(stream)) {
		t.Fatalf("largest source-text case needs %d bytes, pinned revision supplies %d", largest, len(stream))
	}
}

func TestRealisticCorpusMixFollowsTheCensusWeighting(t *testing.T) {
	config, err := LoadCorpusConfig(filepath.Join("..", "..", "config", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Notes) == 0 {
		t.Error("corpus carries no rationale for its case mix")
	}
	classes := map[string]int{}
	storedMultiVolume, encryptedStore, blake2Cases := 0, 0, 0
	for _, item := range config.Cases {
		if !realisticProfiles[item.PayloadProfile] {
			continue
		}
		classes[item.PayloadProfile]++
		if item.Solid {
			t.Errorf("realistic case %q is solid; solid archives are extinct in the surveyed ecosystem", item.ID)
		}
		if item.Store && item.VolumeSize != "" && item.VolumeSize != config.VolumeSize {
			storedMultiVolume++
		}
		if item.Store && item.Encrypted {
			encryptedStore++
		}
		if item.Blake2 {
			blake2Cases++
			if item.Format != 5 {
				t.Errorf("case %q requests BLAKE2sp outside RAR5", item.ID)
			}
		}
	}
	for _, profile := range []string{profileSourceText, profileMachineCode, profileMixed,
		profileFFmpegVideo, profileFFmpegVideoHEVC} {
		if classes[profile] == 0 {
			t.Errorf("corpus has no %q case", profile)
		}
	}
	// The media class must be real encoded video, not the synthesized stand-in.
	for _, item := range config.Cases {
		if item.PayloadProfile == profileMedia && strings.HasPrefix(item.ID, "real-media") {
			t.Errorf("media case %q still uses the synthesized profile instead of real video", item.ID)
		}
	}
	if storedMultiVolume < 4 {
		t.Errorf("stored multi-volume cases = %d; that shape is 84%% of surveyed data and must dominate", storedMultiVolume)
	}
	if encryptedStore < 2 {
		t.Errorf("encrypted stored cases = %d, want the data- and header-encrypted pair", encryptedStore)
	}
	if blake2Cases < 3 {
		t.Errorf("BLAKE2sp cases = %d, want source, machine-code, and stored media coverage", blake2Cases)
	}
}

// A RAR4-format header always stores a modification time, so an unpinned
// directory mtime is enough to make every RAR3/RAR4 archive differ between two
// runs of the same configuration.
func TestPayloadTreeTimestampsArePinnedIncludingDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "payload")
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "a.bin"), filepath.Join(nested, "b.bin")} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := stampDeterministicTree(root); err != nil {
		t.Fatal(err)
	}
	want := time.Unix(946684800, 0).UTC()
	for _, path := range []string{root, nested, filepath.Join(root, "a.bin"), filepath.Join(nested, "b.bin")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().UTC().Equal(want) {
			t.Errorf("%s mtime = %s, want %s", path, info.ModTime().UTC(), want)
		}
	}
}

// Payload policy: video belongs to store-mode cases, and compressed cases must
// carry payloads a compressor can actually work on. Measured on real video, a
// nominally compressed case degenerates - rar auto-selects stored for the member
// and the case benchmarks the store path while claiming to benchmark
// compression.
func TestCompressedCasesCarryCompressiblePayloads(t *testing.T) {
	config, err := LoadCorpusConfig(filepath.Join("..", "..", "config", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	compressible := map[string]bool{
		profileText:        true,
		profileSourceText:  true,
		profileMachineCode: true,
		profileMixed:       true,
	}
	// Two pre-existing cases are knowingly outside the policy:
	// rar5-{v5,v7}-recovery-volume compress the incompressible synthetic binary
	// profile. They exist to exercise the RAR recovery-volume restore path
	// rather than the compressor, and their bytes are frozen so benchmark rounds
	// stay comparable, so the policy is enforced over the cases it governs.
	grandfathered := map[string]bool{
		"rar5-v5-recovery-volume": true,
		"rar5-v7-recovery-volume": true,
	}
	checked := 0
	for _, item := range config.Cases {
		if item.Family != "rar" || item.Store || item.FixtureDir != "" {
			continue
		}
		profile := item.PayloadProfile
		if profile == "" {
			profile = profileBinary
		}
		if videoProfiles[profile] {
			t.Errorf("compressed case %q carries video payload %q; real video makes the writer auto-store, "+
				"so the case would measure the store path", item.ID, profile)
		}
		if grandfathered[item.ID] {
			continue
		}
		if !compressible[profile] {
			t.Errorf("compressed case %q carries payload profile %q, which the compressor cannot work on",
				item.ID, profile)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no compressed cases were checked")
	}
	// The converse half of the policy: every video payload sits on a store case.
	videoCases := 0
	for _, item := range config.Cases {
		if !videoProfiles[item.PayloadProfile] {
			continue
		}
		videoCases++
		if !item.Store {
			t.Errorf("video case %q is not store mode", item.ID)
		}
	}
	if videoCases == 0 {
		t.Fatal("corpus has no real-video case")
	}
}

func TestBlake2OutsideRAR5IsRejected(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].Format = 4
	config.Cases[0].Writer = "rarlab-4.20"
	config.Cases[0].Blake2 = true
	if err := config.Validate(); err == nil {
		t.Fatal("BLAKE2sp was accepted outside RAR5")
	}
}

func TestSourceTextProfileRequiresAPinnedRevision(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].PayloadProfile = profileSourceText
	if err := config.Validate(); err == nil {
		t.Fatal("source-text profile was accepted without a pinned revision")
	}
	config.SourceRev = "not-a-commit"
	if err := config.Validate(); err == nil {
		t.Fatal("an unpinnable source_rev was accepted")
	}
	config.SourceRev = "224566ba1098ddf93d5f58be0233ebb17ca40474"
	if err := config.Validate(); err != nil {
		t.Fatalf("pinned source-text case was rejected: %v", err)
	}
}
