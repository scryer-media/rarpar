package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `payload video` refuses anything but a fully specified request before it
// touches the toolchain lock or Docker, so a generator script that gets the
// invocation wrong fails on the spot instead of encoding the wrong thing.
func TestPayloadVideoRequiresACompleteRequest(t *testing.T) {
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "clip.mkv")
	for name, args := range map[string][]string{
		"no subcommand":         {},
		"unknown subcommand":    {"audio", "--profile", "ffmpeg-video", "--target-bytes", "1024", "--out", out},
		"missing profile":       {"video", "--target-bytes", "1024", "--out", out},
		"missing target":        {"video", "--profile", "ffmpeg-video", "--out", out},
		"zero target":           {"video", "--profile", "ffmpeg-video", "--target-bytes", "0", "--out", out},
		"negative target":       {"video", "--profile", "ffmpeg-video", "--target-bytes", "-5", "--out", out},
		"missing out":           {"video", "--profile", "ffmpeg-video", "--target-bytes", "1024"},
		"positional argument":   {"video", "--profile", "ffmpeg-video", "--target-bytes", "1024", "--out", out, "extra"},
		"unknown flag":          {"video", "--profile", "ffmpeg-video", "--target-bytes", "1024", "--out", out, "--crf", "18"},
		"non-numeric target":    {"video", "--profile", "ffmpeg-video", "--target-bytes", "1M", "--out", out},
		"non-video profile":     {"video", "--profile", "text", "--target-bytes", "1024", "--out", out, "--toolchains", "../../config/toolchains.json"},
		"unknown video profile": {"video", "--profile", "ffmpeg-video-av1", "--target-bytes", "1024", "--out", out, "--toolchains", "../../config/toolchains.json"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := runPayload(ctx, args, &stdout)
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if stdout.Len() != 0 {
				t.Fatalf("%s wrote output despite failing: %q", name, stdout.String())
			}
			if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
				t.Fatalf("%s produced an output file", name)
			}
		})
	}
}

// The command's contract is the same encoder the corpus generator uses; the
// usage text advertises it so the generator scripts can be checked against it.
func TestUsageAdvertisesPayloadVideo(t *testing.T) {
	// usage() prints to stderr; the contract string lives in the source, so
	// assert on the file rather than capturing the descriptor.
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "rarpar-bench payload video --profile ffmpeg-video|ffmpeg-video-hevc --target-bytes BYTES --out PATH") {
		t.Fatal("usage does not advertise the payload video contract")
	}
	if !strings.Contains(string(source), "rarpar-bench toolchains validate|build|resolve [--config PATH] [--docker PATH] [--mirror-base URL] [--publish] [--s3-endpoint URL] [--bucket NAME] [--cache DIR]") {
		t.Fatal("usage does not advertise the toolchain mirror contract")
	}
}

// Publishing is what the protected workflow does; every piece of its
// configuration has to be present before anything is signed or uploaded, and
// each of these requests must fail before it reaches the network.
func TestToolchainsPublishRequiresACompleteConfiguration(t *testing.T) {
	ctx := context.Background()
	config := filepath.Join("..", "..", "config", "toolchains.json")
	t.Setenv("RARPAR_TOOL_MIRROR_BASE", "")
	t.Setenv("R2_CORPUS_ACCESS_KEY_ID", "")
	t.Setenv("R2_CORPUS_SECRET_ACCESS_KEY", "")
	full := []string{"resolve", "--config", config, "--mirror-base", "https://corpus.example.test", "--publish",
		"--s3-endpoint", "https://account.r2.cloudflarestorage.com", "--bucket", "corpus"}
	for name, testCase := range map[string]struct {
		args []string
		want string
	}{
		"no subcommand":   {nil, "validate, build, or resolve"},
		"unknown command": {[]string{"mirror", "--config", config}, "unknown toolchains command"},
		"positional":      {[]string{"validate", "--config", config, "extra"}, "unexpected argument"},
		"no mirror base":  {[]string{"resolve", "--config", config, "--publish"}, "--mirror-base"},
		"no s3 endpoint":  {[]string{"resolve", "--config", config, "--mirror-base", "https://corpus.example.test", "--publish"}, "--s3-endpoint"},
		"no bucket":       {append(append([]string{}, full[:len(full)-4]...), "--s3-endpoint", "https://account.r2.cloudflarestorage.com"), "--bucket"},
		"no credentials":  {full, "R2_CORPUS_ACCESS_KEY_ID"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runToolchains(ctx, testCase.args)
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("err = %v, want it to name %q", err, testCase.want)
			}
		})
	}
}
