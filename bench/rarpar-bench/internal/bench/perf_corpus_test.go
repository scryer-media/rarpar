package bench

import (
	"path/filepath"
	"testing"
)

func TestCasePayloadBytesDefaultAndOverride(t *testing.T) {
	config := validCorpusConfig()
	item := config.Cases[0]
	if got, want := payloadBytesForCase(config, item), config.PayloadBytes; got != want {
		t.Fatalf("default payload bytes = %d, want %d", got, want)
	}

	item.PayloadBytes = 256
	if got := payloadBytesForCase(config, item); got != item.PayloadBytes {
		t.Fatalf("overridden payload bytes = %d, want %d", got, item.PayloadBytes)
	}

	config.Cases[0].PayloadBytes = -1
	if err := config.Validate(); err == nil {
		t.Fatal("negative per-case payload size was accepted")
	}
}

func TestCasePayloadOverridePreservesDeterministicGeneration(t *testing.T) {
	config := validCorpusConfig()
	item := config.Cases[0]
	item.PayloadBytes = 4096
	item.PayloadProfile = "text"

	first, err := writeDeterministicPayload(filepath.Join(t.TempDir(), "payload"), config.Seed, item.ID, payloadBytesForCase(config, item), item.PayloadProfile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := writeDeterministicPayload(filepath.Join(t.TempDir(), "payload"), config.Seed, item.ID, payloadBytesForCase(config, item), item.PayloadProfile)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("deterministic payload file count = %d and %d", len(first), len(second))
	}
	for index := range first {
		if first[index] != second[index] || first[index].Bytes == 0 {
			t.Fatalf("deterministic payload file %d changed or is empty: %#v vs %#v", index, first[index], second[index])
		}
	}
}

func TestDefaultCorpusCoversRARWriterAndEncryptionLadders(t *testing.T) {
	config, err := LoadCorpusConfig(filepath.Join("..", "..", "config", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}

	writers := map[string]bool{}
	cases := map[string]bool{}
	encryption := map[string]bool{}
	ppmdCases := 0
	for _, item := range config.Cases {
		if item.Family != "rar" {
			continue
		}
		writers[item.Writer] = true
		cases[item.ID] = true
		if item.PPMd {
			ppmdCases++
		}
		if item.Encrypted {
			mode := "data"
			if item.HeaderEncrypted {
				mode = "headers"
			}
			encryption[item.Writer+"/"+mode] = true
		}
	}

	for _, writer := range []string{"rarlab-3.93", "rarlab-4.20", "rarlab-5.00", "rarlab-6.24", "rarlab-7.23"} {
		if !writers[writer] {
			t.Errorf("default corpus is missing writer %q", writer)
		}
	}
	for _, mode := range []string{
		"rarlab-3.93/data", "rarlab-3.93/headers",
		"rarlab-4.20/data", "rarlab-4.20/headers",
		"rarlab-5.00/data", "rarlab-5.00/headers",
		"rarlab-7.23/data", "rarlab-7.23/headers",
	} {
		if !encryption[mode] {
			t.Errorf("default corpus is missing encryption case %q", mode)
		}
	}
	for _, id := range []string{
		"rar5-v7-store-single",
		"rar5-v7-normal-single",
		"rar5-v7-solid-multivolume",
		"rar5-v7-recovery-volume",
	} {
		if !cases[id] {
			t.Errorf("default corpus is missing current-writer case %q", id)
		}
	}
	generationFound := false
	for _, item := range config.Cases {
		if item.ID == "par2-generate-rar5-v7-volumes" {
			generationFound = item.Family == "par2" &&
				item.PAR2Operation == "create" &&
				!item.PAR2 &&
				item.PAR2SliceSize == 65_536 &&
				item.PAR2RecoveryPercent == 20 &&
				item.PayloadBytes == 256*1024*1024
		}
	}
	if !generationFound {
		t.Error("default corpus is missing the validated 256 MiB PAR2 generation case")
	}
	if ppmdCases != 4 {
		t.Errorf("default corpus PPMd cases = %d, want 4", ppmdCases)
	}
}

func TestPerformanceCorpusConfigIsTheLongFormRAR5Matrix(t *testing.T) {
	config, err := LoadCorpusConfig(filepath.Join("..", "..", "config", "perf-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}

	const longFormBytes = int64(256 * 1024 * 1024)
	if config.PayloadBytes != longFormBytes {
		t.Fatalf("performance corpus payload bytes = %d, want %d", config.PayloadBytes, longFormBytes)
	}
	if len(config.Cases) != 4 {
		t.Fatalf("performance corpus case count = %d, want 4", len(config.Cases))
	}

	seen := map[string]bool{}
	for _, item := range config.Cases {
		if item.Family != "rar" || item.Format != 5 || item.Writer != "rarlab-5.00" || item.PayloadBytes != 0 {
			t.Fatalf("case %q is not a top-level-sized RAR5 profiling case: %#v", item.ID, item)
		}
		if item.Encrypted || item.PAR2 || item.RecoveryVolumes || item.Mutation != "none" {
			t.Fatalf("case %q includes unrelated benchmark behavior", item.ID)
		}
		if item.PayloadProfile != "binary" && item.PayloadProfile != "text" {
			t.Fatalf("case %q has unexpected payload profile %q", item.ID, item.PayloadProfile)
		}
		mode := "normal"
		if item.Solid {
			mode = "solid"
		}
		matrixKey := item.PayloadProfile + "/" + mode
		if seen[matrixKey] {
			t.Fatalf("duplicate profiling matrix entry for %q", item.ID)
		}
		seen[matrixKey] = true
		if got := payloadBytesForCase(config, item); got != longFormBytes {
			t.Fatalf("case %q resolved payload bytes = %d, want %d", item.ID, got, longFormBytes)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("profiling matrix entries = %d, want 4", len(seen))
	}
}
