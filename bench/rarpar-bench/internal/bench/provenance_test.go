package bench

import (
	"math"
	"strings"
	"testing"
)

func TestCorpusContentDigestIncludesGeneratedSourceBytes(t *testing.T) {
	manifest := CorpusCaseManifest{
		SchemaVersion:    "rarpar-bench-case-v1",
		ID:               "case-a",
		CorpusID:         "corpus-a",
		CorpusDigest:     "old-digest",
		GenerationDigest: "generation-a",
		Seed:             "seed-a",
		Sources:          []SourceFile{{Path: "release.rar", Bytes: 4, SHA256: strings.Repeat("a", 64)}},
	}
	first, err := corpusContentDigest([]CorpusCaseManifest{manifest})
	if err != nil {
		t.Fatal(err)
	}
	manifest.CorpusDigest = "another-embedded-digest"
	sameContent, err := corpusContentDigest([]CorpusCaseManifest{manifest})
	if err != nil {
		t.Fatal(err)
	}
	if first != sameContent {
		t.Fatal("embedded corpus digest changed the content digest")
	}
	manifest.Sources[0].SHA256 = strings.Repeat("b", 64)
	changedContent, err := corpusContentDigest([]CorpusCaseManifest{manifest})
	if err != nil {
		t.Fatal(err)
	}
	if first == changedContent {
		t.Fatal("changed archive bytes did not change the corpus digest")
	}
}

func TestPayloadPartSizesDoNotOverflow(t *testing.T) {
	parts := payloadPartSizes(math.MaxInt64)
	if len(parts) != 3 || parts[0] < 0 || parts[1] < 0 || parts[2] < 0 {
		t.Fatalf("invalid payload parts: %#v", parts)
	}
	if parts[0]+parts[1]+parts[2] != math.MaxInt64 {
		t.Fatalf("payload parts do not preserve total: %#v", parts)
	}
}

func TestSanitizeFailureRedactsPathsAndPassword(t *testing.T) {
	message := sanitizeFailure("open /private/tmp/bench/archive.rar: " + benchmarkPassword + "\nfailed")
	if strings.Contains(message, "/private/") || strings.Contains(message, benchmarkPassword) {
		t.Fatalf("sensitive failure content remained: %q", message)
	}
	if !strings.Contains(message, "[path]") || !strings.Contains(message, "[redacted]") {
		t.Fatalf("failure did not retain useful redaction markers: %q", message)
	}
}
