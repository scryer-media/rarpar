package testcorpus

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// The seam that would rot silently: a recipe added to the ledger and not to the
// orchestrator produces nothing, and the corpus would simply be short a fixture;
// one added here and not to the ledger writes a file no manifest describes.
// Both directions, plus the source path each side records.
func TestUnitsMatchTheLedger(t *testing.T) {
	root := repoRoot(t)
	ledger, err := LoadLedger(filepath.Join(root, filepath.FromSlash(LedgerFile)))
	if err != nil {
		t.Fatal(err)
	}
	declared := make([]string, 0, len(ledger.Generators))
	for name := range ledger.Generators {
		declared = append(declared, name)
	}
	slices.Sort(declared)

	invoked := make([]string, 0, len(Units()))
	for _, unit := range Units() {
		invoked = append(invoked, unit.Name)
	}
	slices.Sort(invoked)

	if !slices.Equal(declared, invoked) {
		t.Fatalf("the ledger's generator table and the orchestrator's unit list disagree:\n  ledger: %v\n  units:  %v", declared, invoked)
	}
	for _, unit := range Units() {
		generator := ledger.Generators[unit.Name]
		if generator.Path != unit.Source {
			t.Errorf("%s: the ledger records source %q, the orchestrator %q", unit.Name, generator.Path, unit.Source)
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(unit.Source))); err != nil {
			t.Errorf("%s: source %s is missing from the tree: %v", unit.Name, unit.Source, err)
		}
	}
}

// Every generated RAR fixture names a RARLAB writer. The UnRAR license permits
// unrar's code and the knowledge of it to be used to read RAR archives, never to
// create them, so a RAR fixture assembled by a script is not something this
// corpus may hold — only RARLAB's writers and unmodified upstream imports.
func TestEveryGeneratedRarFixtureNamesARarlabWriter(t *testing.T) {
	root := repoRoot(t)
	ledger, err := LoadLedger(filepath.Join(root, filepath.FromSlash(LedgerFile)))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, entry := range ledger.Files {
		if entry.Source.Kind != "generated" {
			continue
		}
		generator := ledger.Generators[entry.Source.Generator]
		if generator.Path == "" {
			t.Errorf("%s: generator %q is not declared", entry.Path, entry.Source.Generator)
			continue
		}
		if !isRarPath(entry.Path) {
			continue
		}
		seen++
		found := false
		for _, id := range generator.Toolchains {
			if strings.HasPrefix(id, "rarlab-") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: generator %q declares no RARLAB writer (%v)", entry.Path, entry.Source.Generator, generator.Toolchains)
		}
	}
	if seen == 0 {
		t.Fatal("no generated RAR fixtures found; the check is vacuous")
	}
}

func isRarPath(path string) bool {
	return strings.HasSuffix(path, ".rar") || strings.HasSuffix(path, ".rev") ||
		strings.HasSuffix(path, ".exe") || rarVolumeSuffix(path)
}

// rarVolumeSuffix matches classic volume names (.r00, .r01, …).
func rarVolumeSuffix(path string) bool {
	if len(path) < 4 {
		return false
	}
	tail := path[len(path)-4:]
	return tail[0] == '.' && tail[1] >= 'r' && tail[1] <= 'z' &&
		tail[2] >= '0' && tail[2] <= '9' && tail[3] >= '0' && tail[3] <= '9'
}

// The stage order is the contract that stops a recipe reading an input the run
// has not written yet.
func TestStageZeroWritesTheSharedInputs(t *testing.T) {
	var stageZero []string
	previous := 0
	for _, unit := range Units() {
		if unit.Stage < previous {
			t.Fatalf("%s is out of stage order", unit.Name)
		}
		previous = unit.Stage
		if unit.Stage == 0 {
			stageZero = append(stageZero, unit.Name)
		}
	}
	want := []string{"inputs", "edge_cases"}
	if !slices.Equal(stageZero, want) {
		t.Fatalf("stage 0 is %v, expected %v", stageZero, want)
	}
}

func TestSelectUnits(t *testing.T) {
	all, err := selectUnits(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(Units()) {
		t.Fatalf("no --only should select every unit, got %d", len(all))
	}
	repeated, err := selectUnits([]string{"inputs", "inputs"})
	if err != nil {
		t.Fatal(err)
	}
	if len(repeated) != 1 {
		t.Fatalf("a repeated --only should run once, got %d", len(repeated))
	}
	if _, err := selectUnits([]string{"nope"}); err == nil {
		t.Fatal("an unknown --only must be an error")
	}
}

// The payload generators are the corpus's inputs, so their determinism is the
// property everything downstream rests on.
func TestDeterministicPayloadsAreStable(t *testing.T) {
	first := deterministicBytes("label", 1000)
	if len(first) != 1000 {
		t.Fatalf("length %d", len(first))
	}
	if string(first) != string(deterministicBytes("label", 1000)) {
		t.Fatal("deterministicBytes is not deterministic")
	}
	if string(first) == string(deterministicBytes("other", 1000)) {
		t.Fatal("deterministicBytes ignores its label")
	}
	// A prefix of a longer draw, so a size change never reshuffles what came
	// before it.
	longer := deterministicBytes("label", 2000)
	if string(longer[:1000]) != string(first) {
		t.Fatal("deterministicBytes is not a prefix of a longer draw")
	}

	// The ramps the recovery-volume and multi-volume stored sets are built from.
	binary := ramp(262_144, 1, 0)
	for index := range 512 {
		if binary[index] != byte(index%256) {
			t.Fatalf("binary.bin[%d] = %d", index, binary[index])
		}
	}
	rev := ramp(4096, 17, 23)
	if rev[0] != 23 || rev[1] != 40 || rev[14] != 5 {
		t.Fatalf("recovery ramp starts %v", rev[:16])
	}
}

// The PPMd members' openings and lengths are pinned by tests/integration.rs.
func TestWordSaladOpensWithItsPhraseAndHitsItsLength(t *testing.T) {
	text := wordSalad("ppmd/ppm_part0.txt", 2_881_486, []string{"usenet", "weaver", "stream", "solid"})
	if len(text) != 2_881_486 {
		t.Fatalf("length %d", len(text))
	}
	if got := string(text[:24]); got != "usenet weaver stream sol" {
		t.Fatalf("opening %q", got)
	}
	if string(text) != string(wordSalad("ppmd/ppm_part0.txt", 2_881_486, []string{"usenet", "weaver", "stream", "solid"})) {
		t.Fatal("wordSalad is not deterministic")
	}
}

func TestBase64StreamIsAsciiAndExact(t *testing.T) {
	text := base64Stream("ppmd/restart", 1_600_000)
	if len(text) != 1_600_000 {
		t.Fatalf("length %d", len(text))
	}
	for index, character := range text {
		if character > 0x7f {
			t.Fatalf("byte %d is not ASCII: %d", index, character)
		}
	}
	if got := string(text[:16]); got != "YxEO+bNHr9SXTOi3" {
		t.Fatalf("prefix %q: tests/integration.rs pins this value", got)
	}
}

// The solid LZ members open with bytes tests/integration.rs pins and compress,
// which is the whole point of a mosaic over a small chunk pool.
func TestMosaicKeepsItsPrefixAndRepeatsChunks(t *testing.T) {
	prefix := []byte{0xA5, 0x4D, 0xCA, 0x18, 0x25, 0x30, 0xBB, 0x1D}
	data := mosaic("core/lz_solid/0", 307_200, 4096, 16, prefix)
	if len(data) != 307_200 {
		t.Fatalf("length %d", len(data))
	}
	if string(data[:8]) != string(prefix) {
		t.Fatalf("prefix %v", data[:8])
	}
	unique := map[string]bool{}
	for offset := len(prefix); offset+4096 <= len(data); offset += 4096 {
		unique[string(data[offset:offset+4096])] = true
	}
	if len(unique) > 16 {
		t.Fatalf("mosaic used %d distinct chunks, expected at most 16", len(unique))
	}
}

func TestUudecodeRoundTripsAKnownEncoding(t *testing.T) {
	decoded, err := uudecode([]byte("begin 644 cat.txt\n#0V%T\n`\nend\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "Cat" {
		t.Fatalf("decoded %q", decoded)
	}
	decoded, err = uudecode([]byte("begin 644 x\n,2&5L;&\\L('=O<FQD\n`\nend\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "Hello, world" {
		t.Fatalf("decoded %q", decoded)
	}
	if _, err := uudecode([]byte("no begin\n")); err == nil {
		t.Fatal("missing begin must be an error")
	}
	if _, err := uudecode([]byte("begin 644 x\n#0V%T\n")); err == nil {
		t.Fatal("missing end must be an error")
	}
}

func TestRawURLPinsTheCommit(t *testing.T) {
	upstream := LedgerUpstream{
		Repository: "https://github.com/libarchive/libarchive",
		Commit:     "27cbc7827172698143e440801fc0ba39ccb4f1f5",
		Encoding:   "uuencode",
	}
	url, err := rawURL(upstream, "libarchive/test/test_read_format_rar.rar.uu")
	if err != nil {
		t.Fatal(err)
	}
	const want = "https://raw.githubusercontent.com/libarchive/libarchive/27cbc7827172698143e440801fc0ba39ccb4f1f5/libarchive/test/test_read_format_rar.rar.uu"
	if url != want {
		t.Fatalf("url %q", url)
	}
	upstream.Repository = "https://gitlab.com/x/y"
	if _, err := rawURL(upstream, "a"); err == nil {
		t.Fatal("a non-GitHub upstream must be an error")
	}
}

// No upstream may be private: the publish workflow fetches every import, so one
// it cannot reach is one the corpus cannot be produced from.
func TestNoUpstreamIsPrivate(t *testing.T) {
	ledger, err := LoadLedger(filepath.Join(repoRoot(t), filepath.FromSlash(LedgerFile)))
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Upstreams) == 0 {
		t.Fatal("the ledger declares no upstreams")
	}
	for name, upstream := range ledger.Upstreams {
		if upstream.Private {
			t.Errorf("upstream %s is private", name)
		}
	}
}
