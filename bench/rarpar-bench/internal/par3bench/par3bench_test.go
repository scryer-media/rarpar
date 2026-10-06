package par3bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltInProfilesAreValid(t *testing.T) {
	for name, profile := range Profiles() {
		if err := profile.Validate(); err != nil {
			t.Fatalf("profile %s: %v", name, err)
		}
	}
}

func TestFullProfileCoversTheBriefedShapes(t *testing.T) {
	profile, err := LookupProfile("full")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		input, recovery int64
		lost            int
		field           string
	}{
		"a-gf16": {1024, 103, 50, "gf16"},
		"a-gf8":  {128, 13, 6, "gf8"},
		"a-fft":  {1024, 103, 50, "fft-gf16"},
		"b-gf16": {300, 30, 10, "gf16"},
		"c-gf16": {49152, 4916, 2000, "gf16"},
	}
	for _, config := range profile.Configs {
		expected, ok := want[config.ID]
		if !ok {
			continue
		}
		dataset, _ := profile.Dataset(config.Dataset)
		input := InputBlocks(dataset, config.BlockSize)
		if input != expected.input || config.Recovery != expected.recovery || config.Damage.LostBlocks() != expected.lost || config.ExpectedField != expected.field {
			t.Fatalf("%s: input %d recovery %d lost %d field %s, want %+v", config.ID, input, config.Recovery, config.Damage.LostBlocks(), config.ExpectedField, expected)
		}
		delete(want, config.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing sets: %v", want)
	}
	b, _ := profile.Select([]string{"b-gf16"})
	if got := len(b.Configs[0].Damage.Targets); got != 5 {
		t.Fatalf("set B damages %d files, want 5 of 10", got)
	}
}

func TestReferenceFieldFollowsPar3cmdline(t *testing.T) {
	cases := []struct {
		codec    string
		input    int64
		recovery int64
		want     string
	}{
		{"cauchy", 128, 128, "gf8"},
		{"cauchy", 129, 13, "gf16"}, // more than 128 inputs, even with a small total
		{"cauchy", 120, 137, "gf16"},
		{"fft", 100, 50, "fft-gf8"},   // next_pow2(64+100) = 256
		{"fft", 200, 52, "fft-gf16"},  // next_pow2(64+200) = 512
		{"fft", 1024, 103, "fft-gf16"},
	}
	for _, c := range cases {
		if got := ReferenceField(Config{Codec: c.codec, Recovery: c.recovery}, c.input); got != c.want {
			t.Errorf("%s %d+%d: %s, want %s", c.codec, c.input, c.recovery, got, c.want)
		}
	}
}

func TestCapacityLog2(t *testing.T) {
	for recovery, want := range map[int64]int{1: 0, 2: 1, 52: 6, 64: 6, 65: 7, 103: 7, 4916: 13} {
		if got := (Config{Recovery: recovery}).CapacityLog2(); got != want {
			t.Errorf("recovery %d: capacity log2 %d, want %d", recovery, got, want)
		}
	}
}

func TestProfileValidationRejectsUnrepairableDamage(t *testing.T) {
	profile := smokeProfile()
	profile.Configs[0].Damage = spread("too-much", []int{0}, 20)
	if err := profile.Validate(); err == nil || !strings.Contains(err.Error(), "recovery blocks") {
		t.Fatalf("expected an unrepairable-damage error, got %v", err)
	}
}

func TestDamageOffsetsSpreadEvenly(t *testing.T) {
	got := DamageOffsets(10*MiB, MiB, 5)
	want := []int64{0, 2 * MiB, 4 * MiB, 6 * MiB, 8 * MiB}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// 2000 of 49152 blocks: all distinct and in range.
	seen := map[int64]bool{}
	for _, offset := range DamageOffsets(3*GiB/2, 32*KiB, 2000) {
		if seen[offset] || offset >= 3*GiB/2 || offset%(32*KiB) != 0 {
			t.Fatalf("bad offset %d", offset)
		}
		seen[offset] = true
	}
}

func TestDatasetsAreDeterministicAndCached(t *testing.T) {
	dataset := Dataset{ID: "unit", Files: []FileSpec{{Name: "x.bin", Size: 3*MiB + 5}, {Name: "y.bin", Size: 17}}}
	first := t.TempDir()
	second := t.TempDir()
	a, err := EnsureDataset(first, dataset, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EnsureDataset(second, dataset, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a.SHA256 {
		if a.SHA256[i] != b.SHA256[i] {
			t.Fatalf("generation is not deterministic: %+v vs %+v", a.SHA256[i], b.SHA256[i])
		}
	}
	if a.SHA256[0].SHA256 == a.SHA256[1].SHA256 {
		t.Fatal("different files share a stream")
	}
	// A corrupted cache is detected and regenerated.
	if err := os.WriteFile(filepath.Join(first, "y.bin"), []byte("tampered-tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := EnsureDataset(first, dataset, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.SHA256[1] != a.SHA256[1] {
		t.Fatal("tampered cache was reused")
	}
	if err := checkDigests(first, a.SHA256); err != nil {
		t.Fatal(err)
	}
}

func TestApplyDamageZeroesOnlyTheChosenBlocks(t *testing.T) {
	dir := t.TempDir()
	dataset := Dataset{ID: "dmg", Files: []FileSpec{{Name: "f.bin", Size: 10*KiB + 100}}}
	if _, err := EnsureDataset(dir, dataset, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "f.bin"))
	if err := ApplyDamage(dir, dataset, KiB, Damage{Targets: []DamageTarget{{File: 0, Blocks: 2}}}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "f.bin"))
	if len(after) != len(before) {
		t.Fatal("damage changed the file size")
	}
	// 11 blocks, 2 damaged: indices 0 and 5.
	for i := range after {
		block := int64(i) / KiB
		damaged := block == 0 || block == 5
		if damaged && after[i] != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
		if !damaged && after[i] != before[i] {
			t.Fatalf("byte %d outside the damage changed", i)
		}
	}
}

func TestReferenceNameBytesMatchesTheObservedFailure(t *testing.T) {
	// Observed on macOS with par3cmdline 2971702e and the smoke-fft shape
	// (52 recovery blocks, six volumes): a 158-character output directory
	// failed with "Failed to open Recovery File", a 111-character one worked.
	failing := "/" + strings.Repeat("d", 157)
	working := "/" + strings.Repeat("d", 110)
	if got := ReferenceNameBytes(failing, 52); got < referenceNameBuffer {
		t.Fatalf("failing directory needs %d bytes, expected at least %d", got, referenceNameBuffer)
	}
	if got := ReferenceNameBytes(working, 52); got >= referenceNameBuffer {
		t.Fatalf("working directory needs %d bytes, expected under %d", got, referenceNameBuffer)
	}
	if got := volumeCount(4916); got != 13 {
		t.Fatalf("4916 recovery blocks: %d volumes, want 13", got)
	}
}

func TestCheckReferencePathsRejectsLongWorkDirs(t *testing.T) {
	profile, _ := LookupProfile("full")
	c, _ := profile.Select([]string{"c-gf16"})
	if err := checkReferencePaths(Options{Work: "/w", Profile: c}); err != nil {
		t.Fatal(err)
	}
	err := checkReferencePaths(Options{Work: "/" + strings.Repeat("x", 80), Profile: c})
	if err == nil || !strings.Contains(err.Error(), "Shorten --work") {
		t.Fatalf("expected a work-path error, got %v", err)
	}
}

func TestParseStraceSummary(t *testing.T) {
	text := `% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 40.00    0.004000          10       400           pread64
 20.00    0.002000          20       100           pwrite64
 10.00    0.001000          10       100        12 openat
  5.00    0.000500           5       100           statx
  5.00    0.000500          50        10           fsync
  1.00    0.000100           1       100           futex
------ ----------- ----------- --------- --------- ----------------
100.00    0.010000                   810        12 total
`
	counts, err := ParseStraceSummary(text)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Reads != 400 || counts.Writes != 100 || counts.Opens != 100 || counts.Stats != 100 || counts.Syncs != 10 || counts.Total != 810 {
		t.Fatalf("unexpected counts %+v", counts)
	}
	if _, err := ParseStraceSummary("no table here"); err == nil {
		t.Fatal("expected an error without a table")
	}
}

func TestParseKernelVariant(t *testing.T) {
	variant, err := ParseKernelVariant("gfni-off:WEAVER_GF8_GFNI=0,RARPAR_X=1")
	if err != nil {
		t.Fatal(err)
	}
	if variant.Name != "gfni-off" || len(variant.Env) != 2 {
		t.Fatalf("got %+v", variant)
	}
	for _, bad := range []string{"novalue", "name:", ":A=1", "n:A", "a b:A=1"} {
		if _, err := ParseKernelVariant(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	names := []string{}
	for _, v := range Variants([]int{1, 8}, []KernelVariant{variant}) {
		names = append(names, v.Name+"/"+v.dirName())
	}
	if got := strings.Join(names, ","); got != "reference/ref,rarpar-w1/w1,rarpar-w8/w8,rarpar-w1-gfni-off/w1-gfni-off,rarpar-w8-gfni-off/w8-gfni-off" {
		t.Fatalf("variants %s", got)
	}
}

func TestOrderAlternates(t *testing.T) {
	variants := Variants([]int{1, 8}, nil)
	if orderFor(variants, 0)[0].Tool != ToolReference || orderFor(variants, 1)[0].Tool == ToolReference {
		t.Fatal("order does not alternate")
	}
}

func TestWalkPacketsRejectsNonPAR3Data(t *testing.T) {
	if err := walkPackets([]byte(strings.Repeat("x", 64)), func([]byte, string, []byte) {}); err == nil {
		t.Fatal("expected an error for data without packet magic")
	}
	if err := walkPackets([]byte("short"), func([]byte, string, []byte) {}); err == nil {
		t.Fatal("expected an error for a truncated header")
	}
}

func TestReportShowsMediansRangesAndRatios(t *testing.T) {
	results := &Results{
		Schema: ResultsSchema, Profile: "unit", Ops: []string{OpCreate, OpRepair}, Repeats: 3, Workers: []int{1},
		Variants: Variants([]int{1}, nil),
		Configs:  []ConfigSummary{{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}, InputBlocks: 30}},
	}
	add := func(op, variant, tool string, wall float64, warm bool, identity *Identity, repair *RepairCheck) {
		results.Runs = append(results.Runs, RunRecord{Config: "u", Op: op, Variant: variant, Tool: tool, Warmup: warm, Status: "ok",
			Measurement: Measurement{WallSeconds: wall, UserSeconds: wall, MaxRSSBytes: 10 << 20}, Identity: identity, Repair: repair})
	}
	same := &Identity{Bytes: true}
	differ := &Identity{RecoveryPayloads: true, RecoveryMatched: 3, RecoveryTotal: 3, DifferingTypes: []string{"PAR CRE"}}
	add(OpCreate, "reference", ToolReference, 9, true, same, nil)
	for _, wall := range []float64{2, 1, 3} {
		add(OpCreate, "reference", ToolReference, wall, false, same, nil)
		add(OpCreate, "rarpar-w1", ToolCandidate, wall/2, false, differ, nil)
		add(OpRepair, "reference", ToolReference, wall, false, nil, &RepairCheck{Match: true, ExtraFiles: []string{"f.bin.1"}})
		add(OpRepair, "rarpar-w1", ToolCandidate, wall, false, nil, &RepairCheck{Match: true, ExtraFiles: []string{"f.bin.1"}})
	}
	report := RenderReport(results)
	for _, want := range []string{
		"| reference | 2.000 [1.000–3.000] |",
		"| rarpar-w1 | 1.000 [0.500–1.500] |",
		"| 0.500 | 0.500 | 1.000 |",
		"payloads-only",
		"f.bin.1",
		"recovery payloads 3/3 equal",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "9.000") {
		t.Fatal("warmup leaked into the summary")
	}
}
