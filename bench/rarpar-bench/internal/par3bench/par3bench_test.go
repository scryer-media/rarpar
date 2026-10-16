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
		{"fft", 100, 50, "fft-gf8"},  // next_pow2(64+100) = 256
		{"fft", 200, 52, "fft-gf16"}, // next_pow2(64+200) = 512
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

func TestLongWorkDirsWarnButDoNotRefuse(t *testing.T) {
	profile, _ := LookupProfile("full")
	c, _ := profile.Select([]string{"c-gf16"})
	if warnings := referencePathWarnings(c, "/w"); len(warnings) != 0 {
		t.Fatalf("a short work path must not warn: %v", warnings)
	}
	long := "/" + strings.Repeat("x", 80)
	warnings := referencePathWarnings(c, long)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "(81 characters)") || !strings.Contains(warnings[0], "Running anyway") ||
		!strings.Contains(warnings[0], "DNF") {
		t.Fatalf("expected one running-anyway warning with the character count, got %v", warnings)
	}
	// The warning never blocks option validation.
	options := Options{Reference: os.Args[0], Candidate: os.Args[0], Work: long, Out: t.TempDir(), Profile: c, Repeats: 1}
	if err := validateOptions(&options); err != nil {
		t.Fatalf("a long work path must not be refused: %v", err)
	}
	if options.Timeout != DefaultTimeout || options.ReferenceTimeout != DefaultTimeout {
		t.Fatalf("default timeouts %v/%v, want %v", options.Timeout, options.ReferenceTimeout, DefaultTimeout)
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
	if got := strings.Join(names, ","); got != "reference/ref,rarpar-w1/w1,rarpar-w1-backup/w1-backup,rarpar-w8/w8,rarpar-w8-backup/w8-backup,rarpar-w1-gfni-off/w1-gfni-off,rarpar-w8-gfni-off/w8-gfni-off" {
		t.Fatalf("variants %s", got)
	}
	// A kernel variant named "backup" would collide with the backup row.
	err = CheckVariantNames(Variants([]int{1}, []KernelVariant{{Name: "backup", Env: []string{"A=1"}}}))
	if err == nil || !strings.Contains(err.Error(), `may not be named "backup"`) {
		t.Fatalf("a kernel variant named backup: %v", err)
	}
}

// Every rarpar row runs buffered, so a matrix has one reference row and one
// rarpar row per worker count for every operation (no durable row, no
// -buffered suffix), plus at repair one rarpar-wN-backup row per worker
// count: rarpar-wN repairs in place with no backup, rarpar-wN-backup keeps a
// numbered .1 as the reference does.
func TestOneBufferedRarparRowPerWorkerCount(t *testing.T) {
	variants := Variants([]int{1, 8}, nil)
	var names []string
	for _, v := range variants {
		names = append(names, v.Name)
	}
	if got := strings.Join(names, ","); got != "reference,rarpar-w1,rarpar-w1-backup,rarpar-w8,rarpar-w8-backup" {
		t.Fatalf("variants %s", got)
	}
	rows := RowsByOp(variants, KnownOps)
	for _, op := range KnownOps {
		want := "reference,rarpar-w1,rarpar-w8"
		if op == OpRepair {
			want = "reference,rarpar-w1,rarpar-w1-backup,rarpar-w8,rarpar-w8-backup"
		}
		if got := strings.Join(rows[op], ","); got != want {
			t.Fatalf("%s rows %s, want %s", op, got, want)
		}
	}
	for _, v := range variants {
		if v.Backup != strings.HasSuffix(v.Name, "-backup") {
			t.Fatalf("%s: Backup %t", v.Name, v.Backup)
		}
	}
}

func TestReferenceCreateProblemClassifiesDNF(t *testing.T) {
	config := Config{Recovery: 7}
	empty := t.TempDir()
	cases := []struct {
		result Result
		want   string
	}{
		{Result{Failure: "timeout"}, "timeout"},
		{Result{Measurement: Measurement{ExitCode: 6}, Stderr: "Failed to open Recovery File\n"}, "exit-6"},
		{Result{}, "no-carriers"},
	}
	for _, c := range cases {
		if got, _ := referenceCreateProblem(c.result, empty, config); got != c.want {
			t.Errorf("%+v: %q, want %q", c.result, got, c.want)
		}
	}
	if err := os.WriteFile(filepath.Join(empty, "set.par3"), []byte("not a packet stream at all, long enough for one header....."), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := referenceCreateProblem(Result{}, empty, config); got != "unreadable-carriers" {
		t.Errorf("garbage carriers: %q", got)
	}
	record := RunRecord{Failure: "exit-6", Measurement: Measurement{ExitCode: 6},
		StderrLine: lastLine(Result{Stderr: "\nwriting\nFailed to open Recovery File\n\n"})}
	if got := describeDNF(record); got != "exit 6: Failed to open Recovery File" {
		t.Fatalf("describeDNF = %q", got)
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
		"| 2.000 | 2.000 | 1.000 |",
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

func TestReportShowsBufferedRowsAndReferenceDNF(t *testing.T) {
	results := &Results{
		Schema: ResultsSchema, Profile: "unit", Ops: []string{OpCreate, OpVerify, OpRepair}, Repeats: 2, Workers: []int{1, 8},
		Variants: Variants([]int{1, 8}, nil),
		// An older candidate: create lists --buffered, repair lists neither switch.
		BufferedArgs:        map[string][]string{OpCreate: {"--buffered"}},
		BufferedUnsupported: []string{OpRepair},
		TimeoutSeconds:      1200, ReferenceTimeoutSeconds: 1200,
		Configs: []ConfigSummary{
			{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}, InputBlocks: 30, CanonicalSource: ToolReference},
			{Config: Config{ID: "v", BlockSize: MiB, Recovery: 3, Codec: "fft"}, InputBlocks: 30, CanonicalSource: ToolCandidate},
		},
		Status: StatusOK,
	}
	add := func(config, op, variant, tool string, wall float64) {
		results.Runs = append(results.Runs, RunRecord{Config: config, Op: op, Variant: variant, Tool: tool,
			Status: StatusOK, Measurement: Measurement{WallSeconds: wall, UserSeconds: wall, MaxRSSBytes: 10 << 20}})
	}
	for range 2 {
		add("u", OpCreate, "reference", ToolReference, 4)
		add("u", OpCreate, "rarpar-w1", ToolCandidate, 2)
		add("u", OpCreate, "rarpar-w8", ToolCandidate, 1)
		add("u", OpVerify, "reference", ToolReference, 2)
		add("u", OpVerify, "rarpar-w1", ToolCandidate, 1)
		add("v", OpCreate, "rarpar-w1", ToolCandidate, 2)
		add("v", OpCreate, "rarpar-w8", ToolCandidate, 1)
	}
	results.Runs = append(results.Runs, RunRecord{Config: "v", Op: OpCreate, Variant: "reference", Tool: ToolReference, Canonical: true, Warmup: true,
		Status: StatusDNF, Failure: "exit-6", Measurement: Measurement{ExitCode: 6}, StderrLine: "Failed to open Recovery File"})
	results.Runs = append(results.Runs, RunRecord{Config: "v", Op: OpRepair, Variant: "reference", Tool: ToolReference, Warmup: true,
		Status: StatusDNF, Failure: "timeout", Measurement: Measurement{WallSeconds: 1200, ExitCode: -1}})
	add("v", OpRepair, "rarpar-w1", ToolCandidate, 3)
	results.DNF = []string{"v/create/reference: DNF exit 6: Failed to open Recovery File (canonical seed create)"}

	report := RenderReport(results)
	for _, want := range []string{
		"| variant | wall s | CPU s | RSS MiB | wall ratio | CPU ratio | RSS ratio |",
		"| reference | 4.000 [4.000–4.000] |",
		"| rarpar-w1 | 2.000 [2.000–2.000] | 2.000 [2.000–2.000] | 10 [10–10] | 2.000 | 2.000 | 1.000 |",
		"| rarpar-w8 | 1.000 [1.000–1.000] | 1.000 [1.000–1.000] | 10 [10–10] | 4.000 | 4.000 | 1.000 |",
		"| rarpar-w1 | 1.000 [1.000–1.000] | 1.000 [1.000–1.000] | 10 [10–10] | 2.000 | 2.000 | 1.000 |", // verify
		"| reference | DNF | - | - | - | - | - |",
		"- reference DNF: exit 6: Failed to open Recovery File",
		"- reference DNF: timeout after 20m0s",
		"rarpar's carriers were used for verify and repair",
		"Per-run timeout 20m0s (reference 20m0s)",
		"every rarpar row runs buffered and the bench never passes `--fsync`",
		"`rarpar par3 create` runs with `--buffered`",
		"`rarpar par3 repair` on this candidate has no buffered mode and runs the plain command",
		"status **ok**",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q:\n%s", want, report)
		}
	}
	// Ours against a DNF reference has no ratio.
	if !strings.Contains(report, "| rarpar-w1 | 3.000 [3.000–3.000] | 3.000 [3.000–3.000] | 10 [10–10] | - | - | - |") {
		t.Fatalf("a rarpar row against a DNF reference must show no ratio:\n%s", report)
	}
	// No durability column, label or row is left.
	for _, stale := range []string{"| durability |", "| durable |", "| buffered |", "never syncs) |", "-buffered |"} {
		if strings.Contains(report, stale) {
			t.Fatalf("report still carries %q:\n%s", stale, report)
		}
	}
}

func TestPeakRSSIsARequiredRowField(t *testing.T) {
	results := &Results{Schema: ResultsSchema, Runs: []RunRecord{
		{Config: "u", Op: OpCreate, Variant: "rarpar-w1", Status: StatusOK, Measurement: Measurement{WallSeconds: 1, MaxRSSBytes: 1 << 20}},
		{Config: "u", Op: OpCreate, Variant: "reference", Status: StatusDNF, Failure: "start-failed"},
	}}
	if err := ValidateResults(results); err != nil {
		t.Fatalf("valid results rejected: %v", err)
	}
	results.Runs = append(results.Runs, RunRecord{Config: "u", Op: OpRepair, Variant: "rarpar-w1", Status: StatusOK, Measurement: Measurement{WallSeconds: 1}})
	if err := ValidateResults(results); err == nil || !strings.Contains(err.Error(), "max_rss_bytes") {
		t.Fatalf("an ok row without peak RSS must be invalid, got %v", err)
	}
	path := filepath.Join(t.TempDir(), "results.json")
	if err := writeJSONFile(path, results); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadResults(path); err == nil {
		t.Fatal("ReadResults must refuse a file with an ok row lacking peak RSS")
	}
	// A v1 file (durable rows possible) and a v2 file (its rarpar-wN repair
	// rows kept a numbered backup) are refused with a pointer to the harness
	// that wrote them.
	for schema, why := range map[string]string{
		"rarpar-par3-bench-v1": "predates buffered-only rows",
		"rarpar-par3-bench-v2": "predates the in-place and -backup repair rows",
	} {
		old := filepath.Join(t.TempDir(), "old.json")
		if err := writeJSONFile(old, &Results{Schema: schema}); err != nil {
			t.Fatal(err)
		}
		_, err := ReadResults(old)
		if err == nil || !strings.Contains(err.Error(), `want "rarpar-par3-bench-v4"`) ||
			!strings.Contains(err.Error(), why) || !strings.Contains(err.Error(), "read it with the harness that wrote it") {
			t.Fatalf("a %s results file: %v", schema, err)
		}
	}
	// The field is serialised even when zero, so it is never silently absent.
	if data, _ := os.ReadFile(path); strings.Count(string(data), `"max_rss_bytes"`) != len(results.Runs) {
		t.Fatalf("every run must carry max_rss_bytes:\n%s", data)
	}
	// RSS sits next to wall and CPU in every report table, with its ratio.
	report := RenderReport(&Results{Schema: ResultsSchema, Ops: []string{OpVerify}, Repeats: 1, Variants: Variants([]int{1}, nil),
		Configs: []ConfigSummary{{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}}},
		Runs: []RunRecord{
			{Config: "u", Op: OpVerify, Variant: "reference", Tool: ToolReference, Status: StatusOK, Measurement: Measurement{WallSeconds: 2, MaxRSSBytes: 40 << 20}},
			{Config: "u", Op: OpVerify, Variant: "rarpar-w1", Tool: ToolCandidate, Status: StatusOK, Measurement: Measurement{WallSeconds: 1, MaxRSSBytes: 10 << 20}},
		}})
	if !strings.Contains(report, "| variant | wall s | CPU s | RSS MiB | wall ratio | CPU ratio | RSS ratio |") ||
		!strings.Contains(report, "| rarpar-w1 | 1.000 [1.000–1.000] | 0.000 [0.000–0.000] | 10 [10–10] | 2.000 | - | 4.000 |") {
		t.Fatalf("report lacks the RSS column or ratio:\n%s", report)
	}
}

func TestOnlyUnfinishedReferenceRunsAreDNF(t *testing.T) {
	cases := []struct {
		tool, failure string
		status        string
		finished      bool
	}{
		{ToolReference, "timeout", StatusDNF, true},
		{ToolReference, "signal", StatusDNF, true},
		{ToolReference, "exit-6", StatusDNF, true},
		{ToolReference, "no-carriers", StatusDNF, true},
		{ToolReference, "truncated-carriers", StatusDNF, true},
		{ToolReference, "unreadable-carriers", StatusDNF, true},
		// A reference that ran but contradicted itself or the harness fails
		// the run: every identity verdict would be meaningless.
		{ToolReference, "reference-nondeterministic", StatusFailed, false},
		{ToolReference, "repair-mismatch", StatusFailed, false},
		{ToolReference, "start-failed", StatusFailed, false},
		{ToolReference, FailureMissingRSS, StatusFailed, false},
		// A timed-out rarpar row stays failed but is not retried.
		{ToolCandidate, "timeout", StatusFailed, true},
		{ToolCandidate, "exit-6", StatusFailed, false},
		{ToolCandidate, "repair-mismatch", StatusFailed, false},
	}
	for _, c := range cases {
		record := RunRecord{Tool: c.tool, Status: StatusFailed, Failure: c.failure}
		finished := settleRow(&record)
		if record.Status != c.status || finished != c.finished {
			t.Errorf("%s %s: status %s finished %t, want %s %t", c.tool, c.failure, record.Status, finished, c.status, c.finished)
		}
	}
	if ok := (RunRecord{Tool: ToolReference, Status: StatusOK}); settleRow(&ok) || ok.Status != StatusOK {
		t.Error("an ok run must not end its row")
	}
}

func TestHelpListsFlagMatchesWholeTokens(t *testing.T) {
	for help, want := range map[string]bool{
		"      --buffered       skip the per-output fsync":  true,
		"usage: rarpar par3 create [--buffered] FILES":      true,
		"      --buffered-io    something else":             false,
		"      --no-buffered    always sync":                false,
		"no flag mentioned; see docs for --buffered-output": false,
	} {
		if got := helpListsFlag(help, "--buffered"); got != want {
			t.Errorf("%q: got %t, want %t", help, got, want)
		}
	}
	for help, want := range map[string]bool{
		"      --fsync  After a successful run, fsync every file installed": true,
		"      --fsync-dirs  something else":                                false,
	} {
		if got := helpListsFlag(help, "--fsync"); got != want {
			t.Errorf("%q: got %t, want %t", help, got, want)
		}
	}
}

func TestBufferedArgsFollowTheCandidateGeneration(t *testing.T) {
	for _, c := range []struct {
		name, help string
		args       string
		ok         bool
	}{
		// rarpar 0.7.0+: buffered by default; --fsync is never passed.
		{"0.7.0", "Usage: rarpar par3 repair [OPTIONS] <SET>\n      --fsync  After a successful repair, fsync every file installed\n", "", true},
		// rarpar up to 0.6.x: durable by default, --buffered selects buffered.
		{"0.6.2", "Usage: rarpar par3 create [OPTIONS]\n      --buffered  Flush buffers without requesting durable storage barriers\n", "--buffered", true},
		// Both listed: --buffered is the switch that makes the op buffered.
		{"both", "      --buffered  skip barriers\n      --fsync  sync\n", "--buffered", true},
		// Neither (`par3 repair` before 0.7.0): no buffered mode.
		{"neither", "Usage: rarpar par3 repair [OPTIONS] <SET>\n", "", false},
	} {
		args, ok := bufferedArgsFromHelp(c.help)
		if ok != c.ok || strings.Join(args, " ") != c.args {
			t.Errorf("%s help: args %q ok %t, want %q %t", c.name, args, ok, c.args, c.ok)
		}
		if ok && args == nil {
			t.Errorf("%s help: a buffered op must record a non-nil argument list", c.name)
		}
	}
	if note := noBufferedModeNote(OpRepair); !strings.Contains(note, "`rarpar par3 repair --help`") || !strings.Contains(note, "no buffered repair mode") {
		t.Errorf("note = %q", note)
	}
}

// Every rarpar create and repair runs buffered: --buffered where an older
// candidate lists it, nothing on 0.7.0 and later, and the plain command for an
// op with no buffered mode. No command ever passes --fsync, verify takes no
// switch, and the reference command is untouched.
func TestRarparCommandsRunBufferedAndNeverPassFsync(t *testing.T) {
	config := Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}
	dataset := Dataset{Files: []FileSpec{{Name: "a.bin", Size: 4}}}
	row := Variant{Name: "rarpar-w4", Tool: ToolCandidate, Workers: 4}
	reference := Variant{Name: "reference", Tool: ToolReference}
	for _, c := range []struct {
		name           string
		args           map[string][]string
		unsupported    []string
		create, repair bool // --buffered expected
	}{
		{"0.7.0", map[string][]string{OpCreate: {}, OpRepair: {}}, nil, false, false},
		{"0.6.x create, flagless repair", map[string][]string{OpCreate: {"--buffered"}}, []string{OpRepair}, true, false},
		{"--buffered on both", map[string][]string{OpCreate: {"--buffered"}, OpRepair: {"--buffered"}}, nil, true, true},
	} {
		r := &runner{options: Options{Candidate: "/bin/rarpar", Reference: "/bin/par3"},
			results: &Results{BufferedArgs: c.args, BufferedUnsupported: c.unsupported}}
		create := strings.Join(r.createCommand(config, dataset, "/d", "/o", row).Args, " ")
		repair := strings.Join(r.checkCommand(OpRepair, "/s", row, config).Args, " ")
		verify := strings.Join(r.checkCommand(OpVerify, "/s", row, config).Args, " ")
		if got := strings.HasSuffix(create, " --buffered"); got != c.create {
			t.Errorf("%s: create %q", c.name, create)
		}
		if got := strings.HasSuffix(repair, " --buffered"); got != c.repair {
			t.Errorf("%s: repair %q", c.name, repair)
		}
		if strings.Contains(verify, "--buffered") {
			t.Errorf("%s: verify %q takes a buffered switch", c.name, verify)
		}
		for _, line := range []string{
			create, repair, verify,
			strings.Join(r.createCommand(config, dataset, "/d", "/o", reference).Args, " "),
			strings.Join(r.checkCommand(OpRepair, "/s", reference, config).Args, " "),
		} {
			if strings.Contains(line, "--fsync") {
				t.Errorf("%s: %q passes --fsync", c.name, line)
			}
		}
		for _, line := range []string{
			strings.Join(r.createCommand(config, dataset, "/d", "/o", reference).Args, " "),
			strings.Join(r.checkCommand(OpRepair, "/s", reference, config).Args, " "),
		} {
			if strings.Contains(line, "--buffered") {
				t.Errorf("%s: reference command %q carries a rarpar switch", c.name, line)
			}
		}
	}
}

func TestReferenceRowWithOnlyFailedRunsHasNoSelfRatio(t *testing.T) {
	results := &Results{Schema: ResultsSchema, Ops: []string{OpVerify}, Repeats: 1, Variants: Variants([]int{1}, nil),
		Configs: []ConfigSummary{{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}}},
		Runs: []RunRecord{
			{Config: "u", Op: OpVerify, Variant: "reference", Tool: ToolReference, Status: StatusFailed, Failure: "start-failed"},
			{Config: "u", Op: OpVerify, Variant: "rarpar-w1", Tool: ToolCandidate, Status: StatusOK, Measurement: Measurement{WallSeconds: 1, MaxRSSBytes: 1 << 20}},
		}}
	report := RenderReport(results)
	if !strings.Contains(report, "| reference | - | - | - | - | - | - |") {
		t.Fatalf("a reference row whose runs all failed must not print 1.000 ratios:\n%s", report)
	}
}

func TestValidatePinCPUs(t *testing.T) {
	for _, good := range []string{"", "0", "3", "0-7", "8-15", "63"} {
		if err := ValidatePinCPUs(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	for _, bad := range []string{"0,2", "7-0", "-1", "a-b", "0-64", "x"} {
		if err := ValidatePinCPUs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Two rows with one name would merge their runs into a single row.
func TestDuplicateRowsAreRefused(t *testing.T) {
	if err := CheckVariantNames(Variants([]int{1, 8}, nil)); err != nil {
		t.Fatal(err)
	}
	if err := CheckVariantNames(Variants([]int{1, 1}, nil)); err == nil {
		t.Fatal("--workers 1,1 must be refused")
	}
	kernel := KernelVariant{Name: "gfni-off", Env: []string{"X=1"}}
	if err := CheckVariantNames(Variants([]int{1}, []KernelVariant{kernel, kernel})); err == nil {
		t.Fatal("a kernel variant listed twice must be refused")
	}
}

func TestPortPatchAppliesOffX86Linux(t *testing.T) {
	for _, c := range []struct {
		goos, goarch string
		want         bool
	}{{"darwin", "arm64", true}, {"darwin", "amd64", true}, {"linux", "arm64", true}, {"linux", "amd64", false}, {"windows", "amd64", false}} {
		if got := portPatchApplies(c.goos, c.goarch); got != c.want {
			t.Errorf("portPatchApplies(%s, %s) = %v", c.goos, c.goarch, got)
		}
	}
}

// A create row of any tool that exits 0 without the set it was asked for
// fails: verify and repair read the canonical carriers, so nothing else
// would notice a candidate create that wrote nothing.
func TestCreateOutputProblemRejectsMissingCarriers(t *testing.T) {
	config := Config{Recovery: 3}
	dir := t.TempDir()
	if _, failure, _ := createOutputProblem(dir, config); failure != "no-carriers" {
		t.Errorf("an empty create directory: %q, want no-carriers", failure)
	}
	if err := os.WriteFile(filepath.Join(dir, "set.par3"), []byte("not a packet stream at all, long enough for one header....."), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, failure, _ := createOutputProblem(dir, config); failure != "unreadable-carriers" {
		t.Errorf("garbage carriers: %q, want unreadable-carriers", failure)
	}
	if err := os.WriteFile(filepath.Join(dir, "set.par3"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, failure, detail := createOutputProblem(dir, config); failure != "truncated-carriers" {
		t.Errorf("an index with no recovery blocks: %q (%s), want truncated-carriers", failure, detail)
	}
}

// par3cmdline's verify exits 0 whatever it finds; rarpar's exits 1 when the
// set is not intact. A damaged-verify row accepts only its own tool's code.
func TestDamagedVerifyExitCodesAreChosenByTool(t *testing.T) {
	cases := []struct {
		tool string
		exit int
		want bool
	}{
		{ToolReference, 0, true},
		{ToolReference, 1, false},
		{ToolReference, 2, false},
		{ToolCandidate, 1, true},
		{ToolCandidate, 0, false},
		{ToolCandidate, 2, false},
		{ToolEngine, 0, false},
	}
	for _, c := range cases {
		if got := damagedVerifyAccepted(c.tool, c.exit); got != c.want {
			t.Errorf("%s exit %d: accepted %t, want %t", c.tool, c.exit, got, c.want)
		}
	}
}

func TestVersionProbeProblem(t *testing.T) {
	if problem := versionProbeProblem(Result{}, "par3cmdline version 0.0.1"); problem != "" {
		t.Errorf("a clean probe: %q", problem)
	}
	if problem := versionProbeProblem(Result{}, ""); problem == "" {
		t.Error("a probe that printed nothing must not identify the binary")
	}
	if problem := versionProbeProblem(Result{Measurement: Measurement{ExitCode: 3}, Stdout: "usage\n"}, "usage"); problem == "" {
		t.Error("a probe that exited 3 must not identify the binary")
	}
	if problem := versionProbeProblem(Result{Failure: "start-failed"}, ""); problem == "" {
		t.Error("a probe that did not start must not identify the binary")
	}
}

// A set named twice would run twice under one row key and double its samples.
func TestSelectRejectsADuplicateSet(t *testing.T) {
	profile, err := LookupProfile("smoke")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Select([]string{"smoke-gf8", "smoke-gf8"}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("Select with a repeated set = %v, want a duplicate error", err)
	}
	selected, err := profile.Select([]string{"smoke-gf8"})
	if err != nil || len(selected.Configs) != 1 {
		t.Fatalf("Select of one set = %d configs, %v", len(selected.Configs), err)
	}
}

// strace exits with the traced command's status; a pass whose command did
// not complete its op publishes no counts.
func TestTracedRunProblemChecksTheTracedExit(t *testing.T) {
	createDone := func(code int) bool { return exitAccepted(OpCreate, ToolReference, code) }
	if err := tracedRunProblem(Result{}, createDone); err != nil {
		t.Errorf("a clean traced create: %v", err)
	}
	if err := tracedRunProblem(Result{Measurement: Measurement{ExitCode: 6}}, createDone); err == nil {
		t.Error("a traced create that exited 6 must not be counted")
	}
	if err := tracedRunProblem(Result{Failure: "timeout"}, createDone); err == nil {
		t.Error("a traced run that timed out must not be counted")
	}
	damaged := func(code int) bool { return exitAccepted(OpVerifyDamaged, ToolCandidate, code) }
	if err := tracedRunProblem(Result{Measurement: Measurement{ExitCode: 1}}, damaged); err != nil {
		t.Errorf("rarpar's damaged verdict is a completed verify: %v", err)
	}
	if err := tracedRunProblem(Result{}, damaged); err == nil {
		t.Error("rarpar calling a damaged set intact must not be counted")
	}
}

func TestCheckOpsRefusesDuplicateAndUnknownOps(t *testing.T) {
	if err := CheckOps(KnownOps); err != nil {
		t.Fatalf("every known op once must pass: %v", err)
	}
	if err := CheckOps([]string{OpCreate, OpVerify, OpCreate}); err == nil || !strings.Contains(err.Error(), `op "create" is listed more than once`) {
		t.Fatalf("a repeated op must be refused by name, got %v", err)
	}
	if err := CheckOps([]string{"explode"}); err == nil || !strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("an unknown op must be refused, got %v", err)
	}
	// RunSuite's option validation applies the same check.
	options := Options{Reference: os.Args[0], Candidate: os.Args[0], Work: "/w", Out: t.TempDir(), Ops: []string{OpRepair, OpRepair}, Repeats: 1}
	if err := validateOptions(&options); err == nil || !strings.Contains(err.Error(), `op "repair" is listed more than once`) {
		t.Fatalf("validateOptions must refuse a repeated op, got %v", err)
	}
}

// A repair's numbered backups are told apart from its other leftovers, and
// each rarpar repair row must leave what its mode promises: the -backup row
// at least one numbered backup, the in-place row none.
func TestRepairBackupsFollowTheRowsMode(t *testing.T) {
	dir, canonical := t.TempDir(), t.TempDir()
	write := func(base, name, content string) {
		if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(canonical, "set.par3", "carrier")
	write(dir, "set.par3", "carrier")
	manifest := DatasetManifest{}
	for _, name := range []string{"a.bin", "b.bin"} {
		write(dir, name, "intact "+name)
		digest, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		manifest.SHA256 = append(manifest.SHA256, FileDigest{Name: name, Size: size, SHA256: digest})
	}
	check, err := checkRepair(dir, manifest, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !check.Match || len(check.ExtraFiles) != 0 || len(check.Backups) != 0 {
		t.Fatalf("an in-place repair: %+v", check)
	}
	if problem := backupProblem(false, check); problem != "" {
		t.Fatalf("an in-place row that kept nothing: %q", problem)
	}
	if problem := backupProblem(true, check); !strings.Contains(problem, "left no numbered backup") {
		t.Fatalf("a backup row that kept nothing: %q", problem)
	}
	// A temporary, a backup of an unprotected file and a non-numbered suffix
	// are leftovers, not backups.
	for _, name := range []string{"a.bin.1", "b.bin.12", "a.bin.tmp", "a.bin.", "c.bin.1", "set.par3.1"} {
		write(dir, name, "left behind")
	}
	if check, err = checkRepair(dir, manifest, canonical); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(check.Backups, ","); got != "a.bin.1,b.bin.12" || len(check.ExtraFiles) != 6 {
		t.Fatalf("backups %q extra %v", got, check.ExtraFiles)
	}
	if problem := backupProblem(true, check); problem != "" {
		t.Fatalf("a backup row that kept backups: %q", problem)
	}
	if problem := backupProblem(false, check); !strings.Contains(problem, "in-place row left numbered backups: a.bin.1, b.bin.12") {
		t.Fatalf("an in-place row that kept backups: %q", problem)
	}
}

// On a candidate that cannot repair in place only the backup rows run a
// plain set's repair; a PAR-inside set runs one compatible row, never a
// backup row; create and verify never run a backup row.
func TestRowRunsHonoursBackupAndInPlaceSupport(t *testing.T) {
	variants := Variants([]int{1, 8}, []KernelVariant{{Name: "k", Env: []string{"A=1"}}})
	plain, carrier := Config{ID: "p"}, Config{ID: "c", Carrier: "zip"}
	runs := func(r *runner, config Config, op string) string {
		var names []string
		for _, variant := range variants {
			if r.rowRuns(config, variant, op) {
				names = append(names, variant.Name)
			}
		}
		return strings.Join(names, ",")
	}
	r := &runner{options: Options{Workers: []int{1, 8}}, results: &Results{}}
	for _, c := range []struct {
		config   Config
		op, want string
	}{
		{plain, OpCreate, "reference,rarpar-w1,rarpar-w8,rarpar-w1-k,rarpar-w8-k"},
		{plain, OpVerify, "reference,rarpar-w1,rarpar-w8,rarpar-w1-k,rarpar-w8-k"},
		{plain, OpRepair, "reference,rarpar-w1,rarpar-w1-backup,rarpar-w8,rarpar-w8-backup,rarpar-w1-k,rarpar-w8-k"},
		{carrier, OpRepair, "reference,rarpar-w8"},
		{carrier, OpVerify, "reference,rarpar-w8"},
	} {
		if got := runs(r, c.config, c.op); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.config.ID, c.op, got, c.want)
		}
	}
	r.results.InPlaceUnsupported = true
	if got := runs(r, plain, OpRepair); got != "reference,rarpar-w1-backup,rarpar-w8-backup" {
		t.Errorf("no in-place mode: plain repair rows %s", got)
	}
	if got := runs(r, carrier, OpRepair); got != "reference,rarpar-w8" {
		t.Errorf("no in-place mode: carrier repair rows %s", got)
	}
	if got := runs(r, plain, OpCreate); got != "reference,rarpar-w1,rarpar-w8,rarpar-w1-k,rarpar-w8-k" {
		t.Errorf("no in-place mode: create rows %s", got)
	}
}

// The report, and the repair chart, name which rarpar repair row is like for
// like with the reference on bytes written: the -backup row on a plain set,
// the compatible rs row on a PAR-inside set; the rarpar-wN row repairs in
// place. The header says how each row's mode was selected on this candidate
// and that the compatible front end on a PAR-inside set is not buffered.
func TestReportNamesTheLikeForLikeRepairRow(t *testing.T) {
	results := &Results{
		Schema: ResultsSchema, Profile: "unit", Ops: []string{OpRepair}, Repeats: 1, Workers: []int{1},
		Variants:     Variants([]int{1}, nil),
		BufferedArgs: map[string][]string{OpRepair: {}},
		BackupArgs:   map[string][]string{"rarpar-w1": {}, "rarpar-w1-backup": {"--backup"}},
		Configs: []ConfigSummary{
			{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}, InputBlocks: 30},
			{Config: Config{ID: "c", BlockSize: MiB, Recovery: 3, Codec: "cauchy", Carrier: "zip"}, InputBlocks: 30},
		},
		Status: StatusOK,
	}
	add := func(config, variant, tool string, wall float64, left ...string) {
		check := &RepairCheck{Match: true, ExtraFiles: left}
		for _, name := range left {
			if strings.HasSuffix(name, ".1") {
				check.Backups = append(check.Backups, name)
			}
		}
		results.Runs = append(results.Runs, RunRecord{Config: config, Op: OpRepair, Variant: variant, Tool: tool, Status: StatusOK,
			Measurement: Measurement{WallSeconds: wall, UserSeconds: wall, MaxRSSBytes: 10 << 20}, Repair: check})
	}
	add("u", "reference", ToolReference, 4, "a.bin.1")
	add("u", "rarpar-w1", ToolCandidate, 1)
	add("u", "rarpar-w1-backup", ToolCandidate, 2, "a.bin.1")
	add("c", "reference", ToolReference, 4, "inside.zip.1")
	add("c", "rarpar-w1", ToolCandidate, 2, "inside.zip.1")

	report := RenderReport(results)
	for _, want := range []string{
		"every rarpar row on a plain set runs buffered and the bench never passes `--fsync`",
		"On a PAR-inside set rarpar runs its par3cmdline-compatible front end (`vs`/`rs`) instead, which has no buffered mode: its repair syncs the rebuilt carrier, so those repair rows are not buffered.",
		"- Repair rows: the reference keeps a numbered `.1` backup of every file it repairs.",
		"the `-backup` rows are the rarpar rows that are like for like with the reference on bytes written",
		"On this candidate the in-place rows run plain and the `-backup` rows with `--backup`.",
		"A PAR-inside set has one rarpar row, through the compatible `rs`",
		"Like for like with the reference on bytes written: `rarpar-w1-backup`, which keeps a numbered `.1` backup of every file it repairs, as the reference does. `rarpar-w1` repairs in place and writes no backup.",
		"Like for like with the reference on bytes written: `rarpar-w1`, which runs the compatible `rs` and keeps the damaged carrier as a numbered backup, as the reference does.",
		"| rarpar-w1-backup | 2.000 [2.000–2.000] |",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q:\n%s", want, report)
		}
	}
	chart, ok := renderOpSVG(results, Summarize(results), OpRepair)
	if !ok {
		t.Fatal("no repair chart")
	}
	for _, want := range []string{
		"u / rarpar-w1 — in place, no backup",
		"u / rarpar-w1-backup — retains file like the reference: like for like",
		"c / rarpar-w1 — compatible rs, retains file like the reference: like for like",
		"par3cmdline retains a numbered .1 copy of every file it repairs.",
	} {
		if !strings.Contains(string(chart), want) {
			t.Fatalf("repair chart lacks %q:\n%s", want, chart)
		}
	}
	// A run with no PAR-inside set keeps the plain wording.
	results.Configs = results.Configs[:1]
	results.Runs = results.Runs[:3]
	report = RenderReport(results)
	if !strings.Contains(report, "every rarpar row runs buffered and the bench never passes `--fsync`") ||
		strings.Contains(report, "PAR-inside") {
		t.Fatalf("plain-set report:\n%s", report)
	}
}

// --candidate-arg reaches every candidate run, the par2-rs rows included.
func TestPAR2RSCommandsCarryCandidateArgs(t *testing.T) {
	config := Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy", PAR2: true}
	dataset := Dataset{Files: []FileSpec{{Name: "a.bin", Size: 4}}}
	row := Variant{Name: ToolPAR2, Tool: ToolPAR2}
	r := &runner{options: Options{Candidate: "/bin/rarpar", CandidateArgs: []string{"--x", "y"}}, results: &Results{}}
	for _, args := range [][]string{
		r.createCommand(config, dataset, "/d", "/o", row).Args,
		r.checkCommand(OpVerify, "/s", row, config).Args,
		r.checkCommand(OpRepair, "/s", row, config).Args,
	} {
		if line := strings.Join(args, " "); !strings.HasPrefix(line, "--quiet --x y par ") {
			t.Errorf("par2-rs command %q", line)
		}
	}
}

// The untimed PAR2 seed is written only when a PAR2 verify or repair reads it.
func TestPAR2SeedOnlyForVerifyOrRepair(t *testing.T) {
	config := Config{ID: "u", PAR2: true}
	for ops, want := range map[string]bool{"create": false, "verify-damaged": false, "create,verify-damaged": false, "verify": true, "create,repair": true} {
		r := &runner{options: Options{Ops: strings.Split(ops, ",")}, results: &Results{Variants: PAR2Rows()}}
		if got := r.par2Seeded(config); got != want {
			t.Errorf("ops %s: seeded %v", ops, got)
		}
	}
}
