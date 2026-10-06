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
	if strings.Join(options.Durabilities, ",") != "durable,buffered" {
		t.Fatalf("default durabilities %v", options.Durabilities)
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
	for _, v := range Variants([]int{1, 8}, []KernelVariant{variant}, []string{DurabilityDurable}) {
		names = append(names, v.Name+"/"+v.dirName())
	}
	if got := strings.Join(names, ","); got != "reference/ref,rarpar-w1/w1,rarpar-w8/w8,rarpar-w1-gfni-off/w1-gfni-off,rarpar-w8-gfni-off/w8-gfni-off" {
		t.Fatalf("variants %s", got)
	}
}

func TestDurabilityRowsDoubleOursOnlyForWritingOps(t *testing.T) {
	variants := Variants([]int{1, 8}, nil, nil)
	var names []string
	for _, v := range variants {
		names = append(names, v.Name+":"+v.EffectiveDurability())
	}
	// Durable first (the default, named as before), then buffered; one reference row.
	if got := strings.Join(names, ","); got != "reference:,rarpar-w1:durable,rarpar-w1-buffered:buffered,rarpar-w8:durable,rarpar-w8-buffered:buffered" {
		t.Fatalf("variants %s", got)
	}
	rows := RowsByOp(variants, KnownOps)
	if got := strings.Join(rows[OpCreate], ","); got != "reference,rarpar-w1,rarpar-w1-buffered,rarpar-w8,rarpar-w8-buffered" {
		t.Fatalf("create rows %s", got)
	}
	if got := strings.Join(rows[OpRepair], ","); got != strings.Join(rows[OpCreate], ",") {
		t.Fatalf("repair rows %s", got)
	}
	for _, op := range []string{OpVerify, OpVerifyDamaged} {
		if got := strings.Join(rows[op], ","); got != "reference,rarpar-w1,rarpar-w8" {
			t.Fatalf("%s rows %s: verify writes nothing, so it has no buffered rows", op, got)
		}
	}
	if (Variant{Name: "rarpar-w1", Tool: ToolCandidate}).EffectiveDurability() != DurabilityDurable {
		t.Fatal("a rarpar row from an older results file ran durable")
	}
	for text, want := range map[string]string{"": "durable,buffered", "durable": "durable", "buffered,durable": "buffered,durable"} {
		got, err := ParseDurabilities(text)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("ParseDurabilities(%q) = %v, %v; want %s", text, got, err, want)
		}
	}
	for _, bad := range []string{"buffered", "fsync"} {
		if _, err := ParseDurabilities(bad); err == nil {
			t.Errorf("ParseDurabilities(%q): expected an error", bad)
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
	variants := Variants([]int{1, 8}, nil, nil)
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
		Variants: Variants([]int{1}, nil, []string{DurabilityDurable}),
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
		"| reference | none (never syncs) | 2.000 [1.000–3.000] |",
		"| rarpar-w1 | durable (default) | 1.000 [0.500–1.500] |",
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

func TestReportShowsDurabilityRowsAndReferenceDNF(t *testing.T) {
	results := &Results{
		Schema: ResultsSchema, Profile: "unit", Ops: []string{OpCreate, OpVerify, OpRepair}, Repeats: 2, Workers: []int{1},
		Variants: Variants([]int{1}, nil, nil), Durabilities: KnownDurabilities,
		TimeoutSeconds: 1200, ReferenceTimeoutSeconds: 1200,
		Configs: []ConfigSummary{
			{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}, InputBlocks: 30, CanonicalSource: ToolReference},
			{Config: Config{ID: "v", BlockSize: MiB, Recovery: 3, Codec: "fft"}, InputBlocks: 30, CanonicalSource: ToolCandidate},
		},
		Status: StatusOK,
	}
	add := func(config, op, variant, tool, durability string, wall float64) {
		results.Runs = append(results.Runs, RunRecord{Config: config, Op: op, Variant: variant, Tool: tool, Durability: durability,
			Status: StatusOK, Measurement: Measurement{WallSeconds: wall, UserSeconds: wall, MaxRSSBytes: 10 << 20}})
	}
	for range 2 {
		add("u", OpCreate, "reference", ToolReference, "", 4)
		add("u", OpCreate, "rarpar-w1", ToolCandidate, DurabilityDurable, 2)
		add("u", OpCreate, "rarpar-w1-buffered", ToolCandidate, DurabilityBuffered, 1)
		add("u", OpVerify, "reference", ToolReference, "", 2)
		add("u", OpVerify, "rarpar-w1", ToolCandidate, DurabilityDurable, 1)
		add("v", OpCreate, "rarpar-w1", ToolCandidate, DurabilityDurable, 2)
		add("v", OpCreate, "rarpar-w1-buffered", ToolCandidate, DurabilityBuffered, 1)
	}
	results.Runs = append(results.Runs, RunRecord{Config: "v", Op: OpCreate, Variant: "reference", Tool: ToolReference, Canonical: true, Warmup: true,
		Status: StatusDNF, Failure: "exit-6", Measurement: Measurement{ExitCode: 6}, StderrLine: "Failed to open Recovery File"})
	results.Runs = append(results.Runs, RunRecord{Config: "v", Op: OpRepair, Variant: "reference", Tool: ToolReference, Warmup: true,
		Status: StatusDNF, Failure: "timeout", Measurement: Measurement{WallSeconds: 1200, ExitCode: -1}})
	add("v", OpRepair, "rarpar-w1", ToolCandidate, DurabilityDurable, 3)
	results.DNF = []string{"v/create/reference: DNF exit 6: Failed to open Recovery File (canonical seed create)"}

	report := RenderReport(results)
	for _, want := range []string{
		"| variant | durability | wall s |",
		"| reference | none (never syncs) | 4.000 [4.000–4.000] |",
		"| rarpar-w1 | durable (default) | 2.000 [2.000–2.000] | 2.000 [2.000–2.000] | 10 [10–10] | 0.500 | 0.500 | 1.000 |",
		"| rarpar-w1-buffered | buffered | 1.000 [1.000–1.000] | 1.000 [1.000–1.000] | 10 [10–10] | 0.250 | 0.250 | 1.000 |",
		"| rarpar-w1 | 1.000 [1.000–1.000] |", // verify: no durability column
		"| reference | none (never syncs) | DNF | - | - | - | - | - |",
		"- reference DNF: exit 6: Failed to open Recovery File",
		"- reference DNF: timeout after 20m0s",
		"rarpar's carriers were used for verify and repair",
		"Per-run timeout 20m0s (reference 20m0s)",
		"durable and buffered",
		"status **ok**",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q:\n%s", want, report)
		}
	}
	// Ours against a DNF reference has no ratio.
	if !strings.Contains(report, "| rarpar-w1 | durable (default) | 3.000 [3.000–3.000] | 3.000 [3.000–3.000] | 10 [10–10] | - | - | - |") {
		t.Fatalf("a rarpar row against a DNF reference must show no ratio:\n%s", report)
	}
	if strings.Index(report, "| rarpar-w1 | durable") > strings.Index(report, "| rarpar-w1-buffered |") {
		t.Fatal("the durable row must come before the buffered row")
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
	// The field is serialised even when zero, so it is never silently absent.
	if data, _ := os.ReadFile(path); strings.Count(string(data), `"max_rss_bytes"`) != len(results.Runs) {
		t.Fatalf("every run must carry max_rss_bytes:\n%s", data)
	}
	// RSS sits next to wall and CPU in every report table, with its ratio.
	report := RenderReport(&Results{Schema: ResultsSchema, Ops: []string{OpVerify}, Repeats: 1, Variants: Variants([]int{1}, nil, nil),
		Configs: []ConfigSummary{{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}}},
		Runs: []RunRecord{
			{Config: "u", Op: OpVerify, Variant: "reference", Tool: ToolReference, Status: StatusOK, Measurement: Measurement{WallSeconds: 2, MaxRSSBytes: 40 << 20}},
			{Config: "u", Op: OpVerify, Variant: "rarpar-w1", Tool: ToolCandidate, Status: StatusOK, Measurement: Measurement{WallSeconds: 1, MaxRSSBytes: 10 << 20}},
		}})
	if !strings.Contains(report, "| variant | wall s | CPU s | RSS MiB | wall ratio | CPU ratio | RSS ratio |") ||
		!strings.Contains(report, "| rarpar-w1 | 1.000 [1.000–1.000] | 0.000 [0.000–0.000] | 10 [10–10] | 0.500 | - | 0.250 |") {
		t.Fatalf("report lacks the RSS column or ratio:\n%s", report)
	}
}
