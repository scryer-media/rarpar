package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceIdentityAcceptsNoArgumentBanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reference.sh")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then exit 7; fi\necho 'Reference 1.0'\necho 'Usage: reference <path\\\\>'\nexit 7\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := identifyBinary(context.Background(), path, "reference", false); err == nil {
		t.Fatal("candidate identity unexpectedly accepted a no-argument banner")
	}
	identity, err := identifyBinary(context.Background(), path, "reference", true)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Version != "Reference 1.0" {
		t.Fatalf("unexpected reference identity %q", identity.Version)
	}
}

func TestReferenceRARArgumentsUseDirectoryDestination(t *testing.T) {
	stage := t.TempDir()
	if err := os.WriteFile(filepath.Join(stage, "release.part01.rar"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	args, err := referenceRARArguments(CorpusCaseManifest{}, stage)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(stage, "out") + string(os.PathSeparator)
	if got := args[len(args)-1]; got != want {
		t.Fatalf("destination = %q, want %q", got, want)
	}
}

func TestCandidateRARArgumentsUseDirectExtraction(t *testing.T) {
	stage := t.TempDir()
	archive := filepath.Join(stage, "release.part01.rar")
	if err := os.WriteFile(archive, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	args, err := candidateArguments(CorpusCaseManifest{Config: CaseConfig{Family: "rar"}}, stage, "canonical")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"x", "-idp", "-o+", archive, filepath.Join(stage, "out")}
	if got := strings.Join(args, "\x00"); got != strings.Join(want, "\x00") {
		t.Fatalf("candidate RAR arguments = %q, want %q", args, want)
	}
}

func TestCandidateArgumentsCarryPAR2PlacementPolicy(t *testing.T) {
	stage := t.TempDir()
	if err := os.WriteFile(filepath.Join(stage, "release.par2"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	verify, err := candidateArguments(CorpusCaseManifest{Config: CaseConfig{Family: "par2", Mutation: "none"}}, stage, "canonical")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(verify, "\x00"), strings.Join([]string{"par", "verify", "--par-placement", "canonical", filepath.Join(stage, "release.par2")}, "\x00"); got != want {
		t.Fatalf("verify arguments = %q, want %q", verify, want)
	}

	repair, err := candidateArguments(CorpusCaseManifest{Config: CaseConfig{Family: "par2", Mutation: "damage"}}, stage, "smart")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(repair, "\x00"), strings.Join([]string{"par", "repair", "--par-placement", "smart", filepath.Join(stage, "release.par2")}, "\x00"); got != want {
		t.Fatalf("repair arguments = %q, want %q", repair, want)
	}
}

func TestPayloadGenerationIsDeterministic(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.bin")
	second := filepath.Join(t.TempDir(), "second.bin")
	firstDigest, err := writePayloadFile(first, "seed", "case", "payload/part.bin", 97_321)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := writePayloadFile(second, "seed", "case", "payload/part.bin", 97_321)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || firstDigest != secondDigest {
		t.Fatal("deterministic payload generation changed")
	}
}

func TestToolchainLockRequiresPinnedSources(t *testing.T) {
	lock := validToolchainLock()
	if err := lock.Validate(); err != nil {
		t.Fatal(err)
	}
	lock.RARWriters[0].SHA256 = "not-a-digest"
	if err := lock.Validate(); err == nil {
		t.Fatal("unlocked RAR source was accepted")
	}
}

func TestCorpusConfigRejectsMutatedCaseWithoutRecovery(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].Mutation = "damage"
	if err := config.Validate(); err == nil {
		t.Fatal("damaged case without recovery material was accepted")
	}
}

func TestCorpusConfigRejectsPPMdOutsideRAR4(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].PPMd = true
	if err := config.Validate(); err == nil {
		t.Fatal("PPMd outside RAR4 was accepted")
	}
}

func TestCorpusConfigRequiresTextForPPMd(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].Format = 4
	config.Cases[0].PPMd = true
	if err := config.Validate(); err == nil {
		t.Fatal("binary PPMd case was accepted")
	}
	config.Cases[0].PayloadProfile = "text"
	if err := config.Validate(); err != nil {
		t.Fatalf("text PPMd case was rejected: %v", err)
	}
}

func TestTextPayloadGenerationIsDeterministic(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.txt")
	second := filepath.Join(t.TempDir(), "second.txt")
	firstDigest, err := writePayloadFileWithProfile(first, "seed", "case", "payload/part.txt", 97_321, "text")
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := writePayloadFileWithProfile(second, "seed", "case", "payload/part.txt", 97_321, "text")
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || firstDigest != secondDigest || !bytes.Contains(firstBytes, []byte("archive ")) {
		t.Fatal("deterministic text payload generation changed")
	}
}

func TestImportedFixtureDigestIsPinned(t *testing.T) {
	harnessRoot := t.TempDir()
	fixtureRoot := filepath.Join(harnessRoot, "fixture")
	if err := os.Mkdir(fixtureRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRoot, "case.rar"), []byte("rar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRoot, "case.r00"), []byte("volume"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceManifest(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	item := CaseConfig{ID: "case", FixtureDir: "fixture", FixturePrefix: "case", FixtureSHA256: bytesSHA256(encoded)}
	workRoot := t.TempDir()
	if err := importFixture(workRoot, harnessRoot, item); err != nil {
		t.Fatal(err)
	}
	item.FixtureSHA256 = strings.Repeat("0", 64)
	if err := importFixture(t.TempDir(), harnessRoot, item); err == nil {
		t.Fatal("fixture digest mismatch was accepted")
	}
}

func TestHeavyDamageMutationUsesConfiguredSliceCount(t *testing.T) {
	stage := t.TempDir()
	archive := filepath.Join(stage, "release.rar")
	if err := os.WriteFile(archive, make([]byte, 20*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := CorpusCaseManifest{Config: CaseConfig{
		Mutation:           "heavy-damage",
		DamageCount:        3,
		DamageBytesPerSite: 8,
		PAR2SliceSize:      1024,
	}}
	if err := applyMutation(stage, manifest); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, slice := range []int{5, 10, 15} {
		if got := contents[slice*1024+100 : slice*1024+108]; !bytes.Equal(got, bytes.Repeat([]byte{0xA5}, 8)) {
			t.Fatalf("slice %d was not damaged at the configured offset", slice)
		}
	}
}

func TestPlanOrderIsStable(t *testing.T) {
	ids := []string{"third", "first", "second"}
	first := deterministicOrder(ids, "seed")
	second := deterministicOrder(ids, "seed")
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatal("plan order is not stable")
	}
}

func TestBenchmarkPairsAlternateWhichSubjectRunsFirst(t *testing.T) {
	if referenceRunsFirst(0, true) || !referenceRunsFirst(1, true) || referenceRunsFirst(1, false) {
		t.Fatal("benchmark pair order did not alternate deterministically")
	}
}

func TestRenderSVGIsDeterministicAndEscapesInput(t *testing.T) {
	report := fixtureReport()
	first, err := renderSVG(report, "rar", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderSVG(report, "rar", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("SVG output is not byte deterministic")
	}
	const goldenRARSVG = "ff611fd5c2f9e2ec3942f5254baf7a5f4e74bb01fdea78c8b2f41312388e16c4"
	if got := bytesSHA256(first); got != goldenRARSVG {
		t.Fatalf("RAR SVG changed: got %s, want %s", got, goldenRARSVG)
	}
	for _, required := range []string{"<svg", "role=\"img\"", "1x parity", "&lt;unsafe&gt;", "report_sha256=report-digest", "collector=wall-clock", "par2_placement=canonical"} {
		if !strings.Contains(string(first), required) {
			t.Fatalf("SVG does not contain %q", required)
		}
	}
	if strings.Contains(string(first), "<unsafe>") {
		t.Fatal("SVG text was not escaped")
	}
}

func TestRenderPAR2SVGGolden(t *testing.T) {
	report := fixtureReport()
	report.Comparisons[0].Family = "par2"
	report.Comparisons[0].ReferenceLabel = "par2cmdline-turbo"
	chart, err := renderSVG(report, "par2", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	const goldenPAR2SVG = "ec2af08e88b561b396701a1ebd75a6c463d9675479b3aeeed324ac10f2d7193c"
	if got := bytesSHA256(chart); got != goldenPAR2SVG {
		t.Fatalf("PAR2 SVG changed: got %s, want %s", got, goldenPAR2SVG)
	}
}

func TestRenderSVGLegendIsFamilySpecific(t *testing.T) {
	rar, err := renderSVG(fixtureReport(), "rar", fixtureReport().Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rar), "rarpar / GPU") || !strings.Contains(string(rar), "UnRAR faster") {
		t.Fatalf("unexpected RAR legend: %s", rar)
	}
	report := fixtureReport()
	report.Comparisons[0].Family = "par2"
	report.Comparisons[0].ReferenceLabel = "par2cmdline-turbo"
	par2, err := renderSVG(report, "par2", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(par2), "rarpar / GPU") {
		t.Fatalf("unexpected GPU legend: %s", par2)
	}
	for _, required := range []string{"par2cmdline-turbo faster", "<rect class=\"cpu\" x=\"570\"", "<rect class=\"slower\" x=\"890\""} {
		if !strings.Contains(string(par2), required) {
			t.Fatalf("PAR2 legend does not contain %q", required)
		}
	}
}

func TestRenderComparableCPUAndGPULanes(t *testing.T) {
	cpu := fixtureReport()
	cpu.Plan.Lane = "cpu"
	cpu.Plan.ID = "cpu-plan"
	cpu.InputSHA256 = strings.Repeat("a", 64)
	cpu.Candidate.SHA256 = strings.Repeat("b", 64)
	cpu.Comparisons[0].Family = "par2"
	cpu.Comparisons[0].ReferenceLabel = "par2cmdline-turbo"

	gpu := fixtureReport()
	gpu.Plan.Lane = "wgpu"
	gpu.Plan.ID = "wgpu-plan"
	gpu.InputSHA256 = strings.Repeat("c", 64)
	gpu.Candidate.SHA256 = strings.Repeat("d", 64)
	gpu.Comparisons[0].Family = "par2"
	gpu.Comparisons[0].ReferenceLabel = "par2cmdline-turbo"
	gpu.Comparisons[0].Backend = "wgpu"

	chart, err := renderSVGGroups("par2", []chartGroup{
		{report: cpu, comparisons: cpu.Comparisons},
		{report: gpu, comparisons: gpu.Comparisons},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"/ cpu /", "/ wgpu /", "rarpar / GPU", "class=\"gpu\"", cpu.Candidate.SHA256, gpu.Candidate.SHA256} {
		if !strings.Contains(string(chart), required) {
			t.Fatalf("combined chart does not contain %q", required)
		}
	}
}

func TestRenderChartSetRejectsCollectorModesAcrossFamilies(t *testing.T) {
	rar := fixtureReport()
	rar.CollectorMode = wallClockCollector
	rar.Comparisons[0].Family = "rar"

	par2 := fixtureReport()
	par2.CollectorMode = perfStatCollector
	par2.Comparisons[0].Family = "par2"

	_, err := RenderChartSet([]Report{rar, par2}, filepath.Join(t.TempDir(), "charts"))
	if err == nil || !strings.Contains(err.Error(), "same collector mode") {
		t.Fatalf("mixed collector modes error = %v", err)
	}
}

func TestRenderChartSetRejectsUnsupportedCollectorMode(t *testing.T) {
	report := fixtureReport()
	report.CollectorMode = ""

	_, err := RenderChartSet([]Report{report}, filepath.Join(t.TempDir(), "charts"))
	if err == nil || !strings.Contains(err.Error(), "unsupported benchmark collector mode") {
		t.Fatalf("unsupported collector mode error = %v", err)
	}
}

func TestRenderRejectsMixedCollectorModes(t *testing.T) {
	wallClock := fixtureReport()
	perf := fixtureReport()
	perf.CollectorMode = perfStatCollector
	err := validateChartGroups("rar", []chartGroup{
		{report: wallClock, comparisons: wallClock.Comparisons},
		{report: perf, comparisons: perf.Comparisons},
	})
	if err == nil || !strings.Contains(err.Error(), "collector mode") {
		t.Fatalf("mixed collector modes were accepted: %v", err)
	}
}

func TestChartSummaryDoesNotSerializeOutputPath(t *testing.T) {
	dir := t.TempDir()
	if _, err := RenderCharts(fixtureReport(), dir); err != nil {
		t.Fatal(err)
	}
	summary, err := os.ReadFile(filepath.Join(dir, "chart-summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(summary), dir) || !strings.Contains(string(summary), "rarpar-rar-benchmark.svg") {
		t.Fatalf("chart summary contains an unsafe or missing chart path: %s", summary)
	}
}

func TestReportOmitsUnmatchedOrFailedSamples(t *testing.T) {
	dir := t.TempDir()
	raw := fixtureRunRecord()
	raw.Executions = raw.Executions[:1]
	path := filepath.Join(dir, "raw.json")
	if err := writeJSON(path, raw); err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Comparisons) != 0 || len(report.Omitted) != 1 {
		t.Fatalf("unmatched samples should be omitted: %#v", report)
	}
}

func TestRunRecordNeverSerializesBenchmarkPassword(t *testing.T) {
	raw := fixtureRunRecord()
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), benchmarkPassword) {
		t.Fatal("benchmark password leaked into artifact")
	}
}

func TestFailureDiagnosticsRedactPasswordsAndPaths(t *testing.T) {
	message := commandFailure(os.ErrPermission, nil, []byte("failed /tmp/private "+benchmarkPassword))
	if strings.Contains(message, benchmarkPassword) || strings.Contains(message, "/tmp/private") {
		t.Fatalf("unsafe diagnostic: %s", message)
	}
}

func TestAuditFeaturesFollowBenchmarkLane(t *testing.T) {
	tests := map[string]string{
		"cpu":        "runtime",
		"docker-cpu": "runtime",
		"metal":      "runtime,metal",
	}
	for lane, expected := range tests {
		actual, err := auditFeaturesForLane(lane)
		if err != nil || actual != expected {
			t.Fatalf("lane %q: features=%q err=%v", lane, actual, err)
		}
	}
	if _, err := auditFeaturesForLane("unknown"); err == nil {
		t.Fatal("unknown lane must fail source audit")
	}
	if _, err := auditFeaturesForLane("wgpu"); err == nil {
		t.Fatal("disabled WGPU lane must fail source audit")
	}
}

func TestBackendDetectionIgnoresAnsiFormatting(t *testing.T) {
	log := "\x1b[3mbackend\x1b[0m\x1b[2m=\x1b[0m\x1b[32m\"wgpu\"\x1b[0m"
	backend, fallback := backendFromLogs("wgpu", log)
	if backend != "wgpu" || fallback != "" {
		t.Fatalf("backend=%q fallback=%q", backend, fallback)
	}
}

func TestRAR5PhaseEvidenceSerializesOptionalFields(t *testing.T) {
	staging := int64(12_345)
	measurement := Measurement{RAR5Phases: &RAR5PhaseEvidence{
		StagingNanos:      &staging,
		UnavailableReason: "header scan was not emitted",
	}}
	encoded, err := json.Marshal(measurement)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, required := range []string{`"staging_nanos":12345`, `"unavailable_reason":"header scan was not emitted"`} {
		if !strings.Contains(serialized, required) {
			t.Fatalf("phase evidence did not serialize %q: %s", required, serialized)
		}
	}
	if strings.Contains(serialized, `"header_scan_nanos":0`) {
		t.Fatalf("missing phase was serialized as zero: %s", serialized)
	}
	var decoded Measurement
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RAR5Phases == nil || decoded.RAR5Phases.StagingNanos == nil || *decoded.RAR5Phases.StagingNanos != staging {
		t.Fatalf("phase evidence did not round-trip: %#v", decoded.RAR5Phases)
	}
}

func TestRAR5PhaseDiagnosticsMissingHasReason(t *testing.T) {
	evidence := collectRAR5PhaseDiagnostics([]byte("ordinary output\n"), []byte("ordinary logs\n"))
	if evidence == nil || evidence.UnavailableReason == "" {
		t.Fatalf("missing phase diagnostics did not carry a reason: %#v", evidence)
	}
	if evidence.StagingNanos != nil || evidence.HeaderScanNanos != nil || evidence.WorkerDecodeNanos != nil || evidence.SerialApplyNanos != nil {
		t.Fatalf("missing phase diagnostics fabricated values: %#v", evidence)
	}
	if !strings.Contains(evidence.UnavailableReason, "product hook required") {
		t.Fatalf("unexpected missing-phase reason: %q", evidence.UnavailableReason)
	}
}

func TestRAR5PhaseDiagnosticsAcceptStdoutStderrZeroAndDuplicates(t *testing.T) {
	stdout := []byte(strings.Join([]string{
		`RARPAR_BENCH_PHASE {"phase":"staging","nanos":10}`,
		`RARPAR_BENCH_PHASE {"phase":"worker_decode","nanos":30}`,
	}, "\n"))
	stderr := []byte(strings.Join([]string{
		`RARPAR_BENCH_PHASE {"phase":"staging","nanos":5}`,
		`RARPAR_BENCH_PHASE {"phase":"header_scan","nanos":0}`,
		`RARPAR_BENCH_PHASE {"phase":"serial_apply","nanos":40}`,
	}, "\n"))
	evidence := collectRAR5PhaseDiagnostics(stdout, stderr)
	if evidence.UnavailableReason != "" {
		t.Fatalf("valid diagnostics were rejected: %q", evidence.UnavailableReason)
	}
	for name, result := range map[string]struct {
		actual *int64
		want   int64
	}{
		"staging":       {evidence.StagingNanos, 15},
		"header_scan":   {evidence.HeaderScanNanos, 0},
		"worker_decode": {evidence.WorkerDecodeNanos, 30},
		"serial_apply":  {evidence.SerialApplyNanos, 40},
	} {
		if result.actual == nil || *result.actual != result.want {
			t.Fatalf("%s = %v, want %d", name, result.actual, result.want)
		}
	}
}

func TestRAR5PhaseDiagnosticsRejectDuplicateOverflow(t *testing.T) {
	markers := []byte(strings.Join([]string{
		`RARPAR_BENCH_PHASE {"phase":"worker_decode","nanos":9223372036854775807}`,
		`RARPAR_BENCH_PHASE {"phase":"worker_decode","nanos":1}`,
	}, "\n"))
	evidence := collectRAR5PhaseDiagnostics(markers, nil)
	if evidence.UnavailableReason == "" || !strings.Contains(evidence.UnavailableReason, "overflow") {
		t.Fatalf("overflow did not produce controlled unavailable evidence: %#v", evidence)
	}
	if evidence.StagingNanos != nil || evidence.HeaderScanNanos != nil || evidence.WorkerDecodeNanos != nil || evidence.SerialApplyNanos != nil {
		t.Fatalf("overflow retained wrapped or partial values: %#v", evidence)
	}
}

func TestRAR5PhaseDiagnosticsRejectMalformedAndUnknownMarkers(t *testing.T) {
	tests := map[string]string{
		"malformed": `RARPAR_BENCH_PHASE {`,
		"unknown":   `RARPAR_BENCH_PHASE {"phase":"other","nanos":1}`,
		"negative":  `RARPAR_BENCH_PHASE {"phase":"staging","nanos":-1}`,
	}
	for name, marker := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := collectRAR5PhaseDiagnostics([]byte(marker), nil)
			if evidence.UnavailableReason == "" {
				t.Fatalf("invalid marker was accepted: %#v", evidence)
			}
			if evidence.StagingNanos != nil || evidence.HeaderScanNanos != nil || evidence.WorkerDecodeNanos != nil || evidence.SerialApplyNanos != nil {
				t.Fatalf("invalid marker retained partial values: %#v", evidence)
			}
		})
	}
}

func TestRAR5PhaseEnvironmentIsWarmupOnly(t *testing.T) {
	t.Setenv(phaseDiagnosticEnv, "inherited")
	value := func(environment []string) (string, bool) {
		for _, item := range environment {
			name, value, _ := strings.Cut(item, "=")
			if strings.EqualFold(name, phaseDiagnosticEnv) {
				return value, true
			}
		}
		return "", false
	}
	if _, found := value(benchmarkCommandEnvironment(true, false)); found {
		t.Fatal("measured candidate inherited phase diagnostics")
	}
	if _, found := value(benchmarkCommandEnvironment(false, true)); found {
		t.Fatal("reference execution enabled phase diagnostics")
	}
	if actual, found := value(benchmarkCommandEnvironment(true, true)); !found || actual != "1" {
		t.Fatalf("candidate warmup phase environment = %q, present=%v", actual, found)
	}
}

func TestCommandFailureFiltersPhaseMarkers(t *testing.T) {
	stdout := []byte("ordinary stdout\nRARPAR_BENCH_PHASE {\"phase\":\"staging\",\"nanos\":1}\n")
	stderr := []byte("RARPAR_BENCH_PHASE {malformed}\nordinary stderr\n")
	message := commandFailure(os.ErrPermission, stdout, stderr)
	if strings.Contains(message, phaseDiagnosticPrefix) || strings.Contains(message, "malformed") {
		t.Fatalf("phase marker leaked into failure text: %s", message)
	}
	if !strings.Contains(message, "ordinary stderr") {
		t.Fatalf("ordinary error text was removed: %s", message)
	}
	stdoutMessage := commandFailure(os.ErrPermission, stdout, []byte("RARPAR_BENCH_PHASE {malformed}\n"))
	if strings.Contains(stdoutMessage, phaseDiagnosticPrefix) || !strings.Contains(stdoutMessage, "ordinary stdout") {
		t.Fatalf("stdout phase filtering changed ordinary diagnostics: %s", stdoutMessage)
	}
}

func TestRAR5PhaseReportingUsesSuccessfulWarmupsAndIsDeterministic(t *testing.T) {
	stagingFirst := int64(10)
	stagingSecond := int64(30)
	headerFirst := int64(20)
	headerSecond := int64(40)
	workerFirst := int64(50)
	applyFirst := int64(60)
	measuredOnly := int64(9_999)
	raw := fixtureRunRecord()
	raw.Plan.Warmups = 2
	raw.Executions[0].Measurement.RAR5Phases = &RAR5PhaseEvidence{StagingNanos: &measuredOnly}
	raw.Executions = append(raw.Executions,
		Execution{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Warmup: true, Success: true, Backend: "cpu", Measurement: Measurement{RAR5Phases: &RAR5PhaseEvidence{
			StagingNanos: &stagingFirst, HeaderScanNanos: &headerFirst, WorkerDecodeNanos: &workerFirst, SerialApplyNanos: &applyFirst,
		}}},
		Execution{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 2, Warmup: true, Success: true, Backend: "cpu", Measurement: Measurement{RAR5Phases: &RAR5PhaseEvidence{
			StagingNanos: &stagingSecond, HeaderScanNanos: &headerSecond, UnavailableReason: "worker decode was not emitted",
		}}},
		Execution{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 3, Warmup: true, Success: false, Backend: "cpu", Measurement: Measurement{RAR5Phases: &RAR5PhaseEvidence{StagingNanos: &measuredOnly}}},
	)
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.json")
	if err := writeJSON(path, raw); err != nil {
		t.Fatal(err)
	}
	left, err := BuildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftJSON, rightJSON) {
		t.Fatal("phase report JSON is not deterministic")
	}
	if left.Comparisons[0].Candidate.Median != 500_000_000 {
		t.Fatalf("warmup timing entered the comparison: %#v", left.Comparisons[0].Candidate)
	}
	phases := left.Comparisons[0].CandidateRAR5Phases
	if phases == nil || phases.Staging == nil || phases.Staging.Count != 2 || phases.Staging.Median != 20 {
		t.Fatalf("phase summary was not reported: %#v", left.Comparisons[0])
	}
	if phases.WorkerDecode == nil || phases.WorkerDecode.Count != 1 || phases.WorkerDecode.Median != 50 {
		t.Fatalf("partial phase samples were not summarized: %#v", phases)
	}
	if !strings.Contains(phases.UnavailableReason, "worker decode was not emitted") || !strings.Contains(phases.UnavailableReason, "missing successful samples") {
		t.Fatalf("phase summary lost unavailable reason: %#v", phases)
	}
}

func TestLegacyRawAndReportJSONRemainPhaseCompatible(t *testing.T) {
	raw := fixtureRunRecord()
	encodedRaw, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedRaw), "rar5_phases") {
		t.Fatalf("legacy raw fixture unexpectedly contains phase evidence: %s", encodedRaw)
	}
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.json")
	if err := os.WriteFile(rawPath, encodedRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Comparisons) != 1 || report.Comparisons[0].CandidateRAR5Phases != nil {
		t.Fatalf("legacy raw evidence produced a phase summary: %#v", report.Comparisons)
	}
	encodedReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedReport), "candidate_rar5_phases") {
		t.Fatalf("legacy report unexpectedly contains phase summary: %s", encodedReport)
	}
	var decoded Report
	if err := json.Unmarshal(encodedReport, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Comparisons) != 1 || decoded.Comparisons[0].CandidateRAR5Phases != nil {
		t.Fatalf("legacy report did not round-trip compatibly: %#v", decoded.Comparisons)
	}
}

func validToolchainLock() ToolchainLock {
	digest := strings.Repeat("a", 64)
	return ToolchainLock{
		SchemaVersion: 1,
		DockerBase:    "debian@sha256:" + digest,
		RARWriters: []RARWriter{
			{ID: "rarlab-3.93", Image: "rar3", Platform: "linux/amd64", URL: "https://example.test/rar3", SHA256: digest, Binary: "rar_static"},
			{ID: "rarlab-4.20", Image: "rar4", Platform: "linux/amd64", URL: "https://example.test/rar4", SHA256: digest, Binary: "rar_static"},
			{ID: "rarlab-5.00", Image: "rar5", Platform: "linux/amd64", URL: "https://example.test/rar5", SHA256: digest, Binary: "rar"},
		},
		PAR2Generator: PAR2Generator{ID: "par2", Image: "par2", Platform: "linux/amd64", URL: "https://example.test/par2", SHA256: digest},
	}
}

func validCorpusConfig() CorpusConfig {
	return CorpusConfig{SchemaVersion: 1, ID: "test", Seed: "seed", PayloadBytes: 1024, VolumeSize: "1m", PAR2RedundancyPercent: 10, Cases: []CaseConfig{{ID: "rar", Family: "rar", Writer: "rarlab-5.00", Format: 5, Mutation: "none", Workload: "RAR"}}}
}

func fixtureRunRecord() RunRecord {
	plan := Plan{SchemaVersion: PlanSchemaVersion, ID: "plan-1", CorpusDigest: "corpus-digest", Seed: "seed", Warmups: 0, Repeats: 1, Lane: "cpu", Par2Placement: "canonical", Cases: []PlanCase{{ID: "case-1", Order: 1}}}
	return RunRecord{SchemaVersion: 1, CollectorMode: wallClockCollector, Plan: plan, CorpusDigest: "corpus-digest", Machine: Machine{Label: "test-machine", Architecture: "arm64"}, Candidate: BinaryIdentity{Label: "rarpar", SHA256: "candidate"}, Reference: &BinaryIdentity{Label: "reference", SHA256: "reference"}, Executions: []Execution{
		{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Success: true, Backend: "cpu", Measurement: Measurement{WallNanos: 500_000_000}},
		{Subject: "reference", Role: "reference", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Success: true, Backend: "reference", Measurement: Measurement{WallNanos: 1_000_000_000}},
	}}
}

func fixtureReport() Report {
	return Report{SchemaVersion: 1, CollectorMode: wallClockCollector, InputSHA256: "report-digest", Plan: Plan{ID: "plan-1", Lane: "cpu", Par2Placement: "canonical", Cases: []PlanCase{{ID: "case-1", Order: 1}}}, CorpusDigest: "corpus-digest", Machine: Machine{Label: "test-machine", Architecture: "arm64"}, Candidate: BinaryIdentity{SHA256: "candidate"}, Reference: &BinaryIdentity{SHA256: "reference"}, Comparisons: []Comparison{{CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", CandidateLabel: "rarpar", ReferenceLabel: "UnRAR", Candidate: Summary{Median: 500_000_000}, Reference: Summary{Median: 1_000_000_000}, Ratio: 2, Backend: "cpu"}}}
}
