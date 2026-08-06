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
	if got, want := strings.Join(repair[:4], "\x00"), strings.Join([]string{"auto", "--par-placement", "smart", "--output"}, "\x00"); got != want {
		t.Fatalf("repair arguments = %q, want prefix %q", repair, want)
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
	const goldenRARSVG = "eed298ba1db6925d6cc9e3d74da54f53ffc8ac63b1188abf7ee2b04d9b6ba89e"
	if got := bytesSHA256(first); got != goldenRARSVG {
		t.Fatalf("RAR SVG changed: got %s, want %s", got, goldenRARSVG)
	}
	for _, required := range []string{"<svg", "role=\"img\"", "1x parity", "&lt;unsafe&gt;", "report_sha256=report-digest", "par2_placement=canonical"} {
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
	const goldenPAR2SVG = "916c2208309b03eb3f89d2edb37d9f114cd4c60e8f4c9eecd457b5a6e95e9fbe"
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
	for _, required := range []string{"par2cmdline-turbo faster", "<rect class=\"cpu\" x=\"760\"", "<rect class=\"slower\" x=\"920\""} {
		if !strings.Contains(string(par2), required) {
			t.Fatalf("PAR2 legend does not contain %q", required)
		}
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
	return RunRecord{SchemaVersion: 1, Plan: plan, CorpusDigest: "corpus-digest", Machine: Machine{Label: "test-machine", Architecture: "arm64"}, Candidate: BinaryIdentity{Label: "rarpar", SHA256: "candidate"}, Reference: &BinaryIdentity{Label: "reference", SHA256: "reference"}, Executions: []Execution{
		{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Success: true, Backend: "cpu", Measurement: Measurement{WallNanos: 500_000_000}},
		{Subject: "reference", Role: "reference", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Success: true, Backend: "reference", Measurement: Measurement{WallNanos: 1_000_000_000}},
	}}
}

func fixtureReport() Report {
	return Report{SchemaVersion: 1, InputSHA256: "report-digest", Plan: Plan{ID: "plan-1", Lane: "cpu", Par2Placement: "canonical", Cases: []PlanCase{{ID: "case-1", Order: 1}}}, CorpusDigest: "corpus-digest", Machine: Machine{Label: "test-machine", Architecture: "arm64"}, Candidate: BinaryIdentity{SHA256: "candidate"}, Reference: &BinaryIdentity{SHA256: "reference"}, Comparisons: []Comparison{{CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", CandidateLabel: "rarpar", ReferenceLabel: "UnRAR", Candidate: Summary{Median: 500_000_000}, Reference: Summary{Median: 1_000_000_000}, Ratio: 2, Backend: "cpu"}}}
}
