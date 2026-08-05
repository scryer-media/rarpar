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

func TestPlanOrderIsStable(t *testing.T) {
	ids := []string{"third", "first", "second"}
	first := deterministicOrder(ids, "seed")
	second := deterministicOrder(ids, "seed")
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatal("plan order is not stable")
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
	const goldenRARSVG = "c0c5a03eb13dfb9f95ab9699e4a4f05b22139d28eb1d0da5ba04b5fee85fe1f5"
	if got := bytesSHA256(first); got != goldenRARSVG {
		t.Fatalf("RAR SVG changed: got %s, want %s", got, goldenRARSVG)
	}
	for _, required := range []string{"<svg", "role=\"img\"", "1x parity", "&lt;unsafe&gt;", "report_sha256=report-digest"} {
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
	const goldenPAR2SVG = "f52afcce95404fb00bac986ea8c543c937a46f3d124f6148fd33fab9ceb899d2"
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
	plan := Plan{SchemaVersion: 1, ID: "plan-1", CorpusDigest: "corpus-digest", Seed: "seed", Warmups: 0, Repeats: 1, Lane: "cpu", Cases: []PlanCase{{ID: "case-1", Order: 1}}}
	return RunRecord{SchemaVersion: 1, Plan: plan, CorpusDigest: "corpus-digest", Machine: Machine{Label: "test-machine", Architecture: "arm64"}, Candidate: BinaryIdentity{Label: "rarpar", SHA256: "candidate"}, Reference: &BinaryIdentity{Label: "reference", SHA256: "reference"}, Executions: []Execution{
		{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Success: true, Backend: "cpu", Measurement: Measurement{WallNanos: 500_000_000}},
		{Subject: "reference", Role: "reference", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Success: true, Backend: "reference", Measurement: Measurement{WallNanos: 1_000_000_000}},
	}}
}

func fixtureReport() Report {
	return Report{SchemaVersion: 1, InputSHA256: "report-digest", Plan: Plan{ID: "plan-1", Lane: "cpu", Cases: []PlanCase{{ID: "case-1", Order: 1}}}, CorpusDigest: "corpus-digest", Machine: Machine{Label: "test-machine", Architecture: "arm64"}, Candidate: BinaryIdentity{SHA256: "candidate"}, Reference: &BinaryIdentity{SHA256: "reference"}, Comparisons: []Comparison{{CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", CandidateLabel: "rarpar", ReferenceLabel: "UnRAR", Candidate: Summary{Median: 500_000_000}, Reference: Summary{Median: 1_000_000_000}, Ratio: 2, Backend: "cpu"}}}
}
