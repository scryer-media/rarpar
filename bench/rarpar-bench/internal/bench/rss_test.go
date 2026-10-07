package bench

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/procmeasure"
)

// touchEnv makes the test binary a tool that touches that many MiB and exits
// 0, whatever its arguments.
const touchEnv = "RARPAR_BENCH_TEST_TOUCH_MIB"

// fakePerfMiB is what the fake perf collector touches before it launches its
// workload: far more than the tool, so a harness that read the collector's
// rusage instead of the tool's would see it.
const fakePerfMiB = 160

func TestMain(m *testing.M) {
	procmeasure.MaybeRunShim()
	if filepath.Base(os.Args[0]) == "perf" {
		os.Exit(fakePerf(os.Args[1:]))
	}
	if value := os.Getenv(touchEnv); value != "" {
		touch(value)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func touch(value string) []byte {
	mebibytes, err := strconv.Atoi(value)
	if err != nil {
		os.Exit(2)
	}
	buffer := make([]byte, mebibytes<<20)
	for index := 0; index < len(buffer); index += 4096 {
		buffer[index] = 1
	}
	return buffer
}

// fakePerf stands in for `perf stat --log-fd 3 ... -- PROGRAM ARGS`: it grows
// to fakePerfMiB, runs the workload as its child with descriptors 3 and 4
// passed through, then writes a well-formed counter report to descriptor 3.
func fakePerf(args []string) int {
	buffer := touch(strconv.Itoa(fakePerfMiB))
	separator := -1
	for index, arg := range args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(args) {
		return 125
	}
	logFile := os.NewFile(3, "perf-log")
	cmd := exec.Command(args[separator+1], args[separator+2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{logFile, os.NewFile(4, "rss-report")}
	_ = cmd.Run()
	_, _ = logFile.WriteString(strings.Join([]string{
		"1000,,cycles,1000,100.00",
		"900,,instructions,1000,100.00",
		"1.5,msec,task-clock,1500000,100.00",
		"3,,context-switches,1000,100.00",
		"0,,cpu-migrations,1000,100.00",
		"2000000,ns,duration_time,2000000,100.00",
	}, "\n") + "\n")
	runtime.KeepAlive(buffer)
	return cmd.ProcessState.ExitCode()
}

func testBinary(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// A plain timed launch records the tool's own peak and the native source.
func TestTimedCommandRecordsPeakRSS(t *testing.T) {
	t.Setenv(touchEnv, "64")
	measurement, _, _, err := timedCommand(context.Background(), testBinary(t), nil, t.TempDir(), false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if measurement.MaxRSSBytes < 64<<20 || measurement.RSSSource != procmeasure.NativeRSSSource {
		t.Fatalf("peak %d (%s), want >= 64 MiB from %s", measurement.MaxRSSBytes, measurement.RSSSource, procmeasure.NativeRSSSource)
	}
	if err := requirePeakRSS(measurement); err != nil {
		t.Fatal(err)
	}
}

// Under the perf collector the direct child is perf. The figure must still be
// the tool's: the fake perf grows to 160 MiB, the tool to 8 MiB, and the
// recorded peak is the tool's, read by the rss-exec shim.
func TestPerfCollectorMeasuresTheToolNotPerf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the perf collector is Linux-only; the fake stands in for it on POSIX hosts")
	}
	bin := t.TempDir()
	if err := os.Symlink(testBinary(t), filepath.Join(bin, "perf")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv(touchEnv, "8")
	measurement, _, stderr, err := timedCommand(context.Background(), testBinary(t), nil, t.TempDir(), false, false, true)
	if err != nil {
		t.Fatalf("%v: %s", err, stderr)
	}
	if measurement.RSSSource != procmeasure.RSSSourceShim {
		t.Fatalf("rss source %q, want %q", measurement.RSSSource, procmeasure.RSSSourceShim)
	}
	if measurement.MaxRSSBytes < 8<<20 || measurement.MaxRSSBytes >= fakePerfMiB<<20 {
		t.Fatalf("peak %d MiB: want the tool's (>= 8 MiB), not the collector's %d MiB", measurement.MaxRSSBytes>>20, fakePerfMiB)
	}
	if measurement.Perf == nil || measurement.Instructions == nil || *measurement.Instructions != 900 {
		t.Fatalf("perf counters lost: %+v", measurement)
	}
}

func par2VerifyFixture(t *testing.T) (CorpusCaseManifest, RunOptions) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "fixture-case", "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "fixture-set.par2"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := CorpusCaseManifest{ID: "fixture-case", Config: CaseConfig{ID: "fixture-case", Family: "par2", Mutation: "none", PAR2Operation: "verify", Workload: "PAR2 verify fixture"}}
	options := RunOptions{CorpusRoot: root, Output: t.TempDir(), ReferencePAR2: testBinary(t), Plan: Plan{Par2Placement: "canonical", Lane: "cpu"}}
	return manifest, options
}

// A reference execution carries the reference tool's peak RSS.
func TestReferenceExecutionCarriesPeakRSS(t *testing.T) {
	t.Setenv(touchEnv, "24")
	manifest, options := par2VerifyFixture(t)
	execution := executeReference(context.Background(), BinaryIdentity{Label: "fixture-reference"}, manifest, options, 1, false)
	if !execution.Success {
		t.Fatalf("reference failed: %s", execution.Failure)
	}
	if execution.Measurement.MaxRSSBytes < 24<<20 || execution.Measurement.RSSSource == "" {
		t.Fatalf("measurement %+v lacks the reference's peak", execution.Measurement)
	}
}

// A tool that exits cleanly without a recorded peak is a failed sample
// classified as a harness failure, never a successful row with zero RSS.
func TestMissingPeakRSSIsAFailedExecution(t *testing.T) {
	saved := runTimed
	t.Cleanup(func() { runTimed = saved })
	runTimed = func(context.Context, string, []string, string, bool, bool, bool) (Measurement, []byte, []byte, error) {
		return Measurement{WallNanos: 1_000_000}, nil, nil, nil
	}
	manifest, options := par2VerifyFixture(t)
	for _, execution := range []Execution{
		executeReference(context.Background(), BinaryIdentity{Label: "fixture-reference"}, manifest, options, 1, false),
		executeSubject(context.Background(), "candidate", "rarpar", testBinary(t), manifest, options, 1, false),
	} {
		if execution.Success || !strings.Contains(execution.Failure, procmeasure.FailureMissingRSS) {
			t.Fatalf("%s: success %t failure %q, want a %s failure", execution.Role, execution.Success, execution.Failure, procmeasure.FailureMissingRSS)
		}
	}
}

// A raw record whose successful execution lacks max_rss_bytes is invalid.
func TestReportRejectsSuccessWithoutPeakRSS(t *testing.T) {
	raw := fixtureRunRecord()
	raw.Executions[1].Measurement.MaxRSSBytes = 0
	path := filepath.Join(t.TempDir(), "raw.json")
	if err := writeJSON(path, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildReport(path); err == nil || !strings.Contains(err.Error(), "max_rss_bytes") {
		t.Fatalf("got %v, want a missing max_rss_bytes error", err)
	}
}

func rssRunRecord() RunRecord {
	raw := fixtureRunRecord()
	raw.Plan.Repeats = 3
	raw.Plan.Cases = []PlanCase{{ID: "case-low", Order: 1}, {ID: "case-high", Order: 2}}
	raw.Executions = nil
	add := func(role, caseID string, run int, wall, cpu, rss int64) {
		subject, backend := "rarpar", "cpu"
		if role == "reference" {
			subject, backend = "reference", "reference"
		}
		raw.Executions = append(raw.Executions, Execution{Subject: subject, Role: role, CaseID: caseID, Family: "rar", Workload: "RAR fixture " + caseID, Run: run, Success: true, Backend: backend,
			Measurement: Measurement{WallNanos: wall, UserNanos: cpu, SystemNanos: cpu / 2, MaxRSSBytes: rss << 20, RSSSource: procmeasure.RSSSourceRusage}})
	}
	for run, rss := range []int64{40, 50, 60} {
		add("candidate", "case-low", run+1, 1e9, 2e9, rss)
		add("reference", "case-low", run+1, 2e9, 2e9, 100)
	}
	for run, rss := range []int64{90, 80, 70} {
		add("candidate", "case-high", run+1, 1e9, 1e9, rss)
		add("reference", "case-high", run+1, 1e9, 2e9, 40)
	}
	return raw
}

// The report carries CPU and peak RSS medians [min, max] with
// reference/rarpar ratios, and an rss_summary sorted worst (lowest) ratio first.
func TestReportSummarizesPeakRSS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.json")
	if err := writeJSON(path, rssRunRecord()); err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Comparisons) != 2 {
		t.Fatalf("comparisons %#v", report.Comparisons)
	}
	low := report.Comparisons[0]
	if low.CaseID != "case-low" || low.CandidateRSSBytes != (ValueSummary{Median: 50 << 20, Min: 40 << 20, Max: 60 << 20}) || low.ReferenceRSSBytes.Median != 100<<20 {
		t.Fatalf("case-low RSS %#v / %#v", low.CandidateRSSBytes, low.ReferenceRSSBytes)
	}
	if low.RSSRatio == nil || *low.RSSRatio != 2 || low.CPURatio == nil || *low.CPURatio != 1 {
		t.Fatalf("case-low ratios rss %v cpu %v", low.RSSRatio, low.CPURatio)
	}
	if low.CandidateRSSSource != procmeasure.RSSSourceRusage || low.ReferenceRSSSource != procmeasure.RSSSourceRusage {
		t.Fatalf("sources %q %q", low.CandidateRSSSource, low.ReferenceRSSSource)
	}
	if len(report.RSSSummary) != 2 || report.RSSSummary[0].Scenario != "case-high" || *report.RSSSummary[0].Ratio != 0.5 || report.RSSSummary[1].Scenario != "case-low" {
		t.Fatalf("rss summary not worst-first: %#v", report.RSSSummary)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"rss_summary":[{"scenario":"case-high"`, `"rss_ratio":2`, `"candidate_rss_bytes":{"median":52428800`, `"rarpar_rss_source":"rusage"`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("report JSON lacks %s: %s", field, encoded)
		}
	}
}

func TestReportMarkdownShowsRSSBesideWallAndCPU(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.json")
	if err := writeJSON(path, rssRunRecord()); err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report-rar.json")
	if err := WriteReport(out, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(out), "report-rar.md"))
	if err != nil {
		t.Fatal(err)
	}
	markdown := string(data)
	for _, want := range []string{
		"| case | workload | reference | side | wall s | CPU s | RSS MiB | wall ratio | CPU ratio | RSS ratio |",
		"| case-low | RAR fixture case-low | UnRAR | rarpar | 1.000 [1.000–1.000] | 3.000 [3.000–3.000] | 50.0 [40.0–60.0] | 2.000 | 1.000 | 2.000 |",
		"| | | | reference | 2.000 [2.000–2.000] | 3.000 [3.000–3.000] | 100.0 [100.0–100.0] | 1.000 | 1.000 | 1.000 |",
		"## Peak RSS per scenario",
		"| case-high | 80.0 [70.0–90.0] | 40.0 [40.0–40.0] | 0.500 | rusage | - |",
		"- `rusage`: " + procmeasure.DescribeRSSSource(procmeasure.RSSSourceRusage),
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown lacks %q:\n%s", want, markdown)
		}
	}
	if strings.Index(markdown, "| case-high | 80.0") > strings.Index(markdown, "| case-low | 50.0") {
		t.Fatalf("worst ratio is not first:\n%s", markdown)
	}
}

func TestSVGTimingLineShowsPeakRSS(t *testing.T) {
	comparison := fixtureReport().Comparisons[0]
	if line := timingLine(comparison); line != "1.00 s -> 500.0 ms" {
		t.Fatalf("line without RSS %q", line)
	}
	comparison.ReferenceRSSBytes.Median = 32 << 20
	comparison.CandidateRSSBytes.Median = 48 << 20
	if line := timingLine(comparison); line != "1.00 s -> 500.0 ms  |  peak RSS 32.0 -> 48.0 MiB" {
		t.Fatalf("line with RSS %q", line)
	}
}
