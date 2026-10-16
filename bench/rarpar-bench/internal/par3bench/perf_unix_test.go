//go:build !windows

package par3bench

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// perfStub is a stand-in for Linux perf: it logs every invocation, runs the
// command after `--` for stat and record, writes a CSV for stat and a data
// file for record, and prints three call-chain samples for script.
const perfStub = `#!/bin/sh
printf '%s\n' "$*" >> "$PERF_STUB_LOG"
sub="$1"; shift
case "$sub" in
--version) echo 'perf version 6.8.stub'; exit 0 ;;
stat|record)
  out=''
  while [ "$1" != "--" ]; do
    if [ "$1" = "-o" ]; then out="$2"; shift; fi
    shift
  done
  shift
  "$@"
  rc=$?
  if [ "$sub" = stat ]; then
    printf '# started on stub\n\n1000,,cycles,100.00\n2000,,instructions,100.00\n300,,branches,100.00\n4,,branch-misses,100.00\n5000,,cache-references,100.00\n600,,cache-misses,100.00\n12.5,msec,task-clock,100.00\n7,,context-switches,100.00\n8,,cpu-migrations,100.00\n123456789,,duration_time,100.00\n' > "$out"
  else
    echo stub > "$out"
  fi
  exit $rc ;;
script)
  [ "$1" = -i ] && [ -f "$2" ] || { echo "perf script: no data at $2" >&2; exit 1; }
  printf 'rarpar 123 [001] 1.000: 1 cycles:P:\n\t    aaaa leaf+0x10 (/bin/rarpar)\n\t    bbbb mid+0x20 (/bin/rarpar)\n\t    cccc main (/bin/rarpar)\n\n'
  printf 'rarpar 123 [001] 1.001: 1 cycles:P:\n\t    aaab leaf+0x14 (/bin/rarpar)\n\t    bbbb mid+0x20 (/bin/rarpar)\n\t    cccc main (/bin/rarpar)\n\n'
  printf 'rarpar 124 [002] 1.002: 1 cycles:P:\n\t    dddd <alloc::vec::Vec<T> as core::ops::drop::Drop>::drop+0x5 (/bin/rarpar)\n\t    cccc main (/bin/rarpar)\n\n'
  exit 0 ;;
esac
exit 3
`

// perfFixture is a one-file plain set staged for repair, a stub reference and
// candidate that log where they ran, and Linux perf stubbed on PATH.
type perfFixture struct {
	r                     *runner
	config                Config
	dataset               Dataset
	state                 *targetState
	out, perfLog, toolLog string
	reference, candidate  string
}

func newPerfFixture(t *testing.T, perf PerfOptions) *perfFixture {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, script string) {
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bin, "perf"), perfStub)
	tool := "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$PWD\")\" \"$*\" >> \"$TOOL_LOG\"\nexit 0\n"
	f := &perfFixture{out: filepath.Join(dir, "perf"), perfLog: filepath.Join(dir, "perf.log"), toolLog: filepath.Join(dir, "tool.log"),
		reference: filepath.Join(bin, "par3"), candidate: filepath.Join(bin, "rarpar")}
	write(f.reference, tool)
	write(f.candidate, tool)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PERF_STUB_LOG", f.perfLog)
	t.Setenv("TOOL_LOG", f.toolLog)

	f.dataset = Dataset{ID: "t", Files: []FileSpec{{Name: "f0.bin", Size: 64 * KiB}}}
	f.config = Config{ID: "t", Dataset: "t", BlockSize: 16 * KiB, Recovery: 2, Codec: "cauchy", Damage: spread("lost-1", []int{0}, 1)}
	f.state = &targetState{dataDir: filepath.Join(dir, "data"), canonical: filepath.Join(dir, "k"), stageRoot: filepath.Join(dir, "s")}
	if _, err := EnsureDataset(f.state.dataDir, f.dataset, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{f.state.canonical, f.state.stageRoot} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.state.canonical, carrierName), []byte("carrier"), 0o644); err != nil {
		t.Fatal(err)
	}
	perf.Out = f.out
	if perf.Frequency == 0 {
		perf.Frequency = DefaultPerfFrequency
	}
	variants := Variants([]int{1}, nil)
	results := &Results{Variants: variants, BackupArgs: map[string][]string{"rarpar-w1": nil, "rarpar-w1-backup": {"--backup"}},
		Perf: &PerfPass{StatRepeats: perf.StatRepeats, Ops: perf.Ops, RecordSets: perf.RecordSets}}
	for _, variant := range variants {
		results.Runs = append(results.Runs, RunRecord{Config: "t", Op: OpRepair, Variant: variant.Name, Tool: variant.Tool, Status: StatusOK})
	}
	f.r = &runner{
		options: Options{Reference: f.reference, Candidate: f.candidate, Targets: []Target{{Work: dir}}, Perf: perf,
			Timeout: time.Minute, ReferenceTimeout: time.Minute, Log: io.Discard},
		results:  results,
		finished: map[string]bool{},
	}
	return f
}

// incomplete is the perf directory's INCOMPLETE.txt after finishPerf, or
// "" when finishPerf wrote none.
func (f *perfFixture) incomplete(t *testing.T) string {
	t.Helper()
	if err := f.r.finishPerf(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.out, PerfIncompleteFile))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// The perf pass runs perf stat on every reference and rarpar repair row, as
// many times as asked, each on a fresh stage and with the row's own
// arguments (the in-place row plain, the -backup row --backup), and perf
// record on the rarpar rows of a record set only; it keeps perf's CSV, the
// perf script text and the folded stacks, and reads the counters.
func TestPerfPassRunsEachRowsOwnCommandUnderPerf(t *testing.T) {
	f := newPerfFixture(t, PerfOptions{StatRepeats: 2, Ops: []string{OpRepair}, RecordSets: []string{"t"}})
	f.r.perfPass(t.Context(), OpRepair, f.config, f.dataset, f.state, f.r.results.Variants)

	events := "cycles,instructions,branches,branch-misses,cache-references,cache-misses,task-clock,context-switches,cpu-migrations,duration_time"
	stat := func(row string, n int, command string) string {
		return "stat --no-big-num -x, -e " + events + " -o " + filepath.Join(f.out, "t", "repair-"+row+"-stat"+string(rune('0'+n))+".csv") + " -- " + command
	}
	data := func(dir string) string { return filepath.Join(f.state.stageRoot, "perf-repair-"+dir+".perf.data") }
	rarpar := f.candidate + " --quiet --par3-workers 1 par3 repair " + carrierName
	want := []string{
		stat("reference", 1, f.reference+" r -q "+carrierName),
		stat("reference", 2, f.reference+" r -q "+carrierName),
		stat("rarpar-w1", 1, rarpar),
		stat("rarpar-w1", 2, rarpar),
		"record -F 499 -g --call-graph fp -o " + data("w1") + " -- " + rarpar,
		"script -i " + data("w1"),
		stat("rarpar-w1-backup", 1, rarpar+" --backup"),
		stat("rarpar-w1-backup", 2, rarpar+" --backup"),
		"record -F 499 -g --call-graph fp -o " + data("w1-backup") + " -- " + rarpar + " --backup",
		"script -i " + data("w1-backup"),
	}
	if got := readLines(t, f.perfLog); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("perf invocations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Every measured command really ran, in its own fresh stage.
	tools := readLines(t, f.toolLog)
	if len(tools) != 8 || !strings.HasPrefix(tools[0], "perf-repair-ref r -q ") || !strings.HasPrefix(tools[7], "perf-repair-w1-backup --quiet") {
		t.Fatalf("tool runs: %q", tools)
	}

	runs := f.r.results.PerfRuns
	if len(runs) != 8 || PerfPassRuns(Profile{Configs: []Config{f.config}}, f.r.results.Variants, f.r.options.Perf) != 8 {
		t.Fatalf("%d perf runs, want 8 as PerfPassRuns counts: %+v", len(runs), runs)
	}
	for _, run := range runs {
		if run.Error != "" || run.Skipped != "" {
			t.Fatalf("perf run %s/%s#%d: %s%s", run.Variant, run.Kind, run.Repeat, run.Error, run.Skipped)
		}
		switch run.Kind {
		case PerfKindStat:
			if run.Counters == nil || *run.Counters.Instructions != 2000 || *run.Counters.Cycles != 1000 || len(run.Files) != 1 {
				t.Fatalf("stat run %s#%d: %+v", run.Variant, run.Repeat, run)
			}
		case PerfKindRecord:
			if run.Tool != ToolCandidate || run.Samples != 3 || run.Stacks != 2 ||
				strings.Join(run.Files, ",") != "t/repair-"+run.Variant+".script.gz,t/repair-"+run.Variant+".folded" {
				t.Fatalf("record run %s: %+v", run.Variant, run)
			}
		}
	}
	folded, err := os.ReadFile(filepath.Join(f.out, "t", "repair-rarpar-w1.folded"))
	if err != nil {
		t.Fatal(err)
	}
	if string(folded) != "rarpar;main;mid;leaf 2\nrarpar;main;<alloc::vec::Vec<T> as core::ops::drop::Drop>::drop 1\n" {
		t.Fatalf("folded stacks:\n%s", folded)
	}
	file, err := os.Open(filepath.Join(f.out, "t", "repair-rarpar-w1.script.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	script, err := io.ReadAll(reader)
	if err != nil || !strings.HasPrefix(string(script), "rarpar 123 [001] 1.000:") {
		t.Fatalf("perf script text: %v %q", err, script)
	}
	// perf.data and the stages are scratch.
	if entries, _ := os.ReadDir(f.state.stageRoot); len(entries) != 0 {
		t.Fatalf("the perf pass left scratch behind: %v", entries)
	}
	if text := f.incomplete(t); text != "" || len(f.r.results.Notes) != 0 {
		t.Fatalf("a clean pass is complete: %q %v", text, f.r.results.Notes)
	}

	var report strings.Builder
	writePerfRuns(&report, f.r.results, "t", OpRepair)
	for _, want := range []string{
		"| reference | 2 of 2 | 2.00k | 1.00k | 2.00 | 0.013 | 7 | 8 | 600 | - |",
		"| rarpar-w1 | 2 of 2 | 2.00k | 1.00k | 2.00 | 0.013 | 7 | 8 | 600 | 3 samples, 2 stacks |",
		"| rarpar-w1-backup | 2 of 2 |",
	} {
		if !strings.Contains(report.String(), want) {
			t.Fatalf("perf report lacks %q:\n%s", want, report.String())
		}
	}
}

// A row whose timed runs did not finish cleanly is not run under perf (it
// would only repeat the failure, at its full timeout), and the results say
// so; a set that is not a record set gets no perf record run.
func TestPerfPassSkipsRowsWithNoCleanRun(t *testing.T) {
	f := newPerfFixture(t, PerfOptions{StatRepeats: 1, Ops: []string{OpRepair}})
	f.r.finished[rowKey("t", OpRepair, "reference")] = true
	f.r.results.Runs[2].Status = StatusFailed // rarpar-w1-backup
	f.r.perfPass(t.Context(), OpRepair, f.config, f.dataset, f.state, f.r.results.Variants)

	lines := readLines(t, f.perfLog)
	if len(lines) != 1 || !strings.Contains(lines[0], "-o "+filepath.Join(f.out, "t", "repair-rarpar-w1-stat1.csv")) {
		t.Fatalf("perf invocations: %q", lines)
	}
	skipped := map[string]bool{}
	for _, run := range f.r.results.PerfRuns {
		if run.Skipped != "" {
			skipped[run.Variant] = true
		}
		if run.Kind == PerfKindRecord {
			t.Fatalf("no record set was named, but %s was recorded", run.Variant)
		}
	}
	if len(f.r.results.PerfRuns) != 3 || !skipped["reference"] || !skipped["rarpar-w1-backup"] || skipped["rarpar-w1"] {
		t.Fatalf("perf runs: %+v", f.r.results.PerfRuns)
	}
	var report strings.Builder
	writePerfRuns(&report, f.r.results, "t", OpRepair)
	if !strings.Contains(report.String(), "- reference: skipped: the row has no clean timed run") {
		t.Fatalf("the report must say which rows were skipped:\n%s", report.String())
	}
	// Rows skipped for failed timed runs are not perf problems: the timed
	// results say so already.
	if text := f.incomplete(t); text != "" {
		t.Fatalf("INCOMPLETE.txt: %q", text)
	}
	// Other ops are not covered.
	f.r.perfPass(t.Context(), OpVerify, f.config, f.dataset, f.state, f.r.results.Variants)
	if len(f.r.results.PerfRuns) != 3 {
		t.Fatal("verify is not a --perf-ops op here and must not run under perf")
	}
}

// A perf that cannot count (perf_event_paranoid, a missing PMU) fails its
// runs visibly, with perf's own last line, instead of leaving an empty
// directory behind.
func TestPerfPassRecordsAPerfThatCannotCount(t *testing.T) {
	f := newPerfFixture(t, PerfOptions{StatRepeats: 1, Ops: []string{OpRepair}})
	broken := "#!/bin/sh\necho 'Error: Access to performance monitoring and observability operations is limited.' >&2\nexit 255\n"
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.reference), "perf"), []byte(broken), 0o755); err != nil {
		t.Fatal(err)
	}
	f.r.perfPass(t.Context(), OpRepair, f.config, f.dataset, f.state, f.r.results.Variants)
	if len(f.r.results.PerfRuns) != 3 {
		t.Fatalf("perf runs: %+v", f.r.results.PerfRuns)
	}
	for _, run := range f.r.results.PerfRuns {
		if !strings.Contains(run.Error, "perf stat exited 255: Error: Access to performance monitoring") {
			t.Fatalf("perf run %s error = %q", run.Variant, run.Error)
		}
	}
	text := f.incomplete(t)
	if lines := strings.Split(strings.TrimSpace(text), "\n"); len(lines) != 3 ||
		!strings.HasPrefix(lines[0], "t repair reference perf stat#1: perf stat exited 255: Error: Access") {
		t.Fatalf("INCOMPLETE.txt must list every failed perf run:\n%s", text)
	}
	if !strings.Contains(strings.Join(f.r.results.Notes, "\n"), "perf pass: 3 of 3 perf runs failed") {
		t.Fatalf("notes: %v", f.r.results.Notes)
	}
}

// A pass that ran no perf run at all (every row's timed runs failed) is
// incomplete too.
func TestPerfPassThatRanNothingIsIncomplete(t *testing.T) {
	f := newPerfFixture(t, PerfOptions{StatRepeats: 2, Ops: []string{OpRepair}})
	for i := range f.r.results.Runs {
		f.r.results.Runs[i].Status = StatusFailed
	}
	f.r.perfPass(t.Context(), OpRepair, f.config, f.dataset, f.state, f.r.results.Variants)
	if _, err := os.Stat(f.perfLog); !os.IsNotExist(err) {
		t.Fatal("no row finished a clean timed run, so nothing may run under perf")
	}
	if text := f.incomplete(t); !strings.Contains(text, "the perf pass ran nothing: no plain set had a row of repair with a clean timed run") {
		t.Fatalf("INCOMPLETE.txt: %q", text)
	}
}

// startPerf records the pass; a host without Linux perf skips it with a
// note instead of failing the suite.
func TestStartPerfNeedsLinuxPerf(t *testing.T) {
	saved := perfGOOS
	t.Cleanup(func() { perfGOOS = saved })
	f := newPerfFixture(t, PerfOptions{StatRepeats: 3, Ops: []string{OpRepair}})

	perfGOOS = "darwin"
	if err := f.r.startPerf(t.Context()); err != nil {
		t.Fatal(err)
	}
	if pass := f.r.results.Perf; pass == nil || !strings.Contains(pass.Skipped, "Linux-only") || f.r.options.Perf.Enabled() {
		t.Fatalf("a non-Linux host must skip the pass: %+v", pass)
	}
	if !strings.Contains(strings.Join(f.r.results.Notes, "\n"), "perf pass skipped: perf is Linux-only") {
		t.Fatalf("notes: %v", f.r.results.Notes)
	}
	if text := f.incomplete(t); text != "perf pass skipped: perf is Linux-only and this host runs darwin\n" {
		t.Fatalf("a skipped pass must leave INCOMPLETE.txt: %q", text)
	}

	perfGOOS = "linux"
	f = newPerfFixture(t, PerfOptions{StatRepeats: 3, Ops: []string{OpRepair}})
	if err := f.r.startPerf(t.Context()); err != nil {
		t.Fatal(err)
	}
	pass := f.r.results.Perf
	if pass == nil || pass.Skipped != "" || pass.Version != "perf version 6.8.stub" || !f.r.options.Perf.Enabled() {
		t.Fatalf("pass: %+v", pass)
	}
	if info, err := os.Stat(f.out); err != nil || !info.IsDir() {
		t.Fatalf("the perf directory must exist: %v", err)
	}
	if line := perfSummary(pass); !strings.Contains(line, "perf stat ×3 on every reference and rarpar row of repair") || !strings.Contains(line, "perf version 6.8.stub") {
		t.Fatalf("summary: %s", line)
	}

	t.Setenv("PATH", t.TempDir())
	f.r.results.Perf, f.r.results.Notes = nil, nil
	f.r.options.Perf = PerfOptions{StatRepeats: 3, Ops: []string{OpRepair}, Out: f.out}
	if err := f.r.startPerf(t.Context()); err != nil {
		t.Fatal(err)
	}
	if pass := f.r.results.Perf; pass == nil || pass.Skipped != "perf is not installed" {
		t.Fatalf("a host without perf must skip the pass: %+v", pass)
	}
}

func TestValidatePerfOptions(t *testing.T) {
	fleet, err := LookupProfile("fleet")
	if err != nil {
		t.Fatal(err)
	}
	base := func(perf PerfOptions) *Options {
		return &Options{Ops: []string{OpCreate, OpVerify, OpRepair}, Profile: fleet, Out: "/x/out", Perf: perf}
	}
	options := base(PerfOptions{StatRepeats: 3})
	if err := validatePerf(options); err != nil {
		t.Fatal(err)
	}
	if strings.Join(options.Perf.Ops, ",") != "repair" || options.Perf.Frequency != DefaultPerfFrequency || options.Perf.Out != "/x/out/perf" {
		t.Fatalf("defaults: %+v", options.Perf)
	}
	if err := validatePerf(base(PerfOptions{Ops: []string{OpVerifyDamaged}})); err != nil {
		t.Fatalf("perf ops without any perf run ask for nothing: %v", err)
	}
	for _, tc := range []struct {
		perf PerfOptions
		want string
	}{
		{PerfOptions{StatRepeats: -1}, "--perf-stat cannot be negative"},
		{PerfOptions{StatRepeats: 1, Ops: []string{"explode"}}, "--perf-ops: unknown op"},
		{PerfOptions{StatRepeats: 1, Ops: []string{OpVerifyDamaged}}, "--perf-ops: verify-damaged is not one of the run's ops"},
		{PerfOptions{RecordSets: []string{"z-gf99"}}, `--perf-record: "z-gf99" is not a set of the selected fleet profile`},
		{PerfOptions{RecordSets: []string{"zip-inside"}}, `--perf-record: "zip-inside" is a PAR-inside set`},
		{PerfOptions{RecordSets: []string{"a-4m-gf16", "a-4m-gf16"}}, `--perf-record: set "a-4m-gf16" is listed more than once`},
		{PerfOptions{StatRepeats: 1, Frequency: -5}, "--perf-freq must be positive"},
	} {
		if err := validatePerf(base(tc.perf)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: got %v, want %q", tc.perf, err, tc.want)
		}
	}
}

// perf script text arrives in arbitrary chunks; folding is per sample, root
// first, with each frame's +0x offset and (dso) dropped.
func TestStackFolderFoldsChunkedPerfScript(t *testing.T) {
	text := "rarpar 1 [000] 1.0: 1 cycles:\n\t ffff a::b+0x1f (/bin/x)\n\t eeee main (/bin/x)\n\n" +
		"worker 2 [001] 1.1: 1 cycles:\n\t ffff a::b+0x2 (/bin/x)\n\t eeee main (/bin/x)\n\n" +
		"rarpar 1 [000] 1.2: 1 cycles:\n\t 1234 [unknown] ([unknown])\n\n" +
		"rarpar 1 [000] 1.3: 1 cycles:\n\t ffff a::b+0x3 (/bin/x)\n\t eeee main (/bin/x)"
	folder := newStackFolder()
	for start := 0; start < len(text); start += 7 {
		end := min(start+7, len(text))
		if _, err := folder.Write([]byte(text[start:end])); err != nil {
			t.Fatal(err)
		}
	}
	folder.finish()
	want := "rarpar;main;a::b 2\nrarpar;[unknown] 1\nworker;main;a::b 1\n"
	if got := string(folder.folded()); got != want || folder.samples != 4 {
		t.Fatalf("folded (%d samples):\n%s\nwant:\n%s", folder.samples, got, want)
	}
}
