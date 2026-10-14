package par3bench

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// The perf pass runs the same commands the timed rows run, untimed, under
// Linux perf, after each operation's timed runs. Nothing it measures feeds a
// timed row: perf stat counts what a run did, and perf record samples where
// its time went, which the sampling itself perturbs.

const (
	// DefaultPerfFrequency is perf record's -F unless told otherwise. It is
	// moderate on purpose: a high rate perturbs the work being profiled. The
	// corpus suites' fleet pass samples at the same rate.
	DefaultPerfFrequency = 499

	// PerfKindStat and PerfKindRecord name a perf run's collector.
	PerfKindStat   = "stat"
	PerfKindRecord = "record"

	// PerfIncompleteFile is written into the perf directory when the pass
	// was asked for and fell short: skipped on this host, a perf run that
	// failed, or no perf run at all. Each line is one problem. The fleet run
	// script warns on it, so a pass that collected nothing is never silent.
	PerfIncompleteFile = "INCOMPLETE.txt"
)

// DefaultPerfOps are the operations the perf pass covers unless told
// otherwise: repair, where the in-place and -backup rows differ in what they
// write.
var DefaultPerfOps = []string{OpRepair}

// PerfOptions configures the untimed Linux perf pass. It covers the plain
// sets only (a PAR-inside set's rows run the compatible front end), on the
// first target, and every reference and rarpar row of each op in Ops; engine
// rows drive the library rather than a shipped binary and are left out. A
// row whose timed runs never finished cleanly is skipped, with a record that
// says so: its perf runs would only repeat the failure, at its full timeout.
type PerfOptions struct {
	// StatRepeats is how many `perf stat` runs each row gets per op, each on
	// a freshly staged directory, capped by a set's MaxRepeats as its timed
	// runs are. Zero runs none.
	StatRepeats int
	// Ops are the operations the pass covers; empty means DefaultPerfOps.
	// Every one must be an operation the run measures.
	Ops []string
	// RecordSets are plain sets whose rarpar rows also get one `perf record`
	// run per op, exported as perf script text (gzip) and folded stacks.
	RecordSets []string
	// Frequency is perf record's -F; zero means DefaultPerfFrequency.
	Frequency int
	// Out is where perf's files go; empty means OUT/perf.
	Out string
}

// Enabled reports whether any perf run was asked for.
func (p PerfOptions) Enabled() bool { return p.StatRepeats > 0 || len(p.RecordSets) > 0 }

// PerfPass records what the perf pass was asked to do and whether this host
// could do it.
type PerfPass struct {
	StatRepeats int      `json:"stat_repeats"`
	Ops         []string `json:"ops"`
	RecordSets  []string `json:"record_sets,omitempty"`
	Frequency   int      `json:"frequency,omitempty"`
	// Events is the `perf stat -e` list, the corpus suites' --perf events.
	Events string `json:"events"`
	// Version is `perf --version` and Paranoid the host's
	// kernel.perf_event_paranoid, both recorded when the pass runs.
	Version  string `json:"version,omitempty"`
	Paranoid string `json:"perf_event_paranoid,omitempty"`
	// Skipped says why no perf run happened on this host.
	Skipped string `json:"skipped,omitempty"`
}

// PerfRun is one untimed run under perf, or a row the pass skipped.
type PerfRun struct {
	Config  string `json:"config"`
	Op      string `json:"op"`
	Variant string `json:"variant"`
	Tool    string `json:"tool"`
	// Kind is PerfKindStat or PerfKindRecord.
	Kind   string `json:"kind"`
	Repeat int    `json:"repeat"`
	// Command is the measured command, without perf.
	Command string `json:"command,omitempty"`
	// Files are the evidence files, relative to the perf directory: the
	// perf stat CSV, or the perf script text (gzip) and folded stacks.
	Files       []string `json:"files,omitempty"`
	WallSeconds float64  `json:"wall_seconds,omitempty"`
	ExitCode    int      `json:"exit_code"`
	// Counters are perf stat's counts, read as the corpus suites' --perf
	// collector reads them (stat runs).
	Counters *bench.PerfCounters `json:"counters,omitempty"`
	// Samples is the number of call-chain samples perf script printed and
	// Stacks the distinct folded stacks among them (record runs).
	Samples int64  `json:"samples,omitempty"`
	Stacks  int    `json:"stacks,omitempty"`
	Note    string `json:"note,omitempty"`
	// Skipped says why the row was not run under perf; Error why a perf run
	// produced no usable evidence.
	Skipped string `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
}

// perfGOOS is the platform PerfSupported checks; tests replace it.
var perfGOOS = runtime.GOOS

// PerfSupported reports whether the perf pass can run here: Linux, with perf
// on PATH.
func PerfSupported() (bool, string) {
	if perfGOOS != "linux" {
		return false, "perf is Linux-only and this host runs " + perfGOOS
	}
	if _, err := exec.LookPath("perf"); err != nil {
		return false, "perf is not installed"
	}
	return true, ""
}

// validatePerf checks the perf options against the run and fills their
// defaults. options.Ops, Profile and Out are already settled.
func validatePerf(options *Options) error {
	perf := &options.Perf
	if perf.StatRepeats < 0 {
		return errors.New("--perf-stat cannot be negative")
	}
	if perf.Frequency < 0 {
		return errors.New("--perf-freq must be positive")
	}
	if !perf.Enabled() {
		return nil
	}
	if len(perf.Ops) == 0 {
		perf.Ops = DefaultPerfOps
	}
	if err := CheckOps(perf.Ops); err != nil {
		return fmt.Errorf("--perf-ops: %w", err)
	}
	for _, op := range perf.Ops {
		if !contains(options.Ops, op) {
			return fmt.Errorf("--perf-ops: %s is not one of the run's ops (%s)", op, strings.Join(options.Ops, ","))
		}
	}
	if perf.Frequency == 0 {
		perf.Frequency = DefaultPerfFrequency
	}
	seen := map[string]bool{}
	for _, id := range perf.RecordSets {
		if seen[id] {
			return fmt.Errorf("--perf-record: set %q is listed more than once", id)
		}
		seen[id] = true
		config, ok := profileConfig(options.Profile, id)
		if !ok {
			return fmt.Errorf("--perf-record: %q is not a set of the selected %s profile", id, options.Profile.Name)
		}
		if config.Carrier != "" {
			return fmt.Errorf("--perf-record: %q is a PAR-inside set; the perf pass covers plain sets only", id)
		}
	}
	if perf.Out == "" {
		perf.Out = filepath.Join(options.Out, "perf")
	}
	absolute, err := filepath.Abs(perf.Out)
	if err != nil {
		return err
	}
	perf.Out = absolute
	return nil
}

func profileConfig(profile Profile, id string) (Config, bool) {
	for _, config := range profile.Configs {
		if config.ID == id {
			return config, true
		}
	}
	return Config{}, false
}

// startPerf records the perf pass in the results and turns it off, with a
// note, on a host that cannot run it.
func (r *runner) startPerf(ctx context.Context) error {
	perf := r.options.Perf
	if !perf.Enabled() {
		return nil
	}
	pass := &PerfPass{StatRepeats: perf.StatRepeats, Ops: perf.Ops, RecordSets: perf.RecordSets, Events: bench.PerfStatEvents()}
	if len(perf.RecordSets) > 0 {
		pass.Frequency = perf.Frequency
	}
	r.results.Perf = pass
	if ok, why := PerfSupported(); !ok {
		pass.Skipped = why
		r.results.Notes = append(r.results.Notes, "perf pass skipped: "+why)
		// Off, but finishPerf still writes PerfIncompleteFile under Out.
		r.options.Perf = PerfOptions{Out: perf.Out}
		return nil
	}
	pass.Version = perfVersion(ctx)
	if data, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid"); err == nil {
		pass.Paranoid = strings.TrimSpace(string(data))
	}
	return os.MkdirAll(perf.Out, 0o755)
}

// finishPerf notes a perf pass that fell short of what it was asked for and
// writes PerfIncompleteFile listing why. A row skipped because its timed
// runs failed is not a perf problem (the timed results already say so),
// unless no perf run happened at all.
func (r *runner) finishPerf() error {
	pass := r.results.Perf
	if pass == nil {
		return nil
	}
	var problems []string
	if pass.Skipped != "" {
		problems = append(problems, "perf pass skipped: "+pass.Skipped)
	}
	ran, failed := 0, 0
	for _, run := range r.results.PerfRuns {
		if run.Skipped != "" {
			continue
		}
		ran++
		if run.Error != "" {
			failed++
			problems = append(problems, fmt.Sprintf("%s %s %s perf %s#%d: %s", run.Config, run.Op, run.Variant, run.Kind, run.Repeat+1, run.Error))
		}
	}
	if pass.Skipped == "" && ran == 0 {
		problems = append(problems, fmt.Sprintf("the perf pass ran nothing: no plain set had a row of %s with a clean timed run", strings.Join(pass.Ops, ",")))
		r.results.Notes = append(r.results.Notes, problems[len(problems)-1])
	}
	if failed > 0 {
		r.results.Notes = append(r.results.Notes, fmt.Sprintf("perf pass: %d of %d perf runs failed; see perf_runs and the report", failed, ran))
	}
	if len(problems) == 0 {
		return nil
	}
	out := r.options.Perf.Out
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, PerfIncompleteFile), []byte(strings.Join(problems, "\n")+"\n"), 0o644)
}

func perfVersion(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "perf", "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// perfPass runs one op's perf pass on one plain set, on the first target:
// StatRepeats perf stat runs of every reference and rarpar row, then, on a
// record set, one perf record run of every rarpar row.
func (r *runner) perfPass(ctx context.Context, op string, config Config, dataset Dataset, state *targetState, variants []Variant) {
	perf := r.options.Perf
	if !perf.Enabled() || config.Carrier != "" || !contains(perf.Ops, op) {
		return
	}
	record := contains(perf.RecordSets, config.ID)
	for _, variant := range variants {
		if variant.Tool == ToolEngine || variant.Target != r.options.Targets[0].Name {
			continue
		}
		recorded := record && variant.Tool == ToolCandidate
		if !r.rowCompleted(config.ID, op, variant.Name) {
			skipped := PerfRun{Config: config.ID, Op: op, Variant: variant.Name, Tool: variant.Tool, Kind: PerfKindStat,
				Skipped: "the row has no clean timed run (DNF or failed); its perf runs would repeat the failure"}
			if perf.StatRepeats == 0 {
				skipped.Kind = PerfKindRecord
			}
			if perf.StatRepeats > 0 || recorded {
				r.results.PerfRuns = append(r.results.PerfRuns, skipped)
				r.logf("%s %s %s perf skipped: %s", config.ID, op, variant.Name, skipped.Skipped)
			}
			continue
		}
		for repeat := 0; repeat < measuredRepeats(config, perf.StatRepeats); repeat++ {
			if ctx.Err() != nil {
				return
			}
			r.perfRun(ctx, PerfKindStat, op, config, dataset, state, variant, repeat)
		}
		if recorded && ctx.Err() == nil {
			r.perfRun(ctx, PerfKindRecord, op, config, dataset, state, variant, 0)
		}
	}
}

// PerfPassRuns is the most perf runs the pass makes over profile's sets with
// variants as the run's rows: per plain set and op in perf.Ops, StatRepeats
// (capped as the set's timed runs are) of each reference and rarpar row,
// plus one perf record run of each rarpar row on a record set. Rows skipped
// for want of a clean timed run make it fewer.
func PerfPassRuns(profile Profile, variants []Variant, perf PerfOptions) int {
	total := 0
	for _, config := range profile.Configs {
		if config.Carrier != "" {
			continue
		}
		record := contains(perf.RecordSets, config.ID)
		for _, op := range perf.Ops {
			for _, variant := range variants {
				if variant.Tool == ToolEngine || !variant.RunsOp(op) {
					continue
				}
				total += measuredRepeats(config, perf.StatRepeats)
				if record && variant.Tool == ToolCandidate {
					total++
				}
			}
		}
	}
	return total
}

// rowCompleted reports whether a row has at least one clean run of op on
// config and did not end early (a DNF reference, a timed-out rarpar row).
func (r *runner) rowCompleted(config, op, variant string) bool {
	if r.finished[rowKey(config, op, variant)] {
		return false
	}
	for _, run := range r.results.Runs {
		if run.Config == config && run.Op == op && run.Variant == variant && !run.Canonical && run.Status == StatusOK {
			return true
		}
	}
	return false
}

func (r *runner) perfRun(ctx context.Context, kind, op string, config Config, dataset Dataset, state *targetState, variant Variant, repeat int) {
	run := PerfRun{Config: config.ID, Op: op, Variant: variant.Name, Tool: variant.Tool, Kind: kind, Repeat: repeat}
	dir := filepath.Join(state.stageRoot, "perf-"+op+"-"+variant.dirName())
	defer os.RemoveAll(dir)
	command, err := r.perfCommand(op, config, dataset, state, dir, variant)
	if err == nil {
		run.Command = command.Describe()
		accept := func(exitCode int) bool { return exitAccepted(op, variant.Tool, exitCode) }
		out := r.options.Perf.Out
		base := filepath.Join(config.ID, op+"-"+variant.Name)
		if err = os.MkdirAll(filepath.Join(out, config.ID), 0o755); err == nil {
			switch kind {
			case PerfKindStat:
				err = perfStat(ctx, &run, command, out, fmt.Sprintf("%s-stat%d.csv", base, repeat+1), accept)
			case PerfKindRecord:
				err = perfRecord(ctx, &run, command, r.options.Perf.Frequency, dir+".perf.data", out, base, accept)
			}
		}
	}
	if err != nil {
		run.Error = err.Error()
	}
	r.results.PerfRuns = append(r.results.PerfRuns, run)
	r.logf("%s %s %s perf %s#%d %.3fs exit=%d files=%s %s", config.ID, op, variant.Name, kind, repeat, run.WallSeconds,
		run.ExitCode, strings.Join(run.Files, ","), run.Error)
}

// perfCommand stages dir for one untimed run of op and returns the command
// the row's timed runs ran.
func (r *runner) perfCommand(op string, config Config, dataset Dataset, state *targetState, dir string, variant Variant) (Command, error) {
	if op == OpCreate {
		if err := resetDir(dir); err != nil {
			return Command{}, err
		}
		return r.createCommand(config, dataset, state.dataDir, dir, variant), nil
	}
	if err := stageFrom(dir, dataset, state.dataDir, state.canonical, config, op, state.damaged); err != nil {
		return Command{}, err
	}
	return r.checkCommand(op, dir, variant, config), nil
}

// underPerf is command run as `perf ARGS... -- COMMAND`, keeping its
// directory, environment, pin and timeout. perf runs in the C locale, so its
// numbers read the same on every host.
func underPerf(command Command, args ...string) Command {
	wrapped := command
	wrapped.Path = "perf"
	wrapped.Args = append(append(append([]string(nil), args...), "--", command.Path), command.Args...)
	wrapped.Env = append(append([]string(nil), command.Env...), "LC_ALL=C", "LANG=C")
	return wrapped
}

// PerfStatArgs is the perf stat argument list before `--` and the command:
// the corpus suites' --perf events, as CSV, written to path.
func PerfStatArgs(path string) []string {
	return []string{"stat", "--no-big-num", "-x,", "-e", bench.PerfStatEvents(), "-o", path}
}

// PerfRecordArgs is the perf record argument list before `--` and the
// command: frame-pointer call graphs at frequency, as the corpus suites'
// record pass takes them, written to data.
func PerfRecordArgs(frequency int, data string) []string {
	return []string{"record", "-F", strconv.Itoa(frequency), "-g", "--call-graph", "fp", "-o", data}
}

// perfStat runs command once under perf stat, keeps perf's CSV as out/name
// and reads its counters into run.
func perfStat(ctx context.Context, run *PerfRun, command Command, out, name string, accept func(int) bool) error {
	path := filepath.Join(out, name)
	_ = os.Remove(path)
	result := Run(ctx, underPerf(command, PerfStatArgs(path)...))
	run.WallSeconds, run.ExitCode = result.WallSeconds, result.ExitCode
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		run.Files = append(run.Files, name)
	}
	if err := perfRunProblem("perf stat", result, accept); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("perf stat wrote no counters: %w", err)
	}
	counters, err := bench.ParsePerfStat(data)
	if err != nil {
		return fmt.Errorf("perf stat counters: %w", err)
	}
	run.Counters = counters
	if counters.MinRunningPercent != nil && *counters.MinRunningPercent < 99 {
		run.Note = fmt.Sprintf("counters multiplexed: min running %.1f%%; the counts are perf's scaled estimates", *counters.MinRunningPercent)
	}
	return nil
}

// perfRecord runs command once under perf record, then exports the samples
// as out/base.script.gz (perf script text) and out/base.folded (one line
// per distinct stack, root first, with its sample count, most frequent
// first). The perf.data file is scratch and is removed.
func perfRecord(ctx context.Context, run *PerfRun, command Command, frequency int, data, out, base string, accept func(int) bool) error {
	defer os.Remove(data)
	result := Run(ctx, underPerf(command, PerfRecordArgs(frequency, data)...))
	run.WallSeconds, run.ExitCode = result.WallSeconds, result.ExitCode
	if err := perfRunProblem("perf record", result, accept); err != nil {
		return err
	}
	scriptName, foldedName := base+".script.gz", base+".folded"
	file, err := os.Create(filepath.Join(out, scriptName))
	if err != nil {
		return err
	}
	compressed, err := gzip.NewWriterLevel(file, 6)
	if err != nil {
		file.Close()
		return err
	}
	folder := newStackFolder()
	var stderr tailBuffer
	script := exec.CommandContext(ctx, "perf", "script", "-i", data)
	script.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	script.Stdout = io.MultiWriter(compressed, folder)
	script.Stderr = &stderr
	runErr := script.Run()
	closeErr := compressed.Close()
	if err := file.Close(); closeErr == nil {
		closeErr = err
	}
	run.Files = append(run.Files, scriptName)
	if runErr != nil {
		return fmt.Errorf("perf script: %v: %s", runErr, lastNonEmptyLine(stderr.String()))
	}
	if closeErr != nil {
		return closeErr
	}
	folder.finish()
	if err := os.WriteFile(filepath.Join(out, foldedName), folder.folded(), 0o644); err != nil {
		return err
	}
	run.Files = append(run.Files, foldedName)
	run.Samples, run.Stacks = folder.samples, len(folder.stacks)
	if folder.samples == 0 {
		return errors.New("perf script printed no call-chain samples")
	}
	return nil
}

// perfRunProblem rejects a perf run that did not run, or whose measured
// command exited with a status accept refuses. perf exits with the
// command's status, and with its own when it cannot count at all.
func perfRunProblem(label string, result Result, accept func(int) bool) error {
	if result.Failure != "" {
		return fmt.Errorf("%s %s: %v", label, result.Failure, result.Err)
	}
	if !accept(result.ExitCode) {
		return fmt.Errorf("%s exited %d: %s", label, result.ExitCode, lastLine(result))
	}
	return nil
}

func lastNonEmptyLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// tailBuffer keeps the last 4 KiB written to it.
type tailBuffer struct{ data []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.data = append(t.data, p...)
	if len(t.data) > outputTailBytes {
		t.data = append([]byte(nil), t.data[len(t.data)-outputTailBytes:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.data) }

const outputTailBytes = 4096

// stackFolder folds perf script text into stacks as it streams past: a
// sample is a header line (the command name first) followed by one
// tab-indented frame per line, leaf first, and a blank line. A frame line is
// "ADDRESS SYMBOL+0xOFFSET (DSO)"; the folded frame is SYMBOL without its
// offset, so every return address inside one function folds together.
type stackFolder struct {
	partial []byte
	comm    string
	frames  []string
	stacks  map[string]int64
	samples int64
}

func newStackFolder() *stackFolder { return &stackFolder{stacks: map[string]int64{}} }

func (f *stackFolder) Write(p []byte) (int, error) {
	data := append(f.partial, p...)
	for {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			break
		}
		f.line(string(data[:end]))
		data = data[end+1:]
	}
	f.partial = append([]byte(nil), data...)
	return len(p), nil
}

func (f *stackFolder) line(text string) {
	text = strings.TrimRight(text, "\r")
	if strings.TrimSpace(text) == "" {
		f.flush()
		return
	}
	if text[0] != ' ' && text[0] != '\t' {
		f.flush()
		f.comm = strings.Fields(text)[0]
		return
	}
	fields := strings.Fields(text)
	if len(fields) < 2 {
		return
	}
	symbol := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), fields[0]))
	if open := strings.LastIndex(symbol, " ("); open > 0 && strings.HasSuffix(symbol, ")") {
		symbol = strings.TrimSpace(symbol[:open])
	}
	if plus := strings.LastIndex(symbol, "+0x"); plus > 0 && isHex(symbol[plus+3:]) {
		symbol = symbol[:plus]
	}
	if symbol == "" {
		return
	}
	f.frames = append(f.frames, strings.ReplaceAll(symbol, ";", ":"))
}

func isHex(text string) bool {
	if text == "" {
		return false
	}
	for _, c := range text {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

func (f *stackFolder) flush() {
	if len(f.frames) > 0 {
		parts := make([]string, 0, len(f.frames)+1)
		parts = append(parts, f.comm)
		for i := len(f.frames) - 1; i >= 0; i-- {
			parts = append(parts, f.frames[i])
		}
		f.stacks[strings.Join(parts, ";")]++
		f.samples++
	}
	f.frames = f.frames[:0]
}

// finish folds a last line with no newline and the last sample.
func (f *stackFolder) finish() {
	if len(f.partial) > 0 {
		f.line(string(f.partial))
		f.partial = nil
	}
	f.flush()
}

// folded renders "STACK COUNT" lines, most samples first, ties by stack.
func (f *stackFolder) folded() []byte {
	stacks := make([]string, 0, len(f.stacks))
	for stack := range f.stacks {
		stacks = append(stacks, stack)
	}
	sort.Slice(stacks, func(i, j int) bool {
		if f.stacks[stacks[i]] != f.stacks[stacks[j]] {
			return f.stacks[stacks[i]] > f.stacks[stacks[j]]
		}
		return stacks[i] < stacks[j]
	})
	var b bytes.Buffer
	for _, stack := range stacks {
		fmt.Fprintf(&b, "%s %d\n", stack, f.stacks[stack])
	}
	return b.Bytes()
}

// perfSummary is the report's line about the perf pass, or "" when none was
// asked for.
func perfSummary(pass *PerfPass) string {
	if pass == nil {
		return ""
	}
	var parts []string
	if pass.StatRepeats > 0 {
		parts = append(parts, fmt.Sprintf("perf stat ×%d on every reference and rarpar row of %s (events %s)",
			pass.StatRepeats, strings.Join(pass.Ops, ", "), pass.Events))
	}
	if len(pass.RecordSets) > 0 {
		parts = append(parts, fmt.Sprintf("perf record -F %d with frame-pointer call graphs on the rarpar rows of %s, exported as perf script text and folded stacks",
			pass.Frequency, strings.Join(pass.RecordSets, ", ")))
	}
	line := "- Perf pass (untimed, Linux perf, after each op's timed runs, on the plain sets and the first target): " + strings.Join(parts, "; ") + "."
	if pass.Skipped != "" {
		return line + " **Skipped**: " + pass.Skipped + "."
	}
	if pass.Version != "" {
		line += " " + pass.Version
		if pass.Paranoid != "" {
			line += ", perf_event_paranoid " + pass.Paranoid
		}
		line += "."
	}
	return line + " Files are under the perf directory as SET/OP-ROW-statN.csv, SET/OP-ROW.script.gz and SET/OP-ROW.folded."
}

// writePerfRuns tabulates one configuration and operation's perf runs:
// medians of the perf stat counters per row, and each perf record run's
// sample count. Skipped rows and failed runs are listed under the table.
func writePerfRuns(b *strings.Builder, results *Results, config, op string) {
	type rowRuns struct {
		variant string
		stat    []PerfRun
		record  []PerfRun
		skipped []PerfRun
	}
	var order []*rowRuns
	byVariant := map[string]*rowRuns{}
	for _, run := range results.PerfRuns {
		if run.Config != config || run.Op != op {
			continue
		}
		row, ok := byVariant[run.Variant]
		if !ok {
			row = &rowRuns{variant: run.Variant}
			byVariant[run.Variant] = row
			order = append(order, row)
		}
		switch {
		case run.Skipped != "":
			row.skipped = append(row.skipped, run)
		case run.Kind == PerfKindRecord:
			row.record = append(row.record, run)
		default:
			row.stat = append(row.stat, run)
		}
	}
	if len(order) == 0 {
		return
	}
	fmt.Fprintln(b, "Linux perf (untimed pass; counters are medians over the clean perf stat runs, task-clock is CPU time across threads):")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "| variant | stat runs | instructions | cycles | IPC | task-clock s | context switches | CPU migrations | cache misses | perf record |")
	fmt.Fprintln(b, "|---|---|---|---|---|---|---|---|---|---|")
	var problems []string
	for _, row := range order {
		var instructions, cycles, ipc, taskClock, switches, migrations, misses []float64
		clean := 0
		for _, run := range row.stat {
			if run.Error != "" {
				problems = append(problems, fmt.Sprintf("%s stat#%d: %s", row.variant, run.Repeat+1, run.Error))
			}
			c := run.Counters
			if c == nil || run.Error != "" {
				continue
			}
			clean++
			if c.Instructions != nil {
				instructions = append(instructions, float64(*c.Instructions))
			}
			if c.Cycles != nil {
				cycles = append(cycles, float64(*c.Cycles))
			}
			if c.Instructions != nil && c.Cycles != nil && *c.Cycles > 0 {
				ipc = append(ipc, float64(*c.Instructions)/float64(*c.Cycles))
			}
			if c.TaskClockMillis != nil {
				taskClock = append(taskClock, *c.TaskClockMillis/1000)
			}
			if c.ContextSwitches != nil {
				switches = append(switches, float64(*c.ContextSwitches))
			}
			if c.CPUMigrations != nil {
				migrations = append(migrations, float64(*c.CPUMigrations))
			}
			if c.CacheMisses != nil {
				misses = append(misses, float64(*c.CacheMisses))
			}
		}
		statCell := "-"
		if len(row.stat) > 0 {
			statCell = fmt.Sprintf("%d of %d", clean, len(row.stat))
		}
		recordCell := "-"
		for _, run := range row.record {
			if run.Error != "" {
				recordCell = "failed"
				problems = append(problems, fmt.Sprintf("%s record: %s", row.variant, run.Error))
				continue
			}
			recordCell = fmt.Sprintf("%d samples, %d stacks", run.Samples, run.Stacks)
		}
		for _, run := range row.skipped {
			problems = append(problems, fmt.Sprintf("%s: skipped: %s", row.variant, run.Skipped))
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", row.variant, statCell,
			siMedian(instructions), siMedian(cycles), fixedMedian(ipc, 2), fixedMedian(taskClock, 3),
			siMedian(switches), siMedian(migrations), siMedian(misses), recordCell)
	}
	fmt.Fprintln(b)
	for _, problem := range problems {
		fmt.Fprintf(b, "- %s\n", problem)
	}
	if len(problems) > 0 {
		fmt.Fprintln(b)
	}
}

func siMedian(values []float64) string {
	if len(values) == 0 {
		return "-"
	}
	value := stat(values).Median
	for _, unit := range []struct {
		scale  float64
		suffix string
	}{{1e12, "T"}, {1e9, "G"}, {1e6, "M"}, {1e3, "k"}} {
		if value >= unit.scale {
			return fmt.Sprintf("%.2f%s", value/unit.scale, unit.suffix)
		}
	}
	return fmt.Sprintf("%.0f", value)
}

func fixedMedian(values []float64, decimals int) string {
	if len(values) == 0 {
		return "-"
	}
	return strconv.FormatFloat(stat(values).Median, 'f', decimals, 64)
}
