package par3bench

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

const (
	ResultsSchema = "rarpar-par3-bench-v1"

	OpCreate        = "create"
	OpVerify        = "verify"
	OpVerifyDamaged = "verify-damaged"
	OpRepair        = "repair"

	ToolReference = "reference"
	ToolCandidate = "rarpar"

	carrierName = "set.par3"
)

// KnownOps lists every operation in run order.
var KnownOps = []string{OpCreate, OpVerify, OpVerifyDamaged, OpRepair}

// DefaultOps is what a run measures unless told otherwise.
var DefaultOps = []string{OpCreate, OpVerify, OpRepair}

// KernelVariant is an optional extra candidate row: the same binary with an
// environment override, typically a kernel pin. Variants are data, not code:
// the harness does not know which variables a given rarpar build honours, and
// a variable the build ignores simply reproduces the default row.
type KernelVariant struct {
	Name string   `json:"name"`
	Env  []string `json:"env"`
}

// ParseKernelVariant reads "name:VAR=value[,VAR=value...]".
func ParseKernelVariant(text string) (KernelVariant, error) {
	name, assignments, found := strings.Cut(text, ":")
	if !found || name == "" || assignments == "" {
		return KernelVariant{}, fmt.Errorf("kernel variant %q: want name:VAR=value[,VAR=value]", text)
	}
	if strings.ContainsAny(name, " /\\") {
		return KernelVariant{}, fmt.Errorf("kernel variant name %q may not contain spaces or slashes", name)
	}
	variant := KernelVariant{Name: name}
	for _, assignment := range strings.Split(assignments, ",") {
		key, _, ok := strings.Cut(assignment, "=")
		if !ok || key == "" {
			return KernelVariant{}, fmt.Errorf("kernel variant %q: %q is not VAR=value", text, assignment)
		}
		variant.Env = append(variant.Env, assignment)
	}
	return variant, nil
}

// Options configures one suite run.
type Options struct {
	Reference      string
	Candidate      string
	EnginePerf     string
	Work           string
	Out            string
	Profile        Profile
	Ops            []string
	Warmups        int
	Repeats        int
	Workers        []int
	PinCPUs        string
	KernelVariants []KernelVariant
	IOCount        bool
	MachineLabel   string
	CandidateArgs  []string
	// EnginePerfMemoryMiB is engine_perf's memory budget (the CLI default is 256).
	EnginePerfMemoryMiB int
	KeepStages          bool
	Timeout             time.Duration
	Log                 io.Writer
}

// Variant is one benchmarked tool configuration.
type Variant struct {
	Name    string   `json:"name"`
	Tool    string   `json:"tool"`
	Workers int      `json:"workers,omitempty"`
	Kernel  string   `json:"kernel,omitempty"`
	Env     []string `json:"env,omitempty"`
}

// dirName is the variant's short stage-directory name. Stage paths are kept
// short on purpose: see ReferencePathBudget.
func (v Variant) dirName() string {
	if v.Tool == ToolReference {
		return "ref"
	}
	return strings.TrimPrefix(v.Name, "rarpar-")
}

// Variants expands the reference plus every candidate worker/kernel row.
func Variants(workers []int, kernels []KernelVariant) []Variant {
	variants := []Variant{{Name: "reference", Tool: ToolReference}}
	for _, count := range workers {
		variants = append(variants, Variant{Name: fmt.Sprintf("rarpar-w%d", count), Tool: ToolCandidate, Workers: count})
	}
	for _, kernel := range kernels {
		for _, count := range workers {
			variants = append(variants, Variant{
				Name: fmt.Sprintf("rarpar-w%d-%s", count, kernel.Name), Tool: ToolCandidate,
				Workers: count, Kernel: kernel.Name, Env: kernel.Env,
			})
		}
	}
	return variants
}

// Binary identifies an executable the run used.
type Binary struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version,omitempty"`
}

// RepairCheck is the post-repair comparison against the original inputs.
type RepairCheck struct {
	Match      bool     `json:"match"`
	Mismatched []string `json:"mismatched,omitempty"`
	ExtraFiles []string `json:"extra_files,omitempty"`
}

// RunRecord is one process run.
type RunRecord struct {
	Config   string `json:"config"`
	Op       string `json:"op"`
	Variant  string `json:"variant"`
	Tool     string `json:"tool"`
	Workers  int    `json:"workers,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	Warmup   bool   `json:"warmup"`
	Repeat   int    `json:"repeat"`
	Position int    `json:"position"`
	Command  string `json:"command"`
	Measurement
	Status     string       `json:"status"`
	Failure    string       `json:"failure,omitempty"`
	Error      string       `json:"error,omitempty"`
	StderrTail string       `json:"stderr_tail,omitempty"`
	Identity   *Identity    `json:"identity,omitempty"`
	Repair     *RepairCheck `json:"repair,omitempty"`
}

// IOCountRecord is one untimed strace pass.
type IOCountRecord struct {
	Config  string   `json:"config"`
	Op      string   `json:"op"`
	Variant string   `json:"variant"`
	Counts  IOCounts `json:"counts"`
	Error   string   `json:"error,omitempty"`
}

// EnginePerfRecord is one untimed engine_perf stage-breakdown pass.
type EnginePerfRecord struct {
	Config      string            `json:"config"`
	Op          string            `json:"op"`
	Workers     int               `json:"workers"`
	WallSeconds float64           `json:"wall_seconds"`
	Lines       []json.RawMessage `json:"lines"`
	Error       string            `json:"error,omitempty"`
}

// ConfigSummary is a configuration plus its derived sizes.
type ConfigSummary struct {
	Config
	DatasetBytes int64 `json:"dataset_bytes"`
	InputBlocks  int64 `json:"input_blocks"`
	CapacityLog2 int   `json:"capacity_log2,omitempty"`
}

// Results is the evidence document a run writes.
type Results struct {
	Schema         string             `json:"schema"`
	StartedUTC     string             `json:"started_utc"`
	FinishedUTC    string             `json:"finished_utc"`
	Machine        bench.Machine      `json:"machine"`
	Profile        string             `json:"profile"`
	Ops            []string           `json:"ops"`
	Warmups        int                `json:"warmups"`
	Repeats        int                `json:"repeats"`
	Workers        []int              `json:"workers"`
	PinCPUs        string             `json:"pin_cpus,omitempty"`
	PinApplied     bool               `json:"pin_applied"`
	KernelVariants []KernelVariant    `json:"kernel_variants,omitempty"`
	CandidateArgs  []string           `json:"candidate_args,omitempty"`
	Reference      Binary             `json:"reference"`
	Candidate      Binary             `json:"candidate"`
	EnginePerf     *Binary            `json:"engine_perf,omitempty"`
	Variants       []Variant          `json:"variants"`
	Configs        []ConfigSummary    `json:"configs"`
	Runs           []RunRecord        `json:"runs"`
	IOCounts       []IOCountRecord    `json:"io_counts,omitempty"`
	EnginePerfRuns []EnginePerfRecord `json:"engine_perf_runs,omitempty"`
	Notes          []string           `json:"notes,omitempty"`
	Status         string             `json:"status"`
	Failures       []string           `json:"failures,omitempty"`
}

type runner struct {
	options  Options
	results  *Results
	journal  *os.File
	guards   map[string]Binary
	failures []string
}

func (r *runner) logf(format string, args ...any) {
	if r.options.Log != nil {
		fmt.Fprintf(r.options.Log, "par3: "+format+"\n", args...)
	}
}

// RunSuite executes the suite and writes results.json, runs.jsonl and
// report.md under options.Out. It returns the results even when some runs
// failed; the error is reserved for a run that could not proceed at all.
func RunSuite(ctx context.Context, options Options) (*Results, error) {
	if err := validateOptions(&options); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(options.Out, 0o755); err != nil {
		return nil, err
	}
	journal, err := os.Create(filepath.Join(options.Out, "runs.jsonl"))
	if err != nil {
		return nil, err
	}
	defer journal.Close()

	results := &Results{
		Schema:         ResultsSchema,
		StartedUTC:     time.Now().UTC().Format(time.RFC3339),
		Machine:        CollectMachine(ctx, options.MachineLabel),
		Profile:        options.Profile.Name,
		Ops:            options.Ops,
		Warmups:        options.Warmups,
		Repeats:        options.Repeats,
		Workers:        options.Workers,
		PinCPUs:        options.PinCPUs,
		KernelVariants: options.KernelVariants,
		CandidateArgs:  options.CandidateArgs,
		Variants:       Variants(options.Workers, options.KernelVariants),
	}
	r := &runner{options: options, results: results, journal: journal, guards: map[string]Binary{}}
	if options.PinCPUs != "" {
		results.PinApplied = PinSupported()
		if !results.PinApplied {
			results.Notes = append(results.Notes, fmt.Sprintf("--pin-cpus %s requested but this host cannot pin processes (%s); runs are unpinned", options.PinCPUs, runtime.GOOS))
		}
	}
	if results.Reference, err = r.identify(ctx, options.Reference, "-V"); err != nil {
		return nil, err
	}
	if results.Candidate, err = r.identify(ctx, options.Candidate, "--version"); err != nil {
		return nil, err
	}
	if options.EnginePerf != "" {
		binary, err := r.identify(ctx, options.EnginePerf, "")
		if err != nil {
			return nil, err
		}
		results.EnginePerf = &binary
	}
	if len(options.KernelVariants) > 0 {
		results.Notes = append(results.Notes, "kernel variants only change the environment; a rarpar build that does not read those variables reproduces its default row")
	}
	if options.IOCount {
		if ok, why := IOCountSupported(); !ok {
			results.Notes = append(results.Notes, "--iocount skipped: "+why)
			r.options.IOCount = false
		}
	}

	for _, config := range options.Profile.Configs {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		dataset, _ := options.Profile.Dataset(config.Dataset)
		summary := ConfigSummary{Config: config, DatasetBytes: dataset.TotalBytes(), InputBlocks: InputBlocks(dataset, config.BlockSize)}
		if config.Codec == "fft" {
			summary.CapacityLog2 = config.CapacityLog2()
		}
		results.Configs = append(results.Configs, summary)
		if err := r.runConfig(ctx, config, dataset); err != nil {
			r.failures = append(r.failures, fmt.Sprintf("%s: %v", config.ID, err))
			r.logf("%s: %v", config.ID, err)
			var quarantined *quarantineError
			if errors.As(err, &quarantined) {
				break
			}
		}
	}
	results.FinishedUTC = time.Now().UTC().Format(time.RFC3339)
	results.Failures = r.failures
	results.Status = "ok"
	if len(r.failures) > 0 {
		results.Status = "failed"
	}
	if err := writeJSONFile(filepath.Join(options.Out, "results.json"), results); err != nil {
		return results, err
	}
	report := RenderReport(results)
	if err := os.WriteFile(filepath.Join(options.Out, "report.md"), []byte(report), 0o644); err != nil {
		return results, err
	}
	return results, nil
}

func validateOptions(options *Options) error {
	if options.Reference == "" || options.Candidate == "" {
		return errors.New("--reference and --candidate are required")
	}
	if options.Work == "" || options.Out == "" {
		return errors.New("--work and --out are required")
	}
	if len(options.Ops) == 0 {
		options.Ops = DefaultOps
	}
	for _, op := range options.Ops {
		if !contains(KnownOps, op) {
			return fmt.Errorf("unknown op %q (known: %s)", op, strings.Join(KnownOps, ", "))
		}
	}
	if len(options.Workers) == 0 {
		options.Workers = []int{1, 8}
	}
	for _, workers := range options.Workers {
		if workers < 1 {
			return fmt.Errorf("worker count %d must be at least 1", workers)
		}
	}
	if options.Repeats < 1 {
		return errors.New("--repeats must be at least 1")
	}
	if options.Warmups < 0 {
		return errors.New("--warmups cannot be negative")
	}
	if options.EnginePerfMemoryMiB == 0 {
		options.EnginePerfMemoryMiB = 256
	}
	if err := options.Profile.Validate(); err != nil {
		return err
	}
	for _, path := range []*string{&options.Reference, &options.Candidate, &options.EnginePerf, &options.Work, &options.Out} {
		if *path == "" {
			continue
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		*path = absolute
	}
	for _, path := range []string{options.Reference, options.Candidate, options.EnginePerf} {
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err != nil {
			return fmt.Errorf("binary %s: %w", path, err)
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("binary %s is not a regular file", path)
		}
	}
	return checkReferencePaths(*options)
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// quarantineError stops the run: a binary that vanished or changed under the
// harness (on Windows, almost always Defender) invalidates every later row.
type quarantineError struct{ message string }

func (e *quarantineError) Error() string { return e.message }

func (r *runner) identify(ctx context.Context, path, versionFlag string) (Binary, error) {
	digest, _, err := hashFile(path)
	if err != nil {
		return Binary{}, fmt.Errorf("binary %s: %w", path, err)
	}
	binary := Binary{Path: path, SHA256: digest}
	if versionFlag != "" {
		result := Run(ctx, Command{Path: path, Args: []string{versionFlag}, Timeout: 30 * time.Second})
		if result.Failure == "binary-quarantined" {
			return Binary{}, r.quarantined(ctx, path, "refused to start: "+fmt.Sprint(result.Err))
		}
		binary.Version = strings.TrimSpace(firstLine(result.Stdout + result.Stderr))
	}
	r.guards[path] = binary
	return binary, nil
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	return line
}

// checkBinaries re-hashes every binary before each operation batch. A binary
// that disappeared or changed is reported, never worked around.
func (r *runner) checkBinaries(ctx context.Context) error {
	for path, want := range r.guards {
		digest, _, err := hashFile(path)
		switch {
		case err != nil:
			return r.quarantined(ctx, path, fmt.Sprintf("is no longer readable (%v)", err))
		case digest != want.SHA256:
			return r.quarantined(ctx, path, fmt.Sprintf("changed on disk (sha256 %s, started as %s)", digest, want.SHA256))
		}
	}
	return nil
}

func (r *runner) quarantined(ctx context.Context, path, what string) error {
	message := fmt.Sprintf("binary %s %s", path, what)
	if runtime.GOOS == "windows" {
		message += "; this is the signature of an antivirus quarantine (Windows Defender). The harness does not evade it: restore or allow the binary and rerun"
		if evidence := defenderEvidence(ctx); evidence != "" {
			evidencePath := filepath.Join(r.options.Out, "defender-detections.json")
			if os.WriteFile(evidencePath, []byte(evidence), 0o644) == nil {
				message += "; recent detections saved to " + evidencePath
			}
		}
	}
	r.results.Notes = append(r.results.Notes, message)
	return &quarantineError{message: message}
}

// defenderEvidence reads (never changes) Defender's recent detections.
func defenderEvidence(ctx context.Context) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	result := Run(ctx, Command{
		Path:    "powershell",
		Args:    []string{"-NoProfile", "-NonInteractive", "-Command", "Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ConvertTo-Json -Depth 4"},
		Timeout: 60 * time.Second,
	})
	if result.Failure != "" {
		return ""
	}
	return result.Stdout
}

func (r *runner) record(record RunRecord) {
	r.results.Runs = append(r.results.Runs, record)
	if data, err := json.Marshal(record); err == nil {
		r.journal.Write(append(data, '\n'))
	}
	phase := "measure"
	if record.Warmup {
		phase = "warmup"
	}
	extra := ""
	if record.Identity != nil {
		extra = " carriers=" + record.Identity.Verdict()
	}
	if record.Repair != nil {
		extra = fmt.Sprintf(" repaired=%t", record.Repair.Match)
	}
	r.logf("%s %s %s %s#%d %.3fs user=%.3fs sys=%.3fs rss=%dMiB exit=%d %s%s",
		record.Config, record.Op, record.Variant, phase, record.Repeat, record.WallSeconds,
		record.UserSeconds, record.SysSeconds, record.MaxRSSBytes>>20, record.ExitCode, record.Status, extra)
}

func (r *runner) runConfig(ctx context.Context, config Config, dataset Dataset) error {
	dataDir := filepath.Join(r.options.Work, "data", dataset.ID)
	manifest, err := EnsureDataset(dataDir, dataset, r.logf)
	if err != nil {
		return fmt.Errorf("dataset %s: %w", dataset.ID, err)
	}
	stageRoot := filepath.Join(r.options.Work, "s", config.ID)
	if err := os.RemoveAll(stageRoot); err != nil {
		return err
	}
	if !r.options.KeepStages {
		defer os.RemoveAll(stageRoot)
	}
	if err := r.checkBinaries(ctx); err != nil {
		return err
	}

	// The canonical carriers: one untimed reference create. Every identity
	// check compares against it, and every verify and repair, ours included,
	// reads it, so both tools always work from the same recovery set.
	canonical := filepath.Join(r.options.Work, "k", config.ID)
	if err := os.RemoveAll(canonical); err != nil {
		return err
	}
	if err := os.MkdirAll(canonical, 0o755); err != nil {
		return err
	}
	reference := Variant{Name: "reference", Tool: ToolReference}
	seed := Run(ctx, r.createCommand(config, dataset, dataDir, canonical, reference))
	if seed.Failure != "" || seed.ExitCode != 0 {
		if seed.Failure == "binary-quarantined" {
			return r.quarantined(ctx, r.options.Reference, "refused to start")
		}
		return fmt.Errorf("reference create for the canonical carriers failed (exit %d %s): %s", seed.ExitCode, seed.Failure, firstLine(seed.Stderr))
	}
	canonicalSet, err := ReadCarrierSet(canonical)
	if err != nil {
		return err
	}
	if len(canonicalSet.Files) == 0 {
		return errors.New("reference create wrote no carriers")
	}

	variants := r.results.Variants
	var failed []string
	for _, op := range r.options.Ops {
		if err := r.checkBinaries(ctx); err != nil {
			return err
		}
		for run := 0; run < r.options.Warmups+r.options.Repeats; run++ {
			order := orderFor(variants, run)
			for position, variant := range order {
				record, err := r.runOne(ctx, op, config, dataset, manifest, dataDir, canonical, canonicalSet, stageRoot, variant)
				if err != nil {
					return err
				}
				record.Warmup = run < r.options.Warmups
				record.Repeat = run
				if !record.Warmup {
					record.Repeat = run - r.options.Warmups
				}
				record.Position = position
				r.record(record)
				if record.Status != "ok" {
					failed = append(failed, fmt.Sprintf("%s/%s/%s: %s", config.ID, op, variant.Name, record.Status))
				}
			}
		}
		if r.options.IOCount {
			for _, variant := range variants {
				r.countIO(ctx, op, config, dataset, manifest, dataDir, canonical, stageRoot, variant)
			}
		}
		if r.options.EnginePerf != "" {
			for _, workers := range r.options.Workers {
				r.enginePerf(ctx, op, config, dataset, dataDir, canonical, stageRoot, workers)
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d run(s) failed: %s", len(failed), strings.Join(dedupe(failed), "; "))
	}
	return nil
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// orderFor alternates the variant order every repeat so neither tool always
// runs on a cache the other just warmed.
func orderFor(variants []Variant, run int) []Variant {
	order := append([]Variant(nil), variants...)
	if run%2 == 1 {
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	}
	return order
}

func (r *runner) createCommand(config Config, dataset Dataset, dataDir, outDir string, variant Variant) Command {
	names := make([]string, 0, len(dataset.Files))
	for _, file := range dataset.Files {
		names = append(names, file.Name)
	}
	output := filepath.Join(outDir, carrierName)
	if variant.Tool == ToolReference {
		args := []string{"c", "-q", "-s" + strconv.FormatInt(config.BlockSize, 10), "-c" + strconv.FormatInt(config.Recovery, 10)}
		if config.Codec == "fft" {
			args = append(args, "-e8")
		}
		args = append(args, "-B"+dataDir, output)
		args = append(args, names...)
		return Command{Path: r.options.Reference, Args: args, Dir: dataDir, PinCPUs: r.pin(), Timeout: r.options.Timeout}
	}
	args := append(r.candidateGlobals(variant), "par3", "create", output)
	args = append(args, names...)
	args = append(args, "--base-path", dataDir,
		"-s", strconv.FormatInt(config.BlockSize, 10),
		"-c", strconv.FormatInt(config.Recovery, 10))
	if config.Codec == "fft" {
		args = append(args, "--codec", "fft", "--capacity-log2", strconv.Itoa(config.CapacityLog2()))
	}
	return Command{Path: r.options.Candidate, Args: args, Dir: dataDir, Env: variant.Env, PinCPUs: r.pin(), Timeout: r.options.Timeout}
}

func (r *runner) candidateGlobals(variant Variant) []string {
	args := []string{"--quiet", "--par3-workers", strconv.Itoa(variant.Workers)}
	return append(args, r.options.CandidateArgs...)
}

func (r *runner) pin() string {
	if r.results.PinApplied {
		return r.options.PinCPUs
	}
	return ""
}

func (r *runner) checkCommand(op string, stage string, variant Variant) Command {
	if variant.Tool == ToolReference {
		letter := "v"
		if op == OpRepair {
			letter = "r"
		}
		return Command{Path: r.options.Reference, Args: []string{letter, "-q", carrierName}, Dir: stage, PinCPUs: r.pin(), Timeout: r.options.Timeout}
	}
	sub := "verify"
	if op == OpRepair {
		sub = "repair"
	}
	args := append(r.candidateGlobals(variant), "par3", sub, carrierName)
	return Command{Path: r.options.Candidate, Args: args, Dir: stage, Env: variant.Env, PinCPUs: r.pin(), Timeout: r.options.Timeout}
}

// stage lays out a verify or repair directory: inputs (linked when the op
// cannot write, private copies when it can or when damage is applied) and
// the canonical carriers.
func stage(dir string, dataset Dataset, dataDir, canonical string, config Config, op string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	private := op != OpVerify
	for _, file := range dataset.Files {
		source, destination := filepath.Join(dataDir, file.Name), filepath.Join(dir, file.Name)
		var err error
		if private {
			err = copyFile(source, destination)
		} else {
			err = linkOrCopy(source, destination)
		}
		if err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(canonical)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		source, destination := filepath.Join(canonical, entry.Name()), filepath.Join(dir, entry.Name())
		if op == OpRepair {
			err = copyFile(source, destination)
		} else {
			err = linkOrCopy(source, destination)
		}
		if err != nil {
			return err
		}
	}
	if op == OpVerifyDamaged || op == OpRepair {
		return ApplyDamage(dir, dataset, config.BlockSize, config.Damage)
	}
	return nil
}

func (r *runner) runOne(ctx context.Context, op string, config Config, dataset Dataset, manifest DatasetManifest,
	dataDir, canonical string, canonicalSet CarrierSet, stageRoot string, variant Variant) (RunRecord, error) {
	record := RunRecord{Config: config.ID, Op: op, Variant: variant.Name, Tool: variant.Tool, Workers: variant.Workers, Kernel: variant.Kernel}
	dir := filepath.Join(stageRoot, op+"-"+variant.dirName())
	var command Command
	if op == OpCreate {
		if err := os.RemoveAll(dir); err != nil {
			return record, err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return record, err
		}
		command = r.createCommand(config, dataset, dataDir, dir, variant)
	} else {
		if err := stage(dir, dataset, dataDir, canonical, config, op); err != nil {
			return record, err
		}
		command = r.checkCommand(op, dir, variant)
	}
	record.Command = command.Describe()
	result := Run(ctx, command)
	record.Measurement = result.Measurement
	record.Status = "ok"
	if result.Failure != "" {
		record.Status = "failed"
		record.Failure = result.Failure
		record.Error = fmt.Sprint(result.Err)
		record.StderrTail = result.Stderr
		if result.Failure == "binary-quarantined" {
			return record, r.quarantined(ctx, command.Path, "refused to start: "+fmt.Sprint(result.Err))
		}
		return record, nil
	}
	accepted := result.ExitCode == 0
	if op == OpVerifyDamaged {
		// Damage is expected to be detected. The reference exits 0 once it
		// finds the damage repairable; rarpar exits 1 for "repair needed".
		// Either is a clean verdict; anything else is a failure.
		accepted = result.ExitCode == 0 || result.ExitCode == 1
	}
	if !accepted {
		record.Status = "failed"
		record.Failure = fmt.Sprintf("exit-%d", result.ExitCode)
		record.StderrTail = result.Stderr
		return record, nil
	}
	switch op {
	case OpCreate:
		set, err := ReadCarrierSet(dir)
		if err != nil {
			record.Status = "failed"
			record.Failure = "unreadable-carriers"
			record.Error = err.Error()
			return record, nil
		}
		identity := CompareCarriers(canonicalSet, set)
		record.Identity = &identity
		if variant.Tool == ToolReference && !identity.Bytes {
			// The reference must reproduce itself; if it does not, nothing
			// compared against it means anything.
			record.Status = "failed"
			record.Failure = "reference-nondeterministic"
		}
	case OpRepair:
		check, err := checkRepair(dir, manifest, canonical)
		if err != nil {
			return record, err
		}
		record.Repair = &check
		if !check.Match {
			record.Status = "failed"
			record.Failure = "repair-mismatch"
			record.StderrTail = result.Stderr
		}
	}
	return record, nil
}

// checkRepair hashes every protected file after a repair and lists what else
// the tool left in the directory (backups, temporaries).
func checkRepair(dir string, manifest DatasetManifest, canonical string) (RepairCheck, error) {
	check := RepairCheck{Match: true}
	expected := map[string]bool{}
	for _, digest := range manifest.SHA256 {
		expected[digest.Name] = true
		got, size, err := hashFile(filepath.Join(dir, digest.Name))
		if err != nil || got != digest.SHA256 || size != digest.Size {
			check.Match = false
			check.Mismatched = append(check.Mismatched, digest.Name)
		}
	}
	carriers, err := os.ReadDir(canonical)
	if err != nil {
		return check, err
	}
	for _, entry := range carriers {
		expected[entry.Name()] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return check, err
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			check.ExtraFiles = append(check.ExtraFiles, entry.Name())
		}
	}
	return check, nil
}

func (r *runner) countIO(ctx context.Context, op string, config Config, dataset Dataset, manifest DatasetManifest,
	dataDir, canonical, stageRoot string, variant Variant) {
	record := IOCountRecord{Config: config.ID, Op: op, Variant: variant.Name}
	dir := filepath.Join(stageRoot, "io-"+op+"-"+variant.dirName())
	var command Command
	if op == OpCreate {
		if err := resetDir(dir); err != nil {
			record.Error = err.Error()
		}
		command = r.createCommand(config, dataset, dataDir, dir, variant)
	} else {
		if err := stage(dir, dataset, dataDir, canonical, config, op); err != nil {
			record.Error = err.Error()
		}
		command = r.checkCommand(op, dir, variant)
	}
	if record.Error == "" {
		counts, err := CountIO(ctx, command, stageRoot)
		if err != nil {
			record.Error = err.Error()
		}
		record.Counts = counts
	}
	r.results.IOCounts = append(r.results.IOCounts, record)
	r.logf("%s %s %s iocount reads=%d writes=%d opens=%d stats=%d syncs=%d %s",
		config.ID, op, variant.Name, record.Counts.Reads, record.Counts.Writes, record.Counts.Opens,
		record.Counts.Stats, record.Counts.Syncs, record.Error)
	_ = os.RemoveAll(dir)
}

func resetDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, 0o755)
}

// enginePerf runs the par3-rs engine_perf example once, untimed, for its
// per-stage JSON lines. It drives the library directly, so it explains where
// the CLI's time goes; it is never the headline number.
func (r *runner) enginePerf(ctx context.Context, op string, config Config, dataset Dataset,
	dataDir, canonical, stageRoot string, workers int) {
	if op == OpVerifyDamaged {
		return
	}
	record := EnginePerfRecord{Config: config.ID, Op: op, Workers: workers}
	memory := strconv.Itoa(r.options.EnginePerfMemoryMiB)
	base := filepath.Join(stageRoot, fmt.Sprintf("engine-perf-%s-w%d", op, workers))
	carriers, output, damaged := filepath.Join(base, "carriers"), filepath.Join(base, "output"), filepath.Join(base, "data")
	var args []string
	var setupErr error
	switch op {
	case OpCreate:
		setupErr = errors.Join(resetDir(carriers), resetDir(output))
		args = []string{"create", dataDir, carriers, output, strconv.Itoa(workers), memory,
			config.Codec, strconv.FormatInt(config.BlockSize, 10), strconv.FormatInt(config.Recovery, 10), "0"}
	case OpVerify:
		setupErr = resetDir(output)
		args = []string{"verify", dataDir, canonical, output, strconv.Itoa(workers), memory}
	case OpRepair:
		setupErr = errors.Join(resetDir(output), resetDir(damaged))
		if setupErr == nil {
			for _, file := range dataset.Files {
				if err := copyFile(filepath.Join(dataDir, file.Name), filepath.Join(damaged, file.Name)); err != nil {
					setupErr = err
					break
				}
			}
		}
		if setupErr == nil {
			setupErr = ApplyDamage(damaged, dataset, config.BlockSize, config.Damage)
		}
		args = []string{"repair", damaged, canonical, output, strconv.Itoa(workers), memory}
	}
	if setupErr != nil {
		record.Error = setupErr.Error()
	} else {
		result := Run(ctx, Command{Path: r.options.EnginePerf, Args: args, PinCPUs: r.pin(), Timeout: r.options.Timeout})
		record.WallSeconds = result.WallSeconds
		scanner := bufio.NewScanner(strings.NewReader(result.Stdout))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if json.Valid([]byte(line)) && strings.HasPrefix(line, "{") {
				record.Lines = append(record.Lines, json.RawMessage(line))
			}
		}
		if result.Failure != "" || result.ExitCode != 0 {
			record.Error = fmt.Sprintf("exit %d %s: %s", result.ExitCode, result.Failure, firstLine(result.Stderr))
		}
	}
	r.results.EnginePerfRuns = append(r.results.EnginePerfRuns, record)
	r.logf("%s %s engine_perf w%d %.3fs lines=%d %s", config.ID, op, workers, record.WallSeconds, len(record.Lines), record.Error)
	_ = os.RemoveAll(base)
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// ReadResults loads a results.json.
func ReadResults(path string) (*Results, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var results Results
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if results.Schema != ResultsSchema {
		return nil, fmt.Errorf("%s: schema %q, want %q", path, results.Schema, ResultsSchema)
	}
	return &results, nil
}

// CollectMachine extends the shared host description with a usable CPU name
// on Linux and Windows, where `sysctl machdep.cpu.brand_string` does not exist.
func CollectMachine(ctx context.Context, label string) bench.Machine {
	machine := bench.CollectMachine(ctx, label, "")
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if key, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) == "model name" {
					machine.CPU = strings.TrimSpace(value)
					break
				}
			}
		}
	}
	if runtime.GOOS == "windows" {
		if name := os.Getenv("PROCESSOR_IDENTIFIER"); name != "" {
			machine.CPU = name
		}
		machine.Kernel = "windows"
	}
	if _, err := exec.LookPath("uname"); err != nil && machine.Kernel == "" {
		machine.Kernel = runtime.GOOS
	}
	return machine
}
