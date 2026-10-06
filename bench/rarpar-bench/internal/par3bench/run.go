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

	// StatusOK, StatusFailed and StatusDNF are the run statuses. DNF ("did not
	// finish") is only ever given to the reference: a reference that exits
	// non-zero, times out, or writes no or truncated carriers is recorded and
	// the matrix carries on. It never fails the run or skips a rarpar row.
	StatusOK     = "ok"
	StatusFailed = "failed"
	StatusDNF    = "dnf"

	// FailureMissingRSS marks a run whose process exited but whose peak RSS
	// the harness did not capture. It is a harness bug, so it fails the run
	// for either tool and is never turned into a reference DNF.
	FailureMissingRSS = "harness-missing-rss"

	// DurabilityDurable is rarpar's default: every output file is synced
	// before the command returns. DurabilityBuffered flushes without
	// requesting storage barriers. The reference never syncs, so it has no
	// durability mode and gets one row.
	DurabilityDurable  = "durable"
	DurabilityBuffered = "buffered"

	// DefaultTimeout bounds every timed process ("per row": a row that hits it
	// is finished, see StatusDNF). Set C Cauchy on the reference otherwise
	// runs for hours.
	DefaultTimeout = 20 * time.Minute

	carrierName = "set.par3"
)

// KnownDurabilities lists the rarpar durability modes, default first.
var KnownDurabilities = []string{DurabilityDurable, DurabilityBuffered}

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
	// Durabilities are the rarpar durability rows for create and repair
	// (default: durable, then buffered). Durable is always included.
	Durabilities []string
	// Timeout bounds every timed process (default DefaultTimeout).
	Timeout time.Duration
	// ReferenceTimeout bounds every reference process (default: Timeout).
	ReferenceTimeout time.Duration
	// Targets are the storage locations every row runs on, interleaved.
	// Empty means one unnamed target at Work.
	Targets []Target
	// Rows selects the timed row kinds (KnownRowKinds). Empty means the
	// reference and rarpar, plus engine when EngineWorkers is set.
	Rows []string
	// EngineWorkers adds timed engine_perf rows (needs EnginePerf), one per
	// worker count and durability; EngineVariants adds env-variant rows of
	// them, as KernelVariants does for rarpar.
	EngineWorkers  []int
	EngineVariants []KernelVariant
	// DropCaches drops the page cache before every timed run (Linux, root).
	DropCaches bool
	Log        io.Writer
}

// Variant is one benchmarked tool configuration.
type Variant struct {
	Name    string   `json:"name"`
	Tool    string   `json:"tool"`
	Workers int      `json:"workers,omitempty"`
	Kernel  string   `json:"kernel,omitempty"`
	Env     []string `json:"env,omitempty"`
	// Durability is "durable" or "buffered" for rarpar rows and empty for
	// the reference. Results written before durability rows existed have it
	// empty on rarpar rows too; those ran durable.
	Durability string `json:"durability,omitempty"`
	// Target is the storage target the row runs on; its name is the
	// suffix after "@" in Name. Empty for a run with one unnamed target.
	Target string `json:"target,omitempty"`
}

// EffectiveDurability is the variant's durability mode: "" for the
// reference, "durable" for a rarpar row that does not say.
func (v Variant) EffectiveDurability() string {
	if v.Tool == ToolReference {
		return ""
	}
	if v.Durability == "" {
		return DurabilityDurable
	}
	return v.Durability
}

// RunsOp reports whether the variant has a row for op. Buffered rows exist
// only for the operations that write: create and repair.
func (v Variant) RunsOp(op string) bool {
	return v.EffectiveDurability() != DurabilityBuffered || op == OpCreate || op == OpRepair
}

// dirName is the variant's short stage-directory name. Stage paths are kept
// short on purpose: see ReferencePathBudget.
func (v Variant) dirName() string {
	if v.Tool == ToolReference {
		return "ref"
	}
	name, _, _ := strings.Cut(v.Name, "@")
	return strings.TrimPrefix(name, "rarpar-")
}

// Variants expands the reference plus every candidate worker/kernel row, each
// rarpar row once per durability mode: the durable (default) row first, named
// as before, then "<name>-buffered". Nil durabilities means both modes.
func Variants(workers []int, kernels []KernelVariant, durabilities []string) []Variant {
	if len(durabilities) == 0 {
		durabilities = KnownDurabilities
	}
	variants := []Variant{{Name: "reference", Tool: ToolReference}}
	add := func(base Variant) {
		for _, durability := range KnownDurabilities {
			if !contains(durabilities, durability) {
				continue
			}
			variant := base
			variant.Durability = durability
			if durability != DurabilityDurable {
				variant.Name += "-" + durability
			}
			variants = append(variants, variant)
		}
	}
	for _, count := range workers {
		add(Variant{Name: fmt.Sprintf("rarpar-w%d", count), Tool: ToolCandidate, Workers: count})
	}
	for _, kernel := range kernels {
		for _, count := range workers {
			add(Variant{
				Name: fmt.Sprintf("rarpar-w%d-%s", count, kernel.Name), Tool: ToolCandidate,
				Workers: count, Kernel: kernel.Name, Env: kernel.Env,
			})
		}
	}
	return variants
}

// EngineRows lists the timed engine_perf rows: one per worker count and
// durability, then one per env variant, named like the rarpar rows.
func EngineRows(workers []int, variants []KernelVariant, durabilities []string) []Variant {
	if len(durabilities) == 0 {
		durabilities = KnownDurabilities
	}
	var rows []Variant
	add := func(base Variant) {
		for _, durability := range KnownDurabilities {
			if !contains(durabilities, durability) {
				continue
			}
			row := base
			row.Durability = durability
			if durability != DurabilityDurable {
				row.Name += "-" + durability
			}
			rows = append(rows, row)
		}
	}
	for _, count := range workers {
		add(Variant{Name: fmt.Sprintf("engine-w%d", count), Tool: ToolEngine, Workers: count})
	}
	for _, variant := range variants {
		for _, count := range workers {
			add(Variant{Name: fmt.Sprintf("engine-w%d-%s", count, variant.Name), Tool: ToolEngine,
				Workers: count, Kernel: variant.Name, Env: variant.Env})
		}
	}
	return rows
}

// MatrixRows is every timed row of a run: the CLI rows and the engine rows,
// filtered to the selected kinds, then once per named target ("NAME@TARGET").
func MatrixRows(workers []int, kernels []KernelVariant, durabilities []string,
	engineWorkers []int, engineVariants []KernelVariant, kinds []string, targets []Target) []Variant {
	all := append(Variants(workers, kernels, durabilities), EngineRows(engineWorkers, engineVariants, durabilities)...)
	var rows []Variant
	for _, row := range all {
		if len(kinds) == 0 || contains(kinds, row.Tool) {
			rows = append(rows, row)
		}
	}
	if len(targets) == 0 || (len(targets) == 1 && targets[0].Name == "") {
		return rows
	}
	var expanded []Variant
	for _, target := range targets {
		for _, row := range rows {
			row.Name += "@" + target.Name
			row.Target = target.Name
			expanded = append(expanded, row)
		}
	}
	return expanded
}

// ValidatePinCPUs accepts an empty value, one CPU "N", or an inclusive range
// "N-M". That is the form both pinning paths apply as given (Linux taskset,
// the Windows affinity mask), so a value either takes effect or is refused
// here; a list such as "0,2" would be honoured by taskset and silently
// dropped by the Windows mask while the results still claimed a pin.
func ValidatePinCPUs(pin string) error {
	if pin == "" {
		return nil
	}
	low, high, ranged := strings.Cut(pin, "-")
	if !ranged {
		high = low
	}
	first, err1 := strconv.Atoi(low)
	last, err2 := strconv.Atoi(high)
	if err1 != nil || err2 != nil || first < 0 || last < first {
		return fmt.Errorf("--pin-cpus %q: want one CPU N or an inclusive range N-M", pin)
	}
	if last >= 64 {
		return fmt.Errorf("--pin-cpus %q: CPUs above 63 cannot be pinned (the Windows affinity mask is 64 bits)", pin)
	}
	return nil
}

// CheckVariantNames refuses a matrix with two rows of the same name, such as
// "--workers 1,1" or a kernel variant listed twice: their runs would merge
// into one row and every repeat count and median would be wrong.
func CheckVariantNames(variants []Variant) error {
	seen := map[string]bool{}
	for _, variant := range variants {
		if seen[variant.Name] {
			return fmt.Errorf("row %q appears twice in the matrix; list each worker count and kernel variant once", variant.Name)
		}
		seen[variant.Name] = true
	}
	return nil
}

// ParseDurabilities reads a comma-separated durability list. Durable is the
// default mode and is always measured.
func ParseDurabilities(text string) ([]string, error) {
	var modes []string
	for _, field := range strings.Split(text, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if !contains(KnownDurabilities, field) {
			return nil, fmt.Errorf("unknown durability %q (known: %s)", field, strings.Join(KnownDurabilities, ", "))
		}
		if !contains(modes, field) {
			modes = append(modes, field)
		}
	}
	if len(modes) == 0 {
		return append([]string(nil), KnownDurabilities...), nil
	}
	if !contains(modes, DurabilityDurable) {
		return nil, fmt.Errorf("durability %q must include %q: it is rarpar's default and every ratio starts from it", text, DurabilityDurable)
	}
	return modes, nil
}

// RowsByOp lists, per operation, the row names a matrix produces.
func RowsByOp(variants []Variant, ops []string) map[string][]string {
	rows := map[string][]string{}
	for _, op := range ops {
		for _, variant := range variants {
			if variant.RunsOp(op) {
				rows[op] = append(rows[op], variant.Name)
			}
		}
	}
	return rows
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
	Config  string `json:"config"`
	Op      string `json:"op"`
	Variant string `json:"variant"`
	Tool    string `json:"tool"`
	Workers int    `json:"workers,omitempty"`
	Kernel  string `json:"kernel,omitempty"`
	// Durability is the rarpar durability mode ("durable"/"buffered"); empty
	// for the reference.
	Durability string `json:"durability,omitempty"`
	// Canonical marks the untimed reference create that seeds the canonical
	// carriers. It is only recorded when it did not finish (StatusDNF).
	Canonical bool   `json:"canonical,omitempty"`
	Warmup    bool   `json:"warmup"`
	Repeat    int    `json:"repeat"`
	Position  int    `json:"position"`
	Command   string `json:"command"`
	// Target and Storage say where the run's bytes lived; NFS is the NFS
	// client's counters moved during the run (only on an NFS target),
	// Engine the engine's own disk-work counters (engine rows only), and
	// LoadAverage the 1-minute load average of the machine the harness ran
	// on, sampled just before the run.
	Target      string          `json:"target,omitempty"`
	Storage     *Storage        `json:"storage,omitempty"`
	NFS         *NFSStats       `json:"nfs,omitempty"`
	Engine      *EngineCounters `json:"engine,omitempty"`
	LoadAverage float64         `json:"load_average,omitempty"`
	DropCaches  bool            `json:"drop_caches,omitempty"`
	Measurement
	// Status is "ok", "failed" or "dnf" (reference only). A reference run is
	// "failed" when it ran but contradicted itself or the harness
	// (reference-nondeterministic, repair-mismatch, start-failed,
	// harness-missing-rss); those fail the run.
	Status     string `json:"status"`
	Failure    string `json:"failure,omitempty"`
	Error      string `json:"error,omitempty"`
	StderrTail string `json:"stderr_tail,omitempty"`
	// StderrLine is the last non-empty line the process printed (stderr,
	// else stdout), recorded for every run that did not finish cleanly.
	StderrLine string       `json:"stderr_line,omitempty"`
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
	Durability  string            `json:"durability,omitempty"`
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
	// CanonicalSource is the tool whose create produced the carriers every
	// verify and repair read: "reference" normally, "rarpar" when the
	// reference's seed create did not finish.
	CanonicalSource string `json:"canonical_source,omitempty"`
}

// Results is the evidence document a run writes.
type Results struct {
	Schema         string          `json:"schema"`
	StartedUTC     string          `json:"started_utc"`
	FinishedUTC    string          `json:"finished_utc"`
	Machine        bench.Machine   `json:"machine"`
	Profile        string          `json:"profile"`
	Ops            []string        `json:"ops"`
	Warmups        int             `json:"warmups"`
	Repeats        int             `json:"repeats"`
	Workers        []int           `json:"workers"`
	PinCPUs        string          `json:"pin_cpus,omitempty"`
	PinApplied     bool            `json:"pin_applied"`
	KernelVariants []KernelVariant `json:"kernel_variants,omitempty"`
	CandidateArgs  []string        `json:"candidate_args,omitempty"`
	// Durabilities are the rarpar durability modes measured for create and
	// repair, default first. BufferedArgs records, per op, the arguments that
	// selected buffered output on this candidate; an op the candidate cannot
	// run buffered is missing and listed in BufferedUnsupported.
	Durabilities        []string            `json:"durabilities,omitempty"`
	BufferedArgs        map[string][]string `json:"buffered_args,omitempty"`
	BufferedUnsupported []string            `json:"buffered_unsupported,omitempty"`
	// TimeoutSeconds / ReferenceTimeoutSeconds bound each timed process.
	TimeoutSeconds          float64   `json:"timeout_seconds,omitempty"`
	ReferenceTimeoutSeconds float64   `json:"reference_timeout_seconds,omitempty"`
	Reference               Binary    `json:"reference"`
	Candidate               Binary    `json:"candidate"`
	EnginePerf              *Binary   `json:"engine_perf,omitempty"`
	Variants                []Variant `json:"variants"`
	// Targets describes each storage target's mount; DropCaches records
	// that every timed run started with an empty page cache.
	Targets        []Storage          `json:"targets,omitempty"`
	DropCaches     bool               `json:"drop_caches,omitempty"`
	Rows           []string           `json:"rows,omitempty"`
	EngineWorkers  []int              `json:"engine_workers,omitempty"`
	EngineVariants []KernelVariant    `json:"engine_variants,omitempty"`
	Configs        []ConfigSummary    `json:"configs"`
	Runs           []RunRecord        `json:"runs"`
	IOCounts       []IOCountRecord    `json:"io_counts,omitempty"`
	EnginePerfRuns []EnginePerfRecord `json:"engine_perf_runs,omitempty"`
	Notes          []string           `json:"notes,omitempty"`
	// DNF lists every reference row that did not finish. DNF rows do not
	// change Status.
	DNF      []string `json:"dnf,omitempty"`
	Status   string   `json:"status"`
	Failures []string `json:"failures,omitempty"`
}

type runner struct {
	options  Options
	results  *Results
	journal  *os.File
	guards   map[string]Binary
	failures []string
	// finished marks config/op/variant rows that already ended in DNF; their
	// remaining runs are skipped.
	finished map[string]bool
	// storage describes options.Targets, index for index.
	storage []Storage
}

// targetState is one target's directories for the configuration being run.
type targetState struct {
	storage   Storage
	dataDir   string
	canonical string
	stageRoot string
	// damaged holds a damaged copy of the dataset that read-only damaged
	// stages hard-link from, so they need no private copy per run.
	damaged string
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
		Variants: MatrixRows(options.Workers, options.KernelVariants, options.Durabilities,
			options.EngineWorkers, options.EngineVariants, options.Rows, options.Targets),
		Durabilities:   options.Durabilities,
		DropCaches:     options.DropCaches,
		Rows:           options.Rows,
		EngineWorkers:  options.EngineWorkers,
		EngineVariants: options.EngineVariants,
		BufferedArgs:   map[string][]string{},

		TimeoutSeconds:          options.Timeout.Seconds(),
		ReferenceTimeoutSeconds: options.ReferenceTimeout.Seconds(),
	}
	r := &runner{options: options, results: results, journal: journal, guards: map[string]Binary{}, finished: map[string]bool{}}
	for i, target := range options.Targets {
		if err := os.MkdirAll(target.Work, 0o755); err != nil {
			return nil, err
		}
		storage := DescribeStorage(target)
		r.storage = append(r.storage, storage)
		results.Targets = append(results.Targets, storage)
		r.logf("target %q: %s at %s (%s) %s", target.Name, storage.StorageLabel(), storage.MountPoint, storage.Source, storage.NFSOptions)
		if i > 0 && !contains(options.Rows, ToolReference) {
			// Only the first target's work path seeds the canonical set.
			continue
		}
		for _, warning := range referencePathWarnings(options.Profile, target.Work) {
			r.logf("WARNING: %s", warning)
			results.Notes = append(results.Notes, "work path: "+warning)
		}
	}
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
	if err := r.probeBuffered(ctx); err != nil {
		return nil, err
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
		if err := r.runConfig(ctx, config, dataset, &results.Configs[len(results.Configs)-1]); err != nil {
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
	results.Status = StatusOK
	if len(r.failures) > 0 {
		results.Status = StatusFailed
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
	if (options.Work == "" && len(options.Targets) == 0) || options.Out == "" {
		return errors.New("--work (or --target) and --out are required")
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
	durabilities, err := ParseDurabilities(strings.Join(options.Durabilities, ","))
	if err != nil {
		return err
	}
	options.Durabilities = durabilities
	if options.Timeout < 0 || options.ReferenceTimeout < 0 {
		return errors.New("timeouts cannot be negative")
	}
	if options.Timeout == 0 {
		options.Timeout = DefaultTimeout
	}
	if options.ReferenceTimeout == 0 {
		options.ReferenceTimeout = options.Timeout
	}
	if err := options.Profile.Validate(); err != nil {
		return err
	}
	if err := ValidatePinCPUs(options.PinCPUs); err != nil {
		return err
	}
	if len(options.Rows) == 0 {
		options.Rows = []string{ToolReference, ToolCandidate}
		if len(options.EngineWorkers) > 0 {
			options.Rows = append(options.Rows, ToolEngine)
		}
	}
	for _, kind := range options.Rows {
		if !contains(KnownRowKinds, kind) {
			return fmt.Errorf("unknown row kind %q (known: %s)", kind, strings.Join(KnownRowKinds, ", "))
		}
	}
	if contains(options.Rows, ToolEngine) {
		if options.EnginePerf == "" || len(options.EngineWorkers) == 0 {
			return errors.New("engine rows need --engine-perf and --engine-workers")
		}
		for _, workers := range options.EngineWorkers {
			if workers < 1 {
				return fmt.Errorf("engine worker count %d must be at least 1", workers)
			}
		}
	}
	if len(options.Targets) == 0 {
		options.Targets = []Target{{Work: options.Work}}
	}
	names := map[string]bool{}
	for i := range options.Targets {
		target := &options.Targets[i]
		if len(options.Targets) > 1 && target.Name == "" {
			return errors.New("every target of a multi-target run needs a name")
		}
		if names[target.Name] {
			return fmt.Errorf("target %q listed twice", target.Name)
		}
		names[target.Name] = true
		if target.Work == "" {
			return fmt.Errorf("target %q has no work directory", target.Name)
		}
		absolute, err := filepath.Abs(target.Work)
		if err != nil {
			return err
		}
		target.Work = absolute
	}
	if options.Work == "" {
		options.Work = options.Targets[0].Work
	}
	if options.DropCaches {
		if ok, why := DropCachesSupported(); !ok {
			return errors.New("--drop-caches: " + why)
		}
	}
	rows := MatrixRows(options.Workers, options.KernelVariants, options.Durabilities,
		options.EngineWorkers, options.EngineVariants, options.Rows, options.Targets)
	if len(rows) == 0 {
		return errors.New("the selected row kinds leave no row to run")
	}
	if err := CheckVariantNames(rows); err != nil {
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
	return nil
}

// probeBuffered finds out how this candidate selects buffered output for each
// writing op, from its own --help. An op whose help lists no --buffered flag
// gets no buffered row: running the durable command twice under a buffered
// label would be a lie.
func (r *runner) probeBuffered(ctx context.Context) error {
	if !contains(r.options.Durabilities, DurabilityBuffered) {
		return nil
	}
	for _, op := range []string{OpCreate, OpRepair} {
		if !contains(r.options.Ops, op) {
			continue
		}
		result := Run(ctx, Command{Path: r.options.Candidate, Args: []string{"par3", op, "--help"}, Timeout: 30 * time.Second})
		if result.Failure == "binary-quarantined" {
			return r.quarantined(ctx, r.options.Candidate, "refused to start: "+fmt.Sprint(result.Err))
		}
		if result.Failure != "" || result.ExitCode != 0 {
			// A help screen that did not print says nothing about the flag;
			// guessing "unsupported" would silently drop the buffered rows.
			return fmt.Errorf("probing `%s par3 %s --help` for --buffered failed (%s, exit %d): %s",
				r.options.Candidate, op, firstNonEmpty(result.Failure, "exit"), result.ExitCode, lastLine(result))
		}
		if helpListsFlag(result.Stdout+result.Stderr, "--buffered") {
			r.results.BufferedArgs[op] = []string{"--buffered"}
			continue
		}
		r.results.BufferedUnsupported = append(r.results.BufferedUnsupported, op)
		note := fmt.Sprintf("buffered %s rows not run: `rarpar par3 %s --help` on this candidate lists no --buffered flag, so only its durable %s row exists", op, op, op)
		if r.options.EnginePerf != "" {
			note += fmt.Sprintf("; the untimed engine_perf pass still measures buffered %s (PAR3_BENCH_%s_DURABILITY=buffered)", op, strings.ToUpper(op))
		}
		r.results.Notes = append(r.results.Notes, note)
		r.logf("%s", note)
	}
	return nil
}

// helpListsFlag matches flag as a whole token of a help screen, so
// "--buffered-io" or "--no-buffered" does not count as "--buffered".
func helpListsFlag(help, flag string) bool {
	for _, token := range strings.FieldsFunc(help, func(c rune) bool {
		return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == '[' || c == ']' || c == '=' || c == '|' || c == '<' || c == '(' || c == ')'
	}) {
		if token == flag {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// runsOp reports whether variant has a row for op on this candidate.
func (r *runner) runsOp(variant Variant, op string) bool {
	if !variant.RunsOp(op) {
		return false
	}
	if variant.EffectiveDurability() == DurabilityBuffered {
		return r.results.BufferedArgs[op] != nil
	}
	return true
}

func (r *runner) timeoutFor(tool string) time.Duration {
	if tool == ToolReference {
		return r.options.ReferenceTimeout
	}
	return r.options.Timeout
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
	if record.Canonical {
		phase = "canonical-seed"
	}
	if record.Status != StatusOK && record.Failure != "" {
		extra += " " + record.Failure
	}
	r.logf("%s %s %s %s#%d %.3fs user=%.3fs sys=%.3fs rss=%dMiB exit=%d %s%s",
		record.Config, record.Op, record.Variant, phase, record.Repeat, record.WallSeconds,
		record.UserSeconds, record.SysSeconds, record.MaxRSSBytes>>20, record.ExitCode, record.Status, extra)
}

func (r *runner) runConfig(ctx context.Context, config Config, dataset Dataset, summary *ConfigSummary) error {
	if err := r.checkBinaries(ctx); err != nil {
		return err
	}
	states := map[string]*targetState{}
	var first *targetState
	var manifest DatasetManifest
	for i, target := range r.options.Targets {
		state := &targetState{
			storage:   r.storage[i],
			dataDir:   filepath.Join(target.Work, "data", dataset.ID),
			canonical: filepath.Join(target.Work, "k", config.ID),
			stageRoot: filepath.Join(target.Work, "s", config.ID),
		}
		var err error
		if manifest, err = EnsureDataset(state.dataDir, dataset, r.logf); err != nil {
			return fmt.Errorf("dataset %s on target %q: %w", dataset.ID, target.Name, err)
		}
		if err := os.RemoveAll(state.stageRoot); err != nil {
			return err
		}
		if !r.options.KeepStages {
			defer os.RemoveAll(state.stageRoot)
		}
		states[target.Name] = state
		if first == nil {
			first = state
		}
	}

	// The canonical carriers: one untimed reference create on the first
	// target, copied to the others. Every identity check compares against it,
	// and every verify and repair, ours included, reads it, so both tools
	// always work from the same recovery set on every target.
	canonicalSet, source, err := r.seedCanonical(ctx, config, dataset, first.dataDir, first.canonical)
	if err != nil {
		return err
	}
	summary.CanonicalSource = source
	for _, state := range states {
		if state == first {
			continue
		}
		if err := copyDir(first.canonical, state.canonical); err != nil {
			return fmt.Errorf("copying the canonical carriers: %w", err)
		}
	}
	if contains(r.options.Ops, OpVerifyDamaged) {
		for _, state := range states {
			state.damaged = filepath.Join(filepath.Dir(filepath.Dir(state.canonical)), "x", config.ID)
			if err := resetDir(state.damaged); err != nil {
				return err
			}
			for _, file := range dataset.Files {
				if err := copyFile(filepath.Join(state.dataDir, file.Name), filepath.Join(state.damaged, file.Name)); err != nil {
					return err
				}
			}
			if err := ApplyDamage(state.damaged, dataset, config.BlockSize, config.Damage); err != nil {
				return err
			}
			defer os.RemoveAll(state.damaged)
		}
	}

	var failed []string
	for _, op := range r.options.Ops {
		if err := r.checkBinaries(ctx); err != nil {
			return err
		}
		var variants []Variant
		for _, variant := range r.results.Variants {
			if r.runsOp(variant, op) {
				variants = append(variants, variant)
			}
		}
		for run := 0; run < r.options.Warmups+r.options.Repeats; run++ {
			order := orderFor(variants, run)
			for position, variant := range order {
				key := rowKey(config.ID, op, variant.Name)
				if r.finished[key] {
					continue
				}
				record, err := r.runOne(ctx, op, config, dataset, manifest, states[variant.Target], canonicalSet, source, variant)
				if err != nil {
					return err
				}
				record.Warmup = run < r.options.Warmups
				record.Repeat = run
				if !record.Warmup {
					record.Repeat = run - r.options.Warmups
				}
				record.Position = position
				if settleRow(&record) {
					r.finished[key] = true
				}
				r.record(record)
				switch record.Status {
				case StatusDNF:
					r.noteDNF(record, r.options.Warmups+r.options.Repeats-run-1)
				case StatusFailed:
					failed = append(failed, fmt.Sprintf("%s/%s/%s: %s", config.ID, op, variant.Name, record.Status))
				}
			}
		}
		// The untimed passes run once, on the first target.
		if r.options.IOCount {
			for _, variant := range variants {
				if variant.Tool != ToolEngine && variant.Target == r.options.Targets[0].Name {
					r.countIO(ctx, op, config, dataset, manifest, first.dataDir, first.canonical, first.stageRoot, variant)
				}
			}
		}
		if r.options.EnginePerf != "" && !contains(r.options.Rows, ToolEngine) {
			for _, workers := range r.options.Workers {
				for _, durability := range r.enginePerfDurabilities(op) {
					r.enginePerf(ctx, op, config, dataset, first.dataDir, first.canonical, first.stageRoot, workers, durability)
				}
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d run(s) failed: %s", len(failed), strings.Join(dedupe(failed), "; "))
	}
	return nil
}

// copyDir copies every regular file of source into a fresh destination.
func copyDir(source, destination string) error {
	if err := resetDir(destination); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		if err := copyFile(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func rowKey(config, op, variant string) string { return config + "/" + op + "/" + variant }

// seedCanonical writes the canonical carriers with the reference. When the
// reference does not finish, the seed is recorded as the reference create
// row's DNF and rarpar writes the canonical carriers instead, so every rarpar
// row still runs; identity verdicts are then unavailable for the set.
func (r *runner) seedCanonical(ctx context.Context, config Config, dataset Dataset, dataDir, canonical string) (CarrierSet, string, error) {
	if err := resetDir(canonical); err != nil {
		return CarrierSet{}, "", err
	}
	reference := Variant{Name: "reference", Tool: ToolReference}
	command := r.createCommand(config, dataset, dataDir, canonical, reference)
	seed := Run(ctx, command)
	if seed.Failure == "binary-quarantined" {
		return CarrierSet{}, "", r.quarantined(ctx, r.options.Reference, "refused to start")
	}
	failure, detail := referenceCreateProblem(seed, canonical, config)
	if failure == "" {
		set, err := ReadCarrierSet(canonical)
		return set, ToolReference, err
	}
	if err := ctx.Err(); err != nil {
		return CarrierSet{}, "", err
	}
	if !IsDNFFailure(failure) {
		return CarrierSet{}, "", fmt.Errorf("%s: the reference's canonical create failed (%s): %s %s", config.ID, failure, detail, lastLine(seed))
	}
	record := RunRecord{
		Config: config.ID, Op: OpCreate, Variant: reference.Name, Tool: ToolReference, Canonical: true, Warmup: true,
		Command: command.Describe(), Measurement: seed.Measurement, Status: StatusDNF, Failure: failure, Error: detail,
		StderrTail: seed.Stderr, StderrLine: lastLine(seed),
	}
	r.record(record)
	if contains(r.options.Ops, OpCreate) {
		// The timed reference create would repeat the same failure (or the
		// same timeout); its row is this DNF.
		for _, variant := range r.results.Variants {
			if variant.Tool == ToolReference {
				r.finished[rowKey(config.ID, OpCreate, variant.Name)] = true
			}
		}
	}
	r.noteDNF(record, -1)

	workers := 1
	for _, count := range r.options.Workers {
		if count > workers {
			workers = count
		}
	}
	fallback := Variant{Name: "rarpar-canonical", Tool: ToolCandidate, Workers: workers, Durability: DurabilityDurable}
	if err := resetDir(canonical); err != nil {
		return CarrierSet{}, "", err
	}
	result := Run(ctx, r.createCommand(config, dataset, dataDir, canonical, fallback))
	if result.Failure != "" || result.ExitCode != 0 {
		if result.Failure == "binary-quarantined" {
			return CarrierSet{}, "", r.quarantined(ctx, r.options.Candidate, "refused to start")
		}
		return CarrierSet{}, "", fmt.Errorf("the reference did not finish the canonical create and rarpar's fallback create failed too (exit %d %s): %s",
			result.ExitCode, result.Failure, lastLine(result))
	}
	set, err := ReadCarrierSet(canonical)
	if err != nil {
		return CarrierSet{}, "", fmt.Errorf("rarpar's fallback canonical carriers: %w", err)
	}
	if len(set.Files) == 0 {
		return CarrierSet{}, "", errors.New("rarpar's fallback canonical create wrote no carriers")
	}
	r.results.Notes = append(r.results.Notes, fmt.Sprintf("%s: the reference did not finish the canonical create, so rarpar (durable, %d workers) wrote the carriers every verify and repair read; create identity verdicts are unavailable for this set", config.ID, workers))
	return set, ToolCandidate, nil
}

// settleRow applies the row rules to one finished run and reports whether
// its row is over. A reference that did not finish (IsDNFFailure) becomes
// DNF: recorded once, the row stops, and nothing about it fails the run. A
// rarpar run past its timeout stays failed and its row stops too, since every
// remaining run would only time out again.
func settleRow(record *RunRecord) bool {
	if record.Status == StatusOK {
		return false
	}
	if record.Tool == ToolReference && IsDNFFailure(record.Failure) {
		record.Status = StatusDNF
		return true
	}
	return record.Tool == ToolCandidate && record.Failure == "timeout"
}

// IsDNFFailure reports whether a reference failure class means "did not
// finish": it timed out, was killed, exited non-zero, or left missing, short
// or unreadable carriers. Every other class (start-failed,
// reference-nondeterministic, repair-mismatch, harness-missing-rss) means the
// reference or the harness misbehaved, and that fails the run.
func IsDNFFailure(failure string) bool {
	switch failure {
	case "timeout", "signal", "no-carriers", "truncated-carriers", "unreadable-carriers":
		return true
	}
	return strings.HasPrefix(failure, "exit-")
}

// referenceCreateProblem classifies a reference create that did not finish:
// a failed or timed-out process, a non-zero exit, or carriers that are
// missing, unreadable or short of the requested recovery blocks.
func referenceCreateProblem(result Result, dir string, config Config) (string, string) {
	if result.Failure != "" {
		return result.Failure, fmt.Sprint(result.Err)
	}
	if result.ExitCode != 0 {
		return fmt.Sprintf("exit-%d", result.ExitCode), ""
	}
	set, err := ReadCarrierSet(dir)
	if err != nil {
		return "unreadable-carriers", err.Error()
	}
	if len(set.Files) == 0 {
		return "no-carriers", "the reference exited 0 but wrote no .par3 files"
	}
	if got := int64(len(set.recovery)); got != config.Recovery {
		return "truncated-carriers", fmt.Sprintf("%d of %d recovery blocks present", got, config.Recovery)
	}
	return "", ""
}

// noteDNF lists a DNF row in the results and the log.
func (r *runner) noteDNF(record RunRecord, skipped int) {
	text := fmt.Sprintf("%s/%s/%s: DNF %s", record.Config, record.Op, record.Variant, describeDNF(record))
	if record.Canonical {
		text += " (canonical seed create)"
	}
	if skipped > 0 {
		text += fmt.Sprintf("; its %d remaining run(s) skipped", skipped)
	}
	r.results.DNF = append(r.results.DNF, text)
	r.logf("%s", text)
}

// describeDNF is "exit 6: <stderr line>", "timeout after 20m0s", and so on.
func describeDNF(record RunRecord) string {
	var text string
	switch {
	case record.Failure == "timeout":
		text = "timeout after " + time.Duration(record.WallSeconds*float64(time.Second)).Round(time.Millisecond).String()
	case strings.HasPrefix(record.Failure, "exit-"):
		text = "exit " + strings.TrimPrefix(record.Failure, "exit-")
	default:
		text = fmt.Sprintf("%s (exit %d)", record.Failure, record.ExitCode)
	}
	if record.Error != "" && record.Failure != "timeout" {
		text += " (" + record.Error + ")"
	}
	if record.StderrLine != "" {
		text += ": " + record.StderrLine
	}
	return text
}

// lastLine is the last non-empty output line: stderr first, else stdout.
func lastLine(result Result) string {
	for _, text := range []string{result.Stderr, result.Stdout} {
		lines := strings.Split(strings.TrimSpace(text), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if line := strings.TrimSpace(lines[i]); line != "" {
				return line
			}
		}
	}
	return ""
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
		return Command{Path: r.options.Reference, Args: args, Dir: dataDir, PinCPUs: r.pin(), Timeout: r.timeoutFor(ToolReference)}
	}
	args := append(r.candidateGlobals(variant), "par3", "create", output)
	args = append(args, names...)
	args = append(args, "--base-path", dataDir,
		"-s", strconv.FormatInt(config.BlockSize, 10),
		"-c", strconv.FormatInt(config.Recovery, 10))
	if config.Codec == "fft" {
		args = append(args, "--codec", "fft", "--capacity-log2", strconv.Itoa(config.CapacityLog2()))
	}
	args = append(args, r.durabilityArgs(OpCreate, variant)...)
	return Command{Path: r.options.Candidate, Args: args, Dir: dataDir, Env: variant.Env, PinCPUs: r.pin(), Timeout: r.timeoutFor(ToolCandidate)}
}

// durabilityArgs selects buffered output for a buffered rarpar row; the
// durable row runs the CLI's default.
func (r *runner) durabilityArgs(op string, variant Variant) []string {
	if variant.EffectiveDurability() != DurabilityBuffered {
		return nil
	}
	return r.results.BufferedArgs[op]
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
		return Command{Path: r.options.Reference, Args: []string{letter, "-q", carrierName}, Dir: stage, PinCPUs: r.pin(), Timeout: r.timeoutFor(ToolReference)}
	}
	sub := "verify"
	if op == OpRepair {
		sub = "repair"
	}
	args := append(r.candidateGlobals(variant), "par3", sub, carrierName)
	if op == OpRepair {
		args = append(args, r.durabilityArgs(OpRepair, variant)...)
	}
	return Command{Path: r.options.Candidate, Args: args, Dir: stage, Env: variant.Env, PinCPUs: r.pin(), Timeout: r.timeoutFor(ToolCandidate)}
}

// stage lays out a verify or repair directory: inputs (linked when the op
// cannot write, private copies when it can or when damage is applied) and
// the canonical carriers.
func stage(dir string, dataset Dataset, dataDir, canonical string, config Config, op string) error {
	return stageFrom(dir, dataset, dataDir, canonical, config, op, "")
}

// stageFrom is stage with an optional pre-damaged copy of the inputs: a
// verify-damaged stage then hard-links them instead of copying and damaging
// a private copy per run, since nothing writes to them.
func stageFrom(dir string, dataset Dataset, dataDir, canonical string, config Config, op, damaged string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	inputs := dataDir
	if op == OpVerifyDamaged && damaged != "" {
		inputs = damaged
	}
	private := op == OpRepair || (op == OpVerifyDamaged && damaged == "")
	for _, file := range dataset.Files {
		source, destination := filepath.Join(inputs, file.Name), filepath.Join(dir, file.Name)
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
	if op == OpRepair || (op == OpVerifyDamaged && damaged == "") {
		return ApplyDamage(dir, dataset, config.BlockSize, config.Damage)
	}
	return nil
}

func (r *runner) runOne(ctx context.Context, op string, config Config, dataset Dataset, manifest DatasetManifest,
	state *targetState, canonicalSet CarrierSet, canonicalSource string, variant Variant) (RunRecord, error) {
	storage := state.storage
	record := RunRecord{Config: config.ID, Op: op, Variant: variant.Name, Tool: variant.Tool, Workers: variant.Workers, Kernel: variant.Kernel,
		Durability: variant.EffectiveDurability(), Target: variant.Target, Storage: &storage, DropCaches: r.options.DropCaches}
	dir := filepath.Join(state.stageRoot, op+"-"+variant.dirName())
	if !r.options.KeepStages {
		// One stage at a time: a large set staged once per row and op would
		// otherwise hold many private copies of its inputs at once.
		defer os.RemoveAll(dir)
		defer os.RemoveAll(dir + "-spool")
	}
	var command Command
	if op == OpCreate {
		if err := resetDir(dir); err != nil {
			return record, err
		}
		if variant.Tool == ToolEngine {
			if err := resetDir(dir + "-spool"); err != nil {
				return record, err
			}
			command = r.engineCommand(op, config, state.dataDir, dir, variant)
		} else {
			command = r.createCommand(config, dataset, state.dataDir, dir, variant)
		}
	} else {
		if err := stageFrom(dir, dataset, state.dataDir, state.canonical, config, op, state.damaged); err != nil {
			return record, err
		}
		if variant.Tool == ToolEngine {
			command = r.engineCommand(op, config, state.dataDir, dir, variant)
		} else {
			command = r.checkCommand(op, dir, variant)
		}
	}
	record.Command = command.Describe()
	if r.options.DropCaches {
		if err := DropCaches(); err != nil {
			return record, fmt.Errorf("--drop-caches: %w", err)
		}
	}
	record.LoadAverage = LoadAverage()
	var nfsBefore NFSStats
	watchNFS := false
	if storage.IsNFS() {
		nfsBefore, watchNFS = readNFSStats(storage.MountPoint)
	}
	result := Run(ctx, command)
	if watchNFS {
		if after, ok := readNFSStats(storage.MountPoint); ok {
			delta := after.Sub(nfsBefore)
			record.NFS = &delta
		}
	}
	record.Measurement = result.Measurement
	record.Status = StatusOK
	if variant.Tool == ToolEngine {
		if counters, ok := ParseEngineOutput(result.Stdout); ok {
			record.Engine = &counters
		}
	}
	if result.Failure != "" {
		record.Status = StatusFailed
		record.Failure = result.Failure
		record.Error = fmt.Sprint(result.Err)
		record.StderrTail = result.Stderr
		record.StderrLine = lastLine(result)
		if result.Failure == "binary-quarantined" {
			return record, r.quarantined(ctx, command.Path, "refused to start: "+fmt.Sprint(result.Err))
		}
		if result.Failure == "timeout" && ctx.Err() != nil {
			// The whole run was cancelled, not this row.
			return record, ctx.Err()
		}
		return record, nil
	}
	accepted := result.ExitCode == 0
	if variant.Tool == ToolEngine && record.Engine == nil && accepted {
		// engine_perf prints its totals last; without them the op did not
		// complete as the row claims.
		accepted = false
	}
	if op == OpVerifyDamaged && variant.Tool != ToolEngine {
		// Damage is expected to be detected. The reference exits 0 once it
		// finds the damage repairable; rarpar exits 1 for "repair needed".
		// Either is a clean verdict; anything else is a failure.
		accepted = result.ExitCode == 0 || result.ExitCode == 1
	}
	if !accepted {
		record.Status = StatusFailed
		record.Failure = fmt.Sprintf("exit-%d", result.ExitCode)
		record.StderrTail = result.Stderr
		record.StderrLine = lastLine(result)
		return record, nil
	}
	if result.MaxRSSBytes <= 0 {
		// Peak RSS is a required field of every row. A process that ran to
		// exit without one means the harness failed to measure it.
		record.Status = StatusFailed
		record.Failure = FailureMissingRSS
		record.Error = "the process exited but the harness recorded no peak RSS (" + rssSource() + ")"
		return record, nil
	}
	switch op {
	case OpCreate:
		if variant.Tool == ToolReference {
			if failure, detail := referenceCreateProblem(result, dir, config); failure != "" {
				record.Status = StatusFailed
				record.Failure = failure
				record.Error = detail
				record.StderrLine = lastLine(result)
				return record, nil
			}
		}
		set, err := ReadCarrierSet(dir)
		if err != nil {
			record.Status = StatusFailed
			record.Failure = "unreadable-carriers"
			record.Error = err.Error()
			return record, nil
		}
		if canonicalSource != ToolReference {
			// No reference set to compare against.
			break
		}
		identity := CompareCarriers(canonicalSet, set)
		record.Identity = &identity
		if variant.Tool == ToolReference && !identity.Bytes {
			// The reference must reproduce itself; if it does not, nothing
			// compared against it means anything.
			record.Status = StatusFailed
			record.Failure = "reference-nondeterministic"
		}
	case OpRepair:
		check, err := checkRepair(dir, manifest, state.canonical)
		if err != nil {
			return record, err
		}
		record.Repair = &check
		if !check.Match {
			record.Status = StatusFailed
			record.Failure = "repair-mismatch"
			record.StderrTail = result.Stderr
			record.StderrLine = lastLine(result)
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
	dataDir, canonical, stageRoot string, workers int, durability string) {
	if op == OpVerifyDamaged {
		return
	}
	record := EnginePerfRecord{Config: config.ID, Op: op, Workers: workers, Durability: durability}
	memory := strconv.Itoa(r.options.EnginePerfMemoryMiB)
	base := filepath.Join(stageRoot, fmt.Sprintf("engine-perf-%s-w%d-%s", op, workers, durability))
	var env []string
	if durability == DurabilityBuffered {
		// engine_perf's own switches; unset means its sync-files default.
		env = []string{fmt.Sprintf("PAR3_BENCH_%s_DURABILITY=buffered", strings.ToUpper(op))}
	}
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
		result := Run(ctx, Command{Path: r.options.EnginePerf, Args: args, Env: env, PinCPUs: r.pin(), Timeout: r.options.Timeout})
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
	r.logf("%s %s engine_perf w%d %s %.3fs lines=%d %s", config.ID, op, workers, durability, record.WallSeconds, len(record.Lines), record.Error)
	_ = os.RemoveAll(base)
}

// enginePerfDurabilities is the durability modes the untimed engine_perf pass
// covers for op: every requested mode for the writing ops, durable otherwise.
func (r *runner) enginePerfDurabilities(op string) []string {
	if op == OpCreate || op == OpRepair {
		return r.options.Durabilities
	}
	return []string{DurabilityDurable}
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
	if err := ValidateResults(&results); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &results, nil
}

// ValidateResults enforces the required per-row fields. max_rss_bytes is
// required: every run whose status is "ok" must carry a positive peak RSS, and
// a results file with one that does not is invalid.
func ValidateResults(results *Results) error {
	var bad []string
	for _, run := range results.Runs {
		if run.Status == StatusOK && run.MaxRSSBytes <= 0 {
			bad = append(bad, fmt.Sprintf("%s/%s/%s repeat %d", run.Config, run.Op, run.Variant, run.Repeat))
		}
	}
	if len(bad) > 0 {
		shown := bad
		if len(shown) > 5 {
			shown = append(shown[:5:5], fmt.Sprintf("… %d more", len(bad)-5))
		}
		return fmt.Errorf("%d ok run(s) lack the required max_rss_bytes: %s", len(bad), strings.Join(shown, ", "))
	}
	return nil
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
