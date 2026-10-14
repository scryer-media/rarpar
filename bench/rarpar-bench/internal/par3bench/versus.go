package par3bench

// The PAR2-against-PAR3 comparison: the same generated inputs, block size,
// recovery count and damage protected and repaired by PAR2 (rarpar `par`,
// and par2cmdline-turbo where the host has it) and by PAR3 (rarpar `par3`,
// Cauchy and FFT). Each arm writes its own recovery set from the clean
// inputs, then repairs its own set over an identically damaged copy; every
// repair is checked file by file against the generated inputs' SHA-256.
//
// The one ratio scale is par2 ÷ par3 wall time, so a ratio above 1 means the
// PAR3 arm was faster. Peak RSS is reported raw for every arm, never as a
// ratio. The PAR3 arms run buffered, as the PAR3 suite's rarpar rows do (see
// probeBuffered), and never pass --fsync. A PAR3 arm's repair runs in place
// with no backup, as the suite's rarpar-wN rows do, and its repair-only
// `-backup` twin keeps a numbered `.1` backup of every file it repairs, as
// the suite's rarpar-wN-backup rows do (see probeBackup); every repair's
// leftovers are recorded, so the report can say which PAR2 arm each PAR3
// arm is like for like with on bytes written.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/procmeasure"
)

const (
	// VersusSchema names the comparison's results.json layout. v2 added the
	// buffered PAR3 arms' probed arguments, the in-place PAR3 repair arms
	// and their `-backup` twins, and each repair's numbered backups; a v1
	// PAR3 arm may have run durable and kept a backup.
	VersusSchema = "rarpar-par3-versus-v2"

	// ArmPAR2 is rarpar's own PAR2 engine (`rarpar par`).
	ArmPAR2 = "par2-rs"
	// ArmPAR2Turbo is par2cmdline-turbo; it runs only when a binary is given.
	ArmPAR2Turbo = "par2cmdline-turbo"
	// ArmPAR3Cauchy and ArmPAR3FFT are `rarpar par3` with each codec. Their
	// repair runs in place and keeps no backup, the candidate's default.
	ArmPAR3Cauchy = "par3-cauchy"
	ArmPAR3FFT    = "par3-fft"
	// ArmPAR3CauchyBackup and ArmPAR3FFTBackup are their repair-only twins:
	// the same recovery set, repaired keeping a numbered `.1` backup of
	// every file, the compatible behaviour. A profile never lists them; every
	// PAR3 arm brings its twin (see VersusOpArms).
	ArmPAR3CauchyBackup = ArmPAR3Cauchy + backupArmSuffix
	ArmPAR3FFTBackup    = ArmPAR3FFT + backupArmSuffix
	backupArmSuffix     = "-backup"

	// PAR2 limits shared by both PAR2 tools.
	par2MaxSourceBlocks   = 32768
	par2MaxRecoveryBlocks = 32768

	versusPAR2Name = "set.par2"
)

// PAR2Arms and PAR3Arms are the two sides of every ratio, in report order.
var (
	PAR2Arms = []string{ArmPAR2, ArmPAR2Turbo}
	PAR3Arms = []string{ArmPAR3Cauchy, ArmPAR3FFT}
)

// VersusOps are the timed operations, in run order: every arm's create
// writes the set its repair then reads.
var VersusOps = []string{OpCreate, OpRepair}

// VersusOpArms lists the arms that run op, in report order. Every arm runs
// create. At repair each PAR3 arm is followed by its `-backup` twin, which
// repairs the set the PAR3 arm created; on a candidate that cannot repair in
// place (VersusResults.InPlaceUnsupported) the PAR3 arm itself drops out.
func VersusOpArms(arms []string, op string, inPlaceUnsupported bool) []string {
	if op != OpRepair {
		return arms
	}
	var out []string
	for _, arm := range arms {
		if !contains(PAR3Arms, arm) {
			out = append(out, arm)
			continue
		}
		if !inPlaceUnsupported {
			out = append(out, arm)
		}
		out = append(out, arm+backupArmSuffix)
	}
	return out
}

// isPAR3BackupArm reports whether arm is a PAR3 arm's `-backup` twin.
func isPAR3BackupArm(arm string) bool {
	base, ok := strings.CutSuffix(arm, backupArmSuffix)
	return ok && contains(PAR3Arms, base)
}

// versusSetArm is the arm whose create wrote the set arm repairs: a twin
// repairs its PAR3 arm's set, every other arm its own.
func versusSetArm(arm string) string {
	if isPAR3BackupArm(arm) {
		return strings.TrimSuffix(arm, backupArmSuffix)
	}
	return arm
}

// VersusConfig is one comparison: a dataset, one block size and one explicit
// recovery count for every arm, one damage pattern, and the arms that run.
type VersusConfig struct {
	ID        string   `json:"id"`
	Dataset   string   `json:"dataset"`
	BlockSize int64    `json:"block_size"`
	Recovery  int64    `json:"recovery_count"`
	Arms      []string `json:"arms"`
	Damage    Damage   `json:"damage"`
	Note      string   `json:"note,omitempty"`
}

// RecoveryPercent is the recovery count as a share of the PAR3 input blocks.
func (c VersusConfig) RecoveryPercent(dataset Dataset) float64 {
	return 100 * float64(c.Recovery) / float64(InputBlocks(dataset, c.BlockSize))
}

// par3Config is the PAR3 view of the comparison for one codec, so the
// command line is built exactly as the PAR3 suite builds it.
func (c VersusConfig) par3Config(codec string) Config {
	return Config{ID: c.ID, Dataset: c.Dataset, BlockSize: c.BlockSize, Recovery: c.Recovery, Codec: codec, Damage: c.Damage}
}

// VersusProfile is a named set of comparisons.
type VersusProfile struct {
	Name     string         `json:"name"`
	Datasets []Dataset      `json:"datasets"`
	Configs  []VersusConfig `json:"configs"`
}

// Dataset returns the named dataset.
func (p VersusProfile) Dataset(id string) (Dataset, bool) {
	for _, dataset := range p.Datasets {
		if dataset.ID == id {
			return dataset, true
		}
	}
	return Dataset{}, false
}

// ConfigIDs lists the profile's comparison IDs in order.
func (p VersusProfile) ConfigIDs() []string {
	ids := make([]string, 0, len(p.Configs))
	for _, config := range p.Configs {
		ids = append(ids, config.ID)
	}
	return ids
}

// Select narrows the profile to the named comparisons (all when empty).
func (p VersusProfile) Select(ids []string) (VersusProfile, error) {
	if len(ids) == 0 {
		return p, nil
	}
	selected := VersusProfile{Name: p.Name}
	used := map[string]bool{}
	for _, id := range ids {
		found := false
		for _, config := range p.Configs {
			if config.ID != id {
				continue
			}
			for _, have := range selected.Configs {
				if have.ID == id {
					return VersusProfile{}, fmt.Errorf("set %q is selected more than once", id)
				}
			}
			selected.Configs = append(selected.Configs, config)
			used[config.Dataset] = true
			found = true
		}
		if !found {
			return VersusProfile{}, fmt.Errorf("profile %s has no set %q (known: %s)", p.Name, id, strings.Join(p.ConfigIDs(), ", "))
		}
	}
	for _, dataset := range p.Datasets {
		if used[dataset.ID] {
			selected.Datasets = append(selected.Datasets, dataset)
		}
	}
	return selected, nil
}

// par2SourceBlocks counts PAR2 source blocks: PAR2 never packs file tails.
func par2SourceBlocks(dataset Dataset, blockSize int64) int64 {
	var blocks int64
	for _, file := range dataset.Files {
		blocks += (file.Size + blockSize - 1) / blockSize
	}
	return blocks
}

// Validate checks every comparison: known arms, at least one arm per side,
// shapes inside both formats' limits, and damage every arm can repair.
func (p VersusProfile) Validate() error {
	seen := map[string]bool{}
	for _, config := range p.Configs {
		if seen[config.ID] {
			return fmt.Errorf("duplicate set %q", config.ID)
		}
		seen[config.ID] = true
		dataset, ok := p.Dataset(config.Dataset)
		if !ok {
			return fmt.Errorf("set %s: unknown dataset %q", config.ID, config.Dataset)
		}
		if config.BlockSize <= 0 || config.BlockSize%4 != 0 || config.Recovery <= 0 {
			return fmt.Errorf("set %s: block size must be a positive multiple of 4 (PAR2) and the recovery count positive", config.ID)
		}
		var par2, par3 int
		for _, arm := range config.Arms {
			switch {
			case contains(PAR2Arms, arm):
				par2++
			case contains(PAR3Arms, arm):
				par3++
			default:
				return fmt.Errorf("set %s: unknown arm %q", config.ID, arm)
			}
		}
		if par2 == 0 || par3 == 0 {
			return fmt.Errorf("set %s: needs at least one PAR2 and one PAR3 arm for the par2 ÷ par3 ratio", config.ID)
		}
		if blocks := par2SourceBlocks(dataset, config.BlockSize); blocks > par2MaxSourceBlocks {
			return fmt.Errorf("set %s: %d PAR2 source blocks exceed %d", config.ID, blocks, par2MaxSourceBlocks)
		}
		if config.Recovery > par2MaxRecoveryBlocks {
			return fmt.Errorf("set %s: %d recovery blocks exceed PAR2's %d", config.ID, config.Recovery, par2MaxRecoveryBlocks)
		}
		if blocks := InputBlocks(dataset, config.BlockSize); blocks+config.Recovery > 65536 {
			return fmt.Errorf("set %s: %d PAR3 blocks exceed 65536", config.ID, blocks+config.Recovery)
		}
		if int64(config.Damage.LostBlocks()) > config.Recovery {
			return fmt.Errorf("set %s: damage loses %d blocks but only %d recovery blocks exist", config.ID, config.Damage.LostBlocks(), config.Recovery)
		}
		for _, target := range config.Damage.Targets {
			if target.File < 0 || target.File >= len(dataset.Files) {
				return fmt.Errorf("set %s: damage names file %d of %d", config.ID, target.File, len(dataset.Files))
			}
			if fileBlocks := (dataset.Files[target.File].Size + config.BlockSize - 1) / config.BlockSize; int64(target.Blocks) > fileBlocks {
				return fmt.Errorf("set %s: damage wants %d blocks of a %d-block file", config.ID, target.Blocks, fileBlocks)
			}
		}
	}
	return nil
}

var (
	allArms = []string{ArmPAR2, ArmPAR2Turbo, ArmPAR3Cauchy, ArmPAR3FFT}
	fftArms = []string{ArmPAR2, ArmPAR2Turbo, ArmPAR3FFT}
)

// versusSmokeProfile runs every arm and every kind of row on a few MiB, in
// seconds: it proves the rows run and repair, and measures nothing.
func versusSmokeProfile() VersusProfile {
	smoke := Dataset{ID: "vsmoke", Files: []FileSpec{
		{Name: "v0.bin", Size: 3 * MiB},
		{Name: "v1.bin", Size: 1*MiB + 777},
	}}
	return VersusProfile{
		Name:     "versus-smoke",
		Datasets: []Dataset{smoke},
		Configs: []VersusConfig{
			{
				ID: "vs-equal", Dataset: "vsmoke", BlockSize: 64 * KiB, Recovery: 8, Arms: allArms,
				Damage: spread("lost-4x64k-2files", []int{0, 1}, 2),
				Note:   "every arm at one recovery count",
			},
			{
				ID: "vs-fft10", Dataset: "vsmoke", BlockSize: 16 * KiB, Recovery: 26, Arms: fftArms,
				Damage: spread("lost-16x16k-2files", []int{0, 1}, 8),
				Note:   "FFT-only row, 10% recovery",
			},
			{
				ID: "vs-fft30", Dataset: "vsmoke", BlockSize: 16 * KiB, Recovery: 77, Arms: fftArms,
				Damage: spread("lost-48x16k-2files", []int{0, 1}, 24),
				Note:   "FFT-only row, 30% recovery",
			},
		},
	}
}

// versusProfile is the fleet comparison. The equal-count rows use the PAR3
// suite's Cauchy-class shapes (sets A and B); the FFT-only rows use set A at
// 64 KiB blocks, where PAR3 Cauchy is quadratic and PAR2 still fits its
// 32768-block limit.
func versusProfile() VersusProfile {
	full := fullProfile()
	a, _ := full.Dataset("a")
	b, _ := full.Dataset("b")
	return VersusProfile{
		Name:     "versus",
		Datasets: []Dataset{a, b},
		Configs: []VersusConfig{
			{
				ID: "vs-a-equal", Dataset: "a", BlockSize: 1 * MiB, Recovery: 103, Arms: allArms,
				Damage: spread("lost-50x1m", []int{0}, 50),
				Note:   "set A: 1 GiB, 1 MiB blocks, 1024 + 103 blocks (10%), every arm",
			},
			{
				ID: "vs-b-equal", Dataset: "b", BlockSize: 1 * MiB, Recovery: 30, Arms: allArms,
				Damage: spread("lost-10x1m-5of10files", []int{0, 2, 4, 6, 8}, 2),
				Note:   "set B: 10 x 30 MiB, 1 MiB blocks, 300 + 30 blocks (10%), every arm",
			},
			{
				ID: "vs-a-fft10", Dataset: "a", BlockSize: 64 * KiB, Recovery: 1639, Arms: fftArms,
				Damage: spread("lost-800x64k", []int{0}, 800),
				Note:   "FFT-only row: set A, 64 KiB blocks, 16384 + 1639 blocks (10%)",
			},
			{
				ID: "vs-a-fft30", Dataset: "a", BlockSize: 64 * KiB, Recovery: 4916, Arms: fftArms,
				Damage: spread("lost-2400x64k", []int{0}, 2400),
				Note:   "FFT-only row: set A, 64 KiB blocks, 16384 + 4916 blocks (30%)",
			},
		},
	}
}

// VersusProfiles lists the built-in comparison profiles by name.
func VersusProfiles() map[string]VersusProfile {
	return map[string]VersusProfile{"versus-smoke": versusSmokeProfile(), "versus": versusProfile()}
}

// LookupVersusProfile returns a built-in comparison profile.
func LookupVersusProfile(name string) (VersusProfile, error) {
	profiles := VersusProfiles()
	profile, ok := profiles[name]
	if !ok {
		names := make([]string, 0, len(profiles))
		for known := range profiles {
			names = append(names, known)
		}
		sort.Strings(names)
		return VersusProfile{}, fmt.Errorf("unknown comparison profile %q (known: %s)", name, strings.Join(names, ", "))
	}
	return profile, nil
}

// VersusOptions configures one comparison run.
type VersusOptions struct {
	// Candidate is the rarpar binary (both `par` and `par3`).
	Candidate string
	// PAR2Turbo is par2cmdline-turbo; empty skips its arm (noted).
	PAR2Turbo    string
	Work         string
	Out          string
	Profile      VersusProfile
	Warmups      int
	Repeats      int
	MachineLabel string
	// PinCPUs confines every timed process to an inclusive CPU range, as the
	// PAR3 suite's --pin-cpus does; empty leaves scheduling alone.
	PinCPUs string
	Timeout time.Duration
	Log     func(string, ...any)
	// buffered is what makes each PAR3 op buffered on the candidate, as
	// probed by RunVersus (VersusResults.BufferedArgs).
	buffered map[string][]string
	// backup selects each PAR3 repair arm's backup mode on the candidate,
	// and inPlaceUnsupported records one that cannot repair in place, as
	// probed by RunVersus (VersusResults.BackupArgs).
	backup             map[string][]string
	inPlaceUnsupported bool
}

// VersusRun is one timed process run.
type VersusRun struct {
	Config   string `json:"config"`
	Op       string `json:"op"`
	Arm      string `json:"arm"`
	Warmup   bool   `json:"warmup"`
	Repeat   int    `json:"repeat"`
	Position int    `json:"position"`
	Command  string `json:"command"`
	Measurement
	Status     string       `json:"status"`
	Failure    string       `json:"failure,omitempty"`
	StderrLine string       `json:"stderr_line,omitempty"`
	Repair     *RepairCheck `json:"repair,omitempty"`
}

// VersusResults is the evidence document a comparison writes.
type VersusResults struct {
	Schema      string         `json:"schema"`
	StartedUTC  string         `json:"started_utc"`
	FinishedUTC string         `json:"finished_utc"`
	Machine     bench.Machine  `json:"machine"`
	Profile     string         `json:"profile"`
	Warmups     int            `json:"warmups"`
	Repeats     int            `json:"repeats"`
	PinCPUs     string         `json:"pin_cpus,omitempty"`
	Candidate   Binary         `json:"candidate"`
	PAR2Turbo   *Binary        `json:"par2cmdline_turbo,omitempty"`
	Datasets    []Dataset      `json:"datasets"`
	Configs     []VersusConfig `json:"configs"`
	Runs        []VersusRun    `json:"runs"`
	Notes       []string       `json:"notes,omitempty"`
	Status      string         `json:"status"`
	Failures    []string       `json:"failures,omitempty"`
	// BufferedArgs and BufferedUnsupported record, as in the PAR3 suite's
	// results, the arguments that make the PAR3 arms' create and repair
	// buffered on this candidate, and the ops that have no buffered mode.
	BufferedArgs        map[string][]string `json:"buffered_args,omitempty"`
	BufferedUnsupported []string            `json:"buffered_unsupported,omitempty"`
	// BackupArgs records, per PAR3 repair arm, the arguments that select its
	// backup mode on this candidate, probed as the PAR3 suite probes its
	// repair rows (Results.BackupArgs): the PAR3 arm repairs in place with
	// no backup, its `-backup` twin keeps a numbered `.1`. InPlaceUnsupported
	// records a candidate that cannot repair in place: only the twins ran
	// repair.
	BackupArgs         map[string][]string `json:"backup_args,omitempty"`
	InPlaceUnsupported bool                `json:"in_place_unsupported,omitempty"`
}

// RunVersus runs the comparison and writes results.json and report.md under
// options.Out. Any failed run (a non-zero exit, a repair whose output does not
// hash to the inputs, a missing peak RSS) fails the comparison.
func RunVersus(ctx context.Context, options VersusOptions) (*VersusResults, error) {
	if options.Candidate == "" || options.Work == "" || options.Out == "" {
		return nil, errors.New("--candidate, --work and --out are required")
	}
	if options.Repeats < 1 || options.Warmups < 0 {
		return nil, errors.New("--repeats must be at least 1 and --warmups not negative")
	}
	if options.Timeout <= 0 {
		options.Timeout = DefaultTimeout
	}
	if options.Log == nil {
		options.Log = func(string, ...any) {}
	}
	if err := options.Profile.Validate(); err != nil {
		return nil, err
	}
	if err := ValidatePinCPUs(options.PinCPUs); err != nil {
		return nil, err
	}
	if options.PinCPUs != "" && !PinSupported() {
		options.Log("--pin-cpus %s: this host cannot pin processes; runs are unpinned", options.PinCPUs)
		options.PinCPUs = ""
	}
	for _, path := range []*string{&options.Candidate, &options.PAR2Turbo, &options.Work, &options.Out} {
		if *path == "" {
			continue
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return nil, err
		}
		*path = absolute
	}
	if err := os.MkdirAll(options.Out, 0o755); err != nil {
		return nil, err
	}
	results := &VersusResults{
		Schema: VersusSchema, StartedUTC: time.Now().UTC().Format(time.RFC3339),
		Machine: CollectMachine(ctx, options.MachineLabel), Profile: options.Profile.Name,
		Warmups: options.Warmups, Repeats: options.Repeats, PinCPUs: options.PinCPUs,
		Datasets: options.Profile.Datasets, Configs: options.Profile.Configs,
	}
	var err error
	if results.Candidate, err = identifyBinary(ctx, options.Candidate, "--version"); err != nil {
		return nil, err
	}
	if options.PAR2Turbo != "" {
		binary, err := identifyBinary(ctx, options.PAR2Turbo, "-V")
		if err != nil {
			return nil, err
		}
		results.PAR2Turbo = &binary
	} else {
		results.Notes = append(results.Notes, "no par2cmdline-turbo binary was given, so its arm did not run")
	}
	results.BufferedArgs = map[string][]string{}
	var repairHelp string
	for _, op := range VersusOps {
		flags := "--fsync/--buffered"
		if op == OpRepair {
			flags += " and --backup/--no-backup"
		}
		help, err := opHelp(ctx, options.Candidate, op, flags)
		if err != nil {
			return nil, err
		}
		if op == OpRepair {
			repairHelp = help.Stdout + help.Stderr
		}
		if args, ok := bufferedArgsFromHelp(help.Stdout + help.Stderr); ok {
			results.BufferedArgs[op] = args
			continue
		}
		results.BufferedUnsupported = append(results.BufferedUnsupported, op)
		results.Notes = append(results.Notes, noBufferedModeNote(op))
	}
	options.buffered = results.BufferedArgs
	var inPlaceOK bool
	results.BackupArgs, inPlaceOK = versusBackupArgs(repairHelp)
	if !inPlaceOK {
		results.InPlaceUnsupported = true
		results.Notes = append(results.Notes, "`rarpar par3 repair --help` on this candidate lists neither --backup nor --no-backup, so it cannot be told to repair in place: only the PAR3 -backup arms ran repair, with the plain command, and each run had to leave a numbered backup")
	}
	options.backup, options.inPlaceUnsupported = results.BackupArgs, results.InPlaceUnsupported
	results.Notes = append(results.Notes,
		"every arm runs at its own default thread count (every CPU it may use); rarpar's PAR2 engine has no thread flag, so no arm is given one",
		"each arm repairs the set its own create wrote, over one identically damaged copy of the inputs per run")

	var failures []string
	for _, config := range options.Profile.Configs {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		dataset, _ := options.Profile.Dataset(config.Dataset)
		failed, err := runVersusConfig(ctx, options, results, config, dataset)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", config.ID, err))
			options.Log("%s: %v", config.ID, err)
			continue
		}
		failures = append(failures, failed...)
	}
	results.FinishedUTC = time.Now().UTC().Format(time.RFC3339)
	results.Failures = failures
	results.Status = StatusOK
	if len(failures) > 0 {
		results.Status = StatusFailed
	}
	if err := writeJSONFile(filepath.Join(options.Out, "results.json"), results); err != nil {
		return results, err
	}
	if err := os.WriteFile(filepath.Join(options.Out, "report.md"), []byte(RenderVersusReport(results)), 0o644); err != nil {
		return results, err
	}
	return results, nil
}

// versusBackupArgs gives each PAR3 repair arm the arguments that select its
// backup mode, read from the candidate's `par3 repair --help` as the PAR3
// suite reads them (backupArgsFromHelp): the PAR3 arm repairs in place, its
// `-backup` twin keeps a numbered `.1`. It reports false when the candidate
// cannot repair in place; the PAR3 arms then get no entry and do not run
// repair.
func versusBackupArgs(repairHelp string) (map[string][]string, bool) {
	inPlace, backup, inPlaceOK := backupArgsFromHelp(repairHelp)
	args := map[string][]string{}
	for _, arm := range PAR3Arms {
		if inPlaceOK {
			args[arm] = inPlace
		}
		args[arm+backupArmSuffix] = backup
	}
	return args, inPlaceOK
}

func identifyBinary(ctx context.Context, path, versionFlag string) (Binary, error) {
	digest, _, err := hashFile(path)
	if err != nil {
		return Binary{}, fmt.Errorf("binary %s: %w", path, err)
	}
	result := Run(ctx, Command{Path: path, Args: []string{versionFlag}, Timeout: 30 * time.Second})
	version := strings.TrimSpace(firstLine(result.Stdout + result.Stderr))
	if problem := versionProbeProblem(result, version); problem != "" {
		return Binary{}, fmt.Errorf("binary %s: version probe %s %s", path, versionFlag, problem)
	}
	return Binary{Path: path, SHA256: digest, Version: version}, nil
}

// armsFor is the comparison's arms that can run with these options.
func armsFor(config VersusConfig, options VersusOptions) []string {
	var arms []string
	for _, arm := range config.Arms {
		if arm == ArmPAR2Turbo && options.PAR2Turbo == "" {
			continue
		}
		arms = append(arms, arm)
	}
	return arms
}

func runVersusConfig(ctx context.Context, options VersusOptions, results *VersusResults, config VersusConfig, dataset Dataset) ([]string, error) {
	dataDir := filepath.Join(options.Work, "data", dataset.ID)
	manifest, err := EnsureDataset(dataDir, dataset, options.Log)
	if err != nil {
		return nil, fmt.Errorf("dataset %s: %w", dataset.ID, err)
	}
	root := filepath.Join(options.Work, "vs", config.ID)
	if err := resetDir(root); err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	// One damaged copy of the inputs: every repair stage of every arm starts
	// from these exact bytes.
	damaged := filepath.Join(root, "damaged")
	if err := resetDir(damaged); err != nil {
		return nil, err
	}
	for _, file := range dataset.Files {
		if err := copyFile(filepath.Join(dataDir, file.Name), filepath.Join(damaged, file.Name)); err != nil {
			return nil, err
		}
	}
	if err := ApplyDamage(damaged, dataset, config.BlockSize, config.Damage); err != nil {
		return nil, err
	}
	if checkDigests(damaged, manifest.SHA256) == nil {
		return nil, errors.New("the damage pattern left every input intact")
	}

	arms := armsFor(config, options)
	carriers := map[string]string{}
	var failed []string
	for _, op := range VersusOps {
		opArms := VersusOpArms(arms, op, options.inPlaceUnsupported)
		for run := 0; run < options.Warmups+options.Repeats; run++ {
			order := append([]string(nil), opArms...)
			if run%2 == 1 {
				for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
					order[i], order[j] = order[j], order[i]
				}
			}
			for position, arm := range order {
				if op == OpRepair && carriers[versusSetArm(arm)] == "" {
					continue // its create never succeeded; already failed
				}
				record := runVersusOne(ctx, options, config, dataset, manifest, dataDir, damaged, root, op, arm, carriers)
				record.Warmup = run < options.Warmups
				record.Repeat = run
				if !record.Warmup {
					record.Repeat = run - options.Warmups
				}
				record.Position = position
				results.Runs = append(results.Runs, record)
				options.Log("%s %s %s #%d %.3fs rss=%dMiB %s %s", config.ID, op, arm, record.Repeat,
					record.WallSeconds, record.MaxRSSBytes>>20, record.Status, record.Failure)
				if record.Status != StatusOK {
					failed = append(failed, fmt.Sprintf("%s/%s/%s: %s", config.ID, op, arm, record.Failure))
				}
			}
		}
	}
	return dedupe(failed), nil
}

// runVersusOne runs one create or repair. A create writes into a fresh
// directory; the last good one is kept as the arm's set. A repair stages a
// private copy of the damaged inputs plus the set its arm repairs (a twin's
// PAR3 arm's) and hashes the result; a PAR3 repair must also leave what its
// backup mode promises (see backupProblem).
func runVersusOne(ctx context.Context, options VersusOptions, config VersusConfig, dataset Dataset, manifest DatasetManifest,
	dataDir, damaged, root, op, arm string, carriers map[string]string) VersusRun {
	record := VersusRun{Config: config.ID, Op: op, Arm: arm}
	fail := func(failure string, err error) VersusRun {
		record.Status, record.Failure = StatusFailed, failure
		if err != nil {
			record.StderrLine = err.Error()
		}
		return record
	}
	names := make([]string, 0, len(dataset.Files))
	for _, file := range dataset.Files {
		names = append(names, file.Name)
	}
	var command Command
	var stage string
	if op == OpCreate {
		stage = filepath.Join(root, arm+"-set")
		if err := resetDir(stage); err != nil {
			return fail("stage", err)
		}
		command = versusCreateCommand(options, config, dataDir, stage, arm, names)
	} else {
		stage = filepath.Join(root, arm+"-repair")
		if err := resetDir(stage); err != nil {
			return fail("stage", err)
		}
		for _, name := range names {
			if err := copyFile(filepath.Join(damaged, name), filepath.Join(stage, name)); err != nil {
				return fail("stage", err)
			}
		}
		set := carriers[versusSetArm(arm)]
		entries, err := os.ReadDir(set)
		if err != nil {
			return fail("stage", err)
		}
		for _, entry := range entries {
			if err := copyFile(filepath.Join(set, entry.Name()), filepath.Join(stage, entry.Name())); err != nil {
				return fail("stage", err)
			}
		}
		command = versusRepairCommand(options, stage, arm)
	}
	result := Run(ctx, command)
	record.Command = command.Describe()
	record.Measurement = result.Measurement
	switch {
	case result.Failure != "":
		return fail(result.Failure, result.Err)
	case result.ExitCode != 0:
		record.StderrLine = lastLine(result)
		record.Status, record.Failure = StatusFailed, fmt.Sprintf("exit-%d", result.ExitCode)
		return record
	case record.MaxRSSBytes <= 0:
		return fail(FailureMissingRSS, nil)
	}
	if op == OpCreate {
		entries, err := os.ReadDir(stage)
		if err != nil || len(entries) == 0 {
			return fail("no-carriers", err)
		}
		carriers[arm] = stage
		record.Status = StatusOK
		return record
	}
	check, err := checkRepair(stage, manifest, carriers[versusSetArm(arm)])
	record.Repair = &check
	if err != nil {
		return fail("repair-check", err)
	}
	if !check.Match {
		return fail("repair-mismatch", fmt.Errorf("sha256 differs: %s", strings.Join(check.Mismatched, ", ")))
	}
	if contains(PAR3Arms, versusSetArm(arm)) {
		if problem := backupProblem(isPAR3BackupArm(arm), check); problem != "" {
			return fail("backup-mismatch", errors.New(problem))
		}
	}
	record.Status = StatusOK
	return record
}

func versusCreateCommand(options VersusOptions, config VersusConfig, dataDir, outDir, arm string, names []string) Command {
	block, count := strconv.FormatInt(config.BlockSize, 10), strconv.FormatInt(config.Recovery, 10)
	command := Command{Path: options.Candidate, Dir: dataDir, PinCPUs: options.PinCPUs, Timeout: options.Timeout}
	switch arm {
	case ArmPAR2:
		command.Args = append([]string{"--quiet", "par", "create", "--base-path", dataDir,
			"--block-size", block, "--recovery-count", count, filepath.Join(outDir, versusPAR2Name)}, names...)
	case ArmPAR2Turbo:
		command.Path = options.PAR2Turbo
		command.Args = append([]string{"c", "-q", "-s" + block, "-c" + count, "-B" + dataDir,
			filepath.Join(outDir, versusPAR2Name)}, names...)
	default:
		codec := "cauchy"
		if arm == ArmPAR3FFT {
			codec = "fft"
		}
		par3 := config.par3Config(codec)
		args := append([]string{"--quiet", "par3", "create", filepath.Join(outDir, carrierName)}, names...)
		args = append(args, "--base-path", dataDir, "-s", block, "-c", count)
		if codec == "fft" {
			args = append(args, "--codec", "fft", "--capacity-log2", strconv.Itoa(par3.CapacityLog2()))
		}
		command.Args = append(args, options.buffered[OpCreate]...)
	}
	return command
}

func versusRepairCommand(options VersusOptions, stage, arm string) Command {
	command := Command{Path: options.Candidate, Dir: stage, PinCPUs: options.PinCPUs, Timeout: options.Timeout}
	switch arm {
	case ArmPAR2:
		command.Args = []string{"--quiet", "par", "repair", filepath.Join(stage, versusPAR2Name)}
	case ArmPAR2Turbo:
		command.Path = options.PAR2Turbo
		command.Args = []string{"r", "-q", versusPAR2Name}
	default:
		command.Args = append([]string{"--quiet", "par3", "repair", carrierName}, options.buffered[OpRepair]...)
		command.Args = append(command.Args, options.backup[arm]...)
	}
	return command
}

// VersusCell is one arm's medians for one comparison and op. A repair cell
// also records what its runs left beside the repaired inputs: LeftBehind is
// every extra file name, and Backups says whether the runs kept a numbered
// backup of a repaired file ("true", "false", or "false/true" when they
// disagreed).
type VersusCell struct {
	Runs          int
	WallSeconds   float64
	CPUSeconds    float64
	MaxRSSBytes   int64
	LowRSS, HiRSS int64
	LeftBehind    string
	Backups       string
}

// VersusCells summarises the measured (non-warmup, ok) runs by config, op, arm.
func VersusCells(results *VersusResults) map[string]VersusCell {
	walls, cpus := map[string][]float64{}, map[string][]float64{}
	rss := map[string][]int64{}
	extras, backups := map[string]map[string]bool{}, map[string]map[string]bool{}
	for _, run := range results.Runs {
		if run.Warmup || run.Status != StatusOK {
			continue
		}
		key := run.Config + "/" + run.Op + "/" + run.Arm
		walls[key] = append(walls[key], run.WallSeconds)
		cpus[key] = append(cpus[key], run.UserSeconds+run.SysSeconds)
		rss[key] = append(rss[key], run.MaxRSSBytes)
		if run.Repair != nil {
			if extras[key] == nil {
				extras[key], backups[key] = map[string]bool{}, map[string]bool{}
			}
			for _, name := range run.Repair.ExtraFiles {
				extras[key][name] = true
			}
			backups[key][fmt.Sprint(len(run.Repair.Backups) > 0)] = true
		}
	}
	cells := map[string]VersusCell{}
	for key, values := range walls {
		median, low, high := procmeasure.PeakStats(rss[key])
		cells[key] = VersusCell{Runs: len(values), WallSeconds: medianFloat(values), CPUSeconds: medianFloat(cpus[key]),
			MaxRSSBytes: median, LowRSS: low, HiRSS: high,
			LeftBehind: strings.Join(sortedKeys(extras[key]), " "), Backups: strings.Join(sortedKeys(backups[key]), "/")}
	}
	return cells
}

// likeForLike says whether two repair cells wrote the same kind of bytes:
// both kept a numbered backup of what they repaired, or neither did.
func likeForLike(par2, par3 VersusCell) string {
	switch {
	case par2.Backups == "" || par3.Backups == "" || strings.Contains(par2.Backups, "/") || strings.Contains(par3.Backups, "/"):
		return "–"
	case par2.Backups != par3.Backups:
		return "no"
	case par2.Backups == "true":
		return "yes: both keep a numbered backup"
	default:
		return "yes: neither keeps a backup"
	}
}

func medianFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[middle-1] + sorted[middle]) / 2
	}
	return sorted[middle]
}

// RenderVersusReport is the Markdown report: per comparison, every arm's
// medians, then the par2 ÷ par3 wall-time ratio for each pair of arms.
func RenderVersusReport(results *VersusResults) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PAR2 against PAR3\n\n")
	fmt.Fprintf(&b, "- machine: %s (%s)\n- profile: %s, %d warmup(s), %d repeat(s)\n- rarpar: %s\n",
		results.Machine.Label, results.Machine.CPU, results.Profile, results.Warmups, results.Repeats, results.Candidate.Version)
	if results.PAR2Turbo != nil {
		fmt.Fprintf(&b, "- par2cmdline-turbo: %s\n", results.PAR2Turbo.Version)
	}
	fmt.Fprint(&b, "- PAR3 arms run buffered and never pass `--fsync`.")
	if summary := bufferedSummary(VersusOps, results.BufferedArgs, results.BufferedUnsupported); summary != "" {
		fmt.Fprint(&b, " "+summary)
	}
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- PAR3 repair: `%s` and `%s` repair in place and keep no backup; `%s` and `%s` repair the same sets keeping a numbered `.1` backup of every file they repair, the compatible behaviour. A PAR3 arm is like for like on bytes written with a PAR2 arm that leaves the same (see `left behind`, and the ratio table's last column).",
		ArmPAR3Cauchy, ArmPAR3FFT, ArmPAR3CauchyBackup, ArmPAR3FFTBackup)
	if summary := versusBackupSummary(results); summary != "" {
		fmt.Fprint(&b, " "+summary)
	}
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- status: %s\n\n", results.Status)
	fmt.Fprintf(&b, "Scale: par2 ÷ par3 median wall time; above 1 means the PAR3 arm was faster. Peak RSS is raw MiB (median, range).\n")
	fmt.Fprintf(&b, "Every repair is checked against the inputs' SHA-256; only matching repairs are counted.\n\n")
	cells := VersusCells(results)
	for _, config := range results.Configs {
		var dataset Dataset
		for _, candidate := range results.Datasets {
			if candidate.ID == config.Dataset {
				dataset = candidate
			}
		}
		fmt.Fprintf(&b, "## %s\n\n%s. Block %d B, recovery %d (%.1f%% of %d PAR3 input blocks), damage %s (%d blocks).\n\n",
			config.ID, config.Note, config.BlockSize, config.Recovery, config.RecoveryPercent(dataset),
			InputBlocks(dataset, config.BlockSize), config.Damage.Name, config.Damage.LostBlocks())
		b.WriteString("| op | arm | runs | wall s | cpu s | peak RSS MiB | left behind |\n|---|---|---:|---:|---:|---|---|\n")
		for _, op := range VersusOps {
			for _, arm := range VersusOpArms(config.Arms, op, results.InPlaceUnsupported) {
				cell, ok := cells[config.ID+"/"+op+"/"+arm]
				if !ok {
					fmt.Fprintf(&b, "| %s | %s | 0 | – | – | – | – |\n", op, arm)
					continue
				}
				left := "–"
				if op == OpRepair {
					left = cell.LeftBehind
					if left == "" {
						left = "none"
					}
				}
				fmt.Fprintf(&b, "| %s | %s | %d | %.3f | %.3f | %s | %s |\n", op, arm, cell.Runs, cell.WallSeconds, cell.CPUSeconds,
					procmeasure.MiBRange(cell.MaxRSSBytes, cell.LowRSS, cell.HiRSS), left)
			}
		}
		b.WriteString("\n| op | par2 arm | par3 arm | par2 ÷ par3 | like for like on bytes written |\n|---|---|---|---:|---|\n")
		for _, op := range VersusOps {
			for _, par2 := range PAR2Arms {
				for _, par3 := range VersusOpArms(PAR3Arms, op, results.InPlaceUnsupported) {
					if !contains(config.Arms, par2) || !contains(config.Arms, versusSetArm(par3)) {
						continue
					}
					p, okP := cells[config.ID+"/"+op+"/"+par2]
					q, okQ := cells[config.ID+"/"+op+"/"+par3]
					ratio, like := "–", "–"
					if okP && okQ && q.WallSeconds > 0 {
						ratio = fmt.Sprintf("%.2f", p.WallSeconds/q.WallSeconds)
					}
					if op == OpRepair && okP && okQ {
						like = likeForLike(p, q)
					}
					fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", op, par2, par3, ratio, like)
				}
			}
		}
		b.WriteString("\n")
	}
	if len(results.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, note := range results.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		b.WriteString("\n")
	}
	if len(results.Failures) > 0 {
		b.WriteString("## Failures\n\n")
		for _, failure := range results.Failures {
			fmt.Fprintf(&b, "- %s\n", failure)
		}
	}
	return b.String()
}

// ReadVersusResults loads a comparison's results.json.
func ReadVersusResults(path string) (*VersusResults, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var results VersusResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if results.Schema != VersusSchema {
		hint := ""
		if results.Schema == "rarpar-par3-versus-v1" {
			// A v1 PAR3 arm may have run durable and kept a backup; this
			// harness would report it as buffered and in place.
			hint = "; a v1 file predates the buffered PAR3 arms and the in-place and -backup PAR3 repair arms, so read it with the harness that wrote it"
		}
		return nil, fmt.Errorf("%s: schema %q, want %q%s", path, results.Schema, VersusSchema, hint)
	}
	return &results, nil
}

// versusBackupSummary says how the PAR3 repair arms selected their backup
// mode on this candidate, or "" when the comparison was not probed.
func versusBackupSummary(results *VersusResults) string {
	if results.BackupArgs == nil {
		return ""
	}
	backup := describeArgs(results.BackupArgs[ArmPAR3CauchyBackup])
	if results.InPlaceUnsupported {
		return "This candidate cannot repair in place, so only the `-backup` arms ran repair, " + backup + "."
	}
	return "On this candidate the in-place arms run " + describeArgs(results.BackupArgs[ArmPAR3Cauchy]) + " and the `-backup` arms " + backup + "."
}
