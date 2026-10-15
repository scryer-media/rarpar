package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/par3bench"
)

const par3Usage = `Usage:
  rarpar-bench par3 matrix [--profile smoke|full|fleet] [--set ID]... [--ops LIST] [--workers 1,8]
        [--kernel-variant NAME:VAR=V]... [--json]
  rarpar-bench par3 build-reference --out DIR [--toolchains PATH] [--cache DIR] [--mirror-base URL] [--cmake PATH] [--jobs N]
  rarpar-bench par3 run --reference PATH --candidate PATH --work DIR --out DIR [--profile smoke|full|fleet] [--set ID]...
        [--ops create,verify,repair] [--warmups N] [--repeats N] [--workers 1,8] [--pin-cpus 0-7]
        [--kernel-variant NAME:VAR=V[,VAR=V]]... [--iocount] [--engine-perf PATH]
        [--candidate-arg ARG]... [--machine LABEL] [--timeout 20m] [--reference-timeout DURATION] [--keep-stages]
        [--target NAME=DIR]... [--target-meta NAME:KEY=V[,KEY=V]]... [--rows reference,rarpar,engine]
        [--engine-workers 8] [--engine-variant NAME:VAR=V[,VAR=V]]... [--drop-caches]
        [--perf-stat N] [--perf-ops repair] [--perf-record SET]... [--perf-freq 499] [--perf-out DIR]
  rarpar-bench par3 report --input results.json [--out report.md]
  rarpar-bench par3 render --input results.json --out DIR
  rarpar-bench par3 versus --candidate PATH --work DIR --out DIR [--par2 PATH] [--profile versus-smoke|versus]
        [--set ID]... [--warmups N] [--repeats N] [--pin-cpus 0-7] [--machine LABEL] [--timeout 20m]
  rarpar-bench par3 versus-report --input results.json [--out report.md]
  rarpar-bench par3 versus-render --input [NAME=]results.json... --out DIR

The PAR3 suite benchmarks the shipped rarpar CLI against the pinned par3cmdline
reference on deterministic generated inputs. See docs/benchmarking.md. Every
rarpar row runs buffered, one row per worker count (rarpar-wN) and kernel
variant; the bench never passes --fsync, because durability is the caller's
concern, not PAR3's. A candidate whose par3 create or repair --help lists
--buffered (0.6.x and earlier) gets --buffered; one that lists neither runs
plain, and the results say so.
Repair has two rarpar rows per worker count: rarpar-wN repairs in place and
keeps no backup (the candidate's default), and rarpar-wN-backup keeps a
numbered .1 backup of every file it repairs, as the reference always does, so
the -backup rows are like for like with the reference on bytes written. The
candidate's par3 repair --help picks the switches: one listing --backup gives
the -backup rows --backup; one listing --no-backup (0.7.0 and earlier) gives
the in-place rows --no-backup; one listing neither runs only the -backup rows,
plain, and the results say so. A PAR-inside set keeps one compatible rs row,
which keeps a .1 like the reference.
--perf-stat N and --perf-record SET add an untimed Linux perf pass after each
--perf-ops operation's timed runs (default: repair), on the plain sets and the
first target: N perf stat runs of every reference and rarpar row, each on a
fresh stage, counting the corpus suites' --perf events; and on each named set
one perf record -F 499 run (--perf-freq) of every rarpar row, kept as perf
script text and folded stacks. Files go under --perf-out (default OUT/perf);
a host without Linux perf skips the pass, and the results say so. A pass that
was skipped, had a perf run fail, or ran nothing also writes INCOMPLETE.txt
there, one problem per line.
par3 versus compares PAR2 (rarpar par, and par2cmdline-turbo with --par2) with
PAR3 Cauchy and FFT at one block size, recovery count and damage pattern, on the
scale par2 ÷ par3 (above 1 = PAR3 faster), with every repair SHA-256 checked.
Each PAR3 arm's repair runs in place, and its -backup twin keeps a .1; the
report says which PAR2 arm each is like for like with on bytes written.
par3 versus-render draws one SVG per comparison and op from one or more
machines' versus results.json (repeat --input, in chart order; NAME= sets the
machine's row name), every arm against par2cmdline-turbo, or par2-rs when any
machine has none, for the whole chart.
`

func runPAR3(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, par3Usage)
		return fmt.Errorf("par3 requires matrix, build-reference, run, report, render, versus, versus-report, or versus-render")
	}
	switch args[0] {
	case "matrix":
		return runPAR3Matrix(args[1:], stdout)
	case "build-reference":
		return runPAR3BuildReference(ctx, args[1:], stdout)
	case "run":
		return runPAR3Suite(ctx, args[1:], stdout)
	case "report":
		return runPAR3Report(args[1:], stdout)
	case "render":
		return runPAR3Render(args[1:], stdout)
	case "versus":
		return runPAR3Versus(ctx, args[1:], stdout)
	case "versus-report":
		return runPAR3VersusReport(args[1:], stdout)
	case "versus-render":
		return runPAR3VersusRender(args[1:], stdout)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, par3Usage)
		return nil
	default:
		return fmt.Errorf("unknown par3 command %q", args[0])
	}
}

func parseIntList(text string) ([]int, error) {
	var values []int
	for _, field := range strings.Split(text, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		value, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("%q is not an integer", field)
		}
		values = append(values, value)
	}
	return values, nil
}

func splitList(text string) []string {
	var values []string
	for _, field := range strings.Split(text, ",") {
		if field = strings.TrimSpace(field); field != "" {
			values = append(values, field)
		}
	}
	return values
}

func parseKernelVariants(values []string) ([]par3bench.KernelVariant, error) {
	var variants []par3bench.KernelVariant
	for _, value := range values {
		variant, err := par3bench.ParseKernelVariant(value)
		if err != nil {
			return nil, err
		}
		variants = append(variants, variant)
	}
	return variants, nil
}

func selectedProfile(name string, sets []string) (par3bench.Profile, error) {
	profile, err := par3bench.LookupProfile(name)
	if err != nil {
		return par3bench.Profile{}, err
	}
	profile, err = profile.Select(sets)
	if err != nil {
		return par3bench.Profile{}, err
	}
	return profile, profile.Validate()
}

func runPAR3Matrix(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("par3 matrix", flag.ContinueOnError)
	profileName := flags.String("profile", "smoke", "profile: smoke, full or fleet")
	workers := flags.String("workers", "1,8", "rarpar worker counts")
	ops := flags.String("ops", strings.Join(par3bench.DefaultOps, ","), "operations: "+strings.Join(par3bench.KnownOps, ","))
	jsonOut := flags.Bool("json", false, "emit JSON")
	var sets, kernels stringList
	flags.Var(&sets, "set", "restrict to a set ID (repeatable)")
	flags.Var(&kernels, "kernel-variant", "extra rarpar row NAME:VAR=value[,VAR=value] (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	profile, err := selectedProfile(*profileName, sets)
	if err != nil {
		return err
	}
	workerList, err := parseIntList(*workers)
	if err != nil {
		return err
	}
	variants, err := parseKernelVariants(kernels)
	if err != nil {
		return err
	}
	opList := splitList(*ops)
	if err := par3bench.CheckOps(opList); err != nil {
		return err
	}
	rows := par3bench.Variants(workerList, variants)
	if err := par3bench.CheckVariantNames(rows); err != nil {
		return err
	}
	byOp := par3bench.RowsByOp(rows, opList)
	if *jsonOut {
		return writeJSONTo(stdout, map[string]any{"profile": profile, "ops": opList, "variants": rows, "rows": byOp})
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "SET\tDATASET\tBYTES\tBLOCK\tINPUT\tRECOVERY\tCODEC\tFIELD\tDAMAGE")
	for _, config := range profile.Configs {
		dataset, _ := profile.Dataset(config.Dataset)
		codec := config.Codec
		if codec == "fft" {
			codec = fmt.Sprintf("fft(2^%d)", config.CapacityLog2())
		}
		if config.Carrier != "" {
			// The reference's insert picks the block size and recovery count.
			fmt.Fprintf(table, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s (%d)\n", config.ID, dataset.ID, dataset.TotalBytes(),
				"insert", "insert", fmt.Sprintf("-r%d", config.InsertRedundancy), codec+"/"+config.Carrier+"-inside",
				"insert", config.Damage.Name, config.Damage.LostBlocks())
			continue
		}
		fmt.Fprintf(table, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s (%d)\n", config.ID, dataset.ID, dataset.TotalBytes(),
			config.BlockSize, par3bench.InputBlocks(dataset, config.BlockSize), config.Recovery, codec,
			config.ExpectedField, config.Damage.Name, config.Damage.LostBlocks())
	}
	if err := table.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "\nrows per set (one reference row, which never syncs and keeps a .1 backup of what it repairs; one buffered rarpar row per worker count and kernel variant, repairing in place with no backup; at repair, one rarpar-wN-backup row per worker count that keeps a .1 like the reference, like for like on bytes written):")
	table = tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	for _, op := range opList {
		fmt.Fprintf(table, "  %s\t%s\n", op, strings.Join(byOp[op], ", "))
	}
	if err := table.Flush(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "rarpar rows never pass --fsync: a 0.7.0+ candidate is buffered when run plain, an older one whose `rarpar par3 OP --help` lists --buffered gets it, and an op listing neither runs plain (noted in the results).\n"+
		"repair rows take their backup switch from `rarpar par3 repair --help`: --backup listed gives the -backup rows --backup; only --no-backup listed (0.7.0 and earlier) gives the in-place rows --no-backup; neither listed runs only the -backup rows, plain (noted in the results). A PAR-inside set runs one compatible rs row instead.")
	return err
}

func runPAR3BuildReference(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("par3 build-reference", flag.ContinueOnError)
	out := flags.String("out", "", "build directory (source, build tree, reference.json)")
	toolchains := flags.String("toolchains", defaultPath("config/toolchains.json"), "toolchain lock")
	cache := flags.String("cache", "", "directory for the resolved source archive")
	mirrorBase := flags.String("mirror-base", os.Getenv("RARPAR_TOOL_MIRROR_BASE"), "public read base URL of the tool source mirror")
	cmake := flags.String("cmake", "cmake", "CMake executable")
	jobs := flags.Int("jobs", 0, "parallel build jobs (default: all CPUs)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	lock, err := bench.LoadToolchains(workspacePath(*toolchains))
	if err != nil {
		return err
	}
	build, err := par3bench.BuildReference(ctx, par3bench.ReferenceBuildOptions{
		Lock: lock, Out: workspacePath(*out), Cache: workspacePath(*cache), MirrorBase: *mirrorBase,
		CMake: *cmake, Jobs: *jobs, Log: os.Stderr,
	})
	if err != nil {
		return err
	}
	return writeJSONTo(stdout, build)
}

func runPAR3Suite(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("par3 run", flag.ContinueOnError)
	reference := flags.String("reference", "", "par3cmdline binary")
	candidate := flags.String("candidate", "", "rarpar binary")
	enginePerf := flags.String("engine-perf", "", "optional par3-rs engine_perf example binary for an untimed stage pass")
	work := flags.String("work", "", "work directory: generated datasets, canonical carriers, stages")
	out := flags.String("out", "", "evidence directory: results.json, runs.jsonl, report.md")
	profileName := flags.String("profile", "smoke", "profile: smoke, full or fleet")
	ops := flags.String("ops", strings.Join(par3bench.DefaultOps, ","), "operations: "+strings.Join(par3bench.KnownOps, ","))
	warmups := flags.Int("warmups", 1, "warmup runs per variant (recorded, not summarised)")
	repeats := flags.Int("repeats", 5, "measured runs per variant")
	workers := flags.String("workers", "1,8", "rarpar worker counts")
	pin := flags.String("pin-cpus", "", "confine every timed process to an inclusive CPU range, e.g. 0-7 (Linux taskset, Windows affinity)")
	iocount := flags.Bool("iocount", false, "add an untimed strace -f -c pass per variant and op (Linux)")
	machine := flags.String("machine", "", "machine label recorded in the results")
	memory := flags.Int("engine-perf-memory-mib", 256, "engine_perf memory budget")
	timeout := flags.Duration("timeout", par3bench.DefaultTimeout, "per-run timeout for every timed process; a reference run past it is DNF")
	referenceTimeout := flags.Duration("reference-timeout", 0, "per-run timeout for reference processes (default: --timeout)")
	keep := flags.Bool("keep-stages", false, "keep per-run stage directories")
	engineWorkers := flags.String("engine-workers", "", "add timed engine_perf rows at these worker counts (needs --engine-perf)")
	rows := flags.String("rows", "", "timed row kinds: "+strings.Join(par3bench.KnownRowKinds, ",")+" (default: reference,rarpar, plus engine with --engine-workers)")
	dropCaches := flags.Bool("drop-caches", false, "drop the page cache before every timed run (Linux, root)")
	perfStat := flags.Int("perf-stat", 0, "untimed perf stat runs of every reference and rarpar row per --perf-ops op, after its timed runs (Linux; 0 = none)")
	perfOps := flags.String("perf-ops", strings.Join(par3bench.DefaultPerfOps, ","), "operations the perf pass covers")
	perfFreq := flags.Int("perf-freq", par3bench.DefaultPerfFrequency, "perf record sampling frequency (-F)")
	perfOut := flags.String("perf-out", "", "directory for perf's files (default: OUT/perf)")
	var sets, kernels, candidateArgs, targets, targetMeta, engineVariants, perfRecord stringList
	flags.Var(&perfRecord, "perf-record", "plain set whose rarpar rows also get one untimed perf record run per --perf-ops op (repeatable)")
	flags.Var(&targets, "target", "storage target NAME=DIR; every row runs on every target, interleaved (repeatable; replaces --work)")
	flags.Var(&targetMeta, "target-meta", "facts about a target the client cannot see, NAME:key=value[,key=value] (repeatable)")
	flags.Var(&engineVariants, "engine-variant", "extra engine row NAME:VAR=value[,VAR=value] (repeatable)")
	flags.Var(&sets, "set", "restrict to a set ID (repeatable)")
	flags.Var(&kernels, "kernel-variant", "extra rarpar row NAME:VAR=value[,VAR=value] (repeatable)")
	flags.Var(&candidateArgs, "candidate-arg", "extra global rarpar argument for every candidate run (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	profile, err := selectedProfile(*profileName, sets)
	if err != nil {
		return err
	}
	workerList, err := parseIntList(*workers)
	if err != nil {
		return err
	}
	variants, err := parseKernelVariants(kernels)
	if err != nil {
		return err
	}
	var targetList []par3bench.Target
	for _, text := range targets {
		target, err := par3bench.ParseTarget(text)
		if err != nil {
			return err
		}
		target.Work = workspacePath(target.Work)
		targetList = append(targetList, target)
	}
	for _, text := range targetMeta {
		if err := par3bench.ApplyTargetMeta(targetList, text); err != nil {
			return err
		}
	}
	if len(targetList) > 0 && *work != "" {
		return fmt.Errorf("--work and --target are exclusive; name the work directory as a target")
	}
	engineWorkerList, err := parseIntList(*engineWorkers)
	if err != nil {
		return err
	}
	engineVariantList, err := parseKernelVariants(engineVariants)
	if err != nil {
		return err
	}
	// Every timed process runs in its own process group so a timeout can kill
	// its whole tree; that also keeps it out of the terminal's group, so an
	// interrupt or a SIGTERM to the harness must cancel the context (which
	// kills the group) instead of leaving the child running. A second signal
	// gets the default behaviour back.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	results, err := par3bench.RunSuite(ctx, par3bench.Options{
		Reference: workspacePath(*reference), Candidate: workspacePath(*candidate), EnginePerf: workspacePath(*enginePerf),
		Work: workspacePath(*work), Out: workspacePath(*out), Profile: profile, Ops: splitList(*ops),
		Warmups: *warmups, Repeats: *repeats, Workers: workerList, PinCPUs: *pin, KernelVariants: variants,
		IOCount: *iocount, MachineLabel: *machine, CandidateArgs: candidateArgs, EnginePerfMemoryMiB: *memory,
		KeepStages: *keep, Timeout: *timeout, ReferenceTimeout: *referenceTimeout, Log: os.Stderr,
		Targets: targetList, Rows: splitList(*rows), EngineWorkers: engineWorkerList, EngineVariants: engineVariantList,
		DropCaches: *dropCaches,
		Perf: par3bench.PerfOptions{StatRepeats: *perfStat, Ops: splitList(*perfOps), RecordSets: perfRecord,
			Frequency: *perfFreq, Out: workspacePath(*perfOut)},
	})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprint(stdout, par3bench.RenderReport(results)); err != nil {
		return err
	}
	if results.Status != "ok" {
		return fmt.Errorf("PAR3 suite finished with failures: %s", strings.Join(results.Failures, "; "))
	}
	return nil
}

func runPAR3Report(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("par3 report", flag.ContinueOnError)
	input := flags.String("input", "", "results.json from par3 run")
	out := flags.String("out", "", "write the Markdown here instead of stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	results, err := par3bench.ReadResults(workspacePath(*input))
	if err != nil {
		return err
	}
	report := par3bench.RenderReport(results)
	if *out == "" {
		_, err = fmt.Fprint(stdout, report)
		return err
	}
	return os.WriteFile(workspacePath(*out), []byte(report), 0o644)
}

func runPAR3Versus(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("par3 versus", flag.ContinueOnError)
	candidate := flags.String("candidate", "", "rarpar binary (runs both par and par3)")
	par2 := flags.String("par2", "", "optional par2cmdline-turbo binary; its arm is skipped without one")
	work := flags.String("work", "", "work directory: generated datasets and stages")
	out := flags.String("out", "", "evidence directory: results.json, report.md")
	profileName := flags.String("profile", "versus-smoke", "profile: versus-smoke or versus")
	warmups := flags.Int("warmups", 1, "warmup runs per arm (recorded, not summarised)")
	repeats := flags.Int("repeats", 5, "measured runs per arm")
	machine := flags.String("machine", "", "machine label recorded in the results")
	pin := flags.String("pin-cpus", "", "confine every timed process to an inclusive CPU range, e.g. 0-7")
	timeout := flags.Duration("timeout", par3bench.DefaultTimeout, "per-run timeout for every timed process")
	var sets stringList
	flags.Var(&sets, "set", "restrict to a set ID (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	profile, err := par3bench.LookupVersusProfile(*profileName)
	if err != nil {
		return err
	}
	if profile, err = profile.Select(sets); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	results, err := par3bench.RunVersus(ctx, par3bench.VersusOptions{
		Candidate: workspacePath(*candidate), PAR2Turbo: workspacePath(*par2), Work: workspacePath(*work),
		Out: workspacePath(*out), Profile: profile, Warmups: *warmups, Repeats: *repeats, MachineLabel: *machine,
		PinCPUs: *pin, Timeout: *timeout, Log: func(format string, args ...any) { fmt.Fprintf(os.Stderr, "par3 versus: "+format+"\n", args...) },
	})
	if err != nil {
		return err
	}
	if _, err := fmt.Fprint(stdout, par3bench.RenderVersusReport(results)); err != nil {
		return err
	}
	if results.Status != "ok" {
		return fmt.Errorf("PAR2/PAR3 comparison finished with failures: %s", strings.Join(results.Failures, "; "))
	}
	return nil
}

func runPAR3VersusReport(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("par3 versus-report", flag.ContinueOnError)
	input := flags.String("input", "", "results.json from par3 versus")
	out := flags.String("out", "", "write the Markdown here instead of stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	results, err := par3bench.ReadVersusResults(workspacePath(*input))
	if err != nil {
		return err
	}
	report := par3bench.RenderVersusReport(results)
	if *out == "" {
		_, err = fmt.Fprint(stdout, report)
		return err
	}
	return os.WriteFile(workspacePath(*out), []byte(report), 0o644)
}

func runPAR3Render(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("par3 render", flag.ContinueOnError)
	input := flags.String("input", "", "results.json from par3 run")
	out := flags.String("out", "", "directory for the per-operation SVGs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *out == "" {
		return fmt.Errorf("--input and --out are required")
	}
	results, err := par3bench.ReadResults(workspacePath(*input))
	if err != nil {
		return err
	}
	paths, err := par3bench.RenderSVGs(results, workspacePath(*out))
	if err != nil {
		return err
	}
	for _, path := range paths {
		fmt.Fprintln(stdout, path)
	}
	return nil
}

func runPAR3VersusRender(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("par3 versus-render", flag.ContinueOnError)
	var inputs stringList
	flags.Var(&inputs, "input", "[NAME=]results.json from par3 versus (repeatable, in chart order)")
	out := flags.String("out", "", "directory for the per-comparison SVGs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if len(inputs) == 0 || *out == "" {
		return fmt.Errorf("--input and --out are required")
	}
	var charts []par3bench.VersusChartInput
	for _, input := range inputs {
		name, path := "", input
		if before, after, ok := strings.Cut(input, "="); ok {
			name, path = before, after
		}
		results, err := par3bench.ReadVersusResults(workspacePath(path))
		if err != nil {
			return err
		}
		charts = append(charts, par3bench.VersusChartInput{Name: name, Results: results})
	}
	paths, err := par3bench.RenderVersusSVGs(charts, workspacePath(*out))
	if err != nil {
		return err
	}
	for _, path := range paths {
		fmt.Fprintln(stdout, path)
	}
	return nil
}
