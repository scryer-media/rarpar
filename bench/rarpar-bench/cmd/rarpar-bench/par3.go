package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/par3bench"
)

const par3Usage = `Usage:
  rarpar-bench par3 matrix [--profile smoke|full] [--set ID]... [--workers 1,8] [--kernel-variant NAME:VAR=V]... [--json]
  rarpar-bench par3 build-reference --out DIR [--toolchains PATH] [--cache DIR] [--mirror-base URL] [--cmake PATH] [--jobs N]
  rarpar-bench par3 run --reference PATH --candidate PATH --work DIR --out DIR [--profile smoke|full] [--set ID]...
        [--ops create,verify,repair] [--warmups N] [--repeats N] [--workers 1,8] [--pin-cpus 0-7]
        [--kernel-variant NAME:VAR=V[,VAR=V]]... [--iocount] [--engine-perf PATH] [--candidate-arg ARG]...
        [--machine LABEL] [--timeout DURATION] [--keep-stages]
  rarpar-bench par3 report --input results.json [--out report.md]

The PAR3 suite benchmarks the shipped rarpar CLI against the pinned par3cmdline
reference on deterministic generated inputs. See docs/benchmarking.md.
`

func runPAR3(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, par3Usage)
		return fmt.Errorf("par3 requires matrix, build-reference, run, or report")
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
	profileName := flags.String("profile", "smoke", "profile: smoke or full")
	workers := flags.String("workers", "1,8", "rarpar worker counts")
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
	rows := par3bench.Variants(workerList, variants)
	if *jsonOut {
		return writeJSONTo(stdout, map[string]any{"profile": profile, "variants": rows})
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "SET\tDATASET\tBYTES\tBLOCK\tINPUT\tRECOVERY\tCODEC\tFIELD\tDAMAGE")
	for _, config := range profile.Configs {
		dataset, _ := profile.Dataset(config.Dataset)
		codec := config.Codec
		if codec == "fft" {
			codec = fmt.Sprintf("fft(2^%d)", config.CapacityLog2())
		}
		fmt.Fprintf(table, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s (%d)\n", config.ID, dataset.ID, dataset.TotalBytes(),
			config.BlockSize, par3bench.InputBlocks(dataset, config.BlockSize), config.Recovery, codec,
			config.ExpectedField, config.Damage.Name, config.Damage.LostBlocks())
	}
	if err := table.Flush(); err != nil {
		return err
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.Name)
	}
	_, err = fmt.Fprintf(stdout, "\nvariants: %s\n", strings.Join(names, ", "))
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
	profileName := flags.String("profile", "smoke", "profile: smoke or full")
	ops := flags.String("ops", strings.Join(par3bench.DefaultOps, ","), "operations: "+strings.Join(par3bench.KnownOps, ","))
	warmups := flags.Int("warmups", 1, "warmup runs per variant (recorded, not summarised)")
	repeats := flags.Int("repeats", 5, "measured runs per variant")
	workers := flags.String("workers", "1,8", "rarpar worker counts")
	pin := flags.String("pin-cpus", "", "confine every timed process to an inclusive CPU range, e.g. 0-7 (Linux taskset, Windows affinity)")
	iocount := flags.Bool("iocount", false, "add an untimed strace -f -c pass per variant and op (Linux)")
	machine := flags.String("machine", "", "machine label recorded in the results")
	memory := flags.Int("engine-perf-memory-mib", 256, "engine_perf memory budget")
	timeout := flags.Duration("timeout", 2*time.Hour, "per-process timeout")
	keep := flags.Bool("keep-stages", false, "keep per-run stage directories")
	var sets, kernels, candidateArgs stringList
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
	results, err := par3bench.RunSuite(ctx, par3bench.Options{
		Reference: workspacePath(*reference), Candidate: workspacePath(*candidate), EnginePerf: workspacePath(*enginePerf),
		Work: workspacePath(*work), Out: workspacePath(*out), Profile: profile, Ops: splitList(*ops),
		Warmups: *warmups, Repeats: *repeats, Workers: workerList, PinCPUs: *pin, KernelVariants: variants,
		IOCount: *iocount, MachineLabel: *machine, CandidateArgs: candidateArgs, EnginePerfMemoryMiB: *memory,
		KeepStages: *keep, Timeout: *timeout, Log: os.Stderr,
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
