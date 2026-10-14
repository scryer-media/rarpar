package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/fleet"
)

func runFleet(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fleetUsage()
		return fmt.Errorf("fleet requires run, plan, collect, teardown, or build-unrar")
	}
	switch args[0] {
	case "run":
		return fleetRun(ctx, args[1:])
	case "plan":
		return fleetPlan(ctx, args[1:])
	case "collect":
		return fleetCollect(ctx, args[1:])
	case "teardown":
		return fleetTeardown(ctx, args[1:])
	case "build-unrar":
		return fleetBuildUnrar(ctx, args[1:])
	case "-h", "--help", "help":
		fleetUsage()
		return nil
	default:
		return fmt.Errorf("unknown fleet command %q", args[0])
	}
}

func fleetUsage() {
	fmt.Fprint(os.Stderr, `Usage:
  rarpar-bench fleet plan     --config PATH [--machine NAME]... [--suite NAME]... [--json] [--stage [--no-fetch]]
  rarpar-bench fleet run      --config PATH [--machine NAME]... [--suite NAME]... [--dry-run-aws] [--no-fetch] [--no-render]
  rarpar-bench fleet collect  --config PATH --run-id ID [--machine NAME]...
  rarpar-bench fleet teardown --config PATH [--run-id ID] [--dry-run-aws]
  rarpar-bench fleet build-unrar --source TARBALL --sha256 HEX --out DIR [--url URL] [--binary-sha256 HEX]

One command spawns every configured host in parallel (local SSH and EC2), runs
the full protocol on each, collects results as hosts finish, tears cloud hosts
down with verification, and renders charts plus a fleet summary here.

The rarpar each host runs is the published release asset for its platform,
verified against the release's SHA256SUMS before anything is launched; a
prebuilt bundle is the dev spot-test path. "fleet plan --stage" downloads,
verifies and stages every bundle without contacting a fleet host.

build-unrar runs on a fleet host, from the generated run script: on Linux
arm64, where RARLAB publishes no UnRAR, it builds the unrar-portable-onhost
oracle from the shipped, sha256-pinned source with the audited portable recipe
(stock makefile, CXXFLAGS and LDFLAGS, CXX=g++, no -march/-mcpu/-mtune),
checks that the binary starts and prints UnRAR's banner, and prints the build
record.

The configuration is operator-private and gitignored; start from
bench/fleet.example.toml. See docs/fleet.md.
`)
}

func fleetBuildUnrar(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("fleet build-unrar", flag.ContinueOnError)
	source := flags.String("source", "", "the shipped UnRAR source tarball")
	sha := flags.String("sha256", "", "the source tarball's pinned sha256")
	sourceURL := flags.String("url", "", "where the orchestrator fetched the source (recorded)")
	out := flags.String("out", "", "build directory: src/, the installed unrar, unrar-build.json")
	binarySHA := flags.String("binary-sha256", "", "optional pin on the built binary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	build, err := fleet.BuildUnrar(ctx, fleet.UnrarBuildOptions{
		Source: *source, SourceSHA256: *sha, SourceURL: *sourceURL,
		Out: *out, BinarySHA256: *binarySHA, Log: os.Stderr,
	})
	if err != nil {
		return err
	}
	return writeJSONTo(os.Stdout, build)
}

type fleetFlags struct {
	config    string
	machines  repeatedFlag
	suites    repeatedFlag
	runID     string
	hold      repeatedFlag
	dryRunAWS bool
	noFetch   bool
	noRender  bool
	jsonOut   bool
	stage     bool
}

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }

func (values *repeatedFlag) Set(value string) error {
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func fleetFlagSet(name string, options *fleetFlags) *flag.FlagSet {
	flags := flag.NewFlagSet("fleet "+name, flag.ContinueOnError)
	flags.StringVar(&options.config, "config", "bench/fleet.toml", "fleet configuration (gitignored)")
	flags.Var(&options.machines, "machine", "limit to this machine; repeat for more")
	flags.Var(&options.suites, "suite", "limit to this suite; repeat for more")
	return flags
}

func loadFleet(options *fleetFlags) (fleet.Config, []fleet.Machine, error) {
	config, err := fleet.LoadConfig(workspacePath(options.config))
	if err != nil {
		return fleet.Config{}, nil, err
	}
	machines, err := fleet.Select(config, options.machines, options.suites)
	if err != nil {
		return fleet.Config{}, nil, err
	}
	return config, machines, nil
}

func fleetPlan(ctx context.Context, args []string) error {
	var options fleetFlags
	flags := fleetFlagSet("plan", &options)
	flags.StringVar(&options.runID, "run-id", "", "plan for a specific run id instead of a fresh one")
	flags.BoolVar(&options.jsonOut, "json", false, "emit the plan as JSON")
	flags.BoolVar(&options.stage, "stage", false, "dry check: download and verify every release asset and assemble every bundle under the run directory; no fleet host is contacted and nothing is launched")
	flags.BoolVar(&options.noFetch, "no-fetch", false, "with --stage, fail instead of downloading a missing oracle artifact (release assets are always downloaded and verified)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if options.stage && options.jsonOut {
		return fmt.Errorf("--stage records its result in the run directory's %s; drop --json", fleet.StageStateFile)
	}
	if options.noFetch && !options.stage {
		return fmt.Errorf("--no-fetch only applies with --stage")
	}
	config, machines, err := loadFleet(&options)
	if err != nil {
		return err
	}
	runID := options.runID
	if runID == "" {
		runID = fleet.NewRunID(config.Fleet.RunIDPrefix)
	}
	plan := fleet.BuildPlan(config, machines, runID)
	if options.jsonOut {
		return writeJSONTo(os.Stdout, plan)
	}
	fleet.WritePlanText(os.Stdout, plan)
	if !options.stage {
		return nil
	}
	state, err := fleet.Stage(ctx, fleet.Options{
		Config:     config,
		Machines:   machines,
		RunID:      runID,
		AllowFetch: !options.noFetch,
		Log:        os.Stderr,
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout)
	return fleet.WriteStageText(os.Stdout, state)
}

func fleetRun(ctx context.Context, args []string) error {
	var options fleetFlags
	flags := fleetFlagSet("run", &options)
	flags.StringVar(&options.runID, "run-id", "", "run id (default: a fresh time-ordered id)")
	flags.Var(&options.hold, "hold", "keep this machine's cloud host alive after its evidence is collected (repeat for more); it keeps billing until `fleet teardown --run-id` runs")
	flags.BoolVar(&options.dryRunAWS, "dry-run-aws", false, "exercise every AWS code path except the API mutations; reads still run live")
	flags.BoolVar(&options.noFetch, "no-fetch", false, "fail instead of downloading a missing oracle artifact (release assets are always downloaded and verified)")
	flags.BoolVar(&options.noRender, "no-render", false, "skip SVG rendering")
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, machines, err := loadFleet(&options)
	if err != nil {
		return err
	}
	runID := options.runID
	if runID == "" {
		runID = fleet.NewRunID(config.Fleet.RunIDPrefix)
	}
	summary, err := fleet.Run(ctx, fleet.Options{
		Config:     config,
		Machines:   machines,
		RunID:      runID,
		DryRunAWS:  options.dryRunAWS,
		AllowFetch: !options.noFetch,
		SkipRender: options.noRender,
		Hold:       options.hold,
		Log:        os.Stderr,
	})
	if err != nil {
		return err
	}
	fleet.WriteSummaryText(os.Stdout, summary)
	if !summary.OK {
		return fmt.Errorf("fleet run %s completed with failures", summary.RunID)
	}
	return nil
}

func fleetCollect(ctx context.Context, args []string) error {
	var options fleetFlags
	flags := fleetFlagSet("collect", &options)
	flags.StringVar(&options.runID, "run-id", "", "run id to resume")
	flags.BoolVar(&options.noRender, "no-render", false, "skip SVG rendering")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if options.runID == "" {
		return fmt.Errorf("--run-id is required")
	}
	config, machines, err := loadFleet(&options)
	if err != nil {
		return err
	}
	summary, err := fleet.Resume(ctx, fleet.Options{
		Config:     config,
		Machines:   machines,
		RunID:      options.runID,
		Resume:     true,
		SkipRender: options.noRender,
		Log:        os.Stderr,
	})
	if err != nil {
		return err
	}
	fleet.WriteSummaryText(os.Stdout, summary)
	if !summary.OK {
		return fmt.Errorf("fleet run %s still has failures", summary.RunID)
	}
	return nil
}

func fleetTeardown(ctx context.Context, args []string) error {
	var options fleetFlags
	flags := fleetFlagSet("teardown", &options)
	flags.StringVar(&options.runID, "run-id", "", "tear down the cloud hosts of this run, then sweep")
	flags.BoolVar(&options.dryRunAWS, "dry-run-aws", false, "report what would be torn down without mutating anything")
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := fleet.LoadConfig(workspacePath(options.config))
	if err != nil {
		return err
	}
	return fleet.Teardown(ctx, fleet.TeardownOptions{
		Config:    config,
		RunID:     options.runID,
		DryRunAWS: options.dryRunAWS,
		Log:       os.Stderr,
	})
}
