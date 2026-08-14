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
		return fmt.Errorf("fleet requires run, plan, collect, or teardown")
	}
	switch args[0] {
	case "run":
		return fleetRun(ctx, args[1:])
	case "plan":
		return fleetPlan(args[1:])
	case "collect":
		return fleetCollect(ctx, args[1:])
	case "teardown":
		return fleetTeardown(ctx, args[1:])
	case "-h", "--help", "help":
		fleetUsage()
		return nil
	default:
		return fmt.Errorf("unknown fleet command %q", args[0])
	}
}

func fleetUsage() {
	fmt.Fprint(os.Stderr, `Usage:
  rarpar-bench fleet plan     --config PATH [--machine NAME]... [--suite NAME]... [--json]
  rarpar-bench fleet run      --config PATH [--machine NAME]... [--suite NAME]... [--dry-run-aws] [--no-fetch] [--no-render]
  rarpar-bench fleet collect  --config PATH --run-id ID [--machine NAME]...
  rarpar-bench fleet teardown --config PATH [--run-id ID] [--dry-run-aws]

One command spawns every configured host in parallel (local SSH and EC2), runs
the full protocol on each, collects results as hosts finish, tears cloud hosts
down with verification, and renders charts plus a fleet summary here.

The configuration is operator-private and gitignored; start from
bench/fleet.example.toml. See docs/fleet.md.
`)
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

func fleetPlan(args []string) error {
	var options fleetFlags
	flags := fleetFlagSet("plan", &options)
	flags.StringVar(&options.runID, "run-id", "", "plan for a specific run id instead of a fresh one")
	flags.BoolVar(&options.jsonOut, "json", false, "emit the plan as JSON")
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
	plan := fleet.BuildPlan(config, machines, runID)
	if options.jsonOut {
		return writeJSONTo(os.Stdout, plan)
	}
	fleet.WritePlanText(os.Stdout, plan)
	return nil
}

func fleetRun(ctx context.Context, args []string) error {
	var options fleetFlags
	flags := fleetFlagSet("run", &options)
	flags.StringVar(&options.runID, "run-id", "", "run id (default: a fresh time-ordered id)")
	flags.Var(&options.hold, "hold", "keep this machine's cloud host alive after its evidence is collected (repeat for more); it keeps billing until `fleet teardown --run-id` runs")
	flags.BoolVar(&options.dryRunAWS, "dry-run-aws", false, "exercise every AWS code path except the API mutations; reads still run live")
	flags.BoolVar(&options.noFetch, "no-fetch", false, "fail instead of downloading a missing oracle artifact")
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
