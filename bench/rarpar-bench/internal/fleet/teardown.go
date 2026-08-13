package fleet

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TeardownOptions drive `fleet teardown`, the sweep for strays left behind by an
// interrupted run.
type TeardownOptions struct {
	Config    Config
	RunID     string
	DryRunAWS bool
	Log       io.Writer
}

// Teardown terminates anything still alive from a run (or, with no run id, from
// any run carrying the fleet's resource prefix) and verifies each removal.
func Teardown(ctx context.Context, options TeardownOptions) error {
	if options.Log == nil {
		options.Log = os.Stderr
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(options.Log, "[%s] %s\n", time.Now().UTC().Format("15:04:05Z"), fmt.Sprintf(format, args...))
	}
	settings := options.Config.Fleet.AWS
	profile := ""
	if settings.ProfileEnv != "" {
		profile = os.Getenv(settings.ProfileEnv)
	}
	aws := &AWS{CLI: settings.CLI, Region: settings.Region, Profile: profile, DryRun: options.DryRunAWS, Log: logf}
	if _, err := aws.CheckCredentials(ctx, settings.Account); err != nil {
		return err
	}

	if options.RunID != "" {
		runDir := filepath.Join(options.Config.Fleet.ResultsRoot, options.RunID)
		state, err := LoadRunState(runDir)
		if err != nil {
			return err
		}
		for _, machine := range state.Machines {
			if machine.Cloud == nil || machine.Cloud.InstanceID == "" || machine.Teardown != nil {
				continue
			}
			logf("tearing down %s (%s)", machine.Name, machine.Cloud.InstanceID)
			evidence, err := aws.Terminate(ctx, machine.Cloud)
			machine.Teardown = &evidence
			if err != nil {
				logf("teardown of %s reported: %v", machine.Name, err)
			}
			logf("  instance=%s volume=%s verified=%t", evidence.InstanceState, evidence.VolumeState, evidence.Verified)
		}
		if state.Session != nil {
			lines, err := aws.DeleteSession(ctx, *state.Session)
			if err != nil {
				logf("session teardown: %v", err)
			}
			for _, line := range lines {
				logf("session teardown: %s", line)
			}
			state.Session = nil
		}
		_ = state.Save()
	}

	// Whatever the run state claims, ask the account what is actually alive.
	stray, err := aws.Sweep(ctx, settings.ResourcePrefix)
	if err != nil {
		return err
	}
	if len(stray) == 0 {
		logf("sweep: no %s-prefixed instances, security groups, or keypairs remain in %s", settings.ResourcePrefix, settings.Region)
		return nil
	}
	logf("sweep found %d fleet-tagged resource(s) still present:", len(stray))
	for _, item := range stray {
		logf("  %s", item)
	}
	return fmt.Errorf("teardown incomplete: %s", strings.Join(stray, "; "))
}

func runLocal(program string, args ...string) error {
	command := exec.Command(program, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", program, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// NewRunID produces the run directory name. It is time-ordered so runs sort
// chronologically and never collide within a second.
func NewRunID(prefix string) string {
	if prefix == "" {
		prefix = "fleet"
	}
	return prefix + "-" + time.Now().UTC().Format("20060102T150405Z")
}
