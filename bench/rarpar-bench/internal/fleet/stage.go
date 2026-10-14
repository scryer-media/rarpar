package fleet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// StageStateFile is the state a `fleet plan --stage` dry check leaves in its
// run directory. It is never run-state.json, so `fleet collect --resume` and
// `fleet teardown` cannot mistake a dry check for a round.
const StageStateFile = "stage-state.json"

// Stage is the dry check behind `fleet plan --stage`. It downloads and
// verifies every release asset and assembles every machine's bundle exactly
// as `fleet run` would, then stops: it contacts no fleet host, checks no
// credential and launches nothing. Bundles and the oracle cache go under the
// run directory, never fleet.bundle_cache, so a dry check cannot disturb a
// live run's bundles.
func Stage(ctx context.Context, options Options) (*RunState, error) {
	if options.Log == nil {
		options.Log = os.Stderr
	}
	if err := ValidateRunID(options.RunID); err != nil {
		return nil, err
	}
	options.Config.Fleet.BundleCache = ""
	runDir := filepath.Join(options.Config.Fleet.ResultsRoot, options.RunID)
	if _, err := os.Stat(filepath.Join(runDir, RunStateFile)); err == nil {
		return nil, fmt.Errorf("run %s already has a %s; a dry check would overwrite that round's plan, pick a new run id", options.RunID, RunStateFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return nil, err
	}
	orch := &orchestrator{options: options, runDir: runDir}
	if err := orch.begin(StageStateFile); err != nil {
		return nil, err
	}
	if err := orch.resolveReleases(ctx); err != nil {
		return nil, err
	}
	if err := orch.build(ctx); err != nil {
		return nil, err
	}
	for _, machine := range orch.state.Machines {
		orch.state.SetStatus(machine, StatusStaged)
	}
	orch.state.FinishedUTC = time.Now().UTC().Format(time.RFC3339)
	if err := orch.state.Save(); err != nil {
		return nil, err
	}
	return orch.state, nil
}

// WriteStageText prints what a dry check staged: per machine, the release
// asset with the digests it was verified against, and every binary in the
// assembled bundle.
func WriteStageText(writer io.Writer, state *RunState) error {
	fmt.Fprintf(writer, "STAGED %s (no fleet host contacted, nothing launched)\n", state.RunID)
	fmt.Fprintf(writer, "  run dir     %s\n", state.RunDir)
	fmt.Fprintf(writer, "  state       %s\n", filepath.Join(state.RunDir, StageStateFile))
	for _, machine := range state.Machines {
		var info BuildInfo
		if err := readJSONFile(filepath.Join(machine.BundleDir, "BUILDINFO.json"), &info); err != nil {
			return fmt.Errorf("machine %s: %w", machine.Name, err)
		}
		fmt.Fprintf(writer, "\nMACHINE %s  [%s]  %s\n", machine.Name, machine.Status, machine.BundleDir)
		if release := machine.Release; release != nil {
			fmt.Fprintf(writer, "  release    %s %s (%d bytes, %s)\n", release.Tag, release.Asset, release.Size, release.RustTarget)
			fmt.Fprintf(writer, "  verified   sha256 %s\n", release.SHA256)
			fmt.Fprintf(writer, "             matches %s (sha256 %s)\n", release.SumsURL, release.SumsSHA256)
			fmt.Fprintf(writer, "  unpacked   %s sha256 %s (%d bytes)\n", release.Binary, release.BinarySHA256, release.BinarySize)
		} else {
			fmt.Fprintf(writer, "  bundle     %s (dev spot test, not the published release artifacts)\n", info.Source)
		}
		for index, name := range sortedKeys(info.Binaries) {
			label := ""
			if index == 0 {
				label = "bundled"
			}
			fmt.Fprintf(writer, "  %-10s %-18s sha256 %s\n", label, name, info.Binaries[name])
		}
	}
	return nil
}
