package fleet

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// collectMachine polls one host for its DONE sentinel, pulls the tarball,
// verifies it against the inventory manifest, and only then tears the host down.
// Each host is collected the moment it finishes; a slow host never holds up a
// fast one.
func (orch *orchestrator) collectMachine(ctx context.Context, machine Machine, hostState *MachineState) error {
	if machine.Kind == KindAWSEC2 {
		if hostState.Cloud == nil || hostState.Cloud.InstanceID == "" {
			return fmt.Errorf("machine %s: no launched instance to collect from", machine.Name)
		}
		if orch.options.DryRunAWS || hostState.Cloud.DryRun {
			orch.state.SetStatus(hostState, StatusSkipped)
			return nil
		}
		machine.Connection.Host = hostState.Cloud.PublicIP
		machine.Connection.Auth = "key"
		if orch.session != nil {
			machine.Connection.KeyPath = orch.session.KeyPath
		}
	}
	orch.state.SetStatus(hostState, StatusCollecting)
	transport, err := NewTransport(machine, orch.runDir)
	if err != nil {
		return err
	}
	defer transport.Close()

	layout := LayoutFor(machine, orch.options.RunID)
	deadline := time.Now().Add(time.Duration(orch.options.Config.Fleet.HostTimeoutMinutes) * time.Minute)
	if machine.Kind == KindAWSEC2 && machine.EC2 != nil {
		// The cost cap is a hard deadline, not a target: past it the host is
		// terminated whatever it is doing.
		launched, parseErr := time.Parse(time.RFC3339, hostState.Cloud.LaunchUTC)
		if parseErr == nil {
			costDeadline := launched.Add(time.Duration(machine.EC2.MaxHours * float64(time.Hour)))
			if costDeadline.Before(deadline) {
				deadline = costDeadline
			}
		}
	}
	poll := time.Duration(orch.options.Config.Fleet.PollSeconds) * time.Second

	var done map[string]string
	for {
		sentinel, err := orch.readSentinel(ctx, transport, layout)
		if err == nil && sentinel != nil {
			done = sentinel
			break
		}
		if time.Now().After(deadline) {
			orch.state.Record(hostState, "collect", "deadline passed without a DONE sentinel")
			if machine.Kind == KindAWSEC2 {
				orch.teardownCloud(ctx, machine, hostState)
			}
			return fmt.Errorf("machine %s: timed out after the configured cap without finishing", machine.Name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}

	orch.log("machine %s: DONE (status=%s elapsed=%ss)", machine.Name, done["status"], done["elapsed_seconds"])
	orch.state.Record(hostState, "collect", "DONE sentinel: status=%s elapsed=%ss files=%s",
		done["status"], done["elapsed_seconds"], done["files"])

	resultsDir := filepath.Join(orch.runDir, "hosts", machine.Name)
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return err
	}
	if err := transport.DownloadPath(ctx, layout.Tarball, resultsDir); err != nil {
		return err
	}
	if err := transport.DownloadPath(ctx, layout.Log, resultsDir); err != nil {
		orch.log("machine %s: could not pull run.log: %v", machine.Name, err)
	}
	tarball := filepath.Join(resultsDir, posixBase(layout.Tarball))
	digest, err := fileSHA256(tarball)
	if err != nil {
		return err
	}
	if expected := done["tarball_sha256"]; expected != "" && expected != digest {
		return fmt.Errorf("machine %s: tarball digest %s does not match the sentinel's %s", machine.Name, digest, expected)
	}
	evidence := filepath.Join(resultsDir, "results")
	if err := os.MkdirAll(evidence, 0o755); err != nil {
		return err
	}
	if err := extractTarGz(tarball, evidence); err != nil {
		return err
	}
	manifest, err := verifyManifest(evidence)
	if err != nil {
		return fmt.Errorf("machine %s: %w", machine.Name, err)
	}
	hostState.Manifest = manifest
	hostState.ResultsDir = evidence
	orch.state.Record(hostState, "collect", "verified %d files against MANIFEST.json", len(manifest.Files))

	if machine.Kind == KindAWSEC2 {
		// --hold keeps a collected host alive for an operator-driven extra pass
		// (an env A/B on the same silicon and the same binary). The evidence is
		// already in hand, so this only defers the terminate; the user-data
		// deadman and `fleet teardown --run-id` both still end the instance.
		if orch.holds(machine.Name) {
			orch.state.Record(hostState, "teardown", "HELD by --hold: instance %s is still running; `fleet teardown --run-id %s` ends it",
				hostState.Cloud.InstanceID, orch.options.RunID)
			orch.log("machine %s: HELD ALIVE by --hold (instance %s at %s); it is still billing",
				machine.Name, hostState.Cloud.InstanceID, hostState.Cloud.PublicIP)
		} else {
			orch.teardownCloud(ctx, machine, hostState)
		}
	} else if machine.Paths.Cleanup {
		if _, _, err := transport.RunScript(ctx, "rm -rf "+shellQuote(layout.Base)+" "+shellQuote(layout.Scratch)+"\n"); err != nil {
			orch.log("machine %s: staging cleanup reported: %v", machine.Name, err)
		} else {
			orch.state.Record(hostState, "cleanup", "removed %s and %s", layout.Base, layout.Scratch)
		}
	}

	if manifest.Status != "ok" {
		hostState.Failure = "host reported failures: " + manifest.Failures
		orch.state.SetStatus(hostState, StatusFailed)
		return nil
	}
	if hostState.Status != StatusTornDown {
		orch.state.SetStatus(hostState, StatusDone)
	}
	return nil
}

func (orch *orchestrator) readSentinel(ctx context.Context, transport *Transport, layout RemoteLayout) (map[string]string, error) {
	attempt, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stdout, _, err := transport.RunScript(attempt, "cat "+shellQuote(layout.Done)+" 2>/dev/null || echo __PENDING__\n")
	if err != nil {
		return nil, err
	}
	if strings.Contains(stdout, "__PENDING__") {
		return nil, nil
	}
	values := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			values[key] = value
		}
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values, nil
}

// teardownCloud terminates and then proves the termination. Verification is part
// of a host being finished, not a best-effort afterthought.
func (orch *orchestrator) teardownCloud(ctx context.Context, machine Machine, hostState *MachineState) {
	if hostState.Cloud == nil || hostState.Teardown != nil {
		return
	}
	evidence, err := orch.aws.Terminate(ctx, hostState.Cloud)
	hostState.Teardown = &evidence
	if err != nil {
		orch.log("machine %s: teardown error: %v", machine.Name, err)
		orch.state.Record(hostState, "teardown", "terminate failed: %v", err)
	}
	if launched, parseErr := time.Parse(time.RFC3339, hostState.Cloud.LaunchUTC); parseErr == nil {
		terminated := time.Now().UTC()
		if hostState.Cloud.TerminateUTC != "" {
			if parsed, err := time.Parse(time.RFC3339, hostState.Cloud.TerminateUTC); err == nil {
				terminated = parsed
			}
		}
		hostState.BilledMinutes = terminated.Sub(launched).Minutes()
		if machine.EC2 != nil {
			hostState.CostUSD = roundCents(machine.EC2.HourlyUSD * hostState.BilledMinutes / 60)
		}
	}
	orch.state.Record(hostState, "teardown", "instance=%s volume=%s verified=%t",
		evidence.InstanceState, evidence.VolumeState, evidence.Verified)
	if hostState.Status != StatusFailed {
		orch.state.SetStatus(hostState, StatusTornDown)
	}
	_ = orch.state.Save()
}

func verifyManifest(root string) (*HostManifest, error) {
	manifest := &HostManifest{}
	if err := readJSONFile(filepath.Join(root, "MANIFEST.json"), manifest); err != nil {
		return nil, fmt.Errorf("read the host inventory manifest: %w", err)
	}
	var problems []string
	for _, file := range manifest.Files {
		path := filepath.Join(root, filepath.FromSlash(file.Path))
		info, err := os.Stat(path)
		if err != nil {
			problems = append(problems, file.Path+": missing from the tarball")
			continue
		}
		if info.Size() != file.Bytes {
			problems = append(problems, fmt.Sprintf("%s: %d bytes, manifest says %d", file.Path, info.Size(), file.Bytes))
			continue
		}
		if file.SHA256 == "" {
			continue
		}
		digest, err := fileSHA256(path)
		if err != nil {
			problems = append(problems, file.Path+": "+err.Error())
			continue
		}
		if digest != file.SHA256 {
			problems = append(problems, file.Path+": digest mismatch")
		}
	}
	if len(problems) > 0 {
		return manifest, fmt.Errorf("collected evidence does not match the host manifest:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return manifest, nil
}

func extractTarGz(archive, destination string) error {
	return runLocal("tar", "-xzf", archive, "-C", destination)
}

// ---------------------------------------------------------------- summary ----

type Summary struct {
	SchemaVersion int              `json:"schema_version"`
	RunID         string           `json:"run_id"`
	StartedUTC    string           `json:"started_utc"`
	FinishedUTC   string           `json:"finished_utc"`
	ConfigPath    string           `json:"config_path"`
	ConfigSHA256  string           `json:"config_sha256"`
	RunDir        string           `json:"run_dir"`
	DryRunAWS     bool             `json:"dry_run_aws"`
	Machines      []MachineSummary `json:"machines"`
	TotalCostUSD  float64          `json:"total_cost_usd"`
	Failures      []string         `json:"failures,omitempty"`
	OK            bool             `json:"ok"`
}

type MachineSummary struct {
	Name           string            `json:"name"`
	Kind           string            `json:"kind"`
	PlatformLabel  string            `json:"platform_label"`
	Status         string            `json:"status"`
	Suites         []string          `json:"suites"`
	Endpoint       string            `json:"endpoint"`
	ElapsedSeconds int               `json:"elapsed_seconds"`
	Files          int               `json:"evidence_files"`
	Comparisons    map[string]int    `json:"comparisons,omitempty"`
	Charts         []string          `json:"charts,omitempty"`
	Teardown       *TeardownEvidence `json:"teardown,omitempty"`
	CostUSD        float64           `json:"cost_usd,omitempty"`
	BilledMinutes  float64           `json:"billed_minutes,omitempty"`
	Failure        string            `json:"failure,omitempty"`
	HostFailures   string            `json:"host_failures,omitempty"`
	HostWarnings   string            `json:"host_warnings,omitempty"`
}

func (orch *orchestrator) finish(ctx context.Context) (Summary, error) {
	_ = ctx
	summary := Summary{
		SchemaVersion: 1,
		RunID:         orch.state.RunID,
		StartedUTC:    orch.state.StartedUTC,
		FinishedUTC:   time.Now().UTC().Format(time.RFC3339),
		ConfigPath:    orch.state.ConfigPath,
		ConfigSHA256:  orch.state.ConfigSHA256,
		RunDir:        orch.runDir,
		DryRunAWS:     orch.state.DryRunAWS,
		OK:            true,
	}
	for _, hostState := range orch.state.Machines {
		item := MachineSummary{
			Name:          hostState.Name,
			Kind:          hostState.Kind,
			PlatformLabel: hostState.PlatformLabel,
			Status:        hostState.Status,
			Suites:        hostState.Suites,
			Endpoint:      hostState.Endpoint,
			Teardown:      hostState.Teardown,
			CostUSD:       hostState.CostUSD,
			BilledMinutes: hostState.BilledMinutes,
			Failure:       hostState.Failure,
		}
		if hostState.Manifest != nil {
			item.ElapsedSeconds = hostState.Manifest.ElapsedSeconds
			item.Files = len(hostState.Manifest.Files)
			item.HostFailures = hostState.Manifest.Failures
			item.HostWarnings = hostState.Manifest.Warnings
		}
		if hostState.ResultsDir != "" && orch.options.Config.Fleet.Render.Enabled && !orch.options.SkipRender {
			charts, counts, err := orch.render(hostState)
			if err != nil {
				orch.log("machine %s: render: %v", hostState.Name, err)
				orch.state.Record(hostState, "render", "render failed: %v", err)
			}
			item.Charts = charts
			item.Comparisons = counts
			hostState.Charts = charts
		}
		summary.TotalCostUSD += hostState.CostUSD
		if hostState.Status != StatusDone && hostState.Status != StatusTornDown && hostState.Status != StatusSkipped {
			summary.OK = false
			summary.Failures = append(summary.Failures, fmt.Sprintf("%s: %s %s", hostState.Name, hostState.Status, hostState.Failure))
		}
		if hostState.Teardown != nil && !hostState.Teardown.Verified {
			summary.OK = false
			summary.Failures = append(summary.Failures, hostState.Name+": teardown could not be verified")
		}
		summary.Machines = append(summary.Machines, item)
	}
	summary.TotalCostUSD = roundCents(summary.TotalCostUSD)
	if err := writeJSONFile(filepath.Join(orch.runDir, "fleet-summary.json"), summary); err != nil {
		return summary, err
	}
	text, err := os.Create(filepath.Join(orch.runDir, "fleet-summary.txt"))
	if err != nil {
		return summary, err
	}
	WriteSummaryText(text, summary)
	text.Close()
	_ = orch.state.Save()
	return summary, nil
}

// render turns a host's report.json files into SVGs under the run directory.
// Charts land in the run directory, never in the repository's docs.
func (orch *orchestrator) render(hostState *MachineState) ([]string, map[string]int, error) {
	entries, err := os.ReadDir(hostState.ResultsDir)
	if err != nil {
		return nil, nil, err
	}
	var reports []bench.Report
	counts := map[string]int{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "report-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		var report bench.Report
		if err := readJSONFile(filepath.Join(hostState.ResultsDir, name), &report); err != nil {
			return nil, counts, err
		}
		if len(report.Comparisons) == 0 {
			continue
		}
		family := strings.TrimSuffix(strings.TrimPrefix(name, "report-"), ".json")
		counts[family] = len(report.Comparisons)
		reports = append(reports, report)
	}
	if len(reports) == 0 {
		return nil, counts, nil
	}
	out := filepath.Join(orch.runDir, "charts", hostState.PlatformLabel)
	_ = os.RemoveAll(out)
	paths, err := bench.RenderChartSet(reports, out)
	if err != nil {
		// Reports from separate harness invocations can disagree on a machine
		// field; rendering them individually still produces every chart.
		var all []string
		for index, report := range reports {
			single := filepath.Join(out, fmt.Sprintf("report-%d", index+1))
			_ = os.RemoveAll(single)
			rendered, renderErr := bench.RenderChartSet([]bench.Report{report}, single)
			if renderErr != nil {
				return all, counts, renderErr
			}
			all = append(all, rendered...)
		}
		return all, counts, nil
	}
	return paths, counts, nil
}

func WriteSummaryText(writer io.Writer, summary Summary) {
	fmt.Fprintf(writer, "fleet run %s\n", summary.RunID)
	fmt.Fprintf(writer, "  started  %s\n", summary.StartedUTC)
	fmt.Fprintf(writer, "  finished %s\n", summary.FinishedUTC)
	fmt.Fprintf(writer, "  config   %s (sha256 %s)\n", summary.ConfigPath, short(summary.ConfigSHA256))
	fmt.Fprintf(writer, "  run dir  %s\n", summary.RunDir)
	if summary.DryRunAWS {
		fmt.Fprintln(writer, "  MODE     --dry-run-aws: no AWS mutation was issued")
	}
	fmt.Fprintln(writer)
	for _, machine := range summary.Machines {
		fmt.Fprintf(writer, "%-18s %-10s %-28s %s\n", machine.Name, machine.Status, machine.PlatformLabel, machine.Endpoint)
		fmt.Fprintf(writer, "  suites %s\n", strings.Join(machine.Suites, ", "))
		if machine.ElapsedSeconds > 0 {
			fmt.Fprintf(writer, "  host run %s, %d evidence files\n", formatDuration(machine.ElapsedSeconds), machine.Files)
		}
		if len(machine.Comparisons) > 0 {
			var parts []string
			for _, family := range sortedKeys(machine.Comparisons) {
				parts = append(parts, fmt.Sprintf("%s=%d", family, machine.Comparisons[family]))
			}
			fmt.Fprintf(writer, "  comparisons %s\n", strings.Join(parts, " "))
		}
		for _, chart := range machine.Charts {
			fmt.Fprintf(writer, "  chart %s\n", chart)
		}
		if machine.Teardown != nil {
			fmt.Fprintf(writer, "  teardown instance=%s volume=%s verified=%t\n",
				machine.Teardown.InstanceState, machine.Teardown.VolumeState, machine.Teardown.Verified)
		}
		if machine.CostUSD > 0 {
			fmt.Fprintf(writer, "  cost $%.2f over %.1f billed minutes\n", machine.CostUSD, machine.BilledMinutes)
		}
		if machine.HostWarnings != "" {
			fmt.Fprintf(writer, "  diagnostic warnings (evidence unaffected): %s\n", machine.HostWarnings)
		}
		if machine.HostFailures != "" {
			fmt.Fprintf(writer, "  host-reported failures: %s\n", machine.HostFailures)
		}
		if machine.Failure != "" {
			fmt.Fprintf(writer, "  FAILURE %s\n", machine.Failure)
		}
		fmt.Fprintln(writer)
	}
	if summary.TotalCostUSD > 0 {
		fmt.Fprintf(writer, "total cloud cost $%.2f\n", summary.TotalCostUSD)
	}
	if len(summary.Failures) == 0 {
		fmt.Fprintln(writer, "result: all machines completed")
		return
	}
	fmt.Fprintln(writer, "FAILURES")
	for _, failure := range summary.Failures {
		fmt.Fprintf(writer, "  - %s\n", failure)
	}
	fmt.Fprintf(writer, "resume with: rarpar-bench fleet collect --config <config> --run-id %s\n", summary.RunID)
}

func formatDuration(seconds int) string {
	if seconds < 60 {
		return strconv.Itoa(seconds) + "s"
	}
	return fmt.Sprintf("%dm%02ds", seconds/60, seconds%60)
}
