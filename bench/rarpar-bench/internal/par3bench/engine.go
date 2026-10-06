package par3bench

import (
	"bufio"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// ToolEngine marks a timed row driven by the par3-rs engine_perf example
// instead of the CLI. Its value is the engine's own disk-work counters, which
// the CLI does not print, and the PAR3_BENCH_* switches the CLI does not have
// (buffered repair, verification order). It is not the shipped binary, so its
// rows carry no ratio to the reference.
const ToolEngine = "engine"

// Row kinds selectable with Options.Rows.
var KnownRowKinds = []string{ToolReference, ToolCandidate, ToolEngine}

// EngineCounters is what engine_perf reports about the work it asked of the
// disk: par3-rs ExecutionDiagnostics, cumulative for the whole process.
type EngineCounters struct {
	ReadBytes  int64 `json:"file_read_bytes"`
	ReadCalls  int64 `json:"file_read_calls"`
	WriteBytes int64 `json:"file_write_bytes"`
	WriteCalls int64 `json:"file_write_calls"`
	Opens      int64 `json:"file_opens"`
	Syncs      int64 `json:"file_syncs"`
	Clones     int64 `json:"file_clones"`
	Snapshots  int64 `json:"snapshots"`
	// SyncSeconds is the time the engine spent in fsync.
	SyncSeconds  float64 `json:"sync_seconds"`
	StripePasses int64   `json:"stripe_passes"`
	// WholeFileFirst is the disk verification order the process ran with,
	// when every verified file ran in the same one.
	WholeFileFirst *bool `json:"whole_file_first,omitempty"`
	// MountKind is the filesystem kind ("local", "remote", "unknown") the
	// engine detected for the verified files, when they all agreed; it picks
	// the order unless a variant forces one.
	MountKind string `json:"mount_kind,omitempty"`
	// Status is the assessment engine_perf printed ("Complete", "Ready").
	Status string `json:"status,omitempty"`
}

// ParseEngineOutput reads engine_perf's JSON lines. It reports false when the
// totals line is missing, which means the process did not finish its op.
func ParseEngineOutput(stdout string) (EngineCounters, bool) {
	var counters EngineCounters
	found := false
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &fields) != nil {
			continue
		}
		number := func(key string) (int64, bool) {
			raw, ok := fields[key]
			if !ok {
				return 0, false
			}
			value, err := strconv.ParseInt(string(raw), 10, 64)
			return value, err == nil
		}
		if _, ok := fields["file_syncs"]; ok {
			found = true
			for key, target := range map[string]*int64{
				"file_read_bytes": &counters.ReadBytes, "file_read_calls": &counters.ReadCalls,
				"file_write_bytes": &counters.WriteBytes, "file_write_calls": &counters.WriteCalls,
				"file_opens": &counters.Opens, "file_syncs": &counters.Syncs, "file_clones": &counters.Clones,
				"snapshots": &counters.Snapshots,
			} {
				if value, ok := number(key); ok {
					*target = value
				}
			}
		}
		if value, ok := number("stripe_passes"); ok {
			counters.StripePasses = value
		}
		if raw, ok := fields["whole_file_first"]; ok {
			var value bool
			if json.Unmarshal(raw, &value) == nil {
				counters.WholeFileFirst = &value
			}
		}
		if raw, ok := fields["mount_kind"]; ok {
			_ = json.Unmarshal(raw, &counters.MountKind)
		}
		if raw, ok := fields["status"]; ok {
			_ = json.Unmarshal(raw, &counters.Status)
		}
		if raw, ok := fields["internal_stage"]; ok && string(raw) == `"Sync"` {
			var seconds float64
			if json.Unmarshal(fields["seconds"], &seconds) == nil {
				counters.SyncSeconds = seconds
			}
		}
	}
	return counters, found
}

// engineCommand is the engine_perf invocation for one op. Every op works in
// the staged directory itself, as the CLI does: inputs (`.bin`) and carriers
// (`.par3`) side by side, and a repair installs its outputs in place.
func (r *runner) engineCommand(op string, config Config, dataDir, dir string, variant Variant) Command {
	workers := strconv.Itoa(variant.Workers)
	memory := strconv.Itoa(r.options.EnginePerfMemoryMiB)
	var args []string
	switch op {
	case OpCreate:
		// engine_perf writes DIR/set.par3 and its volumes; the spool goes
		// beside it so the carrier directory holds only the carriers.
		args = []string{"create", dataDir, dir, dir + "-spool", workers, memory,
			config.Codec, strconv.FormatInt(config.BlockSize, 10), strconv.FormatInt(config.Recovery, 10), "0"}
	case OpVerify:
		args = []string{"verify", dir, dir, dir, workers, memory}
	case OpVerifyDamaged:
		// assess accepts whatever status it finds: on a damaged tree it is
		// the repair path's assessment without the repair.
		args = []string{"assess", dir, dir, dir, workers, memory}
	case OpRepair:
		args = []string{"repair", dir, dir, dir, workers, memory}
	}
	env := append([]string(nil), variant.Env...)
	if variant.EffectiveDurability() == DurabilityBuffered {
		env = append(env, fmt.Sprintf("PAR3_BENCH_%s_DURABILITY=buffered", strings.ToUpper(op)))
	}
	return Command{Path: r.options.EnginePerf, Args: args, Dir: filepath.Dir(dir), Env: env, PinCPUs: r.pin(), Timeout: r.timeoutFor(ToolCandidate)}
}
