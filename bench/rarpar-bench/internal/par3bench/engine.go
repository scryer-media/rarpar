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
// (verification order). It is not the shipped binary, so its rows carry no
// ratio to the reference.
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
	// InPlace counts outputs repaired by patching their source.
	InPlace   int64 `json:"file_in_place"`
	Snapshots int64 `json:"snapshots"`
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
		// par3-rs 0.6.0 dropped file_syncs (it issues no storage barrier),
		// so the counter line is recognised by a field every version prints.
		if _, ok := fields["file_read_bytes"]; ok {
			found = true
			for key, target := range map[string]*int64{
				"file_read_bytes": &counters.ReadBytes, "file_read_calls": &counters.ReadCalls,
				"file_write_bytes": &counters.WriteBytes, "file_write_calls": &counters.WriteCalls,
				"file_opens": &counters.Opens, "file_syncs": &counters.Syncs, "file_clones": &counters.Clones,
				"file_in_place": &counters.InPlace, "snapshots": &counters.Snapshots,
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
	env := append(append([]string(nil), variant.Env...), engineBufferedEnv(op)...)
	return Command{Path: r.options.EnginePerf, Args: args, Dir: filepath.Dir(dir), Env: env, PinCPUs: r.pin(), Timeout: r.timeoutFor(ToolCandidate)}
}

// engineBufferedEnv makes an engine_perf create or repair buffered, as the
// rarpar rows are. From par3-rs 0.6.0 the engine issues no storage barrier
// and reads no durability variable, so this changes nothing there; an older
// engine_perf syncs its outputs unless PAR3_BENCH_<OP>_DURABILITY is
// "buffered", and the oldest ignore the repair variable. Every create and
// repair's output is therefore checked afterwards (EngineSyncProblem).
func engineBufferedEnv(op string) []string {
	if op != OpCreate && op != OpRepair {
		return nil
	}
	return []string{fmt.Sprintf("PAR3_BENCH_%s_DURABILITY=buffered", strings.ToUpper(op))}
}

// FailureEngineNotBuffered marks an engine_perf create or repair whose own
// output shows it synced, or cannot show it did not (EngineSyncProblem).
const FailureEngineNotBuffered = "engine-not-buffered"

// EngineSyncProblem reads an engine_perf create or repair's output and says
// why the run cannot count as buffered, or "" when it does. Builds print one
// of four kinds of evidence. From par3-rs 0.6.0 the engine has no storage
// barrier at all: its totals carry file_opens and no file_syncs. The builds
// before that print file_syncs, the fsyncs the run completed. Older ones
// print only a Sync stage line with its call count, and their repair ignores
// PAR3_BENCH_REPAIR_DURABILITY and always syncs. The first print none of
// these, so nothing shows that they did not sync. A create that printed its
// creation_durability must also have run Buffered.
func EngineSyncProblem(op, stdout string) string {
	if op != OpCreate && op != OpRepair {
		return ""
	}
	var durability string
	var syncs, syncCalls int64
	var haveSyncs, haveSyncLine, haveOpens bool
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
		if raw, ok := fields["creation_durability"]; ok {
			_ = json.Unmarshal(raw, &durability)
		}
		if raw, ok := fields["internal_stage"]; ok && string(raw) == `"Sync"` {
			if json.Unmarshal(fields["calls"], &syncCalls) == nil {
				haveSyncLine = true
			}
		}
		if _, totals := fields["file_read_bytes"]; !totals {
			continue
		}
		if raw, ok := fields["file_syncs"]; ok && json.Unmarshal(raw, &syncs) == nil {
			haveSyncs = true
		}
		if _, ok := fields["file_opens"]; ok {
			haveOpens = true
		}
	}
	switch {
	case durability != "" && durability != "Buffered":
		return fmt.Sprintf("engine_perf ran its create with creation_durability %s, not Buffered", durability)
	case haveSyncs && syncs > 0:
		return fmt.Sprintf("engine_perf completed %d file syncs during its %s, so this build did not run it buffered", syncs, op)
	case haveSyncs:
		return ""
	case haveSyncLine && syncCalls > 0 && op == OpRepair:
		return fmt.Sprintf("engine_perf's Sync stage made %d calls: this build predates PAR3_BENCH_REPAIR_DURABILITY and its repair always syncs its outputs", syncCalls)
	case haveSyncLine && syncCalls > 0:
		return fmt.Sprintf("engine_perf's Sync stage made %d calls during its %s, so this build did not run it buffered", syncCalls, op)
	case haveSyncLine, haveOpens:
		return ""
	}
	return "engine_perf printed no sync evidence (no file_syncs, no Sync stage line, no file_opens), so this build cannot be confirmed to run buffered"
}
