package fleet

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const RunStateSchemaVersion = 1

// Status values a machine moves through. They are persisted so `fleet collect
// --resume` can re-enter a run for stragglers and failures only.
const (
	StatusPending    = "pending"
	StatusBuilding   = "building"
	StatusSpawning   = "spawning"
	StatusRunning    = "running"
	StatusCollecting = "collecting"
	StatusDone       = "done"
	StatusFailed     = "failed"
	StatusTornDown   = "torn-down"
	StatusSkipped    = "skipped"
)

type RunState struct {
	SchemaVersion int               `json:"schema_version"`
	RunID         string            `json:"run_id"`
	StartedUTC    string            `json:"started_utc"`
	FinishedUTC   string            `json:"finished_utc,omitempty"`
	ConfigPath    string            `json:"config_path"`
	ConfigSHA256  string            `json:"config_sha256"`
	RunDir        string            `json:"run_dir"`
	DryRunAWS     bool              `json:"dry_run_aws"`
	Session       *SessionResources `json:"aws_session,omitempty"`
	Machines      []*MachineState   `json:"machines"`

	path  string
	mutex sync.Mutex
}

type MachineState struct {
	Name          string                      `json:"name"`
	Kind          string                      `json:"kind"`
	PlatformLabel string                      `json:"platform_label"`
	Status        string                      `json:"status"`
	Suites        []string                    `json:"suites"`
	Endpoint      string                      `json:"endpoint"`
	Remote        RemoteLayout                `json:"remote"`
	BundleDir     string                      `json:"bundle_dir,omitempty"`
	Oracles       map[string]OracleResolution `json:"oracles,omitempty"`
	Cloud         *CloudState                 `json:"cloud,omitempty"`
	Teardown      *TeardownEvidence           `json:"teardown,omitempty"`
	Manifest      *HostManifest               `json:"host_manifest,omitempty"`
	Charts        []string                    `json:"charts,omitempty"`
	ResultsDir    string                      `json:"results_dir,omitempty"`
	Failure       string                      `json:"failure,omitempty"`
	Events        []Event                     `json:"events"`
	StartedUTC    string                      `json:"started_utc,omitempty"`
	FinishedUTC   string                      `json:"finished_utc,omitempty"`
	CostUSD       float64                     `json:"cost_usd,omitempty"`
	BilledMinutes float64                     `json:"billed_minutes,omitempty"`
}

type Event struct {
	UTC     string `json:"utc"`
	Phase   string `json:"phase"`
	Message string `json:"message"`
}

// HostManifest mirrors the inventory the run script writes next to the results.
type HostManifest struct {
	SchemaVersion  int    `json:"schema_version"`
	RunID          string `json:"run_id"`
	Machine        string `json:"machine"`
	PlatformLabel  string `json:"platform_label"`
	StartedUTC     string `json:"started_utc"`
	FinishedUTC    string `json:"finished_utc"`
	ElapsedSeconds int    `json:"elapsed_seconds"`
	Status         string `json:"status"`
	Failures       string `json:"failures"`
	// Warnings are diagnostic passes that did not run. They never invalidate the
	// timed evidence, so they are reported without failing the host.
	Warnings string         `json:"warnings,omitempty"`
	Files    []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func NewRunState(runDir, runID string, config Config, dryRunAWS bool) *RunState {
	return &RunState{
		SchemaVersion: RunStateSchemaVersion,
		RunID:         runID,
		StartedUTC:    time.Now().UTC().Format(time.RFC3339),
		ConfigPath:    config.Path,
		ConfigSHA256:  config.SHA256,
		RunDir:        runDir,
		DryRunAWS:     dryRunAWS,
		path:          filepath.Join(runDir, "run-state.json"),
	}
}

func LoadRunState(runDir string) (*RunState, error) {
	state := &RunState{path: filepath.Join(runDir, "run-state.json")}
	if err := readJSONFile(state.path, state); err != nil {
		return nil, fmt.Errorf("read run state: %w", err)
	}
	state.path = filepath.Join(runDir, "run-state.json")
	return state, nil
}

func (state *RunState) Machine(name string) *MachineState {
	for _, machine := range state.Machines {
		if machine.Name == name {
			return machine
		}
	}
	return nil
}

func (state *RunState) Save() error {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if err := os.MkdirAll(filepath.Dir(state.path), 0o755); err != nil {
		return err
	}
	return writeJSONFile(state.path, state)
}

// Record appends a timeline entry and persists immediately: a crashed
// orchestrator must still leave enough state behind to resume or tear down.
func (state *RunState) Record(machine *MachineState, phase, format string, args ...any) {
	state.mutex.Lock()
	machine.Events = append(machine.Events, Event{
		UTC:     time.Now().UTC().Format(time.RFC3339),
		Phase:   phase,
		Message: fmt.Sprintf(format, args...),
	})
	state.mutex.Unlock()
	_ = state.Save()
}

func (state *RunState) SetStatus(machine *MachineState, status string) {
	state.mutex.Lock()
	machine.Status = status
	state.mutex.Unlock()
	_ = state.Save()
}
