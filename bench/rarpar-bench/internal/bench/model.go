// Package bench owns the deterministic on-disk benchmark contracts.
package bench

import "time"

const (
	CorpusSchemaVersion = 1
	PlanSchemaVersion   = 2
	RunSchemaVersion    = 1
	ReportSchemaVersion = 1
)

type ToolchainLock struct {
	SchemaVersion int           `json:"schema_version"`
	DockerBase    string        `json:"docker_base"`
	RARWriters    []RARWriter   `json:"rar_writers"`
	PAR2Generator PAR2Generator `json:"par2_generator"`
}

type RARWriter struct {
	ID       string `json:"id"`
	Image    string `json:"image"`
	Platform string `json:"platform"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Binary   string `json:"binary"`
}

type PAR2Generator struct {
	ID       string `json:"id"`
	Image    string `json:"image"`
	Platform string `json:"platform"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
}

type CorpusConfig struct {
	SchemaVersion         int          `json:"schema_version"`
	ID                    string       `json:"id"`
	Seed                  string       `json:"seed"`
	PayloadBytes          int64        `json:"payload_bytes"`
	VolumeSize            string       `json:"volume_size"`
	PAR2RedundancyPercent int          `json:"par2_redundancy_percent"`
	Cases                 []CaseConfig `json:"cases"`
}

type CaseConfig struct {
	ID                 string `json:"id"`
	Family             string `json:"family"`
	Writer             string `json:"writer"`
	Format             int    `json:"format"`
	Store              bool   `json:"store"`
	PPMd               bool   `json:"ppmd"`
	PayloadProfile     string `json:"payload_profile"`
	VolumeSize         string `json:"volume_size"`
	Solid              bool   `json:"solid"`
	Encrypted          bool   `json:"encrypted"`
	PAR2               bool   `json:"par2"`
	RecoveryVolumes    bool   `json:"recovery_volumes"`
	Mutation           string `json:"mutation"`
	DamageCount        int    `json:"damage_count,omitempty"`
	DamageBytesPerSite int    `json:"damage_bytes_per_site,omitempty"`
	PAR2SliceSize      int64  `json:"par2_slice_size,omitempty"`
	FixtureDir         string `json:"fixture_dir,omitempty"`
	FixturePrefix      string `json:"fixture_prefix,omitempty"`
	FixtureSHA256      string `json:"fixture_sha256,omitempty"`
	Workload           string `json:"workload"`
}

type ExpectedFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type SourceFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type CorpusCaseManifest struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Config        CaseConfig     `json:"config"`
	CorpusID      string         `json:"corpus_id"`
	CorpusDigest  string         `json:"corpus_digest"`
	Seed          string         `json:"seed"`
	Toolchains    []string       `json:"toolchains"`
	Expected      []ExpectedFile `json:"expected"`
	Sources       []SourceFile   `json:"sources"`
}

type Plan struct {
	SchemaVersion int        `json:"schema_version"`
	ID            string     `json:"id"`
	CorpusDigest  string     `json:"corpus_digest"`
	Seed          string     `json:"seed"`
	Warmups       int        `json:"warmups"`
	Repeats       int        `json:"repeats"`
	Lane          string     `json:"lane"`
	Par2Placement string     `json:"par2_placement"`
	Cases         []PlanCase `json:"cases"`
}

type PlanCase struct {
	ID    string `json:"id"`
	Order int    `json:"order"`
}

type BinaryIdentity struct {
	Label          string `json:"label"`
	Path           string `json:"-"`
	SHA256         string `json:"sha256"`
	Version        string `json:"version"`
	SourceRevision string `json:"source_revision,omitempty"`
}

type Machine struct {
	Label         string `json:"label"`
	OS            string `json:"os"`
	Kernel        string `json:"kernel"`
	Architecture  string `json:"architecture"`
	CPU           string `json:"cpu"`
	CPUCount      int    `json:"cpu_count"`
	MemoryBytes   uint64 `json:"memory_bytes,omitempty"`
	Filesystem    string `json:"filesystem"`
	DockerVersion string `json:"docker_version,omitempty"`
	GPU           string `json:"gpu,omitempty"`
}

type Measurement struct {
	WallNanos       int64   `json:"wall_nanos"`
	UserNanos       int64   `json:"user_nanos"`
	SystemNanos     int64   `json:"system_nanos"`
	ValidationNanos int64   `json:"validation_nanos"`
	Instructions    *uint64 `json:"instructions,omitempty"`
	CollectorNote   string  `json:"collector_note,omitempty"`
}

type Execution struct {
	Subject            string      `json:"subject"`
	Role               string      `json:"role"`
	CaseID             string      `json:"case_id"`
	Family             string      `json:"family"`
	Workload           string      `json:"workload"`
	Run                int         `json:"run"`
	Warmup             bool        `json:"warmup"`
	Success            bool        `json:"success"`
	CompiledCapability string      `json:"compiled_capability"`
	Backend            string      `json:"backend"`
	FallbackReason     string      `json:"fallback_reason,omitempty"`
	Measurement        Measurement `json:"measurement"`
	Failure            string      `json:"failure,omitempty"`
}

type RunRecord struct {
	SchemaVersion int             `json:"schema_version"`
	Plan          Plan            `json:"plan"`
	CorpusDigest  string          `json:"corpus_digest"`
	Machine       Machine         `json:"machine"`
	Candidate     BinaryIdentity  `json:"candidate"`
	Reference     *BinaryIdentity `json:"reference,omitempty"`
	ReferencePAR2 *BinaryIdentity `json:"reference_par2,omitempty"`
	Executions    []Execution     `json:"executions"`
}

type Summary struct {
	Count  int   `json:"count"`
	Median int64 `json:"median_wall_nanos"`
	Min    int64 `json:"min_wall_nanos"`
	Max    int64 `json:"max_wall_nanos"`
	IQR    int64 `json:"iqr_wall_nanos"`
}

type Comparison struct {
	CaseID             string  `json:"case_id"`
	Family             string  `json:"family"`
	Workload           string  `json:"workload"`
	CandidateLabel     string  `json:"candidate_label"`
	ReferenceLabel     string  `json:"reference_label"`
	Candidate          Summary `json:"candidate"`
	Reference          Summary `json:"reference"`
	Ratio              float64 `json:"ratio"`
	CompiledCapability string  `json:"compiled_capability"`
	Backend            string  `json:"backend"`
}

type Report struct {
	SchemaVersion int             `json:"schema_version"`
	InputSHA256   string          `json:"input_sha256"`
	Plan          Plan            `json:"plan"`
	CorpusDigest  string          `json:"corpus_digest"`
	Machine       Machine         `json:"machine"`
	Candidate     BinaryIdentity  `json:"candidate"`
	Reference     *BinaryIdentity `json:"reference,omitempty"`
	ReferencePAR2 *BinaryIdentity `json:"reference_par2,omitempty"`
	Comparisons   []Comparison    `json:"comparisons"`
	Omitted       []string        `json:"omitted,omitempty"`
}

func DurationNanos(value time.Duration) int64 { return value.Nanoseconds() }
