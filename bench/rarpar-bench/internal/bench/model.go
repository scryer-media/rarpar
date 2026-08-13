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
	ID                  string `json:"id"`
	Family              string `json:"family"`
	Writer              string `json:"writer"`
	Format              int    `json:"format"`
	Store               bool   `json:"store"`
	PPMd                bool   `json:"ppmd"`
	PayloadProfile      string `json:"payload_profile"`
	PayloadBytes        int64  `json:"payload_bytes,omitempty"`
	VolumeSize          string `json:"volume_size"`
	Solid               bool   `json:"solid"`
	Encrypted           bool   `json:"encrypted"`
	HeaderEncrypted     bool   `json:"header_encrypted,omitempty"`
	PAR2                bool   `json:"par2"`
	RecoveryVolumes     bool   `json:"recovery_volumes"`
	Mutation            string `json:"mutation"`
	DamageCount         int    `json:"damage_count,omitempty"`
	DamageBytesPerSite  int    `json:"damage_bytes_per_site,omitempty"`
	PAR2Operation       string `json:"par2_operation,omitempty"`
	PAR2SliceSize       int64  `json:"par2_slice_size,omitempty"`
	PAR2RecoveryPercent int    `json:"par2_recovery_percent,omitempty"`
	FixtureDir          string `json:"fixture_dir,omitempty"`
	FixturePrefix       string `json:"fixture_prefix,omitempty"`
	FixtureSHA256       string `json:"fixture_sha256,omitempty"`
	Workload            string `json:"workload"`
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
	SchemaVersion    string         `json:"schema_version"`
	ID               string         `json:"id"`
	Config           CaseConfig     `json:"config"`
	CorpusID         string         `json:"corpus_id"`
	CorpusDigest     string         `json:"corpus_digest"`
	GenerationDigest string         `json:"generation_digest"`
	Seed             string         `json:"seed"`
	Toolchains       []string       `json:"toolchains"`
	Expected         []ExpectedFile `json:"expected"`
	Sources          []SourceFile   `json:"sources"`
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
	WallNanos         int64               `json:"wall_nanos"`
	UserNanos         int64               `json:"user_nanos,omitempty"`
	SystemNanos       int64               `json:"system_nanos,omitempty"`
	ValidationNanos   int64               `json:"validation_nanos"`
	Instructions      *uint64             `json:"instructions,omitempty"`
	CollectorNote     string              `json:"collector_note,omitempty"`
	Perf              *PerfCounters       `json:"perf,omitempty"`
	PerfCollectorNote string              `json:"perf_collector_note,omitempty"`
	RAR5Phases        *RAR5PhaseEvidence  `json:"rar5_phases,omitempty"`
	RAR5Decode        *RAR5DecodeEvidence `json:"rar5_decode,omitempty"`
}

type PerfCounters struct {
	Cycles          *uint64  `json:"cycles,omitempty"`
	Instructions    *uint64  `json:"instructions,omitempty"`
	Branches        *uint64  `json:"branches,omitempty"`
	BranchMisses    *uint64  `json:"branch_misses,omitempty"`
	CacheReferences *uint64  `json:"cache_references,omitempty"`
	CacheMisses     *uint64  `json:"cache_misses,omitempty"`
	TaskClockMillis *float64 `json:"task_clock_millis,omitempty"`
	ContextSwitches *uint64  `json:"context_switches,omitempty"`
	CPUMigrations   *uint64  `json:"cpu_migrations,omitempty"`
	DurationNanos   *uint64  `json:"duration_nanos,omitempty"`
}

// RAR5PhaseEvidence is populated only from the opt-in benchmark diagnostic
// stream. A missing phase is represented by a nil pointer plus a reason; zero
// is never used as a missing-value sentinel. SerialApplyNanos includes inline
// controller decode-and-apply work needed to establish inherited tables.
type RAR5PhaseEvidence struct {
	StagingNanos      *int64 `json:"staging_nanos,omitempty"`
	HeaderScanNanos   *int64 `json:"header_scan_nanos,omitempty"`
	WorkerDecodeNanos *int64 `json:"worker_decode_nanos,omitempty"`
	SerialApplyNanos  *int64 `json:"serial_apply_nanos,omitempty"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// RAR5DecodeEvidence aggregates worker-local counters emitted by the opt-in
// benchmark diagnostic stream. It is collected only outside measured runs.
type RAR5DecodeEvidence struct {
	SchemaVersion           uint32 `json:"schema_version"`
	Batches                 uint64 `json:"batches"`
	TablePrepareNanos       uint64 `json:"table_prepare_nanos"`
	SymbolDecodeNanos       uint64 `json:"symbol_decode_nanos"`
	PoolDispatchNanos       uint64 `json:"pool_dispatch_nanos"`
	PoolWaitNanos           uint64 `json:"pool_wait_nanos"`
	TablePresentBlocks      uint64 `json:"table_present_blocks"`
	TablelessBlocks         uint64 `json:"tableless_blocks"`
	QuickHuffmanHits        uint64 `json:"quick_huffman_hits"`
	SlowHuffmanHits         uint64 `json:"slow_huffman_hits"`
	LiteralSymbols          uint64 `json:"literal_symbols"`
	MatchSymbols            uint64 `json:"match_symbols"`
	RepeatSymbols           uint64 `json:"repeat_symbols"`
	FilterSymbols           uint64 `json:"filter_symbols"`
	DecodedBufferGrowths    uint64 `json:"decoded_buffer_growths"`
	DecodedBufferGrownBytes uint64 `json:"decoded_buffer_grown_bytes"`
	Assignments             uint64 `json:"assignments"`
	ActiveWorkerSlots       uint64 `json:"active_worker_slots"`
	IdleWorkerSlots         uint64 `json:"idle_worker_slots"`
	UnavailableReason       string `json:"unavailable_reason,omitempty"`
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
	CollectorMode string          `json:"collector_mode"`
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
	CaseID              string            `json:"case_id"`
	Family              string            `json:"family"`
	Workload            string            `json:"workload"`
	CandidateLabel      string            `json:"candidate_label"`
	ReferenceLabel      string            `json:"reference_label"`
	Candidate           Summary           `json:"candidate"`
	Reference           Summary           `json:"reference"`
	Ratio               float64           `json:"ratio"`
	CompiledCapability  string            `json:"compiled_capability"`
	Backend             string            `json:"backend"`
	CandidateRAR5Phases *RAR5PhaseSummary `json:"candidate_rar5_phases,omitempty"`
}

type RAR5PhaseSummary struct {
	Staging           *Summary `json:"staging,omitempty"`
	HeaderScan        *Summary `json:"header_scan,omitempty"`
	WorkerDecode      *Summary `json:"worker_decode,omitempty"`
	SerialApply       *Summary `json:"serial_apply,omitempty"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`
}

type Report struct {
	SchemaVersion int             `json:"schema_version"`
	CollectorMode string          `json:"collector_mode"`
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
