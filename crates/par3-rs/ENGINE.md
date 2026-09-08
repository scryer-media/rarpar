# Incremental engine contract for Weaver

The synchronous engine runs inside blocking workers. Weaver owns acquisition,
job scheduling, extraction, persistence, eviction, and output policy. This
contract describes the implemented API and remaining acceptance work; it is
not a production-readiness claim. No Weaver application changes are included.

## Ownership and source identity

Implement `SourceAccess` over decoded source-volume bytes. Assign a stable
`SourceId` independently of paths and bind authenticated relative filenames with
`Par3RepairSession::bind_file`. Carrier sources may use a separate provider.

`snapshot` reports logical length and a content generation. Filling a hole may
keep the generation; replacing a published byte, withdrawing coverage, rebinding,
or truncating must change it. Do not reuse a generation for different bytes.
`read_at` fills the caller's buffer and stops at holes. `next_available` reports
published ranges only. An optional sequential reader starts at zero and stops at
the first hole; verification resumes through later available ranges.

Never substitute zero padding for a hole. Codec padding is derived from the
authenticated logical layout, independently of provider availability. Provider
objects and their backing bytes remain caller-owned allocations. Packet-origin
comparisons include provider identity, so equal numeric IDs in separate
providers cannot establish an exact carrier manifest.

## Arrival and assessment lifecycle

1. Create shared `ExecutionOptions`, a `PacketScanner` per active carrier range,
   and one `Par3RepairSession` per packet `InputSetId`.
2. Poll scanners and route authenticated packets to their set. `NeedData` reports
   an unavailable byte. Preserve the scanner to resume its hash frontier, or
   explicitly seek beyond the hole and retain another scanner for that frontier.
   The same carrier may contain more than one set.
3. Call `merge` and `assess`. `IncompleteMetadata` means referenced descriptions
   have not all arrived. Recovery and Data packets can arrive before metadata.
4. Retain the session while downloading. `RecoveryRequirement` reports the
   selected matrix, cohort, admissible `recovery_indices` span, available global
   indices, and additional count. The span describes codec capacity; it does not
   assert that the downloader can find those packets in a remote carrier.
   A global index belongs to `index % cohorts`; another cohort's surplus cannot
   cover a deficit. Weaver selects the carriers or byte ranges to request.
5. Fill source holes and call `source_arrived` to verify only unknown extents.
   Changed generations invalidate affected evidence on reassessment.
6. When ready, call `repair` with an explicit output root and backup policy.
   Inspect each installed file in the report. A `RepairInterrupted` error carries
   already installed outputs, retained temporary paths, and the underlying cause.

Unchanged reassessment reads snapshots only. Recovery-only merges preserve
source evidence and Data admissions. Identical packet replay does not increase
recovery availability. A newly authenticated replay can replace a stale payload
binding. Source-generation changes remove old payload availability without
rereading protected files.

## In-stream evidence and extraction

Obtain a sealed `BlockLayout` from `session.layout()`. Construct a
`StreamingVerifier` for its file index, source identity, and generation; feed
positioned decoded bytes, then bind the file and pass the returned `FileEvidence`
to `add_evidence`. Evidence is tied to the authenticated layout and cannot be
constructed from caller-supplied verdict bits.

Out-of-order buffering is bounded. Exhaustion drops incomplete hashing work and
leaves its extent unknown for later reading. CRC64 supports localization only.
yEnc CRC32, archive-member CRCs, and independently finalized fragment digests do
not replace PAR3 BLAKE3 fingerprints.

Use file-coordinate unresolved ranges and verified prefixes to determine
extraction readiness. Prefixes stop at unprotected regions. Whole-file hashes
concatenate protected chunks and omit unprotected bytes, including unavailable
embedded packet ranges. Packed tails have individual fingerprints; their shared
logical block has no invented verification checksum. Shared blocks count once
even when they restore several files.

Clean sources can remain virtual. Ordinary repair stages only incomplete files
and verifies staged protected bytes before installation. Weaver may route those
verified outputs back through its extraction machinery. The engine does not
control or publish archive-member outputs. When every logical block is already
available through aliases or Data packets, reconstruction initializes no codec
and copies only blocks referenced by the staged files.

## Creation and embedded protection

`CreationPlan::build` accepts virtual sources, Cauchy or low-rate FFT options,
interleaving, aligned/sliding deduplication, Data packets, and volume layout.
Read `requirements()` before executing into an explicit output and scratch
directory. Existing convenience creation defaults remain unchanged.

`CarrierPlan::capture` requires an ordered, complete authenticated carrier.
It can restore the original packet bytes after source blocks are verified.
`CarrierPlan::replacement` explicitly requests a valid replacement and does not
claim restoration of an unknown layout. Current valid payloads are preserved;
missing recovery packets are regenerated from verified inputs.

`inside::InsertionPlan` validates plain ZIP/ZIP64 or 7z framing, preserves member
bytes and compression, and stages Cauchy protection to a separate output.
`inside::SelfRepairPlan::capture` uses a captured embedded manifest; it reconstructs
protected bytes, validates container framing, fills the protection gap, and
checks the result before exclusive installation. Ordinary file repair refuses
unprotected gaps so it cannot silently remove embedded protection.

Without the original manifest, explicitly request `SelfRepairPlan::replacement`
with authenticated matrix identity and desired recovery indices. It preserves
available authenticated packets and reconstructs only the requested missing
protection. The replacement must fit the authenticated unprotected gap; unused
capacity is zero-filled without moving protected bytes or ZIP footers. Requests
that exceed that capacity fail before execution. `restoration()` and the output
report distinguish exact restoration from replacement: verified protected data
and a complete requested replacement do not prove original packet completeness.
Missing essential metadata remains an error; filenames cannot supply it.

## Resources and operational outcomes

The default shared allocation budget is 256 MiB, with a per-session retained
ceiling of 64 MiB. Reservations are conservative engine accounting, not measured
process RSS; provider storage and allocator bookkeeping are outside that count.
`retained_bytes`, `reserved_bytes`, and the memory budget's peak support eviction
and measurement. Set explicit worker limits when Weaver schedules concurrent
jobs. Clone the same memory, handle, and scan-work budgets to share ceilings.

`max_cauchy_lost_blocks` separately caps each Cauchy solve at 4,096 losses by
default. The limit is checked before staging or building the quadratic
coefficient matrix; callers may explicitly raise it. FFT selection and carrier
regeneration require the reference field generator as well as the field width.

Data packet hashes authenticate their carrier bytes, not their connection to a
protected file. Admission waits until extent fingerprints cover every protected
part of the logical block. Missing checksum packets leave the Data payload
pending; late metadata triggers validation before it can supply repair or
carrier reconstruction. Identical packet replay can replace an unavailable or
failing old provider without discarding unchanged source evidence.

Unix disk snapshots include device, inode and change time. Other platforms use
a bounded full-file hash for each snapshot because stable Rust does not expose
portable file identity/change counters. This preserves correctness for
same-length replacements with preserved timestamps, at the cost of snapshot
reads. Weaver's virtual sources should supply their own immutable generations
through `SourceAccess` to retain read-free reassessment.

Windows scanners instead use `SourceAccess::pin`: a read-only sharing lock
prevents writes and deletion. Acquisition hashes content once; subsequent
generation checks need no content reads. Each
retained carrier uses one handle lease until its scanner and all authenticated
packets are dropped. Lock acquisition can fail if a writer is already open;
handle exhaustion is explicit. Raise both handle limits for large collections,
leaving headroom for verification and staging. All generation hashing is
charged to the cumulative scan-work budget before reading.

`Par3RepairSession::validate_repair` checks readiness and the configured Cauchy
loss and handle ceilings without staging output. It also rejects damaged layouts
with unprotected ranges that require explicit self-repair. Dry-run consumers should call
it instead of treating `Ready` as an unconditional execution guarantee. Sources
can still change and later allocations or output I/O can fail.

Packet admission charges parsed structures as well as wire bytes. Resolving
shared directory/file descriptions has a separate reservation and expansion
limits derived from remaining memory and retained-state headroom. Sessions keep
that reservation for the resolved set's lifetime. The `IncrementalSet::metadata`
convenience method budgets construction but transfers the returned legacy set
to the caller; use a session for retained accounting. Assessment charges include
cohort candidates, recovery references, file paths, damage ranges, and temporary
coverage unions. Incomplete streaming hashes are boxed so one pending extent
does not multiply large hasher storage across unused tree-node slots.

`HandleBudget` reserves each actual engine file before opening it and releases
the lease after close, including error paths and sequential readers. Exhaustion
is a nonblocking `ResourceLimit`; it does not wait while holding other handles.
The default shared ceiling and `open_handles` cap are both 32. Use
`DiskSourceAccess::with_options` to include disk providers in the same ceiling;
custom providers own their internal resources and may acquire leases from that
budget. `used()` and `peak()` expose live and peak handle counts.

FFT admits a private worker pool after field tables, keeping headroom for a
minimal decoder stripe. `FftCodec::worker_count()` reports the admitted ceiling;
small transforms still run on the caller. Each worker reserves a 256 KiB stack
plus 64 KiB of scheduler allowance. Dropping the codec joins every worker before
returning those reservations, including after cancellation. This does not bound
the caller's own worker pool or imply measured process RSS. Cauchy repair uses
the same joined pool lifetime and falls back to the caller when a pool cannot
fit or only one recovery equation needs processing.

`ScanWorkBudget` limits cumulative requested read bytes, including retries,
partial reads, and seeks. Its default is 1 TiB; dropping or recreating a scanner
does not reset a shared budget. Exhaustion is explicit before further I/O.
Cancellation is cooperative between work units and uses a shared token.

`ExecutionOptions::diagnostics` shares cumulative source read counters, engine
file read/write counters, and `stage(Stage)` timings. It retains no event log.
`file_sync()` measures file synchronization attempts, successes, and storage
wait time; this time is already included in enclosing operation stages.
Read requests include short reads and failures; byte counts measure successful
transfers. Disk source reads appear at both the provider and file layers, so do
not sum those layers. Lazy payload reads retain their scanner's diagnostics;
clone the same controls across scanner and session to aggregate them.

An optional `ProgressCallback` receives synchronous Begin, Advance, and End
events with a scope ID. Callbacks must be short and must not panic; they may
cancel the shared token. End means the scope exited, including errors; the API
result establishes success. Streaming verification measures active feed calls,
excluding idle arrival time. Nested/concurrent stage durations overlap and must
not be summed as exclusive wall time. Advance counts consumed bytes for scanning
and verification, produced bytes for codecs/carriers, searched bytes for
placement, and installed carriers for creation; it is not a verified-byte proof.

Handle `EngineError::Io` as the preserved backing-store failure, `Unavailable`
as missing bytes, `SourceChanged` as invalidated input, `ResourceLimit` as a
planning/scheduling constraint, and `Cancelled` as cancellation. Unsupported
execution modes must remain distinct from insufficient recovery. Assessment
statuses separately report incomplete metadata, recovery deficits, readiness,
and completeness. Engine outcomes do not imply a downloader retry policy.
`OutputInterrupted` reports carriers already installed by creation before a
later failure. Creation removes its disposable spool and uninstalled staging
on early exits; successfully installed carriers remain available for the host.

Sessions are disposable. Export `checkpoint_file` (or `FileEvidence::checkpoint`)
and retain its full `digest()` in trusted job metadata independently of the blob.
After restart, replay authenticated packets, restore source bindings, and call
`replay_evidence(bytes, trusted_digest)`. The engine checks the version, digest,
authenticated layout, binding, logical length, and current source generation
before admitting verdicts. Successful replay and unchanged assessment require no
source-byte reads. Unknown extents remain unknown; partial hash state is omitted.

The digest is an integrity anchor, not a signature or a PAR3 file fingerprint.
Never derive the trusted digest from an untrusted replay blob. If trusted job
metadata or stable source generations cannot be established, verify again.
Checkpoint creation and decoding reserve memory and honor cancellation; the
host owns the persisted bytes and their storage policy.

## Read-only Weaver reference

The current Weaver seams motivating this contract are:

- `pipeline/repair/par2.rs`: blocking recovery-only merges into retained sessions
  and retained-session eviction.
- `pipeline/direct_store/wiring/par2.rs`: in-stream proof reuse and reading only
  unresolved slices.
- `pipeline/direct_store/repair.rs`: materializing damaged virtual volumes while
  preserving clean virtual read sources.

These files were inspected under `server/crates/weaver-server-core/src` in the
local Weaver checkout. Their PAR2 proof or readback policies do not automatically
transfer to PAR3; the adapter must use the PAR3 evidence contract above.

## Evidence and remaining acceptance

The fixtures and recipes pin official `par3cmdline` commit
`2971702e501f1350b1c7b9d11369af9157d6ed56`; provenance and digests are recorded in
`tests/fixtures/advanced/README.md` and the workspace corpus ledger. Tests cover
reference Cauchy and FFT packets, interleaved deficits, Data-only reconstruction,
retained evidence, missing ranges, and exact ZIP/ZIP64/7z self-repair. Newly
inserted archives were verified and repaired byte-for-byte by the reference.
The [interoperability record](INTEROPERABILITY.md) also documents reference
repair of larger SIMD/worker-created GF8, GF16, and uneven interleaved sets,
including the recovery equations actually consumed.

The combined `tests/weaver_consumer.rs` harness exercises a blocking host through
late metadata, out-of-order decoded bytes, interior holes, trusted checkpoint
restart, recovery selection, replay, cancellation, stale generations, and
selective materialization. It asserts zero protected-source reads for strong
proof admission, restart, unchanged assessment, and recovery-only merges; only
the changed source is reverified, and clean outputs are not rewritten. Shared
memory and handle ceilings and final reservation cleanup are checked alongside
the dedicated `resource_limits`, `diagnostics`, and interleaved FFT tests.
The creation suite also creates and repairs 65,539 logical 64-byte blocks across
three uneven XOR cohorts, using an explicit larger retained-metadata budget.
The codec's per-cohort geometry does not impose a 65,536-block global limit.

The 2026-09-08 validation ran workspace formatting and all-target/all-feature
Clippy, 2,542 workspace Nextest tests, 24 doctests, all four PAR2 real-world
consumer regressions, and the Go corpus recipe tests successfully. After adding
the large-block-count case, the affected PAR3 suite passed all 339 tests and
Clippy again. The workspace sweep left 12 opt-in tests skipped: native Metal,
throughput probes, reference exporters/interop, and an external RAR fixture gate;
the doctest sweep left one host-hook example ignored. These are not represented
as passing. PAR3 reference checks are recorded separately in `INTEROPERABILITY.md`.

The subsequent tuning pass passed 2,546 workspace Nextest tests and 24 doctests,
plus formatting and all-target/all-feature Clippy, with the same opt-in skips.
Carrier read-ahead and SIMD FFT locator scaling closed the measured small-file
verification and uneven-cohort repair gaps on both native hosts. Each final
matrix passed all 534 invocations, including reference verification and repaired
output hashes. Both codecs exceeded reference verification/repair geometric
means with one and four workers. All cached reassessments still read zero source
bytes, clean files remained unstaged, and memory/handle ceilings held.

Historical timing increases above 5% were investigated with interleaved baseline
and tuned binaries. No >5% median regression reproduced in those checks. See
`PERFORMANCE.md` for the raw measurements, source/binary provenance, resource
observations, and macOS reference adaptation qualification.

These results support Weaver's verification/repair consumption on the measured
native workloads. They do not measure a Weaver application integration. Default
ARM64 FFT creation remains below reference aggregate throughput (89–95%); the
all-operation performance gate remains open separately from this consumer use
case. Earlier emulated reference timings remain interoperability evidence only.

The 13 advanced-corpus tests gated during initial implementation are enabled.
They require the official advanced fixtures, as does the regression that omits
External Data checksums and supplies them later. Missing files fail explicitly;
they are never silently skipped. See `tests/fixtures/advanced/README.md` for the
required corpus. Corpus publication is an operator-owned action outside this
implementation.
