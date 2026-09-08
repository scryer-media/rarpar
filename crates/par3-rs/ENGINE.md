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
   selected matrix, cohort, available global indices, and additional count.
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
`inside::SelfRepairPlan` requires a captured embedded manifest; it reconstructs
protected bytes, validates container framing, fills the protection gap, and
checks the result before exclusive installation. Ordinary file repair refuses
unprotected gaps so it cannot silently remove embedded protection.

## Resources and operational outcomes

The default shared allocation budget is 256 MiB, with a per-session retained
ceiling of 64 MiB. Reservations are conservative engine accounting, not measured
process RSS; provider storage and allocator bookkeeping are outside that count.
`retained_bytes`, `reserved_bytes`, and the memory budget's peak support eviction
and measurement. Set explicit worker limits when Weaver schedules concurrent
jobs. Clone the same memory and scan-work budgets to share ceilings across jobs.

FFT admits a private worker pool after field tables, keeping headroom for a
minimal decoder stripe. `FftCodec::worker_count()` reports the admitted ceiling;
small transforms still run on the caller. Each worker reserves a 256 KiB stack
plus 64 KiB of scheduler allowance. Dropping the codec joins every worker before
returning those reservations, including after cancellation. This does not bound
the caller's own worker pool or imply measured process RSS.

`ScanWorkBudget` limits cumulative requested read bytes, including retries,
partial reads, and seeks. Its default is 1 TiB; dropping or recreating a scanner
does not reset a shared budget. Exhaustion is explicit before further I/O.
Cancellation is cooperative between work units and uses a shared token.

Handle `EngineError::Io` as the preserved backing-store failure, `Unavailable`
as missing bytes, `SourceChanged` as invalidated input, `ResourceLimit` as a
planning/scheduling constraint, and `Cancelled` as cancellation. Unsupported
execution modes must remain distinct from insufficient recovery. Assessment
statuses separately report incomplete metadata, recovery deficits, readiness,
and completeness. Engine outcomes do not imply a downloader retry policy.

Sessions are disposable. After restart, reopen and replay authenticated packets
against current providers. There is currently no serialized engine-evidence
format; do not turn persisted verdict bits into trusted evidence. Any future
evidence replay interface must establish source identity, generation, and layout.

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

Remaining acceptance includes matched native ARM64 and x86-64 performance,
FFT scheduling-threshold tuning, complete diagnostics and progress callbacks, stronger
process-wide handle accounting, durable evidence replay, and embedded replacement
layouts when an original manifest is absent. The current reference runs in a
local x86-64 container under emulation; its timings cannot establish native
throughput parity. Correctness results alone do not satisfy performance acceptance.
