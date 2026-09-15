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

`MemoryBudget::ledger()` attributes those reservations. It returns a snapshot of
every `MemoryCategory` — carrier and packet storage, resolved metadata, layout
and evidence, assessment state, caches, queued payloads, codec tables, codec
scratch, source scratch, worker stacks and output staging — with current bytes,
peak bytes and reservation count. The snapshot allocates nothing and takes no
lock, so a host may sample it from another thread during a job. Categories are
sampled independently: their peaks need not have occurred together, and their
sum is not the budget's own peak. Reservations taken without a category appear
as `Uncategorized`, which stays at zero on the verify, repair and creation paths.

A refusal states whether it could ever have succeeded.
`EngineError::ResourceLimit` carries `{ what, need, limit, available }`, and
`ResourceLimit::cause()` returns `ExceedsLimit` when `need > limit`, meaning
this request would still be refused if this session were alone on the budget
with the same options; the outcome is terminal. It returns `PeerContention` when
`need` fits the ceiling, meaning that with the same options this exact request
is admitted once other reservations release. Which reservations those are is not
something the engine can say: the holder may be a peer session on the same
budget, or this session's own earlier reservations — layout, evidence and
assessment state are all still held when codec scratch is requested — so the
host decides using its own knowledge of what it has in flight. `Unmeasured`
marks the structural refusals that have no byte count, such as an exhausted
packet-count or scanning-work ceiling; treat it as terminal.

Two rules keep the classification honest, and both matter to a host that
requeues on contention. Refusals are measured against the ceiling this session
would have *alone*: metadata expansion compares its demand to
`min(retained_bytes, budget.limit())`, never to `budget.available()`, so a walk
that fits alone is never reported as terminal because a peer happens to hold
memory at that instant. And a refusal against a per-session ceiling —
`retained_bytes`, `max_retained_bytes`, the aggregate retained session state, and
the `SetLimits` derived from them — reports the session's *total* demand under
that ceiling rather than the increment that tripped it, because nothing else
draws on that ceiling and waiting can never admit the request. Weaver should map
`PeerContention` to "waiting for memory" and both `ExceedsLimit` and
`Unmeasured` to "does not fit".

### Stage working sets

Each stage of a repair holds a bounded set, and a stage releases what its
consumer no longer needs before the next one charges its own. Measured on a
16,384-block single-file set with a 128 MiB budget and a 64 MiB retained
ceiling, sampling `MemoryBudget::ledger()` at each stage boundary:

| stage | category | retained bytes | bytes per block | coexists with the previous stage |
| --- | --- | ---: | ---: | --- |
| scan and merge | carrier and packet storage | 398,673 | 24.3 | — |
| metadata and layout | resolved metadata | 460,559 | 28.1 | yes, carriers stay for regeneration |
| metadata and layout | layout and evidence | 4,337 | 0.3 | yes |
| verify and assess | layout and evidence | 12,609 | 0.8 | yes, evidence extends the layout entry |
| verify and assess | assessment state | 6,228 | 0.4 | no, the scratch is released at the handover |
| after repair | all categories | 878,069 | 53.6 | codec banks are released with the codec |
| session dropped | all categories | 0 | 0 | — |

Retained bytes and peak working memory are different answers and are reported
separately: the table above is what each stage leaves resident, and the budget's
high-water mark over the same run is 1,794,446 bytes (109.5 per block), reached
while metadata resolution holds both the carriers and the set it is building.

Two properties hold across block, file, carrier and damage counts, and are
regression-tested at a fixed budget:

- **Assessment retains a result, not a working set.** `assess` takes a scratch
  reservation for the coverage and per-cohort deficit accumulation, releases it
  at the handover, and retains only what the result's own containers measure. At
  sixteen times the blocks that retained figure does not move: it follows files
  and losses. The scratch and the result never coexist at full size.
- **The layout charges what it built.** Runs, tails, inline bytes, paths and the
  block index are charged from their container capacities and trued up to the
  built layout's measurement, rather than a flat per-extent estimate.
- **The layout does not follow the block count.** A contiguous protected chunk
  is one run whatever it maps, and the checksums its extents report are the
  set's, shared rather than copied. At sixteen times the blocks the layout entry
  does not move.

### Layout and evidence representation

A protected chunk that covers whole blocks maps a contiguous span of file bytes
onto a contiguous span of block indices. The layout stores that as a **run** —
file, first block, block count, byte offset — and expands a `FileExtent` only
when one is asked for. What a run cannot express is stored and charged
individually:

| exception | stored as | charged |
| --- | --- | --- |
| described chunk tail | its own block, offset, fingerprint and CRC64 | one entry per tail |
| inline tail | the authenticated bytes themselves | one entry plus the bytes |
| unprotected range | one run of one extent | one entry |
| a block named by more than one extent (aliases, shared and packed blocks) | an ordered-map entry with every location | one map entry and its list per aliased block |

`FileLayout::extents` is a `FileExtents` container rather than a `Vec`: `len`,
`iter` and indexed access answer what they always answered, but `FileExtent` is
yielded **by value**, because no such value is stored. `ExtentKind` and
`FileExtent` are unchanged, in the same order, with the same meanings.

Whole-block extents take `fingerprint` and `rolling_hash` from the set's
authenticated checksum storage instead of copying them. The layout holds that
storage through shared ownership, so it can never dangle and never needs a
second copy; the bytes are charged once, by the `Par3Set` that owns them, under
`resolved metadata`. Those checksums are themselves run-compact: External Data
packets describe consecutive blocks, so a set's checksums are stored as sorted
disjoint runs of `BlockChecksum` values rather than one ordered-map node per
block. `Par3Set::block_checksums` returns a `BlockChecksums` view over that;
`block_checksum(index)` is unchanged.

Cohort membership stays a property of the recovery index, not of the layout: the
block index says which extents name a block and nothing about which cohort it
falls in. Cohort deficits and lost-index lists are produced by walking blocks in
ascending order, so the same inputs in any arrival order yield byte-identical
`RecoveryRequirement` lists.

Verdicts are stored two bits per extent. All four states `ExtentVerdict` names —
unknown, intact, damaged, unprotected — survive, as do per-extent fingerprints
where the metadata records them, partial verification, source generations and
whole-file results. `FileEvidence::verdicts` returns an `ExtentVerdicts` view
with `len`, `get` and `iter`. Sealing, invalidation, `checkpoint_file` and
`replay_evidence` mean exactly what they meant.

### Checkpoint versioning

The evidence checkpoint format is **unchanged** by the compact representation:
the same `P3EV\x01\0\0\0` magic, the same 73-byte header, and one state byte
per extent in layout order, anchored by the same host-trusted digest. A
checkpoint written before this representation change replays against a layout
built after it, because the bytes are the same bytes and the layout identity is
computed from the same authenticated inputs in the same order. A blob whose
magic or version differs is refused with `EngineError::Unsupported("evidence
checkpoint version")`; a blob that does not describe this layout is refused with
`EngineError::InvalidState`. Nothing is ever misread as a different version.

Carrier bytes survive the metadata they were parsed into, deliberately: carrier
regeneration and re-resolution need them, and dropping them would trade memory
for source rereads. Verification evidence likewise survives sealing, because
assessment reads it and re-deriving it means reading sources again. Both are
reported rather than removed; `ExecutionDiagnostics::amplification()` exists so
that a future change here cannot hide the I/O it would cost.

### Continuations

A refusal or a recovery deficit leaves a continuation rather than requiring the
work to start over. `RecoveryRequirement` adds `in_flight`, `outstanding` and
`next_indices` to its existing fields, which keep their names and meanings.
`Par3RepairSession::note_recovery_in_flight` declares the indices a host is
acquiring for a matrix, and `forget_recovery_in_flight` retracts them. The next
assessment then counts those as `in_flight`, subtracts them from `outstanding`,
and offers exactly `outstanding` further admissible indices in `next_indices` —
lowest first, in the right cohort, and never one already available or already
declared. A reassessment after a recovery-only merge therefore advances the
acquisition plan instead of restating it. The declaration is a continuation, not
a promise: an index that never arrives keeps appearing as `in_flight` until the
host retracts it, and one that does arrive moves to `available` by itself. The
set is bounded and charged against the session's retained ceiling, so declaring
more than the budget admits is refused rather than silently truncated.

### Behaviour under pressure

When a stage's configured working set does not fit, the engine narrows before it
refuses: repair and verification stripes are computed from the headroom that is
actually there, worker pools fall back to serial execution, and verification
batches are cut to what admission allows. Each narrowing is recorded in
`ExecutionDiagnostics::waits()`. Widths are never searched by halving a request
until something fits — that charges the budget once per failed step and reports
only the last failure. A stripe admission measures the headroom, charges it, and
on losing a race to a peer measures once more and then stops.

When even the minimum useful set does not fit, the stage returns a single
`ResourceLimit` with honest `need`, `limit` and `available` and the `cause()`
rules above. There is no allocate-fail-wake loop and no internal retry spin. The
refusal is counted once, by cause, in `ExecutionDiagnostics::refusals()`, at the
session boundary the host sees — `merge`, `layout`, `assess` or `repair` — so a
request refused deep inside a stage is reported once rather than at every frame
it passes through.

### Output tiling

Cauchy repair keeps its syndrome bank for the whole solve but produces recovered
rows in tiles: it materialises `t` output rows at a time and scatters them before
producing the next tile, so the row-bank payload is `(m + t)` stripes rather than
`2m`. `t` comes from the admitted worker capacity, bounded by the number of rows
there are to recover. Column order and the one-scatter-per-column write pattern
are unchanged, so a narrower tile costs no extra seeks and produces byte-identical
output; `ExecutionDiagnostics::admission().output_tile` reports the width in force.

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

Packet admission charges parsed structures as well as wire bytes: an
authenticated packet is charged its parsed container capacity, not a multiple of
its wire length. Resolving shared directory/file descriptions has a separate
reservation, and expansion limits are still derived from remaining memory and
retained-state headroom. Resolution now takes its bytes as it allocates them —
one working charge for decoding and indexing the packets, then a per-entry
charge as the directory walk materialises paths, descriptions and frames — and
resizes to the resolved set's measured container capacity when it finishes.
`Par3Set::retained_capacity_bytes()` reports that measurement. A failed charge
part-way through releases everything the resolution took, and a graph that
expands past its headroom fails as a named `ResourceLimit` rather than by
exhaustion. Sessions keep that reservation for the resolved set's lifetime. The
`IncrementalSet::metadata` convenience method budgets construction but transfers
the returned legacy set to the caller; use a session for retained accounting. Assessment charges include
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
It also reports what admission decided and what that cost: `memory()` returns
the ledger of the budget the diagnostics were first used with, so retained and
scratch bytes per category are read from the ledger itself rather than a second
copy kept in step with it; `admission()` gives the effective stripe, stripe
buffer count, output tile, verification batch, worker count and sequential read
window; `waits()` gives the narrowings; `refusals()` counts refused admissions
by `LimitCause`; `caches()` gives current cache occupancy; and `amplification()`
gives the source bytes genuinely fetched twice, the stripe passes a bounded
working set forced over the source and the bytes the codec reconstructed, so a
memory reduction that only moved cost onto the I/O layer is visible next to it.
Successive stripe passes read disjoint slices of each block, so they are counted
as passes and not as rereads; the bytes in `reread_bytes` are the ones a block
named by more than one extent is fetched again for, so each copy can be compared
with the bytes already assembled. Every write is one relaxed atomic operation
per event and every read allocates nothing, so a host may sample these at
work-unit handback from another thread.
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

### CPU work and the gates on it

Verification hashes a source in parallel only when the work is worth a private
pool, and every gate is a number in the code rather than a heuristic:

* at least 1 MiB in one `update` call before BLAKE3's Rayon path is used at all
  (`hash::PARALLEL_HASH_BYTES`), with adjacent protected extents combined into
  runs first so a set of small archive blocks is still hashed in long updates;
* at least 8 MiB of source before a private pool is started for it
  (`hash::PARALLEL_SOURCE_BYTES`);
* at most four workers in that pool (`hash::PARALLEL_HASH_WORKERS`), because
  wider pools cost CPU out of proportion to the wall time they save;
* the verification buffer grows from 64 KiB to 1 MiB only when the shared budget
  admits it, charged to `SourceScratch`, and falls back to 64 KiB when it does
  not. Session verification reuses the pool it was already admitted; under
  pressure it falls back to serial hashing without reacquiring workers.

Measured on this host (Apple silicon, 18 cores, release profile, 64 KiB blocks,
`tests/verification_timing.rs`), verifying one 512 MiB source against the serial
path: two workers 1.31x wall, four workers 1.51x wall for 1.09x the CPU, eight
1.57x for 1.33x, and all eighteen 1.23x for 4.0x. Four is what is in the code.
End to end with that setting, and with every core configured so the cap is what
bounds the pool: 64 MiB in one file 1.49x, 512 MiB in one file 1.49x, 512 MiB
across 64 files 1.43x, and two sessions sharing one budget 1.21x to 1.53x, all
at about 1.06x the CPU of the serial run. A 64 MiB set spread over 64 files is
1 MiB a file, below the 8 MiB gate, so no pool is started for it and the numbers
are the serial ones (1.00x). These are measurements on one host, not a promise
about any other.

An FFT decode ends with a forward transform over the whole domain and then reads
only the lost rows. Stages of stride `2^j` or wider never join rows whose low `j`
bits differ, so those stages are `2^j` independent transforms over the rows that
share their low bits, and every narrower stage stays inside one aligned block of
`2^j` rows. Only the blocks holding a lost row need those narrow stages. The
decoder therefore builds a per-cohort plan — the block width and the list of
blocks to keep — charges it to `CodecScratch` (the lost-row list, a domain bitmap
for the transposes, and a small fixed margin), and skips the rest. The rows the
caller reads are byte-identical to the unpruned transform's, which is the oracle
the tests use.

The plan is chosen on total work, not on butterflies alone: a split replaces one
transform call with `2^j + blocks` of them, and each call has a setup the
butterflies do not pay for (`fft::PLAN_CALL_SYMBOLS`, 8192 symbol operations).
Where a cohort's rows are too narrow for that to pay — the pinned `fft16`
reference geometry is 32 symbols a row — the plan stands aside and the full
transform runs. Measured on this host (`tests/codec_measurements.rs`), with the
plan in force a 256-row GF8 cohort of 4096-symbol rows skips 19% of the decode's
butterflies and runs in 2.0–2.3 ms against 2.5–3.5 ms unpruned, and a 512-row
GF16 cohort of 8192-symbol rows skips 17% and runs in 4.1–4.9 ms against
4.9–8.6 ms. The input inverse transform is *not* pruned: its zero-tail saving
lives in the narrow ascending stages, which are exactly the ones inside a block,
and the derivative between the two transforms makes every row of the workspace a
dependency of the forward pass. Expressing the remaining cross-block stages
would need a single-stage transform primitive, which is a change to
`reedsolomon-rs` rather than to this crate.

Cauchy repair recomputes one code-matrix element per surviving block per
recovery row on every stripe pass; `ExecutionDiagnostics::codec()` counts them.
Measured on this host across the eight corpus sets, that is 0.15%–0.46% of
repair wall time, and under a forced 4 KiB stripe — sixteen passes over 64 KiB
blocks — 31,872 recomputations are 1.6 ms of a 478 ms repair, 0.34%. One element
is an exclusive-or and a table lookup, about 51 ns, against about 3.8 us for the
64 KiB multiply-accumulate that follows it. Caching a source's factors is
therefore not worth its charge at these geometries, and nothing caches them.

### Names the engine will write

A set names its protected files with relative paths carried in the set itself,
which makes those bytes attacker-controlled. `paths::validate_relative_path` is
the engine's only decision about such a name, and both ends call it: creation
before a byte of the set is produced, repair before a byte of output is written
and before the first parent directory is created. It reads no filesystem and
consults no platform, so the verdict for a given sequence of bytes is the same
everywhere; a hostile set refused on Linux is refused identically on Windows
and macOS. The refusal is `EngineError::UnsafePath(PathViolation)`, which names
the rule and the offending component rather than a prose string.

The whole path is refused when it is empty, exceeds `paths::MAX_PATH_BYTES`
(4096, the traditional `PATH_MAX`), or is absolute — a leading `/` or `\`, or a
`X:` drive prefix, which is reported as `Absolute` rather than as a colon
because `c:file` is drive-relative, not a stream name. A `/`-separated
component is refused when it is empty, `.`, `..`, exceeds
`paths::MAX_COMPONENT_BYTES` (255, the per-entry ceiling of ext4, APFS and
NTFS), contains `\`, `:` or an ASCII control byte (NUL and DEL included),
names a Windows character device with or without an extension (`CON`, `PRN`,
`AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, matched case-insensitively against
the stem before the first dot, trailing spaces trimmed, so `con.txt` and
`CON   .txt` are both refused), or ends in a space or a dot, which Windows
silently trims onto an existing name. Bytes, not characters, throughout.

Packet parsing is deliberately narrower and unchanged: `check_name` asks only
whether a name field is a usable single component, because one unwritable name
must not make a whole set unreadable. A set that carries `CON` still parses and
still verifies; only creating that file is refused.

The rules are stricter than the draft, which is silent on all of this, and
stricter than the reference, which rewrites an unusable name in place and
warns. `README.md` records the deviation.

### What a host can read back from a session

Three tallies a consumer would otherwise reconstruct beside the engine:

- `Par3RepairSession::set` lends the session's resolved `Par3Set` rather than
  handing back a clone. File paths and lengths, the directory tree, the block
  layout and `Par3Set::option_packet_count` — the extension packets this crate
  retains and never interprets — are all readable through the borrow, which
  ends at the next `&mut self` call. Resolution is lazy and budgeted, so this
  reports what the session already resolved: call `layout` or `assess` after
  merging metadata, then read it. `None` means no set is resolved yet, never
  that the set is malformed.
- `failed_hash_bytes` is the complete packet bytes of every reauthentication
  the engine performed on this set's payloads and lost. A payload is
  reauthenticated before it is consumed — a stat fingerprint is not
  cryptographic evidence — so a carrier that changed under the reader, or never
  held what its header claimed, is caught there and charged here. Non-zero
  means carrier bytes were hashed and thrown away; it is the price of trusting
  that carrier, in bytes, and a host can use it to stop re-reading a source.
  Scanner candidates rejected before a packet reached a set are not counted:
  they never belonged to one.
- `rejected_packets` counts every packet a merge refused, by any cause — a
  packet naming another input set, a retained-metadata ceiling, a memory
  refusal, a cancellation, a failed reauthentication — including refusals the
  session makes before the set itself sees the packet, so one refusal is
  exactly one rejection. A replay is not a refusal.

Both tallies are monotonic and per set, and neither is ever reset.

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
