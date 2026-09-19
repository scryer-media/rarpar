# Changelog

## 0.4.3

- New `wasm-simd` feature. It forwards blake3's `wasm32_simd`, which is what
  puts blake3's wasm SIMD kernels into a wasm build; without it a `+simd128`
  artifact hashes with the portable ones. Cargo cannot key a feature on a
  `target_feature`, so a wasm build compiled with `-C target-feature=+simd128`
  has to name the feature as well, and a wasm build without simd128 must leave
  it off — blake3's kernels compile in unconditionally once the feature is on,
  and a module that promises no SIMD must not carry v128 instructions. The
  crate fails the build of a `+simd128` wasm artifact that did not forward it,
  by asserting blake3's own reported SIMD degree at compile time, so the
  pairing cannot be lost quietly. Native builds are unaffected: blake3's build
  script only acts on the feature for `wasm32`. PAR3 verification is dominated
  by fingerprinting — 88% of a 16 MiB verify under wasmtime 47 is BLAKE3 — and
  forwarding the feature makes that verify 1.84x faster, the fingerprint itself
  1.96x, and the harness's whole run 1.49x.
- New `wasm_par3_check` example: an end-to-end create, verify, damage and
  repair pass over the published PAR3 corpus, printing a fingerprint for every
  repaired file and every created carrier. It runs natively and under a wasm
  runtime, and CI now diffs each wasm lane's canonical report against the
  native run in the same job, so a lane that computes different parity bytes
  fails rather than merely reporting `PASS`.
- Requires `reedsolomon-rs` 0.4.7, for its wasm GF(2^8) tier.

## 0.4.2

- **Behaviour change:** an interleaved set's recovery carriers are cut and
  named by row, not by global recovery index. A row is one recovery index in
  each cohort, so `vol<first row>+<rows>` of a set with `C` cohorts holds
  `rows * C` Recovery Data packets, whose indices run from `first row * C` to
  `(first row + rows) * C`. Carriers used to be cut on the global index, which
  both named them in units no other implementation writes and split a single
  row across two of them. A non-interleaved set is unchanged, since there a row
  is a recovery index.
- **Behaviour change:** `CreationOptions::first_recovery` and
  `recovery_count` must now name whole rows — each a multiple of the cohort
  count — and a range that does not is refused with
  `EngineError::InvalidState`, since no carrier name can describe a partial
  row. `VolumeLayout::Uniform` and `SizeLimited` are likewise rounded down to
  whole rows, and a limit too small for one row is refused rather than silently
  producing a carrier that splits one.
- The advanced creation API pads both numbers in a carrier name to the width
  the largest of each reaches, as `create` already did and as the format's
  other producers do, so a set's carriers sort as text. A set with fewer than
  ten carriers, and fewer than ten payload packets in each, is unaffected.

## 0.4.1 (2026-09-15)

- An assessment charges the vectors its matrix selection builds — the winning
  matrix's requirement list, each cohort's availability and next-index lists,
  and the payload references it selects — before it builds them, from the
  cohort, recovery and loss counts. They used to grow against a budget that had
  never been told about them; a budget that cannot hold them now refuses with
  `EngineError::ResourceLimit` instead of allocating them.
- A session alone on a budget, whose own admitted packets leave no room to
  resolve them, is refused with `LimitCause::ExceedsLimit` rather than
  `PeerContention`. There is no peer to wait for, so the refusal is terminal,
  and a host told it was contention parked and retried forever. A refusal a
  peer really is causing still reports `PeerContention`.
- **Behaviour change:** `create` now holds every name it is asked to protect
  against `paths::validate_relative_path`, the same table the session creator
  uses, and refuses an unsafe one with the new `Par3Error::UnsafePath`. A set
  naming a reserved device (`con.txt`) or a trailing-dot file could be created
  here and then refused by this crate's own repair on the platform that cannot
  write it.
- The copy path counts one stripe pass per extra pass over the blocks it
  copies, rather than one per block per window, which is what the
  reconstruction path already did. Copying four blocks in sixteen windows
  reported sixty passes where there were fifteen.

## 0.4.0

- Version: this release is `0.4.0`, not `0.3.2`. The entries below change public
  types, and under Cargo's 0.x rules a `par3-rs = "0.3.1"` requirement resolves
  to `0.3.2`, which would have handed those changes to callers that never asked
  for them.
- A transform plan sorts the lost rows it is given before it prices or prunes
  anything. `decode` checks that they are in range and distinct but not that
  they are ordered, and the pruned transform finds its blocks by binary search,
  so an unordered list from a public caller used to misprice every split and
  then prune blocks the decode still needed. The plan a caller gets no longer
  depends on the order it names its losses in.
- The layout's alias charge counts one location per (extent, block) pair rather
  than a fixed two per block, and reserves it before the locations are built
  instead of only comparing it with the ceiling. A carrier whose files alias the
  same blocks deeply is now refused by name rather than admitted and
  materialised. `build_index` also takes a scoped reservation for its own sweep
  workspace, and checks cancellation inside the per-block loop.
- Building a Galois field is charged what it really peaks at during creation and
  carrier regeneration, as repair already did; GF(2^16) costs about 896 KiB, not
  the 512 KiB that was reserved.
- A metadata packet is admitted for its wire bytes and its parsed body together,
  before it is parsed, rather than after the parsed body already exists.
- A Cauchy repair's output tile comes from the worker pool that was admitted,
  not the worker count that was configured, so a repair squeezed onto one thread
  banks one output row instead of reserving rows no worker will fill.
- Every repair destination is resolved before any file is staged, so a set
  carrying a name this platform cannot write is refused with a plain
  `EngineError::UnsafePath` and leaves no temporary behind.
- `note_recovery_in_flight` charges what the in-flight set actually stores, so a
  declaration naming the same index twice can be fully retracted; an index at or
  past a matrix's capacity ceiling no longer cancels a requirement it could
  never fill.
- **Breaking:** `AmplificationSnapshot` gained `stripe_passes`, and
  `reread_bytes` now means what it says. Successive stripe passes read disjoint
  slices of a block, so they are counted as passes; `reread_bytes` counts only
  bytes genuinely fetched twice, which is what a block named by more than one
  extent costs.
- Data-cache occupancy is reported as a per-session delta, so sessions sharing
  one `ExecutionDiagnostics` sum instead of overwriting each other and a
  finished session leaves no phantom cache behind.
- `COM0`, `LPT0` and the superscript aliases `COM¹ COM² COM³ LPT¹ LPT² LPT³` are
  refused as reserved device names.
- Checksum runs are allocated at exactly the size they will hold, instead of
  growing by doubling and then copying into an exact vector while the oversized
  buffer is still live, and the run descriptors are charged in the resolution
  budget. The transient name set a Directory's duplicate-name check builds is
  charged too.
- `Par3RepairSession::layout` documents that the returned layout must not
  outlive the session: it shares the set's block checksums, which are charged to
  the session's resolved-set reservation and not to the layout's.
- A layout allocates a file's extent runs at exactly the count its charge paid
  for. The allocation assumed two runs for every protected chunk while the
  charge counted one for a chunk that is a whole number of blocks, so a set of
  full-block files held capacity the budget never saw and then bought an exact
  copy of it back.
- The block-checksum builder is allocated for every described block before the
  first one is pushed, instead of doubling into as much as twice the slots the
  set's resolution charge covers while the values and runs are laid out beside
  it.
- **Breaking:** `PathRule` gained `ForbiddenCharacter`. The six characters Win32
  forbids in a name — `?`, `*`, `"`, `<`, `>`, `|` — are refused at both ends
  like the separators and the colon already were, so par3-rs no longer creates a
  set naming a file Windows could never write. The enum is `#[non_exhaustive]`,
  and the more specific rules still win: `a:b` is `Absolute` and `ab:c` is
  `Colon`.
- Opening a stage against a second, different `MemoryBudget` with the same
  `ExecutionDiagnostics` is refused with
  `EngineError::InvalidState("diagnostics already bound to another memory
  budget")` rather than silently ignored. One handle aggregates work counters
  across everything sharing it but reports the ledger of one budget, so the two
  must be the same budget; clones of one budget are fine.
- Additive-transform work is counted after the backend has performed it, not
  before, so a cancelled or failed transform no longer inflates the codec
  counters with butterflies it never executed. The pruned path already counted
  afterwards; the two now agree.
- `ResourceLimit::cause` classifies a refusal as `Unmeasured` only when it
  carries neither a need nor a ceiling, which is what the structural constructor
  produces. A positive need against a ceiling of zero — the refusal a
  `MemoryBudget::new(0)` raises for everything — is `ExceedsLimit` with its
  figures intact, and `Display` still prints them.
- `MemoryBudget::is_same` reports whether two handles are clones of one budget.
- `FileExtents::all_unprotected` answers `true` for an empty interval wherever
  it sits, instead of `false` when the two offsets fall inside one protected
  extent. Whole-file verification asks it about the gap between two consecutive
  reads, so any read narrower than a block — a stripe smaller than the block
  size, or a block wider than the 64 KiB serial read — used to look like a skip
  over protected bytes and the whole-file hash came back as `None` on an
  undamaged file.
- Metadata expansion grows its reservation before the entries it covers are
  allocated, not after. The charge still batches in 64 KiB granules, but it now
  reserves a granule ahead and hands the slack back at the end, so heap use
  never runs ahead of the budget and a set that will not fit is refused before
  the allocation it would have needed.
- A Cauchy repair's pool headroom includes the row headers a serial stripe bank
  needs, and if stripe admission is still refused while a pool is held, the pool
  is dropped and the admission is retried once serially (noted through the
  existing worker-narrowing diagnostic). A budget that admitted a pool could
  otherwise take the memory the stripe headers needed and refuse a repair that
  fits serially, so a larger budget could fail where a smaller one succeeded.
- A Root packet is charged for the duplicate-name check the tree walk runs on
  its children. The walk checks the root's children before it checks anything
  else, and that set is as large as the one a directory of the same width
  builds, but only `Directory` was charged for it.
- Resolving a set moves each parsed body out of the packet that carried it
  instead of cloning it. Every File, Directory, External Data, Root, matrix and
  option packet used to exist twice for the length of the resolution — once in
  the packet list and once in the set being built — while the budget was told
  about one copy, so a set resolved close to its ceiling peaked above what it
  had reserved.
- A repair is refused before anything is staged when two of the set's paths
  differ only by letter case *and* the destination filesystem folds case.
  `Readme` and `README` are two names a case-sensitive producer may legitimately
  put in one set, and repairing them onto a case-sensitive filesystem still
  writes two files; on macOS's default filesystem and on Windows they are one
  file, where the second output written would take the first one's place. The
  destination is asked only when the set actually carries such a pair, with a
  uniquely named probe that is always removed.
- A recovery index whose payloads conflict is never offered again. Two
  different payloads claiming one index leave that index unusable for the rest
  of the session, but it used to look unclaimed to the next-index search, which
  handed the host an index it could never satisfy while a usable one went
  unasked for.
- A packet a budget refuses is offered again rather than skipped. The scanner
  counted the packet and stepped its offset past it before asking for the
  memory its parsed body needs; a refusal a peer caused is retryable by
  contract, so the host parked and polled again, and the packet it had already
  stepped over was never yielded. Nothing moves now until the packet exists.
- `note_recovery_in_flight` reserves an upper bound for the set it builds
  before building it, rather than after. A declaration of many indices no
  longer allocates ahead of the budget; one large enough to exceed the ceiling
  is refused before the allocation instead of after it.
- `AmplificationSnapshot::stripe_passes` counts one pass per extra walk over
  the source, as documented. A Cauchy repair took the count inside its loop
  over surviving blocks, so one extra pass over a set of 100 blocks reported
  100.
- `IncrementalSet::failed_hash_bytes` includes a reauthentication lost to a
  carrier rewritten under the reader, which is what its documentation always
  said it counted. Only a hash mismatch was counted before, so the most
  expensive way to lose a packet — read and hashed in full, then thrown away —
  reported nothing. `rejected_packets` still counts only packets this set
  refused, and a carrier that moved is not one.
- A Creator or Comment body's text moves into the `String` the set keeps
  instead of being copied out beside it, and the resolution charge covers a
  lossy decode of a body that is not valid UTF-8, which can reach three bytes
  per byte and was charged as nothing.

- Store a contiguous protected chunk mapping as a run (file, first block, block
  count, byte offset) instead of one materialised extent per block, and expand a
  `FileExtent` only when one is asked for. Described tails, inline tail bytes,
  unprotected ranges and blocks named by more than one extent are the charged
  exceptions. Cohort membership remains a property of the recovery index, not of
  the layout.
- **Breaking:** `FileLayout::extents` is now a `FileExtents` container rather
  than `Vec<FileExtent>`. `len`, `is_empty`, `iter` and `get` answer what they
  answered before, but `iter` and `get` yield `FileExtent` *by value*, because
  no such value is stored; `range`, `block_at`, `is_unprotected`,
  `inline_bytes`, `first_after` and `all_unprotected` read one extent's
  properties without materialising it. `ExtentKind` and `FileExtent` are
  unchanged.
- **Breaking:** `BlockLayout::blocks` returns an iterator of
  `(u64, BlockLocations)` in ascending block order instead of
  `&BTreeMap<u64, Vec<ExtentLocation>>`. `BlockLayout::locations(block)` answers
  one block; `BlockLocations` dereferences to `&[ExtentLocation]`.
  `BlockLayout::referenced_blocks`, `aliased_blocks`, `widest_block` and
  `checksums` are new.
- Share authenticated checksum ownership between a set and the layouts resolved
  from it. Whole-block extents report `fingerprint` and `rolling_hash` from the
  set's storage instead of copying them, and the layout holds that storage
  through shared ownership, so it can never dangle and the bytes are charged
  once, by the set, under `resolved metadata`.
- **Breaking:** `Par3Set::block_checksums` returns `&BlockChecksums` instead of
  `&BTreeMap<u64, BlockChecksum>`. The new type stores checksums as sorted
  disjoint runs — External Data packets describe consecutive blocks — and offers
  `len`, `is_empty`, `runs`, `get`, `contains` and `iter`.
  `Par3Set::block_checksum` is unchanged; `Par3Set::shared_block_checksums` is
  new.
- **Breaking:** `FileEvidence::verdicts` returns `&ExtentVerdicts` instead of
  `&[ExtentVerdict]`. Verdicts are packed two bits per extent and keep all four
  states `ExtentVerdict` names, along with per-extent fingerprints, partial
  verification, source generations and whole-file results. Sealing, invalidation
  and `replay_evidence` are unchanged.
- The evidence checkpoint format is unchanged: the same magic, the same 73-byte
  header, and one state byte per extent, anchored by the same host-trusted
  digest. A checkpoint written before this representation change replays against
  a layout built after it; a blob with a different version is refused with
  `EngineError::Unsupported("evidence checkpoint version")` rather than misread.
- Retained metadata and peak working memory are now reported separately, per
  stage and per block, by the stage inventory and the geometry probe. On the
  16,384-block single-file set the retained total falls from 365.3 to 53.6 bytes
  per block and the budget's high-water mark from 21,126,190 to 1,794,446 bytes;
  on the 131,072-block probe the peak falls from 53,694,630 to 13,706,159 bytes
  and the retained total to 48.9 bytes per block.
- Add a categorised allocation ledger to `MemoryBudget`. `MemoryBudget::ledger`
  returns a `MemoryLedger` giving each `MemoryCategory` its current and peak
  reserved bytes and its reservation count. Reading it allocates nothing and
  takes no lock. Every reservation the engine takes names a category; anything
  that does not is reported as `MemoryCategory::Uncategorized`.
- **Breaking:** `EngineError::ResourceLimit` now carries a `ResourceLimit`
  struct (`what`, `need`, `limit`, `available`) instead of a `&'static str`.
  `ResourceLimit::cause` distinguishes a request that would still be refused
  with this session alone on the budget (`LimitCause::ExceedsLimit`) from one
  that the same options admit once other reservations release
  (`LimitCause::PeerContention`), so a host can queue the second and refuse the
  first. The holder in the contended case may be a peer session or this
  session's own earlier reservations; the engine cannot tell them apart and says
  so. Refusals measure against the ceiling the session would have alone, and
  refusals against a per-session ceiling report the session's total demand
  rather than the increment that tripped them, so neither reads as retryable
  when waiting cannot help. Patterns of the form `EngineError::ResourceLimit(_)`
  are unaffected; patterns naming the string need
  `ResourceLimit { what: "...", .. }`.
- Charge metadata resolution for the allocations it makes instead of reserving
  the whole retained ceiling up front. Packet decode, description resolution and
  directory expansion are charged as they happen, and the charge that survives
  resolution is the resolved set's measured container capacity
  (`Par3Set::retained_capacity_bytes`) rather than a flat multiple of the packet
  bytes it was built from. Sets with many blocks now resolve under ceilings that
  previously refused them; hostile directory graphs are still refused as
  `ResourceLimit` naming the limit they hit.
- Charge retained packets their parsed capacity rather than sixteen times their
  wire length, and resize a scanner's carrier reservation to the packet it
  authenticated.
- Charge GF(2^16) field construction for the `u32` working tables it holds while
  narrowing, which were previously understated by about 400 KiB, and charge the
  Cauchy stripe banks for their per-row vector headers.
- Bound each repair stage's resident working set. `assess` now takes a scratch
  reservation for coverage and per-cohort deficit accumulation, releases it at
  the handover, and retains only what the result's own containers measure, so
  what survives assessment follows files and losses rather than the block count.
  On a 16,384-block set the retained assessment state falls from 10,493,485
  bytes to 6,228, and stays flat from 2,048 to 16,384 blocks.
- Charge the block layout from its containers' capacities — extents, inline
  bytes, paths and the block index — and true the charge up to the built
  layout's measurement, instead of a flat 512 bytes per extent. The same
  16,384-block set falls from 512.0 to 232.3 bytes per block. Together with the
  assessment change, the budget's peak for that repair falls from 21,126,190
  bytes to 6,901,926.
- Produce Cauchy recovery rows in tiles. The syndrome bank is unchanged, but
  recovered rows are materialised and scattered `t` at a time, moving the output
  row bank from `2m` stripes toward `(m + t)`. `t` comes from admitted worker
  capacity. Column order, write count and output bytes are unchanged.
- Add a resumable acquisition continuation. `RecoveryRequirement` gains
  `in_flight`, `outstanding` and `next_indices`; existing fields are unchanged.
  `Par3RepairSession::note_recovery_in_flight` declares indices a host is
  fetching and `forget_recovery_in_flight` retracts them, so reassessment after
  a recovery-only merge advances the plan instead of requesting the same indices
  again. The declared set is bounded and charged against the retained ceiling.
- Report admission on `ExecutionDiagnostics`: `memory()` delegates to the
  budget's ledger, `admission()` gives the effective stripe, stripe buffers,
  output tile, verification batch, workers and read window, `waits()` gives the
  narrowings, `refusals()` counts refused admissions by `LimitCause`, `caches()`
  gives cache occupancy, and `amplification()` gives reread and reconstructed
  bytes so a memory saving cannot hide I/O amplification. Writes are one relaxed
  atomic operation per event; reads allocate nothing.
- Narrow before refusing, and refuse once. Stripe admission computes the width
  from real headroom instead of halving a request until something fits, and
  remeasures at most once after losing a race to a peer. A refusal that reaches
  a host through `merge`, `layout`, `assess` or `repair` is counted exactly once,
  by cause.
- Hash a large source in parallel during verification, under gates rather than
  unconditionally: BLAKE3's Rayon path is used only for updates of at least
  1 MiB, only for sources of at least 8 MiB, and only inside a private pool of
  at most four workers admitted from the shared budget. Adjacent protected
  extents are combined into runs so a file of small archive blocks is still fed
  to the hash in long updates, and a verification buffer grows from 64 KiB to
  1 MiB only when the budget admits the charge. Session verification reuses the
  pool it was already admitted and falls back to serial hashing under pressure
  without reacquiring workers. Serial, parallel and constrained-memory
  verification produce identical evidence, asserted with the checkpoint digest.
  Measured on an 18-core host, four workers verify a 512 MiB source at 1.51x the
  serial wall time for 1.09x the CPU, where eighteen workers reach only 1.23x
  for 4.0x; the numbers and the reasoning are in ENGINE.md.
- Prune an FFT decode's final forward transform to the rows the caller reads.
  The decoder computes a per-cohort plan — a block width and the blocks holding
  a lost row — charges it to `MemoryCategory::CodecScratch`, and skips the
  stages that would only produce rows nobody reads. Output is byte-identical to
  the unpruned transform, which is the oracle the tests use, over both fields,
  light, heavy and spread damage, zero padding, arbitrary recovery selections
  and widths either side of the SIMD and pool thresholds. The plan is chosen on
  total work including each transform call's own setup, so cohorts with rows too
  narrow to pay for the split run the full transform instead. The input inverse
  transform is not pruned; ENGINE.md says why.
- `ExecutionDiagnostics::codec` is new: transform calls, butterflies performed
  and skipped, multiply-accumulates, and Cauchy code-matrix factors computed and
  reused. Counters are relaxed atomics written once per transform call, never
  per symbol.
- Two `#[ignore]`d measurement probes, `tests/verification_timing.rs` and
  `tests/codec_measurements.rs`, print the tables the gates above were chosen
  from: parallel against serial verification at several widths, the FFT work per
  cohort with and without the plan, and what Cauchy factor recomputation costs
  against the multiply-accumulate it precedes. They measure the host they run
  on; the numbers recorded in ENGINE.md are this host's.
- One name-safety rule table, in the new `paths` module, is now the engine's
  only decision about a relative path it is asked to write. `contained_destination`
  (repair) and `creation::validate_name` (set creation) both call
  `paths::validate_relative_path`, so par3-rs never produces a set it would
  refuse to repair, and a hostile set is refused identically on every platform,
  before any output byte is written and before any parent directory is created.
  A component is refused when it is empty, `.`, `..`, longer than
  `paths::MAX_COMPONENT_BYTES` (255), contains `\\`, `:` or an ASCII control
  byte (NUL and DEL included), names a Windows character device (`CON`, `PRN`,
  `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, case-insensitive, with or without
  an extension, so `con.txt` too) or ends in a space or a dot. A path is
  refused when it exceeds `paths::MAX_PATH_BYTES` (4096) or is absolute — by a
  leading `/` or `\\`, or a `X:` drive prefix, which is reported as absolute
  rather than as a colon. Names that were already accepted are unaffected.
- **Breaking:** `EngineError::UnsafePath(PathViolation)` is new, and replaces
  `InvalidState("invalid output path component")` and
  `InvalidState("invalid creation path")`. It names the rule and the offending
  component: `PathViolation { path, component, rule }` with `rule: PathRule`.
  Both text fields are truncated to 255 bytes on a character boundary, so a
  hostile name cannot make the refusal unbounded. `PathRule`, `PathViolation`,
  `MAX_PATH_BYTES` and `MAX_COMPONENT_BYTES` are re-exported at the crate root.
  Packet parsing is unchanged: a set that carries such a name still parses and
  still verifies, because one unwritable name must not make a set unreadable.
- `IncrementalSet::failed_hash_bytes` and `IncrementalSet::rejected_packets`
  are new, with `Par3RepairSession::failed_hash_bytes` and
  `Par3RepairSession::rejected_packets` beside them. Both are monotonic, per
  set, and never reset. `failed_hash_bytes` counts the complete packet bytes of
  every reauthentication the engine performed on this set's payloads and lost —
  a carrier that changed under the reader, or never held what its header
  claimed. `rejected_packets` counts every packet a merge refused, by any
  cause; a replay is not a refusal. A host no longer has to keep these tallies
  beside the engine's.
- `Par3RepairSession::set` lends the session's resolved `Par3Set` instead of
  making a host clone it: file paths and lengths, the directory tree, the block
  layout and the new `Par3Set::option_packet_count` are all readable through
  the borrow. Resolution stays lazy and budgeted, so `set` reports what the
  session has already resolved rather than resolving on demand.
- `PayloadRef::packet_length` reports the complete on-carrier packet length,
  which is the work a reauthentication costs and what a failed one is charged.

## 0.3.1 (2026-09-13)

- Add `Par3RepairSession::set_execution_limits` to adjust worker and stripe
  limits between operations without discarding authenticated session evidence.
- Verify independent sources with the existing private, budgeted worker pool.
  Preserve ordered source hashing, deterministic evidence acceptance and
  generation checks, with serial fallback under resource pressure.
- Reserve aligned Cauchy and FFT repair stripes atomically and shrink them
  under contention without increasing memory ceilings. Account for retained
  peer evidence before a failed parallel verification retries serially.
- Allocate FFT tables and worker stacks before source scratch, retaining room
  for locator state and minimal decode buffers under constrained budgets.
- Charge verification rosters only for available sources needing verification;
  cached-evidence and unbound assessments require no spare roster memory.
- Accept serial verification immediately without a redundant snapshot read;
  retain acceptance checks for concurrent results delayed by peers or retries.
- Probe bounded verification batches and preserve validated peer evidence before
  returning errors. Size worker admission from combined stack and scratch costs.

## 0.3.0 (2026-09-08)

- Pin Windows packet carriers with budgeted read-only sharing locks to avoid
  full-file generation hashes inside scan and payload loops. Charge fallback
  generation hashing to the cumulative work budget.
- Expose `Par3RepairSession::validate_repair` so dry runs and execution share
  readiness, ordinary-repair layout support, and configured Cauchy loss/handle checks.
- Add bounded incremental packet ingestion, virtual source access, positioned
  BLAKE3 verification evidence, retained repair sessions, cancellation, and
  shared memory, handle, and scan-work budgets.
- Support low-rate FFT and interleaved recovery, shared and deduplicated blocks,
  packed tails, Data packets, content placement, and selective reconstruction.
- Add advanced creation, recovery-carrier reconstruction, and explicit staged
  ZIP/ZIP64/7z insertion and self-repair. Existing convenience creation defaults
  remain Cauchy-based.
- Reuse the GF8 and FFT primitives in `reedsolomon-rs` 0.4.5. Verify Data payloads
  against protected-extent fingerprints before admission, validate FFT field
  geometry, and bound Cauchy loss counts before solver allocation.
- Enable the published advanced reference corpus and document the synchronous
  host contract, interoperability, and native verification/repair performance.

This minor version introduces the advanced public engine contract. Consumers
should review the README and ENGINE.md when moving from the 0.2 convenience APIs.

## 0.2.0

An inventory of the recovery data a set carries, the Galois-field arithmetic and
the Cauchy Reed-Solomon codec that recovery data is built from, creating a
complete PAR3 set from a list of input files, repairing one, and an oracle suite
that pins all of it against the reference implementation.

### Added

- `set`: `RecoveryBlock` and `Par3Set::recovery_blocks`, the set's recovery
  blocks sorted by index and then by matrix hash, one per matrix and index and
  deduplicated — the reference implementation repeats its vital packets across
  recovery volumes so that any one volume can be read alone, and identical copies
  of a recovery block collapse into one entry. A block index selects a row of the
  Matrix packet the block names, so a set holding two matrices legitimately holds
  a block 0 for each. Each block reports the Matrix packet it names and whether
  that packet is present.
- `set`: `Par3Set::foreign_recovery_packets`, for Recovery Data packets that name
  some other Root packet. An incremental backup's child set shares its parent's
  InputSetID lineage but not its Root, so such packets are neither this set's
  recovery data nor damage; they are kept aside rather than dropped.
- `set`: `Par3Set::conflicting_recovery_packet_count`, for Recovery Data packets
  left out of the inventory because two or more of them claimed one matrix and
  index without agreeing on the bytes. None of them is listed — nothing stored
  says which is right — but the set still assembles, so a junk recovery packet
  appended to a file costs the caller that recovery block and not the file
  listing.
- `set`: `Par3Set::recovery_block_checksums` and
  `Par3Set::recovery_block_checksum`, mapping Recovery External Data packets by
  Matrix packet hash and recovery block index the way External Data packets are
  mapped by input block index, and `RecoveryBlock::matches_checksum` to check a
  block against one.

- `gf`: `Field`, `Gf8` and `Gf16` — table-driven arithmetic in the two binary
  Galois fields PAR3 uses, with `mul`, `inv`, and the region operations
  `mul_acc` and `mul_into` a codec spends its time in. GF(2^16) symbols are
  little-endian 16-bit words, as the reference implementation reads them.
  Constructors take the generator polynomial a Start packet declares and refuse
  one that is not primitive, because the log tables both fields are built on
  need the element two to reach every value; `gf::for_set` builds the field a
  parsed `GaloisField` names. Scalar and portable: no `unsafe`, no SIMD, no new
  dependencies.
- `cauchy`: `Encoder` and `Decoder`, the streaming Cauchy Reed-Solomon codec.
  The encoder takes input blocks in any order, once each, zero-pads a short one
  the way the reference pads a block holding a chunk tail, and returns the
  recovery blocks. The decoder is told which input blocks are lost and which
  recovery blocks are on hand, accumulates a syndrome per chosen row over the
  surviving blocks, and solves an `n × n` system over the lost columns alone —
  never the whole `input_blocks × recovery_blocks` matrix.
- `cauchy`: `Geometry`, which validates that a set's block counts have a Cauchy
  matrix at all. The row and column values collide unless
  `input_blocks + first_recovery + recovery_blocks <= 2^w`, so GF(2^8) takes 251
  input blocks with 5 recovery blocks and refuses 252 with 5.
- `cauchy`: `default_field`, the reference implementation's rule for choosing
  between the two fields, and `element`, one matrix element on its own.
- `cauchy`: `CodecLimits`, in the style of `ScanLimits` and `SetLimits`, bounding
  the recovery rows, syndromes and matrix a codec allocates from numbers a
  `.par3` file chose, and — since the solve is cubic in the number of lost
  blocks, and a set of two-byte blocks can name thousands of them inside any
  memory budget — the lost blocks one decoder will solve for
  (`max_lost_blocks`, 4096 by default). `Encoder::with_limits` and
  `Decoder::with_limits` take one.
- `error`: `Par3Error::UnsupportedField`, `CodecGeometry`, `CodecBlock`,
  `InsufficientRecovery`, `SingularSystem` and `CodecLimitExceeded`, for the
  ways a field or a codec geometry can be unusable. A hostile geometry is an
  error at construction, never a panic and never an allocation.

- `create`: `create`, which writes an index file and its recovery volumes for
  files under a base directory. It plans the whole set from the file sizes
  alone — block size, chunk map, tail packing, block count, Galois field,
  recovery count — then reads each input exactly once, hashing it, checksumming
  its input blocks and feeding the Cauchy encoder as the bytes go past. Given
  the same inputs and settings, every byte of every file it writes matches what
  the reference implementation writes, the Creator text aside;
  `tests/oracle_create.rs` rebuilds both oracle archives and requires it.
- `create`: `CreateOptions` and `RecoveryAmount`, for the block size (or
  `None` to take the suggested one), the recovery amount as a block count or a
  percentage, the Creator text, an optional comment, and whether an existing
  file may be replaced. Nothing is written until every target has been checked,
  so a refusal to overwrite leaves the directory untouched.
- `create`: `InputSpec`, naming the files a set protects relative to one base
  directory, plus any directories that hold no protected file. Every name is
  checked component by component against the rules the reader enforces, so
  nothing this crate writes can fail to be read back.
- `create`: `CreateReport`, which says what was built: the InputSetID, the block
  size after any rounding, the input and recovery block counts, the field, how
  many chunk tails were packed behind an earlier one, and every file written
  with the index first.
- `create`: `suggest_block_size`, the reference implementation's rule for
  choosing a block size from a set of file sizes.
- `create`: `CreateLimits`, in the same style, bounding the block size, the
  number of input files, the bytes of path text, the blocks held while their
  chunk tails are still filling, and the codec.
- `error`: `Par3Error::CreateInput`, `CreateLimitExceeded` and `FileIo`, for an
  input a set cannot be built from, a set that would exceed `CreateLimits`, and
  anything the file system refused, named by path.

- `repair`: `repair_set`, which puts a set's protected files back from whatever
  survives. It verifies every file, works out which input blocks were lost —
  those of a missing file, those that failed their checksum, the block behind
  every damaged chunk tail, and everything a truncation took away — solves for
  them with the recovery blocks the set carries, and writes each damaged or
  missing file back. Files that verify complete are never touched. Everything
  streams: a file is read a block at a time and written a block at a time, so
  nothing costs the size of a file.
- `repair`: `plan_repair` and `RepairPlan`, the dry run. It reports the
  verification, the input blocks that would have to be rebuilt, the recovery
  blocks that would be spent, how many the set has, and which files would be
  written — and a set with more losses than recovery blocks is a plan, not an
  error, so a caller can say how many more blocks would be needed
  (`missing_recovery_blocks`).
- `repair`: `RepairOptions`, for whether the damaged file is kept. With `backup`
  on, the default, it is renamed to `<name>.1`, or `.2`, and so on up to the
  first free number, the way the reference implementation does it; with it off
  nothing is deleted either — the rebuilt file is renamed over the damaged one,
  which replaces it in one step. Each rebuild is written under a temporary name,
  checked against its File packet there, and only then moved into place, so a
  rebuild that does not check out costs nothing that was still there. The
  temporary is created exclusively — a link planted under its name is refused,
  never followed — and a set directory replaced by a link is refused before its
  file is rebuilt.
- `repair`: `RepairReport` and `RepairedFile`, saying what was written, where the
  damaged file was kept, whether each rebuild checked out, and how the whole set
  verified afterwards.
- `repair`: `RepairLimits`, in the same style, bounding the input blocks a set
  may have, the bytes held for blocks of packed chunk tails that are still
  filling, and the decoder.
- `error`: `Par3Error::UnrepairableSet` and `RepairLimitExceeded`, for a set
  whose own packets do not describe a layout to repair from — two chunks
  claiming the same bytes of one input block, a tail that does not fit, a block
  no file writes, a file that cannot be checked at all, or recovery data
  computed with a matrix this crate does not implement — and for a repair that
  would exceed `RepairLimits`.

- `verify`: `FileVerdict::Damaged::damaged_tail_blocks` and
  `FileVerdict::damaged_tail_blocks`, the input blocks holding a chunk tail that
  did not match. This is the damage `damaged_chunks` names, expressed in the
  blocks a codec works in: a tail block may hold several tails from several
  files, and one wrong tail spoils all of it. An inline tail lives in the File
  packet and occupies no block, so it never appears here.

- `examples/par3rs.rs`: a std-only example front-end with `create`, `verify`,
  `repair` and `list` subcommands, so the API can be tried from a shell without
  writing a program first. It is a demonstration, not a tool, and not official
  PAR3 tooling.

### Changed

- **Breaking:** `Par3Set::recovery_packets` is gone, replaced by
  `Par3Set::recovery_blocks` for the set's own recovery data and
  `Par3Set::foreign_recovery_packets` for packets written against another Root.
  Between them they hold every Recovery Data packet the set kept, each exactly
  once — only packets excluded as contradictory are dropped, and those are
  counted. Keeping the flat list as well would have meant retaining every
  recovery block twice, and a recovery block is as large as an input block.
- **Breaking:** `FileVerdict::Damaged` is now `#[non_exhaustive]` as well as the
  enum, because it gained a field. Match it with a trailing `..`.
- `verify_file_at_path` no longer reads the file into memory. It hashes the file
  in fixed-size pieces, and narrows a mismatch down by reading one region at a
  time, so its working set is `min(block_size, file_size)` plus a fixed 64 KiB
  whatever the file's length. The verdicts are unchanged, and
  `tests/repair.rs` requires them to equal `verify_file`'s on the same bytes for
  every damage case.
- The `CauchyMatrixPacket` documentation now states the reference
  implementation's construction exactly — `inv(I ^ (MAX - R))`, applied to
  little-endian field symbols over zero-padded input blocks — instead of
  describing it loosely.
- The README, the crate documentation and the Matrix and Recovery Data packet
  documentation no longer say that the Galois-field arithmetic is unimplemented
  and that recovery is out of scope. They now draw the line where it actually
  falls: reading, verifying, creating and repairing a set built with the
  reference implementation's default settings are all here, and what is not is
  listed one item at a time.

### Tests

- The oracle suite now covers the recovery volumes as well as the index files:
  their packet layout, their round-trip, assembling a set from the volumes alone
  or from a volume truncated mid-packet, and the recovery inventory.
- `tests/oracle_recovery.rs` recomputes every recovery block in both the GF(2^8)
  and the GF(2^16) oracle archive from the regenerated input blocks, using
  scalar Galois-field arithmetic that lives in the test alone, and asserts the
  result byte for byte against what the reference wrote. It also asserts that
  the published specification's `x_I = I + 1` column numbering does *not*
  reproduce those bytes, so the deviation is pinned rather than incidental.
- `tests/oracle_codec.rs` requires the library's own encoder to reproduce those
  same five recovery blocks byte for byte, and its decoder to rebuild every
  input block that can be lost and still recovered: all fifteen loss patterns of
  the GF(2^8) archive, and every single loss plus two hundred sampled larger
  ones of the GF(2^16) archive. The longhand arithmetic in
  `tests/oracle_recovery.rs` stays where it is, as the independent standard.
- `tests/codec.rs` round-trips random data through geometries the two oracle
  archives do not cover — odd block sizes, blocks of one field symbol, non-zero
  first recovery indices, and input counts at the edge of what each field can
  address — and checks that the order input blocks arrive in does not change the
  result.
- `tests/corpus_sets.rs` holds the library to the eight PAR3 sets in the
  repository's test corpus — `gf8_packed`, `gf16_blocks`, `gf16_by_recovery`,
  `index_only`, `tree`, `tiny_inline`, `auto_block` and `large_stream` — every
  one of them written by the reference implementation, and hydrated from the
  published, signed corpus rather than committed. Each set is read and compared
  with the shape the reference recorded, its inputs are verified whole, it is
  created again from those inputs and matched byte for byte across every index
  and volume file, and damage made in memory on copies of the inputs is
  repaired back to them from the reference's own volumes. `tiny_inline` and
  `auto_block` were written without `-s`, so re-creating them holds
  `suggest_block_size` to the block size the reference chose; `index_only` pins
  the refusal to repair a set that carries no recovery data, and that the
  refusal writes nothing. The tests skip where the corpus has not been
  hydrated.

## 0.1.0

First release. A reading foundation for PAR3: it parses packets, assembles input
sets, and verifies the files a set protects. It does not create PAR3 files and
does not repair anything — see the README for the full scope.

### Added

- `hash`: CRC-64/GO-ISO (`rolling_hash`, `RollingHasher`, `quick_rolling_hash`)
  and 16-byte BLAKE3 (`fingerprint`, `FingerprintHasher`).
- `packet`: the 48-byte header, `PacketType` for all seventeen reserved
  signatures, and typed parse plus re-serialisation for Creator, Comment, Start,
  Data, External Data, Cauchy / Sparse Random / Explicit / FFT Matrix, Recovery
  Data, Recovery External Data, File, Directory and Root. Unrecognised and
  uninterpreted types are retained as `PacketBody::Opaque`, so every packet
  written back is byte-identical to the packet read.
- `scan`: `scan_packets` and friends, which find packets in any byte range,
  verify each header hash, skip damaged packets by resynchronising on the next
  magic sequence, and bound their work with `ScanLimits` — including
  `ScanLimits::max_failed_hash_passes`, which caps the hashing a hostile input
  can provoke by packing overlapping candidate headers that never check out.
- `set`: `Par3Set`, which groups packets by InputSetID, deduplicates them, and
  resolves the Root packet's tree into `Par3File` and `Par3Directory` entries
  with `/`-joined paths, under `SetLimits` — including
  `SetLimits::max_path_bytes`, which meters the path text a directory graph
  expands into rather than only counting entries. Every chunk's whole block
  range — not only its first index — is validated against the Root packet's
  block count, so verification can walk a range without re-checking it.
- `verify`: `verify_file`, `verify_file_at_path` and `verify_set`, which check
  files against their File packet's fingerprint and narrow a mismatch down to
  input blocks using the set's External Data checksums. Localisation stops at
  the end of the file being checked: blocks that begin past it are absent rather
  than wrong, and are left to be read off the reported sizes.
