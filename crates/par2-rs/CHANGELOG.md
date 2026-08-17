# Changelog


## 0.4.2

This is a patch release from 0.4.1: a rebuilt creation encode pipeline and one
additive plan field. No existing public item changed shape or meaning, so it
stays inside the 0.4.x compatibility range.

### Public API

- `Par2CreatePlan::skipped_empty`: the inputs a plan excluded because they are
  zero-length, in input order, as the caller spelled them. A PAR2 set cannot
  describe an empty file — the format protects slices and an empty file has
  none — so such inputs get no packets and are invisible to verify and repair.
  The exclusion itself is long-standing and matches the reference tool
  ("Skipping 0 byte file"); what is new is that the plan now names the excluded
  files instead of dropping them silently, so a caller can no longer read the
  set as protection it does not provide. Produced sets are byte-identical to
  before.

### Runtime Behavior

- Packet-inventory loading is bounded: [`PacketScanBudget`]/`PacketScanLimits`
  meter packets examined, packets retained, and retained metadata bytes across
  every input file of one load, with checked arithmetic and cancellation polled
  on every charge. Nothing in the container format bounds the physical packet
  stream, so a small input could previously inflate into tens of megabytes of
  retained parse metadata. Exceeding a limit is `ResourceLimitExceeded`, never
  a truncated set. Bounded entry points (`scan_packets_bounded` and friends)
  are additive; the existing entry points keep their signatures on default
  limits.
- The ordered canonical repair scanner admits its working set against the
  configured memory limit before allocating: worker count, Phase-A staging
  windows, and per-worker match scratch are derived from the remaining budget,
  and slice sizes whose ordered working set cannot fit route to the generic
  mmap scanner instead of allocating past the limit.

- Creation now encodes stripe-major behind a producer-fed ring: bands of
  recovery rows run as scoped OS threads dispatched once per stripe, and every
  input batch is staged once and streamed to all bands, instead of a fresh
  dispatch per batch. Whole-file source hashing is fused into the same feed —
  the raw batch rides the ring beside its staged form, and the band that owns
  a batch hashes it under an ordered turn before releasing the slot — so the
  pass never runs more busy threads than the host admits. The serial MD5 head
  this folds away was 9–14% of create CPU on 4-vCPU x86 hosts, and the
  dedicated-hasher shape it replaces gave 9% of create wall back to the
  scheduler on those same hosts. `WEAVER_PAR2_CREATE_AREAS` pins the ring
  depth for A/B.

- Creation's staging areas de-alias the L1D: kernel-family lanes and output
  rows sit 1 KiB off a 4 KiB period instead of at power-of-two strides, so one
  pass's streams stop competing for a single cache set. Neoverse N1 went from
  35 L1D refills per thousand instructions to 3 on the eight-volume create
  corpus case. The aarch64 CLMUL create family also grew its input batch from
  twelve sources to sixteen — a whole number of kernel passes per batch;
  `WEAVER_PAR2_CREATE_GROUPING` pins the batch width.

- Creation's staging area is now **block-interleaved** for the aarch64 CLMUL
  family: the sixteen sources the wide kernel pass folds into a destination
  share one contiguous stream, thirty-two bytes each in turn, instead of
  sitting in separate slices the pass reads at a common offset. Lane-major, a
  pass puts every source line plus a destination line into one L1D set per
  block, which no stride residue can make fit a 2-way set — the lane/row skew
  above moved Cortex-A72's 2-way L1D only from 29 refills per thousand
  instructions to 26. Interleaved, the pass is one sequential stream plus its
  destination: two streams, which any associativity holds. The x86 folded
  family has always laid its staging out this way and never had the problem;
  the x86 kernels, the packed XOR-JIT family and the word-wise reference path
  keep lane-major, which is the right shape for each of their kernels. On the
  bench fleet this pipeline takes create from 0.54× the reference tool to
  1.22× on Cortex-A72 and from 0.77× to 1.10× on Neoverse V2, byte-identical
  sets throughout. `WEAVER_PAR2_CREATE_INTERLEAVE=N` pins the interleave
  width (`1` = the lane-major layout) so layouts can be compared without a
  rebuild.

- Create's automatic kernel ladder now prefers the folded shuffle family over
  the packed XOR-JIT tier when both are available: on create's access shape
  the JIT tier measured 1.3–4.4× slower than shuffle2x-256 at 64/16/8 KiB
  slices on Zen 2. Repair's XOR-JIT codebook and selection are untouched.

## 0.4.1

This is a patch release from 0.4.0. Additive only: no existing item changed
shape or meaning, so it stays inside the 0.4.x compatibility range.

### Public API

- `SliceEvidence::from_in_stream_crc32`: mint a slice verdict a caller derived
  itself, in stream, from the slice's PAR2 CRC32. This is for a caller that
  already hashes every payload byte for its own reasons and can cut that hash
  on the recovery set's block grid — it hands over the conclusion rather than
  the bytes, so nothing is read, buffered or hashed twice.
- `InStreamCrc32Proof` / `InStreamCrc32ProofError`: the attestation such a
  verdict carries. Like `ContiguousAssemblyProof`, it verifies nothing itself;
  it records that the caller asserted the slice's full extent was covered, over
  bytes the repair source will serve, with an independent second-grid CRC32 over
  the same span — and refuses to exist otherwise.
- `SliceEvidence::in_stream_proof` and `SliceEvidence::may_seed_repair_input`:
  read the attestation, and ask whether a repair session may act on a verdict.
- `ProgressPhase` and `ProgressUpdate::phase`: which pass within a stage an
  update came from. `ProgressStage::Creating` covers two passes that count
  different things — the source scan counts files, the recovery encode counts
  stripes — and their totals coincide whenever a set has as many files as the
  encoder has stripes, which left consumers unable to tell the passes apart.
  Every existing field keeps its meaning and every existing emitter keeps its
  stage; consumers that reset per-pass state should key on `phase` rather than
  on a change in `total`. (A consumer that constructs `ProgressUpdate` by
  literal — a test double, say — must add the field; the default is
  `ProgressPhase::Whole`.)
- `md5_simd::max_lanes`: how many independent messages the active multi-buffer
  MD5 kernel hashes per pass on this host. Callers sizing their own batches
  should use it rather than assuming a width.
- `md5_simd::md5_multi_into`: `md5_multi` writing into a caller-owned slice,
  for loops that would otherwise allocate a `Vec` per batch. `md5_multi` itself
  is unchanged in signature and meaning, but no longer caps its input at four
  messages — it now accepts any number and chunks internally.

### Runtime Behavior

- A repair session now admits an attested in-stream CRC32 verdict where it
  previously admitted only `Crc32AndMd5`. A **bare** CRC32 comparison with no
  attestation — what `VerificationSession::verify_from_slice_crcs` produces — is
  refused exactly as before; the refusal reason now says "unattested".
- Repair and settle-time behaviour are unchanged. Repair still re-derives both
  the IFSC CRC32 and MD5 over every byte it consumes, so a mistaken attestation
  fails the repair loudly rather than installing wrong bytes, and an attested
  verdict never promotes a file to a whole-file match.
- Transaction-owned files are identified by a retained open handle on every
  platform that has one, rather than by a set of numbers read back off the path.
  On Unix that replaces `(device, inode, birth)`, a triple forgeable on
  inode-recycling filesystems: overlayfs hands a freed inode straight back
  (measured 9/9 deterministic), and file times come off a coarse clock, so a
  delete+recreate inside one tick could make a foreign file read as ours. On
  Windows it replaces nothing — the non-Unix arm held no handle, dropped the one
  it was handed, and answered "yes, still ours" unconditionally, so *any* foreign
  file at an owned path satisfied the pin. Either way the transaction could
  quarantine or overwrite someone else's data. While the pin lives the record
  cannot be recycled, so no other file can carry our identity, and the handle
  follows the file through the quarantine rename.
- `FileIdentity::Windows` carries the file's creation time alongside
  `(volume, index)`, the counterpart of `birth` on the Unix and wasi arms, taken
  from the `GetFileInformationByHandle` call that already reports the index. It
  hardens the sites that have no pin to consult; it is not a substitute for one.
  NTFS **file tunneling** replays a removed file's creation time onto a file
  recreated with the same name in the same directory — measured 10/10
  same-directory rounds against 0/10 cross-directory — and every comparison site
  in the creation transaction is same-name and same-directory. The filesystem
  forges this timestamp deliberately and reliably, exactly where the check
  matters, which is the Windows counterpart of the coarse-clock birth-time
  replay that rules out a timestamp-only fix on Linux.
- The forgery NTFS does *not* offer is the Unix one: its 64-bit file index pairs
  the MFT record number with a sequence number the volume bumps on every reuse,
  so a delete-and-recreate produced a different index in 0 of 20 measured rounds
  even unpinned. Windows was never one plausible-looking number away from safety;
  it was missing the comparison. The retained handle is what makes the answer
  authoritative on both platforms.
- No behaviour change on wasi or any other target without a handle to hold. The
  wasi arm still pins nothing and still says so explicitly.

### Performance

- Multi-buffer MD5 now backs slice hashing on **both** the creation and the
  verify/repair sides. One MD5 stream is a serial dependency chain that no SIMD
  can widen, so the kernel instead holds one independent message per 32-bit
  lane and advances all of them with a single vector round. Lane width follows
  the ISA only — 8 on AVX2, 4 on NEON/SSE2/wasm-simd128, 1 scalar — with no
  per-microarchitecture tuning and no `target-cpu` flags.
  - Creation's source scan hashes a batch of consecutive slices per pass
    instead of one slice at a time. The whole-file and first-16 KiB digests
    stay single serial streams over the same bytes: they are different
    messages and cannot be laned within a file, and laning them *across* files
    would have to displace the existing per-file rayon parallelism, so it is
    deliberately not done.
  - The verifier and the repair scanner already batched four slices per pass;
    they now take the kernel's full width, so an AVX2 host hashes eight.
  - The kernel no longer materializes a zero-padded copy of each message. Block
    pointers resolve straight into the caller's buffer, with at most 192 bytes
    of per-lane scratch for the straddling and final blocks, so a long PAR2 tail
    pad costs no allocation and no payload copy.
  - Messages of differing lengths may now share one batch; lanes retire
    independently at their own final block.
- Digests are unchanged. PAR2 output is byte-identical to the previous release
  on every lane width, and the scalar, NEON, SSE2, AVX2 and wasm-simd128 kernels
  are cross-checked against each other and against the `md-5` reference.
- Slice CRC32 gains a 256-bit VPCLMULQDQ folding kernel on the one x86-64 class
  `crc-fast` leaves on a slower tier than its instruction set allows: a CPU with
  VPCLMULQDQ but without AVX-512VL (Intel client parts from Alder Lake through
  Arrow Lake) currently falls all the way to a 128-bit SSE fold. On that class
  the CRC itself runs 1.48x faster and costs 32% less CPU for the same bytes.
  - Everywhere else the dispatch stands aside, by design: with AVX-512VL
    present `crc-fast`'s wider ZMM fold is the faster kernel, and on aarch64
    and wasm it is already on the best kernel it has. The cost when standing
    aside is one predictable branch per update, on a call that processes
    kilobytes; on targets with no tier the branch constant-folds away.
  - Honestly bounded: PAR2 never computes a CRC alone. Every hot CRC is paired
    with MD5 over the same bytes, and MD5 is roughly 25x the cost, so a slice
    pass sees 0.9% less CPU and a full verify or create sees no change that
    rises above run-to-run noise. The win is real but it is a CPU-efficiency
    win at the slice-hash level, not a throughput change to any workflow.
  - `WEAVER_CRC32_VPCLMUL` overrides the tier gate: `0` pins `crc-fast` (so the
    two can be A/B'd on one binary without a rebuild), `1` engages wherever the
    instructions exist. It widens *policy* only — the ISA probe is never
    bypassed, so forcing it on a CPU without VPCLMULQDQ is refused rather than
    executing an undefined opcode.
  - CRC32 values are unchanged. The kernel is pinned against `crc-fast` by an
    exhaustive differential suite (every length 0..=192 at every alignment mod
    64, seven initial values across nineteen length classes, and 64 randomized
    streaming-split trials), and the seam is checked at every prefix of update
    sequences that cross the tier threshold in both directions.
- PAR2 creation got a round of structural work, and the sum crossed a line:
  create now beats `par2cmdline-turbo` outright on Zen 4 (1.13×) and Haswell
  (1.05×) in the current benchmark round (>1 = this crate is faster), while
  still flushing and re-validating every written recovery volume before
  commit, which the reference tool does not do.
  - The source scan no longer hashes every file twice: the plan rebuild
    reuses the scan's digests instead of re-reading the sources.
  - The recovery feed is chunk-tiled with per-kernel tile constants,
    default-on. `WEAVER_PAR2_CREATE_STRIPE_MIB` additionally caps the stripe
    working set; it ships default-off as a documented hatch because its win
    is microarchitecture-dependent.
  - GF(2¹⁶) kernel selection for create follows the reference tool's ladder
    arm for arm (see the `reedsolomon-rs` changelog for the ladder and the
    new 512-bit shuffle kernel). `WEAVER_PAR2_CREATE_KERNEL` overrides the
    arm for single-binary A/Bs; the capability probe is never bypassed.
  - The XOR-JIT arm builds its packed code once per input batch and reuses it
    across every stripe. The per-row rebuild it replaces — codegen, mapping,
    and both W^X transitions per output row per stripe — measured at 60% of
    create wall time on AVX-512-without-GFNI silicon. Admission reserves the
    whole store up front, so a cache miss can never allocate past what the
    plan admitted.

## 0.4.0

This release leaves the 0.3.x compatibility range because `Par2Error` gained
variants; everything else is additive.

### Migration

- `Par2Error` gained creation-related variants (`InvalidCreationOptions`,
  `UnsafeCreationSource`, `CreationSourceChanged`, `CreationOutputExists`,
  `UnsafeCreationOutput`, and related), and existing variant positions moved.
  Exhaustive `match` arms over `Par2Error` need updating; matching with a
  catch-all arm is unaffected.
- `ProgressUpdate` values from phases that hash concurrently (creation's
  source scan) are delivered from multiple threads: individually accurate but
  unordered. Consumers should latch maxima rather than assume each update
  supersedes the previous one; the struct documentation describes this.

### Public API

- PAR2 creation: `Par2Creator`, `Par2CreatorOptions`, `Par2CreatePlan`,
  `Par2CreateOutcome`, `Par2MemoryPlan`, `BlockSizing`, `RecoveryAmount`,
  `RecoveryVolumePlan`, `VolumeScheme`, `CreationBackend`, `CreationSource`,
  and `ForwardKernel`. Creation plans deterministically, validates every
  written volume against expected hashes, and commits atomically.
- `CacheEvictionDeferral`: an RAII scope that defers the crate's page-cache
  eviction (`POSIX_FADV_DONTNEED`) until the outermost scope drops, so
  multi-pass flows (verify, then repair, then re-verify) are served from page
  cache instead of re-reading payloads from physical storage.
  `execute_repair_with_options` holds one for the repair duration; callers
  orchestrating their own multi-pass flows should hold one across the whole
  span.

### Runtime Behavior

- Creation encodes recovery data across all cores (banded accumulation with
  a staging pipeline), hashes source files in parallel, and validates written
  volumes in parallel. Output is byte-identical at every thread count;
  `WEAVER_PAR2_CREATE_THREADS=1` pins the sequential path.
- Repair no longer re-reads verified payloads from disk between its passes
  (the eviction deferral above); on network block storage this removed a
  fixed multi-second cost per repair.
- `Par2MemoryPlan` values now account for concurrent workers, so reported
  peaks are host-parallelism-dependent.

## 0.3.0

This is a minor release from 0.2.4 and contains source-compatible additions as
well as the migration items below.

### Migration

- `BlockLocation::path: PathBuf` is now
  `BlockLocation::source: SourceLocation`. Use `location.path()` when only a
  filesystem path is useful, `location.file_id()` for access-backed sources,
  or match `SourceLocation::{Path, Access}` when both must be handled.
- `Par2RepairSessionOptions` and `Par2RepairSessionDiagnostics` are now
  `#[non_exhaustive]`. Construct options with `new`, `with_source_access`,
  `from_set`, or `Default`, then assign public fields. Do not construct or
  destructure these types exhaustively outside the crate.
- `execute_repair_with_solver` accepts caller-provided solvers only on
  `wasm32`. Native callers must use `execute_repair_with_options` or the
  higher-level repairer/session APIs, which use the streamed CPU controller.

### Public API

- Added access-backed repair sessions for sources that are addressed by
  `FileId` rather than filesystem path. New APIs include
  `with_source_access`, `from_set`, `add_slice_evidence_for_file`,
  `invalidate_file`, `invalidate_access_sources`, `source_generation`, and
  `set_source_access`.
- Added `FileAccess::open_range_reader` with a default implementation returning
  `None`. Existing `FileAccess` implementations continue to compile; they may
  override it to reuse one seekable reader across many repair ranges.
- Added access-source counters to retained-session diagnostics.

### Runtime Behavior

- Native CPU repair now uses the bounded streaming repair controller for all
  repair sizes, with explicit cancellation, backpressure, staging, and memory
  accounting.
- Repair output is staged until compute and content verification succeed.
- The declared minimum supported Rust version is 1.97.1.

