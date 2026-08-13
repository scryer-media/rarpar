# Changelog

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

