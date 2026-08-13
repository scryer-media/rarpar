# Changelog

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

