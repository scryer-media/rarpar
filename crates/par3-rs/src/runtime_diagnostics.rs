//! Allocation-free cumulative measurements and synchronous bounded-work events.
use super::{EngineError, EngineResult, ExecutionOptions, LimitCause, MemoryBudget, MemoryLedger};
use crate::source::{SourceAccess, SourceId};
use std::io::{self, Read};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

/// Independently measured engine stages. Nested durations overlap deliberately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Stage {
    /// One incremental scanner poll.
    Scan,
    /// Authenticated metadata and layout construction.
    Metadata,
    /// Source or staged-output fingerprint verification.
    Verify,
    /// Retained availability and recovery requirements.
    Assess,
    /// Content-based candidate placement.
    Placement,
    /// Creation planning and encoding.
    Create,
    /// Protected-data reconstruction and installation.
    Repair,
    /// Recovery-carrier regeneration.
    Carrier,
    /// Container inspection, insertion, or self-repair.
    Container,
    /// Evidence checkpoint export or replay.
    Checkpoint,
    /// Recovery equation encoding, including callback I/O.
    Encode,
    /// Lost-block decoding, including callback I/O.
    Decode,
}
const STAGES: usize = 12;

/// An operation scope beginning, advancing, or ending (including error exits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressPhase {
    /// Scope has started.
    Begin,
    /// Another bounded work unit completed.
    Advance,
    /// Scope ended; the API result, not this event, determines success.
    End,
}

/// Callback event; operation IDs are unique within a shared diagnostics object.
#[derive(Clone, Copy, Debug)]
pub struct ProgressEvent {
    /// Scope correlation ID, including nested or concurrent work.
    pub operation: u64,
    /// Stage being measured.
    pub stage: Stage,
    /// Scope transition.
    pub phase: ProgressPhase,
    /// Completed work units in this scope; bytes where the stage streams bytes.
    pub completed: u64,
    /// Wall time since the scope began.
    pub elapsed: Duration,
}

/// Synchronous callback; it may request cancellation using the shared token.
#[derive(Clone)]
pub struct ProgressCallback(Arc<dyn Fn(ProgressEvent) + Send + Sync>);
impl ProgressCallback {
    /// The host owns callback storage and any events it chooses to retain.
    pub fn new(callback: impl Fn(ProgressEvent) + Send + Sync + 'static) -> Self {
        Self(Arc::new(callback))
    }
}
impl std::fmt::Debug for ProgressCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProgressCallback(..)")
    }
}

/// Counters at one sampling instant; concurrent updates need not be atomic as a group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoSnapshot {
    /// Attempted reads, including short reads and failures.
    pub read_calls: u64,
    /// Bytes requested from reads.
    pub read_requested: u64,
    /// Bytes actually returned by successful reads.
    pub read_bytes: u64,
    /// Attempted writes, including failures.
    pub write_calls: u64,
    /// Bytes actually accepted by successful writes.
    pub write_bytes: u64,
    /// Failed read or write calls.
    pub errors: u64,
}
#[derive(Debug, Default)]
pub(crate) struct IoCounters {
    reads: AtomicU64,
    requested: AtomicU64,
    read_bytes: AtomicU64,
    writes: AtomicU64,
    write_bytes: AtomicU64,
    errors: AtomicU64,
}
/// Move a counter by a signed delta, clamped at zero. A subtraction larger than
/// the counter holds means a holder has already been accounted for; the floor
/// keeps that from wrapping into an absurd total.
fn adjust(counter: &AtomicU64, delta: i64) {
    if delta == 0 {
        return;
    }
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(if delta >= 0 {
            current.saturating_add(delta as u64)
        } else {
            current.saturating_sub(delta.unsigned_abs())
        })
    });
}

fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(value))
    });
}
impl IoCounters {
    pub(crate) fn read(
        &self,
        requested: usize,
        read: impl FnOnce() -> io::Result<usize>,
    ) -> io::Result<usize> {
        add(&self.reads, 1);
        add(&self.requested, requested as u64);
        match read() {
            Ok(n) if n <= requested => {
                add(&self.read_bytes, n as u64);
                Ok(n)
            }
            Ok(_) => {
                add(&self.errors, 1);
                Err(EngineError::InvalidState("source returned an invalid read length").into_io())
            }
            Err(error) => {
                add(&self.errors, 1);
                Err(error)
            }
        }
    }
    pub(crate) fn write(&self, write: impl FnOnce() -> io::Result<usize>) -> io::Result<usize> {
        add(&self.writes, 1);
        match write() {
            Ok(n) => {
                add(&self.write_bytes, n as u64);
                Ok(n)
            }
            Err(error) => {
                add(&self.errors, 1);
                Err(error)
            }
        }
    }
    fn snapshot(&self) -> IoSnapshot {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        IoSnapshot {
            read_calls: get(&self.reads),
            read_requested: get(&self.requested),
            read_bytes: get(&self.read_bytes),
            write_calls: get(&self.writes),
            write_bytes: get(&self.write_bytes),
            errors: get(&self.errors),
        }
    }
}

/// The working-set sizes the engine actually admitted, as opposed to the ones
/// it was configured to want. Each field holds the most recent admission, so a
/// host reading at work-unit handback sees what the unit just ran at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdmissionSnapshot {
    /// Bytes in the most recently admitted codec stripe.
    pub stripe_bytes: u64,
    /// Stripe-sized buffers that admission covered.
    pub stripe_buffers: u64,
    /// Lost rows solved and scattered per tile in the most recent Cauchy pass.
    pub output_tile: u64,
    /// Files in the most recently admitted verification batch.
    pub verify_batch: u64,
    /// Worker threads the most recently admitted pool holds. One means the
    /// stage is running on the calling thread.
    pub workers: u64,
    /// Bytes in the most recently admitted sequential read window.
    pub window_bytes: u64,
}

/// Refused admissions, counted by what [`LimitCause`] said about them. A host
/// requeues on `peer_contention` and fails on the other two.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefusalSnapshot {
    /// Requests that would have been refused with this session alone.
    pub exceeds_limit: u64,
    /// Requests the same options admit once other reservations release.
    pub peer_contention: u64,
    /// Refusals that were never expressed in bytes.
    pub unmeasured: u64,
}

/// Why a stage ran narrower than it was configured to. These are not stalls:
/// the engine never blocks waiting for memory, it proceeds at the width it
/// could admit, and each counter says which width had to give.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitSnapshot {
    /// Stripe admissions that had to shrink below the configured stripe.
    pub stripe_narrowed: u64,
    /// Worker pools that could not be admitted, so the stage ran serially.
    pub workers_refused: u64,
    /// Verification batches cut short because the next file was not admitted.
    pub batch_narrowed: u64,
}

/// Work a bounded working set moved onto the I/O layer. A memory reduction that
/// only pushed cost here is not a reduction, so these are reported beside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AmplificationSnapshot {
    /// Source bytes read again: bytes fetched from a source that had already
    /// been fetched during this run. A block named by several aliased extents
    /// is the case that produces them, because each extent's copy is fetched
    /// and compared against the bytes already assembled.
    ///
    /// Reading a block in successive stripe passes does not appear here: each
    /// pass fetches a different part of the block, so no byte is fetched twice.
    /// The cost of running in passes at all is [`Self::stripe_passes`].
    pub reread_bytes: u64,
    /// Bytes the codec reconstructed and scattered into staged output.
    pub reconstructed_bytes: u64,
    /// Stripe passes a bounded working set forced over the source beyond the
    /// first. Zero means every block was covered in one pass; `n` means the
    /// source was walked `n` extra times, each time for a different slice of
    /// every block.
    pub stripe_passes: u64,
}

/// Transform and coefficient work the codecs actually performed.
///
/// These are counted once per call with the call's own totals, never once per
/// symbol: a butterfly touches a whole row, and a counter on that inner loop
/// would cost more than the arithmetic it measures. `skipped` is what a
/// pruning plan decided not to compute, so `butterflies + skipped` is what the
/// same decode would have cost without the plan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodecSnapshot {
    /// Additive-transform invocations, including the ones a plan split.
    pub transform_calls: u64,
    /// Butterflies executed across those calls.
    pub butterflies: u64,
    /// Butterflies a transform plan established were not needed.
    pub butterflies_skipped: u64,
    /// Symbol-wide multiply-accumulates those butterflies performed: one per
    /// butterfly per symbol in the rows it joined.
    pub multiply_accumulates: u64,
    /// Cauchy code-matrix elements computed.
    pub factors_computed: u64,
    /// Code-matrix elements answered from an admitted table instead.
    pub factors_reused: u64,
}

/// What the admission and deduplication caches are holding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheSnapshot {
    /// Entries currently retained.
    pub entries: u64,
    /// Bytes those entries are charged.
    pub bytes: u64,
}

#[derive(Debug, Default)]
struct AdmissionCounters {
    stripe_bytes: AtomicU64,
    stripe_buffers: AtomicU64,
    output_tile: AtomicU64,
    verify_batch: AtomicU64,
    workers: AtomicU64,
    window_bytes: AtomicU64,
    refusals: [AtomicU64; 3],
    stripe_narrowed: AtomicU64,
    workers_refused: AtomicU64,
    batch_narrowed: AtomicU64,
    reread_bytes: AtomicU64,
    reconstructed_bytes: AtomicU64,
    stripe_passes: AtomicU64,
    cache_entries: AtomicU64,
    cache_bytes: AtomicU64,
    transform_calls: AtomicU64,
    butterflies: AtomicU64,
    butterflies_skipped: AtomicU64,
    multiply_accumulates: AtomicU64,
    factors_computed: AtomicU64,
    factors_reused: AtomicU64,
}

/// Cumulative wall-time and work totals for ended stage scopes.
#[derive(Clone, Copy, Debug, Default)]
pub struct StageSnapshot {
    /// Number of scopes ended, including failures and cancellation.
    pub calls: u64,
    /// Sum of elapsed wall times. Concurrent and nested scopes overlap.
    pub elapsed: Duration,
    /// Completed bounded work units.
    pub completed: u64,
}
#[derive(Debug, Default)]
struct StageCounters {
    calls: AtomicU64,
    nanos: AtomicU64,
    completed: AtomicU64,
}
#[derive(Debug, Default)]
struct State {
    source: IoCounters,
    files: IoCounters,
    stages: [StageCounters; STAGES],
    sync: StageCounters,
    next: AtomicU64,
    admission: AdmissionCounters,
    /// The budget these diagnostics report on, learned from the first stage
    /// opened against them. Written at most once and never read on the hot
    /// path; the link runs one way so the two `Arc`s cannot form a cycle.
    budget: OnceLock<MemoryBudget>,
}

/// Shared counters with fixed storage; no unbounded internal event log.
///
/// # One budget per diagnostics
///
/// A diagnostics handle may be shared by any number of operations, and their
/// work counters aggregate. [`Self::memory`], though, is the ledger of one
/// [`MemoryBudget`]: the handle binds to the budget of the first stage opened
/// against it and reports that one for its whole life. Sharing a handle across
/// two different budgets would therefore aggregate the work of both while
/// reporting the ledger of one, so the engine refuses it — the second stage
/// fails with `EngineError::InvalidState("diagnostics already bound to another
/// memory budget")`. Clones of one budget are one budget and are fine; a
/// second `MemoryBudget::new` is not. Give each budget its own diagnostics.
#[derive(Clone, Debug, Default)]
pub struct ExecutionDiagnostics(Arc<State>);
impl ExecutionDiagnostics {
    /// Bind these diagnostics to `budget`, or refuse a second, different one.
    ///
    /// Binds on the first call; afterwards it only checks. `get_or_init` makes
    /// the decision once even if two threads open their first stage at the
    /// same moment, so the loser of that race is checked against the winner
    /// rather than silently ignored.
    pub(crate) fn bind_budget(&self, budget: &MemoryBudget) -> EngineResult<()> {
        if self.0.budget.get_or_init(|| budget.clone()).is_same(budget) {
            Ok(())
        } else {
            Err(EngineError::InvalidState(
                "diagnostics already bound to another memory budget",
            ))
        }
    }
    /// Reads requested through SourceAccess, including virtual and disk sources.
    pub fn source_io(&self) -> IoSnapshot {
        self.0.source.snapshot()
    }
    /// Engine file I/O (scratch, output, and cooperating disk providers).
    /// Disk provider bytes also appear in source_io; do not sum the two layers.
    pub fn file_io(&self) -> IoSnapshot {
        self.0.files.snapshot()
    }
    /// File synchronization barriers, including time waiting for storage.
    /// `calls` counts attempts and `completed` counts successes. Durations are
    /// already included in enclosing operation stages; do not add them again.
    pub fn file_sync(&self) -> StageSnapshot {
        StageSnapshot {
            calls: self.0.sync.calls.load(Ordering::Relaxed),
            elapsed: Duration::from_nanos(self.0.sync.nanos.load(Ordering::Relaxed)),
            completed: self.0.sync.completed.load(Ordering::Relaxed),
        }
    }
    pub(crate) fn sync(&self, sync: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let started = Instant::now();
        let result = sync();
        add(&self.0.sync.calls, 1);
        add(
            &self.0.sync.nanos,
            started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        );
        if result.is_ok() {
            add(&self.0.sync.completed, 1);
        }
        result
    }
    /// Cumulative measurements for one stage.
    pub fn stage(&self, stage: Stage) -> StageSnapshot {
        let c = &self.0.stages[stage as usize];
        StageSnapshot {
            calls: c.calls.load(Ordering::Relaxed),
            elapsed: Duration::from_nanos(c.nanos.load(Ordering::Relaxed)),
            completed: c.completed.load(Ordering::Relaxed),
        }
    }
    /// Reserved bytes by category, from the budget these diagnostics were first
    /// used with. `None` before any stage has run against a budget.
    ///
    /// One handle reports one budget for its whole life; opening a stage
    /// against a second, different budget is refused. See the type's own
    /// documentation.
    ///
    /// This is the ledger itself, not a copy kept in step with it: retained and
    /// scratch are told apart by category and by `current` against `peak`.
    /// Reading allocates nothing and takes no lock.
    #[must_use]
    pub fn memory(&self) -> Option<MemoryLedger> {
        self.0.budget.get().map(MemoryBudget::ledger)
    }

    /// The widths the engine last admitted.
    #[must_use]
    pub fn admission(&self) -> AdmissionSnapshot {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let counters = &self.0.admission;
        AdmissionSnapshot {
            stripe_bytes: get(&counters.stripe_bytes),
            stripe_buffers: get(&counters.stripe_buffers),
            output_tile: get(&counters.output_tile),
            verify_batch: get(&counters.verify_batch),
            workers: get(&counters.workers),
            window_bytes: get(&counters.window_bytes),
        }
    }

    /// Refused admissions by cause.
    #[must_use]
    pub fn refusals(&self) -> RefusalSnapshot {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let counters = &self.0.admission.refusals;
        RefusalSnapshot {
            exceeds_limit: get(&counters[0]),
            peer_contention: get(&counters[1]),
            unmeasured: get(&counters[2]),
        }
    }

    /// Why stages ran narrower than they were configured to.
    #[must_use]
    pub fn waits(&self) -> WaitSnapshot {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let counters = &self.0.admission;
        WaitSnapshot {
            stripe_narrowed: get(&counters.stripe_narrowed),
            workers_refused: get(&counters.workers_refused),
            batch_narrowed: get(&counters.batch_narrowed),
        }
    }

    /// Bytes bounded working sets moved onto the I/O layer.
    #[must_use]
    pub fn amplification(&self) -> AmplificationSnapshot {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let counters = &self.0.admission;
        AmplificationSnapshot {
            reread_bytes: get(&counters.reread_bytes),
            reconstructed_bytes: get(&counters.reconstructed_bytes),
            stripe_passes: get(&counters.stripe_passes),
        }
    }

    /// Transform and coefficient work the codecs performed.
    #[must_use]
    pub fn codec(&self) -> CodecSnapshot {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let counters = &self.0.admission;
        CodecSnapshot {
            transform_calls: get(&counters.transform_calls),
            butterflies: get(&counters.butterflies),
            butterflies_skipped: get(&counters.butterflies_skipped),
            multiply_accumulates: get(&counters.multiply_accumulates),
            factors_computed: get(&counters.factors_computed),
            factors_reused: get(&counters.factors_reused),
        }
    }

    /// Record additive-transform work: `calls` invocations performing
    /// `butterflies` butterflies over rows of `symbols` symbols, with
    /// `skipped` butterflies a plan established were not needed.
    pub(crate) fn note_transform(
        &self,
        calls: u64,
        butterflies: u64,
        symbols: usize,
        skipped: u64,
    ) {
        let counters = &self.0.admission;
        add(&counters.transform_calls, calls);
        add(&counters.butterflies, butterflies);
        add(&counters.butterflies_skipped, skipped);
        add(
            &counters.multiply_accumulates,
            butterflies.saturating_mul(symbols as u64),
        );
    }

    /// Record Cauchy code-matrix elements: those computed, and those an
    /// admitted table answered without recomputing.
    pub(crate) fn note_factors(&self, computed: u64, reused: u64) {
        let counters = &self.0.admission;
        add(&counters.factors_computed, computed);
        add(&counters.factors_reused, reused);
    }

    /// What the admission caches are currently holding.
    #[must_use]
    pub fn caches(&self) -> CacheSnapshot {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let counters = &self.0.admission;
        CacheSnapshot {
            entries: get(&counters.cache_entries),
            bytes: get(&counters.cache_bytes),
        }
    }

    /// Record an admitted stripe. `target` is what was asked for, so a smaller
    /// admission is also recorded as a narrowing.
    pub(crate) fn note_stripe(&self, stripe: usize, buffers: usize, target: usize) {
        let counters = &self.0.admission;
        counters
            .stripe_bytes
            .store(stripe as u64, Ordering::Relaxed);
        counters
            .stripe_buffers
            .store(buffers as u64, Ordering::Relaxed);
        if stripe < target {
            add(&counters.stripe_narrowed, 1);
        }
    }

    /// Record the output tile width a Cauchy pass admitted, with the stripe it
    /// runs at.
    pub(crate) fn note_tiling(&self, stripe: usize, buffers: usize, tile: usize) {
        let counters = &self.0.admission;
        counters
            .stripe_bytes
            .store(stripe as u64, Ordering::Relaxed);
        counters
            .stripe_buffers
            .store(buffers as u64, Ordering::Relaxed);
        counters.output_tile.store(tile as u64, Ordering::Relaxed);
    }

    /// Record the width a worker pool admitted. One means serial execution, and
    /// is recorded as a refusal to widen when more was configured.
    pub(crate) fn note_workers(&self, admitted: usize, configured: usize) {
        let counters = &self.0.admission;
        counters.workers.store(admitted as u64, Ordering::Relaxed);
        if admitted < configured.max(1) {
            add(&counters.workers_refused, 1);
        }
    }

    /// Record a verification batch and whether admission cut it short.
    pub(crate) fn note_batch(&self, admitted: usize, wanted: usize) {
        let counters = &self.0.admission;
        counters
            .verify_batch
            .store(admitted as u64, Ordering::Relaxed);
        if admitted < wanted {
            add(&counters.batch_narrowed, 1);
        }
    }

    /// Record the sequential read window in force.
    pub(crate) fn note_window(&self, bytes: usize) {
        self.0
            .admission
            .window_bytes
            .store(bytes as u64, Ordering::Relaxed);
    }

    /// Classify one refused admission. Errors that are not resource limits are
    /// not admission decisions and are not counted.
    pub(crate) fn note_refusal(&self, error: &EngineError) {
        let EngineError::ResourceLimit(limit) = error else {
            return;
        };
        let slot = match limit.cause() {
            LimitCause::ExceedsLimit => 0,
            LimitCause::PeerContention => 1,
            LimitCause::Unmeasured => 2,
        };
        add(&self.0.admission.refusals[slot], 1);
    }

    /// Source bytes fetched that had already been fetched in this run. Only a
    /// second fetch of the same bytes belongs here; walking disjoint slices of
    /// a block in successive passes reads each byte once and is counted by
    /// [`Self::note_stripe_pass`].
    pub(crate) fn note_reread(&self, bytes: usize) {
        add(&self.0.admission.reread_bytes, bytes as u64);
    }

    /// One stripe pass over the source beyond the first.
    pub(crate) fn note_stripe_pass(&self) {
        add(&self.0.admission.stripe_passes, 1);
    }

    /// Bytes reconstructed by the codec and scattered into staged output.
    pub(crate) fn note_reconstructed(&self, bytes: usize) {
        add(&self.0.admission.reconstructed_bytes, bytes as u64);
    }

    /// Change cache occupancy by one holder's own delta.
    ///
    /// Deltas, not absolutes. Several sessions may share one
    /// [`ExecutionDiagnostics`], and a holder that stored its own total would
    /// erase what its peers hold and leave its own behind when it went away.
    /// Every holder pairs its additions with subtractions when it clears and
    /// when it is dropped, so the counters return to zero on their own.
    pub(crate) fn note_cache_delta(&self, entries: i64, bytes: i64) {
        let counters = &self.0.admission;
        adjust(&counters.cache_entries, entries);
        adjust(&counters.cache_bytes, bytes);
    }

    pub(crate) fn files(&self) -> &IoCounters {
        &self.0.files
    }
    pub(crate) fn read_at(
        &self,
        access: &dyn SourceAccess,
        source: SourceId,
        offset: u64,
        out: &mut [u8],
    ) -> io::Result<usize> {
        self.0
            .source
            .read(out.len(), || access.read_at(source, offset, out))
    }
    pub(crate) fn read(&self, reader: &mut dyn Read, out: &mut [u8]) -> io::Result<usize> {
        self.0.source.read(out.len(), || reader.read(out))
    }
}

pub(crate) struct StageGuard {
    stats: ExecutionDiagnostics,
    callback: Option<ProgressCallback>,
    stage: Stage,
    operation: u64,
    started: Instant,
    completed: u64,
}
impl StageGuard {
    pub(crate) fn advance(&mut self, units: u64) {
        self.completed = self.completed.saturating_add(units);
        self.emit(ProgressPhase::Advance);
    }
    fn emit(&self, phase: ProgressPhase) {
        if let Some(callback) = &self.callback {
            (callback.0)(ProgressEvent {
                operation: self.operation,
                stage: self.stage,
                phase,
                completed: self.completed,
                elapsed: self.started.elapsed(),
            });
        }
    }
}
impl Drop for StageGuard {
    fn drop(&mut self) {
        let counts = &self.stats.0.stages[self.stage as usize];
        add(&counts.calls, 1);
        add(
            &counts.nanos,
            self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        );
        add(&counts.completed, self.completed);
        if !std::thread::panicking() {
            self.emit(ProgressPhase::End);
        }
    }
}
impl ExecutionOptions {
    pub(crate) fn stage(&self, stage: Stage) -> EngineResult<StageGuard> {
        self.validate()?;
        // Learn the budget once, so `ExecutionDiagnostics::memory` can report
        // the ledger without the host having to carry the budget separately.
        // A second, different budget is refused rather than ignored: the work
        // counters would aggregate both while the ledger named only the first.
        self.diagnostics.bind_budget(&self.memory)?;
        let guard = StageGuard {
            stats: self.diagnostics.clone(),
            callback: self.progress.clone(),
            stage,
            operation: self.diagnostics.0.next.fetch_add(1, Ordering::Relaxed),
            started: Instant::now(),
            completed: 0,
        };
        guard.emit(ProgressPhase::Begin);
        self.cancel.check()?;
        Ok(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::ExecutionOptions;

    fn options(diagnostics: &ExecutionDiagnostics, memory: MemoryBudget) -> ExecutionOptions {
        ExecutionOptions {
            workers: 1,
            diagnostics: diagnostics.clone(),
            memory,
            ..ExecutionOptions::default()
        }
    }

    /// PR #73 round 2, finding 4. The budget was learned with a `OnceLock` set
    /// that discarded a later, different budget without a word, so diagnostics
    /// shared across two budgets aggregated the work of both and reported the
    /// ledger of one. The second binding is now refused.
    #[test]
    fn diagnostics_shared_across_two_budgets_are_refused_not_silently_merged() {
        let diagnostics = ExecutionDiagnostics::default();
        let first = MemoryBudget::new(1 << 20);
        let second = MemoryBudget::new(1 << 20);

        let one = options(&diagnostics, first.clone());
        one.stage(Stage::Verify).expect("binds the first budget");

        // The same budget, cloned into another options value, is the same
        // ledger and is fine.
        let same = options(&diagnostics, first.clone());
        same.stage(Stage::Assess)
            .expect("a clone of the bound budget is the bound budget");

        // A second budget with an identical ceiling is a different ledger.
        let other = options(&diagnostics, second);
        match other.stage(Stage::Verify) {
            Err(EngineError::InvalidState(message)) => assert_eq!(
                message, "diagnostics already bound to another memory budget",
                "refused for the wrong reason"
            ),
            Err(error) => panic!("refused with the wrong error: {error}"),
            Ok(_) => panic!("a second, different budget was accepted"),
        }

        // And the ledger it reports is still the one it bound.
        assert!(
            diagnostics.memory().is_some(),
            "the first budget was never bound"
        );
        assert_eq!(first.limit(), 1 << 20);
    }
}
