//! Allocation-free cumulative measurements and synchronous bounded-work events.
use super::{EngineError, EngineResult, ExecutionOptions};
use crate::source::{SourceAccess, SourceId};
use std::io::{self, Read};
use std::sync::{
    Arc,
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
}

/// Shared counters with fixed storage; no unbounded internal event log.
#[derive(Clone, Debug, Default)]
pub struct ExecutionDiagnostics(Arc<State>);
impl ExecutionDiagnostics {
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
