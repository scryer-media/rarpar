//! Shared resource limits, cancellation and typed errors for incremental work.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use thiserror::Error;

/// Failure of an incremental engine operation. Missing bytes are not I/O errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EngineError {
    /// An authenticated packet or set could not be interpreted.
    #[error(transparent)]
    Format(#[from] crate::Par3Error),
    /// A real backing-store error, with its original error chain preserved.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The requested work exceeds a configured resource budget.
    #[error("PAR3 resource limit: {0}")]
    ResourceLimit(&'static str),
    /// Previously published source bytes changed.
    #[error("PAR3 source changed: {0:?}")]
    SourceChanged(crate::source::SourceId),
    /// A required range has not arrived, or contains a hole.
    #[error("PAR3 source {source_id:?} unavailable at {offset}")]
    Unavailable {
        /// Source containing the range.
        source_id: crate::source::SourceId,
        /// First unavailable byte.
        offset: u64,
    },
    /// The caller cancelled the operation.
    #[error("PAR3 operation cancelled")]
    Cancelled,
    /// A supported parser recognized an unsupported execution mode.
    #[error("unsupported PAR3 feature: {0}")]
    Unsupported(&'static str),
    /// A session operation cannot run in its current state.
    #[error("invalid PAR3 engine state: {0}")]
    InvalidState(&'static str),
    /// Repair stopped after creating outputs. Installed files remain valid;
    /// temporary paths are reported so the caller can inspect or remove them.
    #[error("PAR3 repair stopped: {cause}")]
    RepairInterrupted {
        /// Verified files already installed before the failure.
        installed: Vec<crate::session_repair::InstalledFile>,
        /// Engine-created temporary files which have not been installed.
        temporary: Vec<std::path::PathBuf>,
        /// Original failure, including its underlying I/O error when applicable.
        #[source]
        cause: Box<EngineError>,
    },
}

/// Result returned by incremental engine operations.
pub type EngineResult<T> = std::result::Result<T, EngineError>;

/// Cloneable cooperative cancellation, independent of an async runtime.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Request cancellation of every operation using this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Check cancellation between bounded units of work.
    pub fn check(&self) -> EngineResult<()> {
        if self.0.load(Ordering::Acquire) {
            Err(EngineError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct BudgetState {
    limit: usize,
    used: AtomicUsize,
    peak: AtomicUsize,
}

/// A caller-owned allocation budget that may be shared across sessions.
///
/// Reservations precede allocation and include conservative bookkeeping costs.
/// Caller-owned sources and the allocator's own metadata are outside this budget.
#[derive(Clone, Debug)]
pub struct MemoryBudget(Arc<BudgetState>);

impl MemoryBudget {
    /// Create a budget with an explicit byte ceiling.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(BudgetState {
            limit,
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }))
    }

    /// Configured ceiling.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.0.limit
    }

    /// Bytes currently reserved.
    #[must_use]
    pub fn used(&self) -> usize {
        self.0.used.load(Ordering::Acquire)
    }

    /// Highest concurrent reservation observed.
    #[must_use]
    pub fn peak(&self) -> usize {
        self.0.peak.load(Ordering::Acquire)
    }

    /// Bytes available for another reservation.
    #[must_use]
    pub fn available(&self) -> usize {
        self.limit().saturating_sub(self.used())
    }

    pub(crate) fn reserve(&self, bytes: usize) -> EngineResult<Reservation> {
        let mut previous = self.used();
        loop {
            let next = previous
                .checked_add(bytes)
                .filter(|next| *next <= self.limit())
                .ok_or(EngineError::ResourceLimit("memory budget"))?;
            match self.0.used.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.0.peak.fetch_max(next, Ordering::AcqRel);
                    return Ok(Reservation {
                        budget: self.clone(),
                        bytes,
                    });
                }
                Err(current) => previous = current,
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct Reservation {
    budget: MemoryBudget,
    bytes: usize,
}

impl Reservation {
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn belongs_to(&self, budget: &MemoryBudget) -> bool {
        Arc::ptr_eq(&self.budget.0, &budget.0)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.0.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Cumulative scanning work shared across scanners and retained sessions.
/// Each requested read is charged before I/O, including short reads, holes,
/// replay and explicit seeks. Charges are not released when a scanner is dropped.
#[derive(Clone, Debug)]
pub struct ScanWorkBudget(Arc<ScanWorkState>);

#[derive(Debug)]
struct ScanWorkState {
    limit: u64,
    used: AtomicU64,
}

impl ScanWorkBudget {
    /// Bound cumulative requested carrier bytes, independently of allocation.
    pub fn new(limit: u64) -> Self {
        Self(Arc::new(ScanWorkState {
            limit,
            used: AtomicU64::new(0),
        }))
    }
    /// Cumulative byte-read requests admitted so far.
    pub fn used(&self) -> u64 {
        self.0.used.load(Ordering::Acquire)
    }
    /// Configured work ceiling.
    pub fn limit(&self) -> u64 {
        self.0.limit
    }
    pub(crate) fn charge(&self, bytes: usize) -> EngineResult<()> {
        self.0
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes as u64)
                    .filter(|next| *next <= self.0.limit)
            })
            .map(|_| ())
            .map_err(|_| EngineError::ResourceLimit("cumulative scanning work"))
    }
}

/// Synchronous execution controls for a session.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ExecutionOptions {
    /// Total allocation budget, including retained state.
    pub memory: MemoryBudget,
    /// Cumulative carrier scanning requests; clones share the same ceiling.
    pub scan_work: ScanWorkBudget,
    /// Per-session retained-state ceiling, also charged to `memory`.
    pub retained_bytes: usize,
    /// Maximum native workers. One is useful for hosts scheduling many jobs.
    pub workers: usize,
    /// Maximum concurrently open engine-owned handles.
    pub open_handles: usize,
    /// Target I/O and arithmetic stripe size; execution may use smaller stripes.
    pub stripe_bytes: usize,
    /// Cancellation shared with the host.
    pub cancel: CancellationToken,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            memory: MemoryBudget::new(256 << 20),
            scan_work: ScanWorkBudget::new(1 << 40),
            retained_bytes: 64 << 20,
            workers: std::thread::available_parallelism().map_or(1, usize::from),
            open_handles: 32,
            stripe_bytes: 64 << 10,
            cancel: CancellationToken::default(),
        }
    }
}

impl ExecutionOptions {
    pub(crate) fn validate(&self) -> EngineResult<()> {
        if self.workers == 0 || self.open_handles == 0 || self.stripe_bytes == 0 {
            return Err(EngineError::InvalidState(
                "execution limits must be nonzero",
            ));
        }
        self.cancel.check()
    }
}
