//! Shared resource limits, cancellation and typed errors for incremental work.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use thiserror::Error;

#[path = "runtime_handles.rs"]
mod handles;
pub(crate) use handles::{EngineFile, OpenBudgeted};
pub use handles::{HandleBudget, HandleLease};

#[path = "runtime_diagnostics.rs"]
mod diagnostics;
pub(crate) use diagnostics::StageGuard;
pub use diagnostics::{
    ExecutionDiagnostics, IoSnapshot, ProgressCallback, ProgressEvent, ProgressPhase, Stage,
    StageSnapshot,
};

/// Failure of an incremental engine operation. Missing bytes are not I/O errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EngineError {
    /// An authenticated packet or set could not be interpreted.
    #[error(transparent)]
    Format(#[from] crate::Par3Error),
    /// A real backing-store error, with its original error chain preserved.
    #[error(transparent)]
    Io(std::io::Error),
    /// The requested work exceeds a configured resource budget.
    #[error("PAR3 resource limit: {0}")]
    ResourceLimit(ResourceLimit),
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
    /// Creation stopped after installing some independently authenticated carriers.
    #[error("PAR3 output installation stopped: {cause}")]
    OutputInterrupted {
        /// Explicit destinations already installed successfully.
        installed: Vec<std::path::PathBuf>,
        /// Original cancellation or I/O failure.
        #[source]
        cause: Box<EngineError>,
    },
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

/// Why a budgeted request was refused.
///
/// A refusal that was never expressed in bytes — a handle ceiling, a packet
/// count, a structural bound — reports `limit` zero and [`LimitCause::Unmeasured`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceLimit {
    /// Name of the structure or budget that refused the request.
    pub what: &'static str,
    /// Bytes the refused request needed, when the refusal was measured.
    pub need: usize,
    /// Configured ceiling for `what`, when the refusal was measured.
    pub limit: usize,
    /// Bytes still available under that ceiling when the request was refused.
    pub available: usize,
}

/// Whether a refused request could ever be admitted under the same ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitCause {
    /// This request would still be refused if this session were alone on the
    /// budget with the same options. No amount of waiting admits it.
    ExceedsLimit,
    /// With the same options, this exact request is admitted once other
    /// reservations release.
    ///
    /// Which reservations those are is not something this type can tell: the
    /// holder may be a peer session sharing the budget, or this session's own
    /// earlier reservations — layout, evidence and assessment state are all
    /// still held when codec scratch is requested. The host decides which,
    /// using its own knowledge of what it has in flight.
    PeerContention,
    /// The refusal was not measured in bytes.
    Unmeasured,
}

impl ResourceLimit {
    pub(crate) const fn named(what: &'static str) -> Self {
        Self {
            what,
            need: 0,
            limit: 0,
            available: 0,
        }
    }

    pub(crate) const fn measured(
        what: &'static str,
        need: usize,
        limit: usize,
        available: usize,
    ) -> Self {
        Self {
            what,
            need,
            limit,
            available,
        }
    }

    /// Classify the refusal for a host deciding between queueing and failing.
    ///
    /// [`LimitCause::ExceedsLimit`] means "this request would still be refused
    /// if this session were alone on the budget with the same options".
    /// [`LimitCause::PeerContention`] means "with the same options, this exact
    /// request is admitted once other reservations release".
    /// [`LimitCause::Unmeasured`] means the refusal was never expressed in
    /// bytes; treat it as terminal, like `ExceedsLimit`.
    ///
    /// The distinction is the one a host needs to requeue rather than fail:
    /// `PeerContention` is worth retrying, the other two never are.
    #[must_use]
    pub fn cause(self) -> LimitCause {
        if self.limit == 0 {
            LimitCause::Unmeasured
        } else if self.need > self.limit {
            LimitCause::ExceedsLimit
        } else {
            LimitCause::PeerContention
        }
    }

    /// Whether the request could be admitted once the memory currently held —
    /// by a peer, or by this session itself — is released. An unmeasured
    /// refusal is never reported as contention.
    #[must_use]
    pub fn contended(self) -> bool {
        self.cause() == LimitCause::PeerContention
    }
}

impl std::fmt::Display for ResourceLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.cause() {
            LimitCause::Unmeasured => formatter.write_str(self.what),
            LimitCause::ExceedsLimit => write!(
                formatter,
                "{} does not fit alone (needs {} bytes, ceiling {})",
                self.what, self.need, self.limit
            ),
            LimitCause::PeerContention => write!(
                formatter,
                "{} does not fit beside the memory already reserved (needs {} bytes, {} of {} available)",
                self.what, self.need, self.available, self.limit
            ),
        }
    }
}

impl EngineError {
    /// A refusal whose ceiling is structural rather than a byte count.
    pub(crate) const fn resource_limit(what: &'static str) -> Self {
        Self::ResourceLimit(ResourceLimit::named(what))
    }

    /// A refusal measured against a byte ceiling, distinguishing a request that
    /// can never fit from one a peer is currently holding out.
    pub(crate) const fn budget_limit(
        what: &'static str,
        need: usize,
        limit: usize,
        available: usize,
    ) -> Self {
        Self::ResourceLimit(ResourceLimit::measured(what, need, limit, available))
    }
}

/// Result returned by incremental engine operations.
pub type EngineResult<T> = std::result::Result<T, EngineError>;

impl From<std::io::Error> for EngineError {
    fn from(error: std::io::Error) -> Self {
        // SourceAccess and Read transport typed engine failures through io::Error.
        // Preserve all other backing-store errors exactly, including their chain.
        if error.get_ref().is_some_and(|inner| inner.is::<Self>()) {
            *error
                .into_inner()
                .expect("checked inner")
                .downcast::<Self>()
                .expect("checked type")
        } else {
            Self::Io(error)
        }
    }
}

impl EngineError {
    pub(crate) fn into_io(self) -> std::io::Error {
        match self {
            Self::Io(error) => error,
            error => std::io::Error::other(error),
        }
    }
}

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

/// What a reservation pays for, so a refusal or a peak names a structure rather
/// than an anonymous total. Categories describe lifetimes, not allocators.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(usize)]
#[non_exhaustive]
pub enum MemoryCategory {
    /// Reservations taken by code paths that have not been categorised.
    Uncategorized,
    /// Scanner read-ahead and authenticated packet bytes held for a carrier.
    CarrierPackets,
    /// The resolved metadata tree: descriptions, paths and block checksums.
    ResolvedMetadata,
    /// Block layouts, extents and sealed verification evidence.
    LayoutEvidence,
    /// Retained assessment state, requirements and recovery references.
    Assessment,
    /// Admission caches and deduplication maps that outlive one operation.
    Caches,
    /// Lazy payload references and out-of-order verification fragments.
    QueuedPayloads,
    /// Transform fields, Cauchy coefficients and other codec tables.
    CodecTables,
    /// Per-operation codec rows, stripes, locators and syndrome banks.
    CodecScratch,
    /// Per-operation buffers for reading, hashing or searching source bytes.
    SourceScratch,
    /// Private worker pool stacks, charged until the workers are joined.
    WorkerStacks,
    /// Output path bookkeeping and staged write buffers.
    OutputStaging,
}

/// Number of distinct [`MemoryCategory`] values.
pub const MEMORY_CATEGORIES: usize = 12;

impl MemoryCategory {
    /// Every category, in ledger order.
    pub const ALL: [Self; MEMORY_CATEGORIES] = [
        Self::Uncategorized,
        Self::CarrierPackets,
        Self::ResolvedMetadata,
        Self::LayoutEvidence,
        Self::Assessment,
        Self::Caches,
        Self::QueuedPayloads,
        Self::CodecTables,
        Self::CodecScratch,
        Self::SourceScratch,
        Self::WorkerStacks,
        Self::OutputStaging,
    ];

    /// Stable lowercase name, also used when a refusal names this category.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Uncategorized => "memory budget",
            Self::CarrierPackets => "carrier and packet storage",
            Self::ResolvedMetadata => "resolved metadata",
            Self::LayoutEvidence => "layout and evidence",
            Self::Assessment => "assessment state",
            Self::Caches => "caches",
            Self::QueuedPayloads => "queued payloads",
            Self::CodecTables => "codec tables",
            Self::CodecScratch => "codec scratch",
            Self::SourceScratch => "source scratch",
            Self::WorkerStacks => "worker stacks",
            Self::OutputStaging => "output staging",
        }
    }
}

/// One category's reservations at a sampling instant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryCategorySnapshot {
    /// Bytes reserved right now.
    pub current: u64,
    /// Highest `current` observed for this category.
    pub peak: u64,
    /// Reservations taken, including those already released.
    pub reservations: u64,
}

/// Categorised reservations at one sampling instant.
///
/// Categories are sampled independently, so their peaks need not have occurred
/// together and their sum is not the budget's own peak.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryLedger {
    entries: [MemoryCategorySnapshot; MEMORY_CATEGORIES],
}

impl MemoryLedger {
    /// Reservations attributed to one category.
    #[must_use]
    pub fn category(&self, category: MemoryCategory) -> MemoryCategorySnapshot {
        self.entries[category as usize]
    }

    /// Every category in ledger order.
    pub fn iter(&self) -> impl Iterator<Item = (MemoryCategory, MemoryCategorySnapshot)> + '_ {
        MemoryCategory::ALL
            .into_iter()
            .map(|category| (category, self.category(category)))
    }

    /// Sum of the categories' current reservations. This equals
    /// [`MemoryBudget::used`] whenever no reservation is being taken concurrently.
    #[must_use]
    pub fn current(&self) -> u64 {
        self.entries.iter().map(|entry| entry.current).sum()
    }
}

#[derive(Debug, Default)]
struct CategoryLedger {
    current: AtomicU64,
    peak: AtomicU64,
    reservations: AtomicU64,
}

impl CategoryLedger {
    fn acquire(&self, bytes: usize) {
        let bytes = bytes as u64;
        let next = self.current.fetch_add(bytes, Ordering::Relaxed) + bytes;
        self.peak.fetch_max(next, Ordering::Relaxed);
        self.reservations.fetch_add(1, Ordering::Relaxed);
    }

    fn release(&self, bytes: usize) {
        self.current.fetch_sub(bytes as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> MemoryCategorySnapshot {
        MemoryCategorySnapshot {
            current: self.current.load(Ordering::Relaxed),
            peak: self.peak.load(Ordering::Relaxed),
            reservations: self.reservations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct BudgetState {
    limit: usize,
    used: AtomicUsize,
    peak: AtomicUsize,
    ledger: [CategoryLedger; MEMORY_CATEGORIES],
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
            ledger: std::array::from_fn(|_| CategoryLedger::default()),
        }))
    }

    /// Categorised reservations. Reading the ledger allocates nothing, takes no
    /// lock, and does not synchronise the categories with each other.
    #[must_use]
    pub fn ledger(&self) -> MemoryLedger {
        MemoryLedger {
            entries: std::array::from_fn(|index| self.0.ledger[index].snapshot()),
        }
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

    /// Reserve aligned stripes atomically; another session may consume the
    /// observed headroom before our reservation, so shrink on contention.
    pub(crate) fn reserve_stripes(
        &self,
        category: MemoryCategory,
        target: usize,
        count: usize,
        alignment: usize,
    ) -> EngineResult<(usize, Reservation)> {
        self.reserve_stripes_with_overhead(category, target, count, alignment, 0)
    }

    pub(crate) fn reserve_stripes_with_overhead(
        &self,
        category: MemoryCategory,
        target: usize,
        count: usize,
        alignment: usize,
        overhead: usize,
    ) -> EngineResult<(usize, Reservation)> {
        if count == 0 || alignment == 0 {
            return Err(EngineError::InvalidState("invalid repair stripe layout"));
        }
        let available = || self.available().saturating_sub(overhead) / count;
        let mut stripe = target.min(available()) / alignment * alignment;
        while stripe != 0 {
            match self.reserve_as(category, stripe * count + overhead) {
                Ok(reservation) => return Ok((stripe, reservation)),
                Err(EngineError::ResourceLimit(_)) => {
                    stripe = (stripe / 2).min(available()) / alignment * alignment;
                }
                Err(error) => return Err(error),
            }
        }
        Err(EngineError::budget_limit(
            "minimum repair stripe",
            alignment.saturating_mul(count).saturating_add(overhead),
            self.limit(),
            self.available(),
        ))
    }

    /// Reserve without naming a structure. Kept for call sites that have not
    /// been categorised; the ledger reports these as `Uncategorized`.
    pub(crate) fn reserve(&self, bytes: usize) -> EngineResult<Reservation> {
        self.reserve_as(MemoryCategory::Uncategorized, bytes)
    }

    pub(crate) fn reserve_as(
        &self,
        category: MemoryCategory,
        bytes: usize,
    ) -> EngineResult<Reservation> {
        self.charge(category, bytes)?;
        Ok(Reservation {
            budget: self.clone(),
            category,
            bytes,
        })
    }

    fn charge(&self, category: MemoryCategory, bytes: usize) -> EngineResult<()> {
        let mut previous = self.used();
        loop {
            let Some(next) = previous
                .checked_add(bytes)
                .filter(|next| *next <= self.limit())
            else {
                return Err(EngineError::budget_limit(
                    category.name(),
                    bytes,
                    self.limit(),
                    self.limit().saturating_sub(previous),
                ));
            };
            match self.0.used.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.0.peak.fetch_max(next, Ordering::AcqRel);
                    self.0.ledger[category as usize].acquire(bytes);
                    return Ok(());
                }
                Err(current) => previous = current,
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct Reservation {
    budget: MemoryBudget,
    category: MemoryCategory,
    bytes: usize,
}

impl Reservation {
    pub(crate) fn shrink_to(&mut self, bytes: usize) {
        assert!(bytes <= self.bytes, "reservation can only shrink");
        let released = self.bytes - bytes;
        self.budget.0.used.fetch_sub(released, Ordering::AcqRel);
        self.budget.0.ledger[self.category as usize].release(released);
        self.bytes = bytes;
    }
    /// Take `bytes` more of the same category, or leave the reservation intact.
    /// Growing an existing reservation keeps one unwind point for a sequence of
    /// allocations, so a refusal part-way through releases everything it took.
    pub(crate) fn grow_by(&mut self, bytes: usize) -> EngineResult<()> {
        self.budget.charge(self.category, bytes)?;
        self.bytes += bytes;
        Ok(())
    }
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn category(&self) -> MemoryCategory {
        self.category
    }
    pub(crate) fn belongs_to(&self, budget: &MemoryBudget) -> bool {
        Arc::ptr_eq(&self.budget.0, &budget.0)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.0.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.budget.0.ledger[self.category as usize].release(self.bytes);
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
            .map_err(|_| EngineError::resource_limit("cumulative scanning work"))
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
    /// FFT butterfly CPU selection; `kernel()` reports the detected shuffle ISA.
    /// This does not change the independent Cauchy dispatch.
    pub fft_backend: reedsolomon_rs::gf_simd::LinearBackend,
    /// Maximum concurrently open engine-owned handles.
    pub open_handles: usize,
    /// Shared handle ceiling across cloned options and cooperating providers.
    pub handles: HandleBudget,
    /// Target I/O and arithmetic stripe size; execution may use smaller stripes.
    pub stripe_bytes: usize,
    /// Maximum losses in one Cauchy solve, independent of buffer size.
    /// Defaults to [`crate::cauchy::CodecLimits::DEFAULT_MAX_LOST_BLOCKS`].
    /// Raise only when the caller accepts the quadratic coefficient work.
    pub max_cauchy_lost_blocks: u64,
    /// Cancellation shared with the host.
    pub cancel: CancellationToken,
    /// Shared cumulative counters and stage timings; clones aggregate work.
    pub diagnostics: ExecutionDiagnostics,
    /// Optional synchronous observer. Callbacks must be short and must not panic.
    pub progress: Option<ProgressCallback>,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            memory: MemoryBudget::new(256 << 20),
            scan_work: ScanWorkBudget::new(1 << 40),
            retained_bytes: 64 << 20,
            workers: std::thread::available_parallelism().map_or(1, usize::from),
            fft_backend: reedsolomon_rs::gf_simd::LinearBackend::Auto,
            open_handles: 32,
            handles: HandleBudget::new(32),
            stripe_bytes: 64 << 10,
            max_cauchy_lost_blocks: crate::cauchy::CodecLimits::DEFAULT_MAX_LOST_BLOCKS,
            cancel: CancellationToken::default(),
            diagnostics: ExecutionDiagnostics::default(),
            progress: None,
        }
    }
}

/// Private pools join their workers before releasing stack reservations.
pub(crate) struct WorkerPool {
    pool: Option<rayon::ThreadPool>,
    threads: Vec<std::thread::JoinHandle<()>>,
    _memory: Reservation,
}

impl WorkerPool {
    const STACK_BYTES: usize = 256 << 10;
    const WORKER_BYTES: usize = Self::STACK_BYTES + (64 << 10);

    pub(crate) fn for_work_with_scratch(
        options: &ExecutionOptions,
        maximum: usize,
        per_worker: usize,
    ) -> EngineResult<Option<Self>> {
        let workers = options
            .workers
            .min(maximum)
            .min(options.memory.available() / Self::WORKER_BYTES.saturating_add(per_worker));
        Self::for_work(options, workers, workers.saturating_mul(per_worker))
    }

    pub(crate) fn for_work(
        options: &ExecutionOptions,
        maximum: usize,
        headroom: usize,
    ) -> EngineResult<Option<Self>> {
        options.validate()?;
        let workers = options
            .workers
            .min(maximum)
            .min(options.memory.available().saturating_sub(headroom) / Self::WORKER_BYTES);
        if workers < 2 {
            return Ok(None);
        }
        let memory = options
            .memory
            .reserve_as(MemoryCategory::WorkerStacks, workers * Self::WORKER_BYTES)?;
        let mut threads = Vec::with_capacity(workers);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .stack_size(Self::STACK_BYTES)
            .spawn_handler(|worker| {
                threads.push(
                    std::thread::Builder::new()
                        .stack_size(Self::STACK_BYTES)
                        .spawn(move || worker.run())?,
                );
                Ok(())
            })
            .build();
        match pool {
            Ok(pool) => Ok(Some(Self {
                pool: Some(pool),
                threads,
                _memory: memory,
            })),
            Err(error) => {
                for thread in threads {
                    let _ = thread.join();
                }
                Err(EngineError::Io(std::io::Error::other(error)))
            }
        }
    }

    pub(crate) fn pool(&self) -> &rayon::ThreadPool {
        self.pool.as_ref().expect("live worker pool")
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        drop(self.pool.take());
        for thread in self.threads.drain(..) {
            let _ = thread.join();
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

#[cfg(test)]
mod stripe_tests {
    use super::*;

    #[test]
    fn verification_workers_include_only_admitted_scratch() {
        let options = ExecutionOptions {
            workers: 8,
            memory: MemoryBudget::new(1 << 20),
            ..ExecutionOptions::default()
        };
        let pool = WorkerPool::for_work_with_scratch(&options, 8, 128 << 10)
            .unwrap()
            .expect("two workers and their scratch fit");
        assert_eq!(pool.pool().current_num_threads(), 2);
        let scratch = options.memory.reserve(2 * (128 << 10)).unwrap();
        assert!(options.memory.used() <= options.memory.limit());
        drop(scratch);
        drop(pool);
        assert_eq!(options.memory.used(), 0);
    }

    #[test]
    fn aligned_stripes_share_and_release_the_physical_budget() {
        let memory = MemoryBudget::new(1024);
        let held = memory.reserve(400).unwrap();
        let (stripe, reservation) = memory
            .reserve_stripes(MemoryCategory::CodecScratch, 1024, 3, 2)
            .unwrap();
        assert_eq!(stripe, 208);
        assert_eq!(memory.used(), 1024);
        assert!(
            memory
                .reserve_stripes(MemoryCategory::CodecScratch, 8, 2, 2)
                .is_err()
        );
        drop(reservation);
        drop(held);
        assert_eq!(memory.used(), 0);
        assert!(
            memory
                .reserve_stripes(MemoryCategory::CodecScratch, 8, 0, 2)
                .is_err()
        );
        assert!(
            memory
                .reserve_stripes(MemoryCategory::CodecScratch, 8, 2, 0)
                .is_err()
        );
        assert!(
            memory
                .reserve_stripes(MemoryCategory::CodecScratch, 1, 2, 2)
                .is_err()
        );
    }
}
