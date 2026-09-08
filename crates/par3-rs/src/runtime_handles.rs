//! Reservations follow actual open-file lifetimes, including sequential readers.
use super::{EngineError, EngineResult, ExecutionOptions, MemoryBudget, Reservation};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Shared, nonblocking limit for engine-owned handles. Providers may acquire
/// leases from the same budget for their own handles. Exhaustion never waits
/// while holding other handles; callers can retry after releasing work.
#[derive(Clone, Debug)]
pub struct HandleBudget(MemoryBudget);

impl HandleBudget {
    /// Create a handle ceiling, independent of allocation accounting.
    pub fn new(limit: usize) -> Self {
        Self(MemoryBudget::new(limit))
    }
    /// Configured concurrent ceiling.
    pub fn limit(&self) -> usize {
        self.0.limit()
    }
    /// Live handle reservations.
    pub fn used(&self) -> usize {
        self.0.used()
    }
    /// Highest concurrent handle count observed.
    pub fn peak(&self) -> usize {
        self.0.peak()
    }
    /// Reserve one handle before opening it; dropping the lease releases it.
    pub fn acquire(&self) -> EngineResult<HandleLease> {
        self.0
            .reserve(1)
            .map(HandleLease)
            .map_err(|_| EngineError::ResourceLimit("open handles"))
    }
}

/// Keep this lease alive until the associated handle has closed.
#[derive(Debug)]
pub struct HandleLease(#[allow(dead_code)] Reservation);

pub(crate) trait OpenBudgeted {
    fn open_budgeted(&self, path: &Path, options: &ExecutionOptions) -> EngineResult<EngineFile>;
}
impl OpenBudgeted for OpenOptions {
    fn open_budgeted(&self, path: &Path, options: &ExecutionOptions) -> EngineResult<EngineFile> {
        options.validate()?;
        let lease = options.handles.acquire()?;
        // The shared atomic reservation also makes the per-operation cap safe
        // when callers clone options and concurrently open files.
        if options.handles.used() > options.open_handles {
            return Err(EngineError::ResourceLimit("open handles"));
        }
        let file = self.open(path)?;
        Ok(EngineFile {
            file,
            _lease: lease,
        })
    }
}

pub(crate) struct EngineFile {
    // Declaration order closes the OS file before releasing its lease.
    file: File,
    _lease: HandleLease,
}
impl EngineFile {
    pub(crate) fn open(path: &Path, options: &ExecutionOptions) -> EngineResult<Self> {
        OpenOptions::new().read(true).open_budgeted(path, options)
    }
    pub(crate) fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }
    pub(crate) fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }
    pub(crate) fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}
impl Read for EngineFile {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.file.read(out)
    }
}
impl Write for EngineFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for EngineFile {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.file.seek(from)
    }
}
