//! Reservations follow actual open-file lifetimes, including sequential readers.
use super::{EngineError, EngineResult, ExecutionOptions, MemoryBudget, Reservation};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};

/// Shared, nonblocking limit for engine-owned handles. Providers may acquire
/// leases from the same budget for their own handles. Exhaustion never waits
/// while holding other handles; callers can retry after releasing work.
///
/// Handles the engine keeps open between operations only to avoid reopening
/// them stay charged here, and are closed for any acquirer the budget would
/// otherwise refuse.
#[derive(Clone, Debug)]
pub struct HandleBudget(MemoryBudget, Arc<IdleRegistry>);

/// Engine caches holding open handles that no operation is using right now.
pub(crate) trait IdleHandles: Send + Sync {
    /// Close one idle handle without blocking, returning whether one closed.
    fn close_idle(&self) -> bool;
}

#[derive(Default)]
struct IdleRegistry(Mutex<Vec<Weak<dyn IdleHandles>>>);

impl std::fmt::Debug for IdleRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("IdleHandles")
    }
}

impl HandleBudget {
    /// Create a handle ceiling, independent of allocation accounting.
    pub fn new(limit: usize) -> Self {
        Self(MemoryBudget::new(limit), Arc::default())
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
        loop {
            match self.0.reserve(1) {
                Ok(reservation) => return Ok(HandleLease(reservation)),
                Err(_) if self.close_idle() => {}
                Err(_) => return Err(EngineError::resource_limit("open handles")),
            }
        }
    }

    /// [`Self::acquire`] under a per-operation ceiling that may be lower than
    /// the shared limit. Idle cached handles are closed before refusing.
    pub(crate) fn acquire_within(&self, ceiling: usize) -> EngineResult<HandleLease> {
        let lease = self.acquire()?;
        while self.used() > ceiling {
            if !self.close_idle() {
                return Err(EngineError::resource_limit("open handles"));
            }
        }
        Ok(lease)
    }

    /// Let acquirers close `cache`'s idle handles. The budget keeps only a
    /// weak reference, so registration never extends the cache's lifetime.
    pub(crate) fn register_idle(&self, cache: Weak<dyn IdleHandles>) {
        let mut caches = self.1.0.lock().unwrap_or_else(|error| error.into_inner());
        caches.retain(|cache| cache.strong_count() != 0);
        caches.push(cache);
    }

    // Callbacks run after the registry lock is released, and each one only
    // tries its own lock, so a cache that is itself opening never deadlocks.
    fn close_idle(&self) -> bool {
        let caches: Vec<_> = self
            .1
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        caches.iter().any(|cache| cache.close_idle())
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
        EngineFile::open_with(options, || self.open(path))
    }
}

pub(crate) struct EngineFile {
    // Declaration order closes the OS file before releasing its lease.
    file: File,
    _lease: HandleLease,
    diagnostics: super::ExecutionDiagnostics,
}
impl EngineFile {
    pub(crate) fn open_with(
        options: &ExecutionOptions,
        open: impl FnOnce() -> io::Result<File>,
    ) -> EngineResult<Self> {
        options.validate()?;
        // The shared atomic reservation also makes the per-operation cap safe
        // when callers clone options and concurrently open files.
        let lease = options.handles.acquire_within(options.open_handles)?;
        let file = open()?;
        options.diagnostics.note_open();
        Ok(Self {
            file,
            _lease: lease,
            diagnostics: options.diagnostics.clone(),
        })
    }

    pub(crate) fn open(path: &Path, options: &ExecutionOptions) -> EngineResult<Self> {
        OpenOptions::new().read(true).open_budgeted(path, options)
    }
    pub(crate) fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }
    #[cfg(windows)]
    pub(crate) fn as_std(&self) -> &File {
        &self.file
    }
    pub(crate) fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }
    pub(crate) fn sync_all(&self) -> io::Result<()> {
        self.diagnostics.sync(|| self.file.sync_all())
    }

    /// Read at `offset` without a separate seek. Unix and Windows leave the
    /// shared file position alone, so concurrent readers need no lock; other
    /// targets seek first and must not share the handle.
    pub(crate) fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        self.diagnostics.files().read(out.len(), || {
            #[cfg(unix)]
            {
                std::os::unix::fs::FileExt::read_at(&self.file, out, offset)
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::FileExt::seek_read(&self.file, out, offset)
            }
            #[cfg(not(any(unix, windows)))]
            {
                (&self.file).seek(SeekFrom::Start(offset))?;
                (&self.file).read(out)
            }
        })
    }

    /// Write all of `bytes` at `offset`, with the same positioning as
    /// [`Self::read_at`].
    pub(crate) fn write_all_at(&self, mut offset: u64, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let written = self.diagnostics.files().write(|| {
                #[cfg(unix)]
                {
                    std::os::unix::fs::FileExt::write_at(&self.file, bytes, offset)
                }
                #[cfg(windows)]
                {
                    std::os::windows::fs::FileExt::seek_write(&self.file, bytes, offset)
                }
                #[cfg(not(any(unix, windows)))]
                {
                    (&self.file).seek(SeekFrom::Start(offset))?;
                    (&self.file).write(bytes)
                }
            });
            match written {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    bytes = &bytes[count..];
                    offset += count as u64;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
impl Read for EngineFile {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.diagnostics
            .files()
            .read(out.len(), || self.file.read(out))
    }
}
impl Write for EngineFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.diagnostics.files().write(|| self.file.write(bytes))
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
