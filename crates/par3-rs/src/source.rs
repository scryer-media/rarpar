//! Positioned access to immutable generations of disk, memory or virtual bytes.

use crate::runtime::{EngineFile as File, ExecutionOptions};
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use crate::runtime::{EngineError, EngineResult};

/// Stable caller-assigned identity, independent of a file's name or location.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(pub u64);

/// A source's logical length and content generation.
///
/// Filling a previously unavailable range may preserve the generation. Changing
/// any published byte, truncating, rebinding, or withdrawing coverage must change
/// it. A generation must never be reused for different published bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSnapshot {
    /// Logical length, including ranges which have not arrived.
    pub len: u64,
    /// Caller-owned content generation.
    pub generation: u64,
}

/// Read-only source contract for both protected files and packet carriers.
///
/// A short read stops at a hole or EOF. Never synthesize zeros for missing bytes.
/// `next_available` must describe only published bytes and must make progress.
/// Methods may be called concurrently; errors preserve real backing-store faults.
pub trait SourceAccess: Send + Sync {
    /// Optionally return an immutable view for a scanner and its lazy payloads.
    /// The view must prevent mutation for its entire lifetime, preserve source
    /// coordinates, and charge setup reads, memory and handles to `options`.
    /// Return `None` to keep checking the original provider's generations.
    fn pin(
        &self,
        _source: SourceId,
        _options: &ExecutionOptions,
    ) -> io::Result<Option<Arc<dyn SourceAccess>>> {
        Ok(None)
    }

    /// Current identity snapshot, or `None` for an absent source.
    fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>>;

    /// Read at most `out.len()` bytes without allocating an intermediate buffer.
    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize>;

    /// First available contiguous range at or after `offset`.
    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>>;

    /// Optional efficient forward reader beginning at offset zero. It must stop
    /// at the first hole, without skipping bytes or synthesizing padding. The
    /// verifier resumes through `next_available` after this prefix and checks
    /// generations. Return `None` if an honest forward prefix is unavailable.
    fn open_sequential(&self, _source: SourceId) -> io::Result<Option<Box<dyn Read + Send>>> {
        Ok(None)
    }
}

/// Disk source registry. Positioned reads retain no handles; sequential readers
/// hold one shared lease until dropped. Windows scanners use [`SourceAccess::pin`]
/// to retain a budgeted read-only sharing lock and hash the carrier once.
/// Drop the scanner and all scanned packets to release that carrier lock.
///
/// Unix generations include device, inode and change time. On other platforms,
/// snapshots hash the file through bounded buffers because length and mtime do
/// not identify replaced content. These reads consume the scan-work budget.
/// Unpinned snapshots cost a full read each; callers
/// with immutable backing objects should implement [`SourceAccess`] with their
/// own stable generations to retain read-free reassessment.
#[derive(Debug, Default)]
pub struct DiskSourceAccess {
    paths: BTreeMap<SourceId, PathBuf>,
    options: ExecutionOptions,
}

impl DiskSourceAccess {
    /// Share the engine's allocation, cancellation, and handle controls.
    pub fn with_options(options: ExecutionOptions) -> Self {
        Self {
            paths: BTreeMap::new(),
            options,
        }
    }

    /// Register a caller-selected path. File selection and containment belong to
    /// the caller; PAR3 paths are never interpreted by this registry.
    pub fn insert(&mut self, id: SourceId, path: PathBuf) {
        self.paths.insert(id, path);
    }

    fn path(&self, id: SourceId) -> io::Result<&PathBuf> {
        self.paths
            .get(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unregistered PAR3 source"))
    }
}

impl SourceAccess for DiskSourceAccess {
    #[cfg(windows)]
    fn pin(
        &self,
        source: SourceId,
        options: &ExecutionOptions,
    ) -> io::Result<Option<Arc<dyn SourceAccess>>> {
        use crate::runtime::OpenBudgeted;
        use std::os::windows::fs::OpenOptionsExt;
        let path = self.path(source)?;
        let reservation = options
            .memory
            .reserve(std::mem::size_of::<PinnedDiskSource>())
            .map_err(EngineError::into_io)?;
        // FILE_SHARE_READ denies writers and deletion for the view's lifetime.
        // An existing writer makes this fail instead of admitting unstable data.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open_budgeted(path, options)
            .map_err(EngineError::into_io)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PAR3 source is not a regular file",
            ));
        }
        let mut hash = disk_metadata_hash(&metadata);
        hash_open_disk_contents(&mut file, source, &metadata, options, &mut hash)
            .map_err(EngineError::into_io)?;
        let generation = u64::from_le_bytes(
            hash.finalize().as_bytes()[..8]
                .try_into()
                .expect("eight bytes"),
        );
        Ok(Some(Arc::new(PinnedDiskSource {
            source,
            snapshot: SourceSnapshot {
                len: metadata.len(),
                generation,
            },
            file: std::sync::Mutex::new(file),
            _reservation: reservation,
        })))
    }

    fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>> {
        let Some(path) = self.paths.get(&source) else {
            return Ok(None);
        };
        let metadata = match std::fs::metadata(path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PAR3 source is not a regular file",
            ));
        }
        #[allow(unused_mut)]
        let mut hash = disk_metadata_hash(&metadata);
        #[cfg(not(unix))]
        hash_disk_contents(path, source, &metadata, &self.options, &mut hash)
            .map_err(EngineError::into_io)?;
        let generation = u64::from_le_bytes(
            hash.finalize().as_bytes()[..8]
                .try_into()
                .expect("eight bytes"),
        );
        Ok(Some(SourceSnapshot {
            len: metadata.len(),
            generation,
        }))
    }

    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        let mut file =
            File::open(self.path(source)?, &self.options).map_err(EngineError::into_io)?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(out)
    }

    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        Ok(self
            .snapshot(source)?
            .and_then(|value| (offset < value.len).then_some(offset..value.len)))
    }

    fn open_sequential(&self, source: SourceId) -> io::Result<Option<Box<dyn Read + Send>>> {
        Ok(Some(Box::new(
            File::open(self.path(source)?, &self.options).map_err(EngineError::into_io)?,
        )))
    }
}

fn disk_metadata_hash(metadata: &std::fs::Metadata) -> blake3::Hasher {
    let mut hash = blake3::Hasher::new();
    hash.update(&metadata.len().to_le_bytes());
    if let Ok(modified) = metadata.modified() {
        let elapsed = modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        hash.update(&elapsed.as_nanos().to_le_bytes());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hash.update(&metadata.dev().to_le_bytes());
        hash.update(&metadata.ino().to_le_bytes());
        hash.update(&metadata.ctime().to_le_bytes());
        hash.update(&metadata.ctime_nsec().to_le_bytes());
    }
    hash
}

// Stable Rust exposes no portable file identity/change counter outside Unix.
// Hash bytes there rather than reuse evidence based only on length and mtime.
#[cfg(any(not(unix), test))]
fn hash_disk_contents(
    path: &std::path::Path,
    source: SourceId,
    expected: &std::fs::Metadata,
    options: &ExecutionOptions,
    hash: &mut blake3::Hasher,
) -> EngineResult<()> {
    let mut file = File::open(path, options)?;
    hash_open_disk_contents(&mut file, source, expected, options, hash)
}

#[cfg(any(not(unix), test))]
fn hash_open_disk_contents(
    file: &mut File,
    source: SourceId,
    expected: &std::fs::Metadata,
    options: &ExecutionOptions,
    hash: &mut blake3::Hasher,
) -> EngineResult<()> {
    let size = options.stripe_bytes.min(64 << 10);
    let _memory = options.memory.reserve(size)?;
    let mut buffer = vec![0; size];
    let mut remaining = expected.len();
    while remaining != 0 {
        options.cancel.check()?;
        let take = remaining.min(size as u64) as usize;
        options.scan_work.charge(take)?;
        let count = file.read(&mut buffer[..take])?;
        if count == 0 {
            return Err(EngineError::SourceChanged(source));
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let current = file.metadata()?;
    options.scan_work.charge(1)?;
    if file.read(&mut [0])? != 0
        || current.len() != expected.len()
        || current.modified()? != expected.modified()?
    {
        return Err(EngineError::SourceChanged(source));
    }
    Ok(())
}

// Hash once under the sharing lock, which keeps that generation immutable.
#[cfg(windows)]
struct PinnedDiskSource {
    source: SourceId,
    snapshot: SourceSnapshot,
    file: std::sync::Mutex<File>,
    _reservation: crate::runtime::Reservation,
}

#[cfg(windows)]
impl SourceAccess for PinnedDiskSource {
    fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>> {
        Ok((source == self.source).then_some(self.snapshot))
    }

    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        if source != self.source {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unregistered PAR3 source",
            ));
        }
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("poisoned PAR3 source lock"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(out)
    }

    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        Ok(self
            .snapshot(source)?
            .and_then(|value| (offset < value.len).then_some(offset..value.len)))
    }
}

/// Immutable memory source registry, useful for callers which already own bytes.
#[derive(Debug, Default)]
pub struct MemorySourceAccess {
    sources: BTreeMap<SourceId, (u64, Arc<[u8]>)>,
}

impl MemorySourceAccess {
    /// Register bytes with their caller-assigned generation.
    pub fn insert(&mut self, id: SourceId, generation: u64, data: Arc<[u8]>) {
        self.sources.insert(id, (generation, data));
    }
}

impl SourceAccess for MemorySourceAccess {
    fn snapshot(&self, source: SourceId) -> io::Result<Option<SourceSnapshot>> {
        Ok(self
            .sources
            .get(&source)
            .map(|(generation, data)| SourceSnapshot {
                len: data.len() as u64,
                generation: *generation,
            }))
    }

    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        let (_, data) = self
            .sources
            .get(&source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unregistered PAR3 source"))?;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let take = out.len().min(data.len() - start);
        out[..take].copy_from_slice(&data[start..start + take]);
        Ok(take)
    }

    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        Ok(self
            .snapshot(source)?
            .and_then(|value| (offset < value.len).then_some(offset..value.len)))
    }

    fn open_sequential(&self, source: SourceId) -> io::Result<Option<Box<dyn Read + Send>>> {
        Ok(self
            .sources
            .get(&source)
            .map(|(_, data)| Box::new(io::Cursor::new(Arc::clone(data))) as Box<dyn Read + Send>))
    }
}

pub(crate) fn read_exact_at(
    diagnostics: &crate::runtime::ExecutionDiagnostics,
    access: &dyn SourceAccess,
    source: SourceId,
    offset: u64,
    out: &mut [u8],
) -> EngineResult<()> {
    let mut done = 0;
    while done < out.len() {
        let at = offset
            .checked_add(done as u64)
            .ok_or(EngineError::InvalidState("source offset overflow"))?;
        let read = diagnostics.read_at(access, source, at, &mut out[done..])?;
        if read == 0 {
            return Err(EngineError::Unavailable {
                source_id: source,
                offset: at,
            });
        }
        if read > out.len() - done {
            return Err(EngineError::InvalidState(
                "source returned an invalid read length",
            ));
        }
        done += read;
    }
    Ok(())
}

pub(crate) fn ensure_snapshot(
    access: &dyn SourceAccess,
    source: SourceId,
    expected: SourceSnapshot,
) -> EngineResult<()> {
    if access.snapshot(source)? != Some(expected) {
        return Err(EngineError::SourceChanged(source));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "par3-source-test-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn carrier_scanning_is_linear_and_keeps_work_cumulative() {
        use crate::ingest::{PacketScanner, ScanEvent};
        use crate::runtime::{HandleBudget, ScanWorkBudget};
        let directory = TestDirectory::new();
        let path = directory.path().join("untrusted.par3");
        let size = 4 << 20;
        let expected_reads = if cfg!(windows) { 2 * size } else { size } as u64;
        let expected_work = expected_reads + u64::from(cfg!(windows));
        std::fs::write(&path, vec![0; size]).unwrap();
        let options = ExecutionOptions {
            open_handles: 1,
            handles: HandleBudget::new(1),
            scan_work: ScanWorkBudget::new(expected_work),
            ..ExecutionOptions::default()
        };
        let mut disk = DiskSourceAccess::with_options(options.clone());
        disk.insert(SourceId(0), path.clone());
        let access: Arc<dyn SourceAccess> = Arc::new(disk);
        let mut scanner = PacketScanner::new(
            access.clone(),
            SourceId(0),
            options.clone(),
            crate::ScanLimits::default(),
        )
        .unwrap();
        assert!(matches!(scanner.poll().unwrap(), ScanEvent::End));
        assert_eq!(options.diagnostics.file_io().read_bytes, expected_reads);
        assert_eq!(options.scan_work.used(), expected_work);
        #[cfg(windows)]
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        drop(scanner);
        assert_eq!(options.handles.used(), 0);
        assert_eq!(options.memory.used(), 0);
        let replay = PacketScanner::new(
            access,
            SourceId(0),
            options.clone(),
            crate::ScanLimits::default(),
        );
        assert!(matches!(
            replay.and_then(|mut scanner| scanner.poll()),
            Err(EngineError::ResourceLimit("cumulative scanning work"))
        ));
        std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    }

    #[test]
    fn fallback_generation_hashes_are_charged_before_reading() {
        let directory = TestDirectory::new();
        let path = directory.path().join("source");
        std::fs::write(&path, vec![1; 1024]).unwrap();
        let options = ExecutionOptions {
            scan_work: crate::runtime::ScanWorkBudget::new(100),
            ..ExecutionOptions::default()
        };
        let result = hash_disk_contents(
            &path,
            SourceId(0),
            &std::fs::metadata(&path).unwrap(),
            &options,
            &mut blake3::Hasher::new(),
        );
        assert!(matches!(
            result,
            Err(EngineError::ResourceLimit("cumulative scanning work"))
        ));
        assert_eq!(options.diagnostics.file_io().read_bytes, 0);
        assert_eq!(options.handles.used(), 0);
        assert_eq!(options.memory.used(), 0);
    }

    #[test]
    fn disk_generations_detect_replacement_with_preserved_length_and_mtime() {
        let directory = std::env::temp_dir().join(format!(
            "par3-generation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("source");
        let replacement = directory.join("replacement");
        std::fs::write(&path, b"original").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let options = ExecutionOptions {
            stripe_bytes: 3,
            ..ExecutionOptions::default()
        };
        let mut access = DiskSourceAccess::with_options(options.clone());
        access.insert(SourceId(1), path.clone());
        let before = access.snapshot(SourceId(1)).unwrap().unwrap();
        #[cfg(windows)]
        {
            let pinned = access.pin(SourceId(1), &options).unwrap().unwrap();
            assert_eq!(pinned.snapshot(SourceId(1)).unwrap(), Some(before));
        }
        let content_hash = || {
            let mut hash = blake3::Hasher::new();
            hash_disk_contents(&path, SourceId(1), &metadata, &options, &mut hash).unwrap();
            hash.finalize()
        };
        let before_hash = content_hash();
        std::fs::write(&replacement, b"replaced").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_modified(metadata.modified().unwrap())
            .unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let after = access.snapshot(SourceId(1)).unwrap().unwrap();
        #[cfg(windows)]
        {
            let pinned = access.pin(SourceId(1), &options).unwrap().unwrap();
            assert_eq!(pinned.snapshot(SourceId(1)).unwrap(), Some(after));
            let reads = options.diagnostics.file_io().read_bytes;
            assert_eq!(pinned.snapshot(SourceId(1)).unwrap(), Some(after));
            assert_eq!(options.diagnostics.file_io().read_bytes, reads);
        }
        assert_eq!(before.len, after.len);
        assert_ne!(before.generation, after.generation);
        assert_ne!(before_hash, content_hash());
        assert_eq!(after, access.snapshot(SourceId(1)).unwrap().unwrap());
        assert_eq!(options.memory.used(), 0);
        assert_eq!(options.handles.used(), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
