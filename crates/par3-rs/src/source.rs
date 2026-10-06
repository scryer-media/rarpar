//! Positioned access to immutable generations of disk, memory or virtual bytes.

use crate::runtime::{EngineFile as File, ExecutionOptions};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

/// The open local file behind a source, from [`SourceAccess::open_file`]. It
/// has no public interface; only the engine uses it.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub struct SourceFile(pub(crate) Arc<File>);

impl std::fmt::Debug for SourceFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SourceFile")
    }
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

    /// Optionally the open local file behind `source`, so that an output
    /// which begins with the source's bytes can be staged as a clone of it
    /// where the filesystem shares extents. The engine uses the file only
    /// once its metadata matches the source's snapshot. Only
    /// [`DiskSourceAccess`] returns one; a wrapper around it forwards this.
    fn open_file(&self, _source: SourceId) -> io::Result<Option<SourceFile>> {
        Ok(None)
    }
}

/// Disk source registry. Sequential readers hold one shared lease until dropped.
/// Windows scanners use [`SourceAccess::pin`] to retain a budgeted read-only
/// sharing lock for the scan. Drop the scanner and all scanned packets to
/// release that carrier lock.
///
/// On Unix and Windows, positioned reads keep a few read handles open between
/// calls, at most a quarter of the handle budget. Each stays charged to the
/// budget, is closed for any acquirer the budget would otherwise refuse, and is
/// closed as soon as a snapshot finds the path naming a different file;
/// dropping the registry closes them all. Windows opens them, like sequential
/// readers, sharing reads, writes and deletion: a cached handle admits writers,
/// renames and deletes, which the next snapshot sees, and refuses only an
/// opener that denies reads, as any open read handle does. Windows caches
/// them only on volumes with POSIX unlink and rename (NTFS on Windows 10 1809
/// and later); on FAT, exFAT and SMB a held handle would leave a deleted file
/// pending deletion and refuse renames over it. Elsewhere every positioned
/// read opens the file.
///
/// Unix generations include device, inode and change time. Windows generations
/// include the volume serial number, the 128-bit file id and the change time,
/// read through one attribute-only open. Other platforms, and Windows
/// filesystems which report no file id or change time, hash the file through
/// bounded buffers because length and mtime do not identify replaced content.
/// These reads consume the scan-work budget and cost a full read per unpinned
/// snapshot; callers with immutable backing objects should implement
/// [`SourceAccess`] with their own stable generations to retain read-free
/// reassessment.
#[derive(Debug, Default)]
pub struct DiskSourceAccess {
    paths: BTreeMap<SourceId, PathBuf>,
    options: ExecutionOptions,
    handles: Arc<ReadHandles>,
}

impl DiskSourceAccess {
    /// Share the engine's allocation, cancellation, and handle controls.
    pub fn with_options(options: ExecutionOptions) -> Self {
        Self {
            paths: BTreeMap::new(),
            options,
            handles: Arc::default(),
        }
    }

    /// Register a caller-selected path. File selection and containment belong to
    /// the caller; PAR3 paths are never interpreted by this registry.
    pub fn insert(&mut self, id: SourceId, path: PathBuf) {
        let closed = self.handles.lock().remove(id);
        drop(closed);
        self.paths.insert(id, path);
    }

    fn path(&self, id: SourceId) -> io::Result<&PathBuf> {
        self.paths
            .get(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unregistered PAR3 source"))
    }

    fn cached_handles(&self) -> usize {
        if cfg!(any(unix, windows)) {
            CACHED_READ_HANDLES.min(self.options.open_handles.min(self.options.handles.limit()) / 4)
        } else {
            0
        }
    }
}

/// Most read handles one disk registry keeps open between positioned reads.
const CACHED_READ_HANDLES: usize = 8;

/// The file a path or handle names, used to tell whether a cached handle still
/// reads what the path does. Bytes and length are not part of it: a handle and
/// a path naming the same file always read the same bytes.
type FileIdentity = (u64, u64);

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

/// Fold a volume serial number and 128-bit file id into a [`FileIdentity`].
/// ReFS ids use all 128 bits, so the whole of both is hashed rather than
/// truncated: equal identities name the same file but for a 2^-128 collision.
#[cfg(windows)]
fn file_identity(volume: u64, id: &[u8; 16]) -> FileIdentity {
    let mut hash = blake3::Hasher::new();
    hash.update(&volume.to_le_bytes());
    hash.update(id);
    let bytes = hash.finalize();
    let (first, second) = bytes.as_bytes()[..16].split_at(8);
    (
        u64::from_le_bytes(first.try_into().expect("eight bytes")),
        u64::from_le_bytes(second.try_into().expect("eight bytes")),
    )
}

/// The file an open handle reads.
fn handle_identity(file: &File) -> Option<FileIdentity> {
    #[cfg(unix)]
    {
        file.metadata().ok().as_ref().and_then(file_identity)
    }
    #[cfg(windows)]
    {
        crate::repair_tree::windows::file_id(file.as_std())
            .ok()
            .flatten()
            .map(|(volume, id)| file_identity(volume, &id))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        None
    }
}

/// What a snapshot learns about the file a path names.
struct DiskStat {
    metadata: std::fs::Metadata,
    /// Identity and change time, `None` where the filesystem lacks either.
    #[cfg(windows)]
    stamp: Option<crate::repair_tree::windows::FileStamp>,
}

impl DiskStat {
    #[cfg(not(windows))]
    fn of(path: &std::path::Path) -> io::Result<Self> {
        Ok(Self {
            metadata: std::fs::metadata(path)?,
        })
    }

    // One attribute-only open, as `std::fs::metadata` itself makes on Windows,
    // so the metadata, identity and change time all describe one file. No data
    // access is requested, so no sharing mode can refuse it or be refused by it.
    // Backup semantics open a directory too, refused as not a file like on Unix.
    #[cfg(windows)]
    fn of(path: &std::path::Path) -> io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_ALL: u32 = 7;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let file = std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let metadata = file.metadata()?;
        let stamp = if metadata.is_file() {
            crate::repair_tree::windows::file_stamp(&file)?
        } else {
            None
        };
        Ok(Self { metadata, stamp })
    }

    fn identity(&self) -> Option<FileIdentity> {
        if !self.metadata.is_file() {
            return None;
        }
        #[cfg(unix)]
        {
            file_identity(&self.metadata)
        }
        #[cfg(windows)]
        {
            self.stamp
                .as_ref()
                .map(|stamp| file_identity(stamp.volume, &stamp.id))
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }
}

/// Positioned-read handles kept open between calls, least recently used closed
/// first.
///
/// A cached handle keeps reading the file it opened even after the path is
/// replaced, so a snapshot that finds the path naming another file closes it.
/// A handle opened before such a snapshot is never cached: each source's
/// epoch advances whenever its snapshots see a different file, and a handle
/// is admitted only if no such change happened while it was being opened.
#[derive(Default)]
struct ReadHandles {
    slots: Mutex<ReadSlots>,
    registered: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for ReadHandles {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReadHandles")
    }
}

#[derive(Default)]
struct ReadSlots {
    sources: HashMap<SourceId, ReadSlot>,
    open: usize,
    clock: u64,
}

#[derive(Default)]
struct ReadSlot {
    handle: Option<CachedRead>,
    /// The file the path named at the last snapshot.
    seen: Option<FileIdentity>,
    epoch: u64,
}

struct CachedRead {
    file: Arc<File>,
    identity: FileIdentity,
    used: u64,
}

impl ReadHandles {
    fn lock(&self) -> std::sync::MutexGuard<'_, ReadSlots> {
        self.slots.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// The cached handle, or the epoch an uncached open must still match.
    fn lookup(&self, source: SourceId) -> Result<Arc<File>, u64> {
        let mut slots = self.lock();
        slots.clock += 1;
        let clock = slots.clock;
        match slots.sources.get_mut(&source) {
            Some(ReadSlot {
                handle: Some(cached),
                ..
            }) => {
                cached.used = clock;
                Ok(Arc::clone(&cached.file))
            }
            Some(slot) => Err(slot.epoch),
            None => Err(0),
        }
    }

    /// Cache a freshly opened handle unless the path changed while opening it.
    fn offer(
        self: &Arc<Self>,
        source: SourceId,
        epoch: u64,
        file: &Arc<File>,
        capacity: usize,
        budget: &crate::runtime::HandleBudget,
    ) {
        // Held open on a volume without POSIX unlink and rename, a handle would
        // leave a deleted source pending deletion (its next snapshot refused as
        // PermissionDenied) and refuse renames over it, installs included.
        #[cfg(windows)]
        if !crate::repair_tree::windows::posix_unlink_rename(file.as_std()) {
            return;
        }
        let Some(identity) = handle_identity(file) else {
            return;
        };
        let mut slots = self.lock();
        let (cached, current, seen) = slots.sources.get(&source).map_or((false, 0, None), |slot| {
            (slot.handle.is_some(), slot.epoch, slot.seen)
        });
        if cached || current != epoch || seen.is_some_and(|seen| seen != identity) {
            return;
        }
        let evicted = (slots.open >= capacity)
            .then(|| slots.take_lru(|_| true))
            .flatten();
        slots.open += 1;
        let used = slots.clock;
        slots.sources.entry(source).or_default().handle = Some(CachedRead {
            file: Arc::clone(file),
            identity,
            used,
        });
        drop(slots);
        drop(evicted);
        if !self
            .registered
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            let weak: std::sync::Weak<Self> = Arc::downgrade(self);
            budget.register_idle(weak);
        }
    }

    /// Record which file the path names now, closing a handle on another one.
    fn observe(&self, source: SourceId, identity: Option<FileIdentity>) {
        let mut slots = self.lock();
        let slot = slots.sources.entry(source).or_default();
        let stale = slot
            .handle
            .take_if(|cached| Some(cached.identity) != identity);
        if slot.seen != identity {
            slot.seen = identity;
            slot.epoch += 1;
        }
        if stale.is_some() {
            slots.open -= 1;
        }
        drop(slots);
        drop(stale);
    }

    /// Close `file` if it is still the cached handle for `source`.
    fn forget(&self, source: SourceId, file: &Arc<File>) {
        let mut slots = self.lock();
        let stale = slots.sources.get_mut(&source).and_then(|slot| {
            slot.handle
                .take_if(|cached| Arc::ptr_eq(&cached.file, file))
        });
        if stale.is_some() {
            slots.open -= 1;
        }
        drop(slots);
        drop(stale);
    }
}

impl ReadSlots {
    fn take_lru(&mut self, eligible: impl Fn(&CachedRead) -> bool) -> Option<CachedRead> {
        let source = self
            .sources
            .iter()
            .filter_map(|(source, slot)| Some((*source, slot.handle.as_ref()?)))
            .filter(|(_, cached)| eligible(cached))
            .min_by_key(|(_, cached)| cached.used)?
            .0;
        let cached = self.sources.get_mut(&source)?.handle.take();
        self.open -= 1;
        cached
    }

    fn remove(&mut self, source: SourceId) -> Option<ReadSlot> {
        let slot = self.sources.remove(&source)?;
        if slot.handle.is_some() {
            self.open -= 1;
        }
        Some(slot)
    }
}

impl crate::runtime::IdleHandles for ReadHandles {
    // Only a handle no read is using releases its lease when closed. Never
    // waits: the caller may be this registry, opening another file.
    fn close_idle(&self) -> bool {
        let Ok(mut slots) = self.slots.try_lock() else {
            return false;
        };
        let closed = slots.take_lru(|cached| Arc::strong_count(&cached.file) == 1);
        drop(slots);
        closed.is_some()
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
            .reserve_as(
                crate::runtime::MemoryCategory::CarrierPackets,
                std::mem::size_of::<PinnedDiskSource>(),
            )
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
        // The same generation an unpinned snapshot computes, from this handle.
        let mut hash = disk_metadata_hash(&metadata);
        match crate::repair_tree::windows::file_stamp(file.as_std())? {
            Some(stamp) => hash_file_stamp(&stamp, &mut hash),
            None => hash_open_disk_contents(&mut file, source, &metadata, options, &mut hash)
                .map_err(EngineError::into_io)?,
        }
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
        let stat = DiskStat::of(path);
        if self.cached_handles() != 0 {
            let identity = stat.as_ref().ok().and_then(DiskStat::identity);
            self.handles.observe(source, identity);
        }
        let stat = match stat {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = &stat.metadata;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PAR3 source is not a regular file",
            ));
        }
        #[allow(unused_mut)]
        let mut hash = disk_metadata_hash(metadata);
        #[cfg(windows)]
        match &stat.stamp {
            Some(stamp) => hash_file_stamp(stamp, &mut hash),
            None => hash_disk_contents(path, source, metadata, &self.options, &mut hash)
                .map_err(EngineError::into_io)?,
        }
        #[cfg(not(any(unix, windows)))]
        hash_disk_contents(path, source, metadata, &self.options, &mut hash)
            .map_err(EngineError::into_io)?;
        Ok(Some(SourceSnapshot {
            len: metadata.len(),
            generation: disk_generation(hash),
        }))
    }

    fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        let path = self.path(source)?;
        let capacity = self.cached_handles();
        if capacity == 0 {
            let file = File::open(path, &self.options).map_err(EngineError::into_io)?;
            return file.read_at(offset, out);
        }
        self.options.validate().map_err(EngineError::into_io)?;
        let epoch = match self.handles.lookup(source) {
            Ok(file) => match file.read_at(offset, out) {
                Ok(read) => return Ok(read),
                // The handle may have gone stale under a replaced path, as on
                // network mounts; read through the path as before.
                Err(_) => {
                    self.handles.forget(source, &file);
                    self.handles.lookup(source).err().unwrap_or(0)
                }
            },
            Err(epoch) => epoch,
        };
        let file = Arc::new(File::open(path, &self.options).map_err(EngineError::into_io)?);
        self.handles
            .offer(source, epoch, &file, capacity, &self.options.handles);
        file.read_at(offset, out)
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

    /// The cached read handle when there is one, so the file is not opened
    /// again; otherwise a fresh read-only handle, cached as a positioned read
    /// would cache it, so the reads that follow do not open the file again.
    fn open_file(&self, source: SourceId) -> io::Result<Option<SourceFile>> {
        let path = self.path(source)?;
        let capacity = self.cached_handles();
        if capacity == 0 {
            let file = File::open(path, &self.options).map_err(EngineError::into_io)?;
            return Ok(Some(SourceFile(Arc::new(file))));
        }
        self.options.validate().map_err(EngineError::into_io)?;
        let epoch = match self.handles.lookup(source) {
            Ok(file) => return Ok(Some(SourceFile(file))),
            Err(epoch) => epoch,
        };
        let file = Arc::new(File::open(path, &self.options).map_err(EngineError::into_io)?);
        self.handles
            .offer(source, epoch, &file, capacity, &self.options.handles);
        Ok(Some(SourceFile(file)))
    }
}

fn disk_generation(hash: blake3::Hasher) -> u64 {
    u64::from_le_bytes(
        hash.finalize().as_bytes()[..8]
            .try_into()
            .expect("eight bytes"),
    )
}

/// The snapshot [`DiskSourceAccess`] reports for a file with `metadata`. On
/// Unix it depends on the metadata alone, so a handle to a file says whether
/// that file is the one a disk snapshot was taken of.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn disk_snapshot(metadata: &std::fs::Metadata) -> SourceSnapshot {
    SourceSnapshot {
        len: metadata.len(),
        generation: disk_generation(disk_metadata_hash(metadata)),
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

/// Fold a Windows file's identity and change time into its generation, the
/// counterpart of Unix's device, inode and ctime.
#[cfg(windows)]
fn hash_file_stamp(stamp: &crate::repair_tree::windows::FileStamp, hash: &mut blake3::Hasher) {
    hash.update(&stamp.volume.to_le_bytes());
    hash.update(&stamp.id);
    hash.update(&stamp.change.to_le_bytes());
}

// Without a file identity and change counter, as on WASI or a Windows
// filesystem reporting neither, hash bytes rather than reuse evidence based
// only on length and mtime.
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

/// The scan-work refusal of a generation hash.
#[cfg(any(not(unix), test))]
const GENERATION_HASH_WORK: &str = "cumulative scanning work (source generation hashes)";

#[cfg(any(not(unix), test))]
fn hash_open_disk_contents(
    file: &mut File,
    source: SourceId,
    expected: &std::fs::Metadata,
    options: &ExecutionOptions,
    hash: &mut blake3::Hasher,
) -> EngineResult<()> {
    // Name what spent the scan-work budget: a repair stopped here ran out
    // hashing source generations, not scanning carriers.
    let charge = |bytes| {
        options
            .scan_work
            .charge(bytes)
            .map_err(|_| EngineError::resource_limit(GENERATION_HASH_WORK))
    };
    let size = options.stripe_bytes.min(64 << 10);
    let _memory = options
        .memory
        .reserve_as(crate::runtime::MemoryCategory::SourceScratch, size)?;
    let mut buffer = vec![0; size];
    let mut remaining = expected.len();
    while remaining != 0 {
        options.cancel.check()?;
        let take = remaining.min(size as u64) as usize;
        charge(take)?;
        let count = file.read(&mut buffer[..take])?;
        if count == 0 {
            return Err(EngineError::SourceChanged(source));
        }
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let current = file.metadata()?;
    charge(1)?;
    if file.read(&mut [0])? != 0
        || current.len() != expected.len()
        || current.modified()? != expected.modified()?
    {
        return Err(EngineError::SourceChanged(source));
    }
    Ok(())
}

// Settle the generation once under the sharing lock, which keeps it immutable.
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
        use std::io::{Seek, SeekFrom};
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

/// Snapshot checks owed for bytes already read and not yet vouched for.
///
/// A pass reading many ranges of a source records each read here and settles
/// once, after its last read and before anything derived from those reads is
/// verified, installed or carried into the next pass, so each source is checked
/// once, after every read the output can depend on.
#[derive(Default)]
pub(crate) struct OwedChecks(Mutex<std::collections::BTreeSet<(SourceId, u64, u64)>>);

impl OwedChecks {
    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeSet<(SourceId, u64, u64)>> {
        self.0.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn owe(&self, source: SourceId, snapshot: SourceSnapshot) {
        self.lock()
            .insert((source, snapshot.len, snapshot.generation));
    }

    /// Check every owed source once. Call after the last read an output may
    /// depend on and before that output is relied on.
    pub(crate) fn settle(&self, access: &dyn SourceAccess) -> EngineResult<()> {
        let mut owed = self.lock();
        for &(source, len, generation) in owed.iter() {
            ensure_snapshot(access, source, SourceSnapshot { len, generation })?;
        }
        owed.clear();
        Ok(())
    }

    /// [`Self::settle`], passing over `skip`: sources whose bytes are proven
    /// some other way.
    pub(crate) fn settle_except(
        &self,
        access: &dyn SourceAccess,
        skip: &[SourceId],
    ) -> EngineResult<()> {
        if skip.is_empty() {
            return self.settle(access);
        }
        self.lock().retain(|(source, _, _)| !skip.contains(source));
        self.settle(access)
    }
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
        // Pinning a Windows carrier settles its generation from its identity
        // and change time, so it reads no more than an unpinned Unix scan.
        let expected_reads = size as u64;
        let expected_work = expected_reads;
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
            Err(EngineError::ResourceLimit(crate::runtime::ResourceLimit {
                what: "cumulative scanning work",
                ..
            }))
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
            Err(EngineError::ResourceLimit(crate::runtime::ResourceLimit {
                what: GENERATION_HASH_WORK,
                ..
            }))
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

    #[cfg(any(unix, windows))]
    #[test]
    fn disk_snapshots_read_nothing_and_see_rewrites_keeping_length_and_mtime() {
        use std::io::Write;
        let directory = TestDirectory::new();
        let path = directory.path().join("source");
        std::fs::write(&path, b"original").unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        // A snapshot that read the file would exceed this budget.
        let options = ExecutionOptions {
            scan_work: crate::runtime::ScanWorkBudget::new(0),
            ..ExecutionOptions::default()
        };
        let mut access = DiskSourceAccess::with_options(options.clone());
        access.insert(SourceId(1), path.clone());
        let before = access.snapshot(SourceId(1)).unwrap().unwrap();
        assert_eq!(access.snapshot(SourceId(1)).unwrap(), Some(before));
        let mut out = [0; 8];
        assert_eq!(access.read_at(SourceId(1), 0, &mut out).unwrap(), 8);
        // Change times move at the clock's granularity. The cached read
        // handle does not refuse this writer.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all(b"rewrite!").unwrap();
        file.set_modified(modified).unwrap();
        drop(file);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
        let after = access.snapshot(SourceId(1)).unwrap().unwrap();
        assert_eq!(after.len, before.len);
        assert_ne!(after.generation, before.generation);
        // Still the same file, so the cached handle stays and reads the new bytes.
        assert_eq!(access.read_at(SourceId(1), 0, &mut out).unwrap(), 8);
        assert_eq!(&out, b"rewrite!");
        // A volume without POSIX unlink and rename caches no handle, so there
        // each read opens the file.
        #[cfg(windows)]
        let cached =
            crate::repair_tree::windows::posix_unlink_rename(&std::fs::File::open(&path).unwrap());
        #[cfg(unix)]
        let cached = true;
        assert_eq!(options.diagnostics.file_opens(), if cached { 1 } else { 2 });
        assert_eq!(options.diagnostics.file_io().read_bytes, 16);
        assert_eq!(options.scan_work.used(), 0);
        // Nor does it keep the file from being deleted.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(access.snapshot(SourceId(1)).unwrap(), None);
        assert_eq!(options.handles.used(), 0);
    }
}
