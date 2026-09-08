//! Positioned access to immutable generations of disk, memory or virtual bytes.

use std::collections::BTreeMap;
use std::fs::File;
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

/// Disk source registry. No handles are retained between operations.
#[derive(Debug, Default)]
pub struct DiskSourceAccess {
    paths: BTreeMap<SourceId, PathBuf>,
}

impl DiskSourceAccess {
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
        let mut file = File::open(self.path(source)?)?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(out)
    }

    fn next_available(&self, source: SourceId, offset: u64) -> io::Result<Option<Range<u64>>> {
        Ok(self
            .snapshot(source)?
            .and_then(|value| (offset < value.len).then_some(offset..value.len)))
    }

    fn open_sequential(&self, source: SourceId) -> io::Result<Option<Box<dyn Read + Send>>> {
        Ok(Some(Box::new(File::open(self.path(source)?)?)))
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
        let read = access.read_at(source, at, &mut out[done..])?;
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
