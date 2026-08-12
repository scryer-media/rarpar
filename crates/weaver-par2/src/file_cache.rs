use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

const LARGE_FILE_CACHE_ADVICE_MIN_BYTES: u64 = 64 * 1024 * 1024;

/// Multi-pass operations (repair: verify then accumulate then re-verify) read
/// the same payload more than once. Evicting after each pass forces the next
/// pass back to physical storage — on network block storage that re-read
/// dominates the whole operation. While at least one deferral scope is
/// active, evictions are recorded instead of issued; the last scope to drop
/// evicts each recorded file once. The drain is advisory and approximate:
/// it re-opens by path and evicts the whole file, so a range-limited drop
/// becomes whole-file, and a file renamed, unlinked, or shrunk below the
/// size gate before the drain is simply not evicted.
static EVICTION_DEFERRAL_DEPTH: AtomicUsize = AtomicUsize::new(0);

fn deferred_evictions() -> &'static Mutex<HashSet<PathBuf>> {
    static DEFERRED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    DEFERRED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// RAII guard deferring page-cache eviction until the outermost scope drops.
///
/// Evictions requested after the last scope has dropped are issued
/// immediately, exactly as if no scope had existed — keep the scope alive
/// for the whole multi-pass operation. The depth is process-global: scopes
/// held by concurrent operations combine, and the last one out drains.
pub struct CacheEvictionDeferral(());

impl CacheEvictionDeferral {
    /// Open a deferral scope. Callers running a multi-pass operation (an
    /// external verify-then-repair flow, for example) hold this across every
    /// pass so intermediate reads stay cached until the operation completes.
    ///
    /// The guard must be dropped: leaking it (`mem::forget`, a leaked task
    /// still holding it) leaves the depth raised and disables the eviction
    /// discipline for the rest of the process.
    pub fn acquire() -> Self {
        EVICTION_DEFERRAL_DEPTH.fetch_add(1, Ordering::SeqCst);
        Self(())
    }
}

impl Drop for CacheEvictionDeferral {
    fn drop(&mut self) {
        if EVICTION_DEFERRAL_DEPTH.fetch_sub(1, Ordering::SeqCst) != 1 {
            return;
        }
        let drained: Vec<PathBuf> = {
            let mut deferred = deferred_evictions()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            deferred.drain().collect()
        };
        for path in drained {
            evict_path_now(&path);
        }
    }
}

fn eviction_deferred(path: &Path) -> bool {
    if EVICTION_DEFERRAL_DEPTH.load(Ordering::SeqCst) == 0 {
        return false;
    }
    deferred_evictions()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path.to_path_buf());
    true
}

fn evict_path_now(path: &Path) {
    // The drain runs from a Drop over paths recorded much earlier; a path
    // replaced by a FIFO would block a plain open forever, and following a
    // symlink swap would advise the wrong file. Advisory-only, so refuse
    // both rather than risk hanging after a successful operation.
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = File::open(path);
    let Ok(file) = opened else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if !metadata.is_file() || metadata.len() < LARGE_FILE_CACHE_ADVICE_MIN_BYTES {
        return;
    }
    log_cache_advice(
        "dontneed",
        path,
        raw_cache_advice(&file, 0, metadata.len(), CacheAdvice::DontNeed),
    );
}

pub(crate) struct CacheAdvisedReader {
    file: File,
    path: PathBuf,
    file_len: u64,
    touched: u64,
}

impl CacheAdvisedReader {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        advise_sequential(&file, path, file_len);
        Ok(Self {
            file,
            path: path.to_path_buf(),
            file_len,
            touched: 0,
        })
    }
}

impl Read for CacheAdvisedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.file.read(buf)?;
        self.touched = self.touched.saturating_add(read as u64);
        Ok(read)
    }
}

impl Drop for CacheAdvisedReader {
    fn drop(&mut self) {
        drop_touched_file_cache(&self.file, &self.path, self.file_len, 0, self.touched);
    }
}

pub(crate) fn read_to_vec(path: &Path) -> io::Result<Vec<u8>> {
    let mut reader = CacheAdvisedReader::open(path)?;
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    Ok(data)
}

pub(crate) fn advise_sequential(file: &File, path: &Path, len: u64) {
    advise_range_sequential(file, path, 0, len);
}

pub(crate) fn advise_range_sequential(file: &File, path: &Path, offset: u64, len: u64) {
    if len < LARGE_FILE_CACHE_ADVICE_MIN_BYTES {
        return;
    }
    log_cache_advice(
        "sequential",
        path,
        raw_cache_advice(file, offset, len, CacheAdvice::Sequential),
    );
}

pub(crate) fn drop_file_cache(file: &File, path: &Path, offset: u64, len: u64) {
    if len < LARGE_FILE_CACHE_ADVICE_MIN_BYTES {
        return;
    }
    if eviction_deferred(path) {
        return;
    }
    log_cache_advice(
        "dontneed",
        path,
        raw_cache_advice(file, offset, len, CacheAdvice::DontNeed),
    );
}

pub(crate) fn drop_touched_file_cache(
    file: &File,
    path: &Path,
    file_len: u64,
    offset: u64,
    touched: u64,
) {
    if file_len < LARGE_FILE_CACHE_ADVICE_MIN_BYTES || touched == 0 {
        return;
    }
    if eviction_deferred(path) {
        return;
    }
    log_cache_advice(
        "dontneed",
        path,
        raw_cache_advice(file, offset, touched, CacheAdvice::DontNeed),
    );
}

pub(crate) fn drop_path_cache(path: &Path) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let len = file.metadata().ok().map_or(0, |metadata| metadata.len());
    drop_file_cache(&file, path, 0, len);
}

fn log_cache_advice(operation: &'static str, path: &Path, result: io::Result<()>) {
    match result {
        Ok(()) => tracing::trace!(operation, path = %path.display(), "file cache advice applied"),
        Err(error) => {
            tracing::debug!(operation, path = %path.display(), error = %error, "file cache advice failed")
        }
    }
}

#[derive(Clone, Copy)]
enum CacheAdvice {
    Sequential,
    DontNeed,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn raw_cache_advice(file: &File, offset: u64, len: u64, advice: CacheAdvice) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let offset: libc::off_t = offset
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cache advice offset overflow"))?;
    let len: libc::off_t = len
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cache advice length overflow"))?;
    let advice = match advice {
        CacheAdvice::Sequential => libc::POSIX_FADV_SEQUENTIAL,
        CacheAdvice::DontNeed => libc::POSIX_FADV_DONTNEED,
    };
    let rc = unsafe { libc::posix_fadvise(file.as_raw_fd(), offset, len, advice) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn raw_cache_advice(_file: &File, _offset: u64, _len: u64, _advice: CacheAdvice) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_to_vec_preserves_contents() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), b"cache-advised payload").unwrap();

        assert_eq!(read_to_vec(temp.path()).unwrap(), b"cache-advised payload");
    }

    #[test]
    fn path_drop_swallows_missing_file() {
        drop_path_cache(Path::new("/definitely/missing/weaver/par2-cache.bin"));
    }

    // The deferral depth and deferred set are process-global; these tests
    // must not overlap with each other.
    static DEFERRAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn eviction_deferral_records_and_drains() {
        let _serial = DEFERRAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let temp = tempfile::NamedTempFile::new().unwrap();
        let file = File::open(temp.path()).unwrap();
        {
            let _outer = CacheEvictionDeferral::acquire();
            let _inner = CacheEvictionDeferral::acquire();
            assert!(EVICTION_DEFERRAL_DEPTH.load(Ordering::SeqCst) >= 2);
            // Above the size gate so the deferral path records the file.
            drop_file_cache(&file, temp.path(), 0, LARGE_FILE_CACHE_ADVICE_MIN_BYTES + 1);
            assert!(deferred_evictions().lock().unwrap().contains(temp.path()));
        }
        // Both scopes dropped: this test's entry drained without panicking.
        // (Assert on OUR path only — other tests in this binary may hold
        // their own scopes concurrently, keeping unrelated entries alive.)
        assert!(!deferred_evictions().lock().unwrap().contains(temp.path()));
    }

    #[test]
    fn below_threshold_drops_are_never_deferred() {
        let _serial = DEFERRAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let temp = tempfile::NamedTempFile::new().unwrap();
        let file = File::open(temp.path()).unwrap();
        let _scope = CacheEvictionDeferral::acquire();
        drop_file_cache(&file, temp.path(), 0, 1024);
        drop_touched_file_cache(&file, temp.path(), 1024, 0, 1024);
        assert!(!deferred_evictions().lock().unwrap().contains(temp.path()));
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    fn cache_advice_noops_on_unsupported_platforms() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let file = File::open(temp.path()).unwrap();

        assert!(raw_cache_advice(&file, 0, 0, CacheAdvice::Sequential).is_ok());
        assert!(raw_cache_advice(&file, 0, 0, CacheAdvice::DontNeed).is_ok());
    }
}
