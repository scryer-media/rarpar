//! Scratch-file windows for `rarpar xz` decodes.
//!
//! A decoder keeps its dictionary (for a threaded decode, the whole block) in
//! one buffer. One larger than `--memory-mib` is refused, unless
//! `--scratch-mib` gives a disk budget: it is then decoded in a file of that
//! size, created in the temporary directory, removed from it at once, and
//! mapped into memory. The file lives only as long as its block: the system
//! reclaims it when the map is dropped, and on any exit.
//!
//! The budget bounds every scratch file alive at once, summed, so a hostile
//! stream declaring a 4 GiB dictionary, or many large blocks decoded in
//! parallel, cannot fill the temporary volume. A window the budget cannot
//! take fails the decode as a resource error before any file is made.
//!
//! The file's storage is reserved before it is mapped. A sparse file on a
//! full file system would map, and then fault on the decoder's first write
//! to a page with no block behind it (SIGBUS) instead of failing the decode.

use std::fs::File;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use lzma_turbo::{WindowAllocator, WindowBacking, WindowMemory};
use memmap2::MmapMut;

/// Lends every window over `in_memory_limit` bytes from a mapped scratch
/// file, with at most `budget` bytes of them alive at once.
pub fn scratch_backing(in_memory_limit: u64, budget: u64) -> WindowBacking {
    WindowBacking::new(Arc::new(ScratchFiles::new(budget)), in_memory_limit).with_max_len(budget)
}

/// Makes one unlinked, mapped scratch file per window, within a budget of
/// bytes shared by every window alive.
struct ScratchFiles {
    left: Arc<AtomicU64>,
    budget: u64,
}

impl ScratchFiles {
    fn new(budget: u64) -> Self {
        Self {
            left: Arc::new(AtomicU64::new(budget)),
            budget,
        }
    }
}

impl WindowAllocator for ScratchFiles {
    fn allocate(&self, len: usize) -> io::Result<Box<dyn WindowMemory>> {
        let bytes = len as u64;
        let taken = self
            .left
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(bytes)
            });
        if taken.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                format!(
                    "--scratch-mib {} is spent by the scratch files already open",
                    self.budget >> 20
                ),
            ));
        }
        let held = Held {
            left: Arc::clone(&self.left),
            bytes,
        };
        let file = tempfile::tempfile()?;
        reserve(&file, bytes)?;
        // SAFETY: the file was made by this call with no name in the file
        // system (on Windows, a random name deleted on close), and this is
        // its one handle, so nothing else resizes, writes or maps it while
        // the map lives.
        let map = unsafe { MmapMut::map_mut(&file) }?;
        Ok(Box::new(ScratchWindow {
            map,
            _file: file,
            _held: held,
        }))
    }
}

/// Bytes of the budget a window holds, returned when it drops, including
/// when making its file fails.
struct Held {
    left: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.left.fetch_add(self.bytes, Ordering::AcqRel);
    }
}

/// Gives `file`, new and empty, `len` bytes with storage behind every one,
/// or the error that stopped it (no space, a quota).
fn reserve(file: &File, len: u64) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;

        let Ok(size) = libc::off_t::try_from(len) else {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        };
        // SAFETY: a plain call on a descriptor this process owns.
        match unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, size) } {
            0 => return Ok(()),
            // A file system that cannot preallocate: write the bytes below.
            libc::EOPNOTSUPP | libc::EINVAL => {}
            code => return Err(io::Error::from_raw_os_error(code)),
        }
    }
    write_zeros(file, len)
}

/// Writes `len` zero bytes from the start of `file`, so the file system
/// allocates them now, when running out is still an error.
fn write_zeros(mut file: &File, len: u64) -> io::Result<()> {
    const CHUNK: usize = 1 << 20;
    let zeros = vec![0u8; CHUNK];
    let mut left = len;
    while left > 0 {
        let n = usize::try_from(left).map_or(CHUNK, |left| left.min(CHUNK));
        file.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    Ok(())
}

/// A mapped scratch file, unmapped and closed on drop.
struct ScratchWindow {
    map: MmapMut,
    _file: File,
    _held: Held,
}

// SAFETY: the map covers the whole file, `len()` bytes, which `allocate`
// sized to at least the length asked for. Mapped file pages read as the
// file's contents, zero for a file just reserved, so every byte is
// initialized. The mapping's address does not move when the `Box` does, and
// it is unmapped only when this value drops. Nothing else holds the file or
// the map, so the decoder has the memory to itself.
unsafe impl WindowMemory for ScratchWindow {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.map.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scratch_window_is_the_size_asked_and_writable() {
        let mut window = ScratchFiles::new(3 << 20).allocate(3 << 20).unwrap();
        assert_eq!(window.len(), 3 << 20);
        let ptr = window.as_mut_ptr();
        // SAFETY: the contract above: `len()` writable bytes at `ptr`.
        let bytes = unsafe { std::slice::from_raw_parts_mut(ptr, window.len()) };
        bytes.fill(0xA5);
        assert!(bytes.iter().all(|&b| b == 0xA5));
    }

    #[test]
    fn the_budget_bounds_the_windows_alive_at_once() {
        let files = ScratchFiles::new(3 << 20);
        let first = files.allocate(2 << 20).unwrap();
        let refused = files.allocate(2 << 20).err().unwrap();
        assert_eq!(refused.kind(), io::ErrorKind::QuotaExceeded);
        let _second = files.allocate(1 << 20).unwrap();
        drop(first);
        let _third = files.allocate(2 << 20).unwrap();
    }

    #[test]
    fn write_zeros_reserves_every_byte_of_an_odd_length() {
        let file = tempfile::tempfile().unwrap();
        write_zeros(&file, (2 << 20) + 7).unwrap();
        assert_eq!(file.metadata().unwrap().len(), (2 << 20) + 7);
    }
}
