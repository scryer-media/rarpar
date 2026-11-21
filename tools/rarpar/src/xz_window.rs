//! Scratch-file windows for `rarpar xz` decodes.
//!
//! A decoder keeps its dictionary (for a threaded decode, the whole block) in
//! one buffer. One larger than `--memory-mib` would otherwise be refused; it
//! is decoded instead in a file of that size, created in the temporary
//! directory, removed from it at once, and mapped into memory. The file
//! lives only as long as its block: the system reclaims it when the map is
//! dropped, and on any exit.
//!
//! The file's storage is reserved before it is mapped. A sparse file on a
//! full file system would map, and then fault on the decoder's first write
//! to a page with no block behind it (SIGBUS) instead of failing the decode.

use std::fs::File;
use std::io::{self, Write};
use std::sync::Arc;

use lzma_turbo::{WindowAllocator, WindowBacking, WindowMemory};
use memmap2::MmapMut;

/// Lends every window over `in_memory_limit` bytes from a mapped scratch
/// file.
pub fn scratch_backing(in_memory_limit: u64) -> WindowBacking {
    WindowBacking::new(Arc::new(ScratchFiles), in_memory_limit)
}

/// Makes one unlinked, mapped scratch file per window.
struct ScratchFiles;

impl WindowAllocator for ScratchFiles {
    fn allocate(&self, len: usize) -> io::Result<Box<dyn WindowMemory>> {
        let file = tempfile::tempfile()?;
        reserve(&file, len as u64)?;
        // SAFETY: the file was made by this call with no name in the file
        // system (on Windows, a random name deleted on close), and this is
        // its one handle, so nothing else resizes, writes or maps it while
        // the map lives.
        let map = unsafe { MmapMut::map_mut(&file) }?;
        Ok(Box::new(ScratchWindow { map, _file: file }))
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
        let mut window = ScratchFiles.allocate(3 << 20).unwrap();
        assert_eq!(window.len(), 3 << 20);
        let ptr = window.as_mut_ptr();
        // SAFETY: the contract above: `len()` writable bytes at `ptr`.
        let bytes = unsafe { std::slice::from_raw_parts_mut(ptr, window.len()) };
        bytes.fill(0xA5);
        assert!(bytes.iter().all(|&b| b == 0xA5));
    }

    #[test]
    fn write_zeros_reserves_every_byte_of_an_odd_length() {
        let file = tempfile::tempfile().unwrap();
        write_zeros(&file, (2 << 20) + 7).unwrap();
        assert_eq!(file.metadata().unwrap().len(), (2 << 20) + 7);
    }
}
