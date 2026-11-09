//! The RAR 2.9 PPMd model arena in a caller's [`WindowAllocator`] memory.
//!
//! `ppmd-turbo` lends an arena through its own allocator trait. This adapts
//! the caller's window allocator to it, so one allocator serves the LZ window
//! and the PPMd arena under one memory contract, and keeps `ppmd-turbo`'s
//! types out of this crate's public API.

use std::io;
use std::sync::{Arc, Mutex};

use ppmd_turbo::{ArenaAllocError, ArenaAllocator, ArenaMemory, ErrorKind as PpmErrorKind};

use crate::error::RarError;
use crate::window_memory::{WindowAllocator, WindowMemory};

/// Window memory handed to `ppmd-turbo` as an arena.
struct LentArena(Box<dyn WindowMemory>);

// SAFETY: `WindowMemory`'s contract is `ArenaMemory`'s: a non-null pointer to
// at least the length asked for of initialized (to any value), readable and
// writable bytes, at an address that stays put until the value is dropped,
// moves of the `Box` included, and exclusive to its holder until then. Both
// accessors forward to the window memory unchanged, and `ppmd-turbo`, like
// the window, calls each once, so the window allocator's implementation is
// held to exactly what it promised.
unsafe impl ArenaMemory for LentArena {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// The caller's window allocator, asked for PPMd arenas.
///
/// One lender belongs to one decoder. `ppmd-turbo` keeps only the
/// `io::ErrorKind` of an allocator's error, so the lender keeps the error
/// itself for the decoder to report in
/// [`RarError::WindowAllocatorFailed`].
pub(crate) struct ArenaLender {
    allocator: Arc<dyn WindowAllocator>,
    refusal: Mutex<Option<io::Error>>,
}

impl ArenaLender {
    pub(crate) fn new(allocator: Arc<dyn WindowAllocator>) -> Self {
        Self {
            allocator,
            refusal: Mutex::new(None),
        }
    }

    /// The error the allocator last refused with, if not yet taken.
    fn take_refusal(&self) -> Option<io::Error> {
        self.refusal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    /// The error for a `ppmd-turbo` error that may be a lent arena's, with
    /// the allocator's own error put back in when it refused.
    pub(crate) fn error(&self, err: RarError) -> RarError {
        match err {
            RarError::WindowAllocatorFailed { bytes, error } => RarError::WindowAllocatorFailed {
                bytes,
                error: self.take_refusal().unwrap_or(error),
            },
            other => other,
        }
    }
}

impl ArenaAllocator for ArenaLender {
    fn allocate(&self, len: usize) -> Result<Box<dyn ArenaMemory>, ArenaAllocError> {
        match self.allocator.allocate(len) {
            Ok(memory) => Ok(Box::new(LentArena(memory))),
            Err(error) => {
                // `ppmd-turbo` reads the kind from the error it is given and
                // drops the rest; the error itself waits here.
                let kind = error.kind();
                *self
                    .refusal
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
                Err(Box::new(io::Error::from(kind)))
            }
        }
    }
}

/// [`RarError::WindowAllocatorFailed`] for a lent arena `ppmd-turbo` could
/// not get or refused, in the shapes the lent window uses, or `None` for an
/// error that is not about lent memory.
///
/// An allocation failure that carries an `io::ErrorKind` came from an
/// allocator: the decoder's own memory reports none.
pub(crate) fn lent_arena_error(kind: PpmErrorKind) -> Option<RarError> {
    let (bytes, error) = match kind {
        PpmErrorKind::AllocationFailed {
            bytes,
            io_kind: Some(io_kind),
            ..
        } => (bytes, io::Error::from(io_kind)),
        PpmErrorKind::ArenaMemoryLength {
            requested,
            provided,
            ..
        } => {
            let detail = if provided < requested {
                format!("allocator returned {provided} bytes")
            } else if provided > isize::MAX as u64 {
                format!("allocator returned {provided} bytes, more than isize::MAX")
            } else {
                "allocator returned a null pointer".to_owned()
            };
            (requested, io::Error::other(detail))
        }
        _ => return None,
    };
    Some(RarError::WindowAllocatorFailed { bytes, error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ppmd_turbo::{Params, RarPpmd, Symbol};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Heap memory filled with non-zero junk, counted while it lives; it can
    /// report a shorter length than it holds.
    struct Junk {
        bytes: Box<[u8]>,
        reported: usize,
        live: Arc<AtomicUsize>,
    }

    // SAFETY: a heap buffer this value alone owns, at least `reported` bytes
    // long whenever the allocator below hands it out as valid; moving the
    // box does not move it.
    unsafe impl WindowMemory for Junk {
        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }

        fn len(&self) -> usize {
            self.reported
        }
    }

    impl Drop for Junk {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct JunkAllocator {
        live: Arc<AtomicUsize>,
        asked: AtomicUsize,
        /// Report this many bytes fewer than were asked for.
        short_by: usize,
        refuse: bool,
    }

    impl WindowAllocator for JunkAllocator {
        fn allocate(&self, len: usize) -> io::Result<Box<dyn WindowMemory>> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.refuse {
                return Err(io::Error::new(io::ErrorKind::StorageFull, "scratch full"));
            }
            let bytes: Box<[u8]> = (0..len)
                .map(|i| (i as u8).wrapping_mul(29) | 0x41)
                .collect();
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Junk {
                bytes,
                reported: len - self.short_by,
                live: Arc::clone(&self.live),
            }))
        }
    }

    /// One MiB, order 2: the smallest RAR model.
    fn params() -> Params {
        Params::rar(2, 1).unwrap()
    }

    /// Every byte the decoder gives for `input` after starting a model, and
    /// the error it stopped on.
    fn decode(ppm: &mut RarPpmd, input: &[u8]) -> (Vec<u8>, Option<String>) {
        if let Err(err) = ppm.start_block(Some(params())) {
            return (Vec::new(), Some(err.to_string()));
        }
        let mut out = Vec::new();
        let mut at = 0;
        while out.len() < 256 {
            match ppm.next_symbol(&input[at..], true) {
                Ok((consumed, Symbol::Byte(byte))) => {
                    at += consumed;
                    out.push(byte);
                }
                // Only the coder's init bytes went.
                Ok((consumed, Symbol::NeedInput)) if consumed != 0 => at += consumed,
                Ok((_, _)) => break,
                Err(err) => return (out, Some(err.to_string())),
            }
        }
        (out, None)
    }

    fn lent(allocator: &Arc<JunkAllocator>) -> (RarPpmd, Arc<ArenaLender>) {
        let lender = Arc::new(ArenaLender::new(allocator.clone()));
        let mut ppm = RarPpmd::new();
        ppm.set_arena_allocator(0, lender.clone());
        (ppm, lender)
    }

    #[test]
    fn junk_filled_lent_arena_decodes_like_an_owned_one() {
        let input: Vec<u8> = (0..512u32).map(|i| ((i * 7919) >> 3) as u8).collect();
        let expected = decode(&mut RarPpmd::new(), &input);
        assert!(!expected.0.is_empty());

        let allocator = Arc::new(JunkAllocator::default());
        let (mut ppm, _lender) = lent(&allocator);
        assert_eq!(decode(&mut ppm, &input), expected);
        assert_eq!(allocator.asked.load(Ordering::SeqCst), 1);
        assert_eq!(allocator.live.load(Ordering::SeqCst), 1);
        drop(ppm);
        assert_eq!(allocator.live.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn short_lent_memory_is_refused_and_released() {
        let allocator = Arc::new(JunkAllocator {
            short_by: 1,
            ..JunkAllocator::default()
        });
        let (mut ppm, _lender) = lent(&allocator);
        let err = ppm.start_block(Some(params())).unwrap_err();
        assert_eq!(allocator.live.load(Ordering::SeqCst), 0);
        match lent_arena_error(err.kind) {
            Some(RarError::WindowAllocatorFailed { bytes, error }) => {
                assert_eq!(bytes, 1 << 20);
                assert_eq!(
                    error.to_string(),
                    format!("allocator returned {} bytes", bytes - 1)
                );
            }
            other => panic!("expected WindowAllocatorFailed, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_keeps_the_allocators_error() {
        let allocator = Arc::new(JunkAllocator {
            refuse: true,
            ..JunkAllocator::default()
        });
        let (mut ppm, lender) = lent(&allocator);
        let err = ppm.start_block(Some(params())).unwrap_err();
        let err = lender.error(lent_arena_error(err.kind).expect("a lent arena error"));
        match err {
            RarError::WindowAllocatorFailed { bytes, error } => {
                assert_eq!(bytes, 1 << 20);
                assert_eq!(error.kind(), io::ErrorKind::StorageFull);
                assert_eq!(error.to_string(), "scratch full");
            }
            other => panic!("expected WindowAllocatorFailed, got {other:?}"),
        }
    }
}
