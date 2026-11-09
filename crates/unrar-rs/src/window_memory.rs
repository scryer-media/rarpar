//! Caller-supplied memory for the LZ dictionary window.
//!
//! RAR5 and RAR7 archives may declare a dictionary of up to 64 GiB. By default
//! the decoder allocates the window on the heap, and [`Limits::max_dict_size`]
//! refuses any dictionary above it with [`RarError::DictionaryTooLarge`].
//!
//! An application that can back a large window with something other than RAM,
//! such as a memory-mapped scratch file, sets
//! [`Limits::window_allocator`]. A dictionary at or under
//! [`Limits::max_dict_size`] is still allocated on the heap, exactly as
//! without an allocator. A larger one, up to
//! [`Limits::max_allocated_dict_size`], is asked of the allocator instead of
//! being refused.
//!
//! This covers the LZ window of every format: RAR5/RAR7, RAR 2.9 LZ, and RAR
//! 1.5 to 2.6. The RAR 2.9 PPMd model arena is separate and is not allocated
//! here.
//!
//! # The memory contract
//!
//! [`WindowAllocator::allocate`] is asked for `len` bytes and returns a
//! [`WindowMemory`] that must give:
//!
//! - at least `len` bytes, readable and writable, starting at
//!   [`WindowMemory::as_mut_ptr`]; the decoder uses exactly the first `len`;
//! - the same address for as long as the value lives, including after the
//!   value itself (the `Box`) is moved: the memory must live outside the value,
//!   as a heap buffer or a mapping does;
//! - exclusive use by the decoder: nothing else reads or writes those bytes
//!   until the value is dropped.
//!
//! The memory does **not** need to be zeroed. The decoder never reads a window
//! byte it has not written since the member's window was set up: a match that
//! reaches further back than what was written is filled with zeros instead of
//! read, as UnRAR does. So whatever a reused scratch file holds never reaches
//! the output, even on a corrupt archive.
//!
//! The decoder drops the value when it is done with the window: when a larger
//! window replaces it, or when whatever owns the decoder is dropped. A
//! [`RarArchive`](crate::RarArchive) keeps its decoder, and so its window,
//! between members, so the memory is released when the archive is dropped;
//! a one-shot decode call releases it before it returns, error or not.
//!
//! [`Limits::max_dict_size`]: crate::Limits::max_dict_size
//! [`Limits::window_allocator`]: crate::Limits::window_allocator
//! [`Limits::max_allocated_dict_size`]: crate::Limits::max_allocated_dict_size
//! [`RarError::DictionaryTooLarge`]: crate::RarError::DictionaryTooLarge

use std::io;

/// Memory for one LZ dictionary window, owned by the decoder until it drops
/// the value.
///
/// # Safety
///
/// The decoder writes through the pointer without further checks, so an
/// implementation must uphold the contract in the [module docs](self):
/// [`as_mut_ptr`](Self::as_mut_ptr) returns a non-null pointer to at least
/// [`len`](Self::len) bytes that are valid for reads and writes, that pointer
/// and length stay the same for the life of the value (moves of the value
/// included), and nothing else touches those bytes until the value is dropped.
pub unsafe trait WindowMemory: Send + Sync {
    /// Start of the memory. Called once, right after allocation.
    fn as_mut_ptr(&mut self) -> *mut u8;

    /// Usable bytes at [`as_mut_ptr`](Self::as_mut_ptr). Must be at least the
    /// length that was asked for.
    fn len(&self) -> usize;

    /// Whether [`len`](Self::len) is zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Supplies window memory for dictionaries larger than
/// [`Limits::max_dict_size`](crate::Limits::max_dict_size).
///
/// One allocator can serve many extractions at once, so it is shared through an
/// `Arc` in [`Limits`](crate::Limits) and must be `Send + Sync`.
pub trait WindowAllocator: Send + Sync {
    /// Supply `len` bytes of window memory.
    ///
    /// An error fails the member's extraction with
    /// [`RarError::WindowAllocatorFailed`](crate::RarError::WindowAllocatorFailed),
    /// which carries this error.
    fn allocate(&self, len: usize) -> io::Result<Box<dyn WindowMemory>>;
}
