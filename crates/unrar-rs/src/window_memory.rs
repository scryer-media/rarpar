//! Caller-supplied memory for the LZ dictionary window.
//!
//! RAR5 and RAR7 archives may declare a dictionary of up to 64 GiB. By default
//! the decoder allocates the window on the heap, and [`Limits::max_dict_size`]
//! refuses any dictionary above it with [`RarError::DictionaryTooLarge`].
//!
//! An application that can back a large window with something other than RAM,
//! such as a memory-mapped scratch file, lends the memory through
//! [`Limits::with_window_allocator`]. A dictionary at or under
//! [`Limits::max_dict_size`] is still allocated on the heap, exactly as
//! without an allocator. A larger one, up to
//! [`Limits::max_allocated_dict_size`], is asked of the allocator instead of
//! being refused.
//!
//! This covers the LZ window of every format: RAR5/RAR7, RAR 2.9 LZ, and RAR
//! 1.5 to 2.6.
//!
//! # The PPMd model arena
//!
//! The same allocator can also lend the RAR 2.9 PPMd model arena, which a
//! block header may declare at up to 256 MiB. An arena at or under
//! [`Limits::max_heap_ppmd_arena_size`] stays in the decoder's own memory, as
//! without an allocator; that limit defaults to the format's 256 MiB
//! ceiling, so no arena is lent until it is lowered. A larger one, up to
//! [`Limits::max_ppmd_arena_size`], is asked of the allocator, under the
//! contract below. Arena memory need not be zeroed either: the model never
//! reads a byte of it that it has not written.
//!
//! The decoder asks for an arena when a block header resets the model and the
//! arena in hand cannot back it (it is too small, or more than twice the
//! size needed), and when a damaged PPMd block makes it restart the model
//! over a 1 MiB arena. The arena, like the window, lives as long as the
//! decoder, across members and solid members. A refusal, or memory shorter
//! than asked, is [`RarError::WindowAllocatorFailed`], as for a window.
//!
//! # The memory contract
//!
//! [`WindowAllocator::allocate`] is asked for `len` bytes and returns a
//! [`WindowMemory`]. The decoder calls [`WindowMemory::as_mut_ptr`] and
//! [`WindowMemory::len`] once each, right after allocation, and from then on
//! uses the pointer alone. The memory must be:
//!
//! - **at least `len` bytes long.** The decoder uses exactly the first `len`.
//!   A request or a returned length above `isize::MAX` is refused with
//!   [`RarError::WindowAllocatorFailed`] before any byte is touched, and the
//!   memory is dropped.
//! - **initialized, readable and writable.** The decoder builds Rust slices
//!   over the bytes, so they must hold some value: a fresh anonymous or file
//!   mapping does, a raw `malloc` of uninitialized heap memory does not. The
//!   value does **not** need to be zero.
//! - **at a stable address until the value is dropped,** including after the
//!   value itself (the `Box`) is moved: the memory must live outside the
//!   value, as a heap buffer or a mapping does.
//! - **exclusive to the decoder until the value is dropped.** Nothing else
//!   reads or writes those bytes meanwhile.
//!
//! Why zeroing is not needed: the decoder never reads a window byte it has not
//! written since the member's window was set up. A match that reaches further
//! back than what was written is filled with zeros instead of read, as UnRAR
//! does. So whatever a reused scratch file holds never reaches the output, even
//! on a corrupt archive.
//!
//! # When the allocator is called, and from where
//!
//! [`WindowAllocator::allocate`] can be called from any thread that extracts,
//! and more than once per archive: when a later member needs a larger
//! dictionary than the window it has, and when a RAR 1.5–2.9 archive switches
//! unpack version between members, which builds that version's decoder with a
//! window of its own.
//!
//! The decoder drops a [`WindowMemory`] when it is done with it: when a larger
//! window replaces it, or when whatever owns the decoder is dropped. A
//! [`RarArchive`](crate::RarArchive) keeps its decoder, and so its window,
//! between members, so the memory is released when the archive is dropped. A
//! one-shot decode releases it before it returns, error or not.
//!
//! # Threading
//!
//! Lending the window changes nothing about threads. The decode mode the
//! caller chose ([`RarArchive::set_decode_mode`](crate::RarArchive::set_decode_mode))
//! and the parallel RAR5 decoder's worker pool are used unchanged: the workers
//! decode blocks into buffers of their own and never touch the window, which
//! only the extracting thread writes. That is why [`WindowMemory`] needs
//! to be [`Send`] (the decoder may move to another thread with its window) and
//! not [`Sync`].
//!
//! [`Limits::max_dict_size`]: crate::Limits::max_dict_size
//! [`Limits::with_window_allocator`]: crate::Limits::with_window_allocator
//! [`Limits::max_allocated_dict_size`]: crate::Limits::max_allocated_dict_size
//! [`Limits::max_heap_ppmd_arena_size`]: crate::Limits::max_heap_ppmd_arena_size
//! [`Limits::max_ppmd_arena_size`]: crate::Limits::max_ppmd_arena_size
//! [`RarError::DictionaryTooLarge`]: crate::RarError::DictionaryTooLarge
//! [`RarError::WindowAllocatorFailed`]: crate::RarError::WindowAllocatorFailed

use std::io;

/// Memory for one LZ dictionary window or one PPMd model arena, owned by the
/// decoder until it drops the value.
///
/// # Safety
///
/// The decoder reads and writes through the pointer without further checks,
/// so an implementation must uphold the contract in the
/// [module docs](self): [`as_mut_ptr`](Self::as_mut_ptr) returns a non-null
/// pointer to at least [`len`](Self::len) initialized bytes that are valid for
/// reads and writes; that pointer and length stay valid until the value is
/// dropped, moves of the value included; and nothing else touches those bytes
/// until the value is dropped.
pub unsafe trait WindowMemory: Send {
    /// Start of the memory. Called once, right after allocation.
    fn as_mut_ptr(&mut self) -> *mut u8;

    /// Usable bytes at [`as_mut_ptr`](Self::as_mut_ptr). Called once, right
    /// after allocation. Must be at least the length that was asked for.
    fn len(&self) -> usize;

    /// Whether [`len`](Self::len) is zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Supplies window memory for dictionaries larger than
/// [`Limits::max_dict_size`](crate::Limits::max_dict_size), and arena memory
/// for PPMd models larger than
/// [`Limits::max_heap_ppmd_arena_size`](crate::Limits::max_heap_ppmd_arena_size).
///
/// One allocator can serve many extractions at once, on any thread, so it is
/// shared through an `Arc` in [`Limits`](crate::Limits) and must be
/// `Send + Sync`. It can be called more than once per archive; see the
/// [module docs](self) for when.
///
/// A lent window leaves threading as the caller set it: the decode mode and
/// the parallel decoder's workers are unchanged, and the workers never touch
/// the window.
pub trait WindowAllocator: Send + Sync {
    /// Supply at least `len` bytes of window or arena memory.
    ///
    /// An error fails the member's extraction with
    /// [`RarError::WindowAllocatorFailed`](crate::RarError::WindowAllocatorFailed),
    /// which carries this error. The archive is not marked damaged.
    fn allocate(&self, len: usize) -> io::Result<Box<dyn WindowMemory>>;
}
