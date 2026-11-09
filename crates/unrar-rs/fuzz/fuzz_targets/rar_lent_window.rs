#![no_main]

//! The lent LZ window and the lent PPMd model arena against the decoder's
//! own memory.
//!
//! Every input is extracted twice: once with the decoder's own zeroed heap
//! window and arena, once with every window and every RAR 2.9 PPMd arena lent
//! by a [`WindowAllocator`] whose memory is filled with junk. The two runs
//! must write the same bytes and fail with the same error, member by member.
//! A difference means the decoder read a window or arena byte it had not
//! written, which on lent memory leaks whatever the caller's scratch space
//! held; a crash or a sanitizer report means the lent path broke the memory
//! contract.
//!
//! Both runs refuse a dictionary above [`MAX_WINDOW`] and an arena above
//! [`MAX_PPMD_ARENA`], so one input cannot make the allocator fill gigabytes,
//! and refuse them the same way.

use std::io::{self, Cursor, Write};
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use unrar_rs::{Limits, RarArchive, WindowAllocator, WindowMemory};

/// Inputs above this are the fuzzer wandering rather than finding structure.
const MAX_INPUT_BYTES: usize = 1 << 20;
/// Members extracted per input.
const MAX_MEMBERS: usize = 32;
/// Decoded bytes kept from one input, across all its members.
const MAX_OUTPUT_BYTES: usize = 16 << 20;
/// Largest dictionary either run accepts.
const MAX_WINDOW: u64 = 16 << 20;
/// Largest PPMd model arena either run accepts.
const MAX_PPMD_ARENA: u64 = 16 << 20;
/// Below every real window (the smallest is 256 KiB), so every window of the
/// lent run comes from the allocator.
const HEAP_LIMIT_WHEN_LENT: u64 = 64 << 10;

struct JunkWindow(Box<[u8]>);

// SAFETY: a heap buffer of `len` initialized bytes that this value alone owns;
// moving the box does not move it.
unsafe impl WindowMemory for JunkWindow {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

struct JunkAllocator;

impl WindowAllocator for JunkAllocator {
    fn allocate(&self, len: usize) -> io::Result<Box<dyn WindowMemory>> {
        // Non-zero and position-dependent, so a stray read shows in the output.
        let bytes = (0..len)
            .map(|i| (i as u8).wrapping_mul(167) ^ 0xa5 | 1)
            .collect();
        Ok(Box::new(JunkWindow(bytes)))
    }
}

/// Keeps what is written, up to a budget shared by every member.
struct BoundedCollect<'a> {
    out: Vec<u8>,
    remaining: &'a mut usize,
}

impl Write for BoundedCollect<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if *self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "fuzz output budget exhausted",
            ));
        }
        let accepted = buf.len().min(*self.remaining);
        *self.remaining -= accepted;
        self.out.extend_from_slice(&buf[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Each member's written bytes and error text.
fn extract(data: &[u8], limits: Limits) -> Option<Vec<(Vec<u8>, Option<String>)>> {
    let mut archive = RarArchive::open(Cursor::new(data.to_vec())).ok()?;
    archive.set_limits(limits);
    let mut remaining = MAX_OUTPUT_BYTES;
    let mut members = Vec::new();
    for index in 0..archive.len().min(MAX_MEMBERS) {
        let mut sink = BoundedCollect {
            out: Vec::new(),
            remaining: &mut remaining,
        };
        let error = archive
            .by_index(index)
            .and_then(|entry| entry.copy_to(&mut sink))
            .err()
            .map(|error| error.to_string());
        members.push((sink.out, error));
        if remaining == 0 {
            break;
        }
    }
    Some(members)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut heap = Limits::default();
    heap.max_dict_size = MAX_WINDOW;
    heap.max_ppmd_arena_size = MAX_PPMD_ARENA;
    let Some(expected) = extract(data, heap) else {
        return;
    };

    let mut lent = Limits::default();
    lent.max_dict_size = HEAP_LIMIT_WHEN_LENT;
    lent.max_ppmd_arena_size = MAX_PPMD_ARENA;
    let lent = lent
        .with_window_allocator(Arc::new(JunkAllocator))
        .with_max_allocated_dict_size(MAX_WINDOW)
        .with_max_heap_ppmd_arena_size(0);
    let actual = extract(data, lent).expect("the archive opened the first time");

    assert!(
        actual == expected,
        "lent memory decoded differently from the decoder's own"
    );
});
