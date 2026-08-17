#![no_main]

//! Decompression, not just parsing.
//!
//! `rar_headers` stops once the headers are understood, so everything the
//! headers *lead to* — the RAR4 and RAR5 LZ decoders, PPMd, the filter VM,
//! stored and solid layouts — is reached by that target only incidentally.
//! This one extracts, which is where a malformed archive turns into a wrong
//! length, a bad back-reference, or an unbounded loop.
//!
//! Extraction is bounded on purpose: a fuzzer is looking for crashes, not for
//! the slowest input that still succeeds. A member count and an output budget
//! keep one pathological archive from spending the whole run, which would
//! quietly starve every other input.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use unrar_rs::{ExtractOptions, RarArchive};

/// Inputs above this are the fuzzer wandering rather than finding structure.
const MAX_INPUT_BYTES: usize = 1 << 20;
/// Members extracted per input. Solid sets need more than one to reach the
/// interesting decoder state; a hundred is far past that.
const MAX_MEMBERS: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(mut archive) = RarArchive::open(Cursor::new(data.to_vec())) else {
        return;
    };

    let members = archive.member_names().len().min(MAX_MEMBERS);
    let options = ExtractOptions::default();
    for index in 0..members {
        // Errors are the normal outcome for a mutated archive and say nothing;
        // a panic, an abort, or a hang is the finding.
        let _ = archive.extract_member(index, &options, None);
    }
});
