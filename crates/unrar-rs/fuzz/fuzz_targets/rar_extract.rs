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

use std::io::{Cursor, Write};

use libfuzzer_sys::fuzz_target;
use unrar_rs::RarArchive;

/// Inputs above this are the fuzzer wandering rather than finding structure.
const MAX_INPUT_BYTES: usize = 1 << 20;
/// Members extracted per input. Solid sets need more than one to reach the
/// interesting decoder state; a hundred is far past that.
const MAX_MEMBERS: usize = 32;
/// Decoded bytes accepted from one input, across all its members.
///
/// The budget the module docs promised but never had: `copy_to` used to be
/// handed `io::sink()`, so a header declaring gigabytes got them, one member
/// at a time, for as long as the decoder could keep producing. That is the
/// whole `timeout-*` cluster this budget was reconstructed for. 64 MiB is far
/// more than any fixture-sized archive needs and still bounds a single unit to
/// well under libFuzzer's per-unit timeout.
const MAX_OUTPUT_BYTES: u64 = 64 << 20;

/// A sink that stops accepting bytes once the budget is spent.
///
/// The error surfaces through the extraction API as an ordinary IO error,
/// which is one of the outcomes the target already ignores, so a budget stop
/// is not itself a finding.
struct BoundedSink {
    remaining: u64,
}

impl Write for BoundedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "fuzz output budget exhausted",
            ));
        }
        let accepted = (buf.len() as u64).min(self.remaining);
        self.remaining -= accepted;
        Ok(accepted as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(mut archive) = RarArchive::open(Cursor::new(data.to_vec())) else {
        return;
    };

    let members = archive.len().min(MAX_MEMBERS);
    let mut sink = BoundedSink {
        remaining: MAX_OUTPUT_BYTES,
    };
    for index in 0..members {
        // Errors are the normal outcome for a mutated archive and say nothing;
        // a panic, an abort, or a hang is the finding. The bytes go to a
        // counting sink: what is under test is the decode, not the
        // destination.
        let _ = archive
            .by_index(index)
            .and_then(|entry| entry.copy_to(&mut sink));
        if sink.remaining == 0 {
            break;
        }
    }
});
