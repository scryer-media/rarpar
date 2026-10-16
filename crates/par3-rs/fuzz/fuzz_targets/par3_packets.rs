#![no_main]

//! The PAR3 packet scanner over arbitrary bytes.
//!
//! `scan_packets` is where every byte of a `.par3` file first meets the
//! crate: it hunts for the magic, checks each candidate's header and hash,
//! types File and Explicit Matrix packets by the Start packet of their input
//! set, and bounds what it retains by `ScanLimits`. A mutated stream must come
//! back as packets or an error, never a panic or an allocation the limits did
//! not allow.

use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let _ = par3_rs::scan_packets(data);
});
