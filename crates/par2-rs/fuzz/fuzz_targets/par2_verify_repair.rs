#![no_main]

//! Verification and repair planning, past the packet parser.
//!
//! `par2_packets` proves a mutated packet stream cannot crash the scanner. What
//! it never reaches is everything the packets *describe*: slice checksums
//! compared against files that do not match them, a recovery set whose
//! exponents and slice counts disagree with reality, and the planner that has
//! to decide from all that which slices to reconstruct and how much memory to
//! reserve. Those are arithmetic on attacker-controlled counts, which is a
//! different failure surface from parsing.
//!
//! Repair itself is deliberately not executed: it writes files and its cost is
//! set by numbers taken straight from the input, so a fuzzer would spend the
//! run on one input's reconstruction. Planning reaches the arithmetic without
//! paying for it.

use std::io::Write;
use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use par2_rs::disk::DiskFileAccess;
use par2_rs::{Par2FileSet, plan_repair, verify_all};

const MAX_INPUT_BYTES: usize = 1 << 20;
/// The data file the set claims to protect. Its bytes come from the input too,
/// so verification finds real mismatches rather than a missing file every time.
const MAX_PARTS: usize = 4;

/// Split into length-prefixed parts: the first becomes the `.par2`, the rest
/// become data files it may or may not describe.
fn split(data: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut rest = data;
    while parts.len() < MAX_PARTS {
        let Some((prefix, tail)) = rest.split_at_checked(2) else {
            break;
        };
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        let Some((part, tail)) = tail.split_at_checked(length) else {
            break;
        };
        parts.push(part);
        rest = tail;
    }
    parts
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let parts = split(data);
    let Some((par2_bytes, data_parts)) = parts.split_first() else {
        return;
    };

    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let par2_path = directory.path().join("fuzz.par2");
    let Ok(mut par2_file) = std::fs::File::create(&par2_path) else {
        return;
    };
    if par2_file.write_all(par2_bytes).is_err() {
        return;
    }
    drop(par2_file);

    // Data files are named the way a set describes them, so verification has
    // something to compare against instead of reporting everything missing.
    for (index, part) in data_parts.iter().enumerate() {
        let path = directory.path().join(format!("file{index}.dat"));
        if std::fs::write(&path, part).is_err() {
            return;
        }
    }

    let paths = [PathBuf::from(&par2_path)];
    let Ok(par2_set) = Par2FileSet::from_paths(&paths) else {
        return;
    };
    let access = DiskFileAccess::new(directory.path().to_path_buf(), &par2_set);
    let verification = verify_all(&par2_set, &access);
    let _ = plan_repair(&par2_set, &verification);
});
