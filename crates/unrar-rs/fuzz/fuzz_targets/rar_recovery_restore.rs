#![no_main]

//! Recovery-volume restore: reconstructing missing volumes from `.rev` parity.
//!
//! This is the path that aborted an embedder with a stack overflow before
//! unrar-rs 0.5.3 — inside a rayon split, under fat LTO, on a set whose volumes
//! were large enough to recurse deeply. That class of bug reaches no test that
//! only opens archives, and it is not a parsing bug at all: the headers were
//! well formed and the arithmetic behind them was what went wrong. So it gets
//! its own target.
//!
//! Restore works on *paths*, and on a *set*, so the input is split into several
//! files rather than handed over as one blob. The split is length-prefixed
//! rather than arbitrary-derived: the shape stays obvious in a crash artifact,
//! and a minimiser can shrink each part without the framing collapsing.

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use unrar_rs::recovery::{RecoveryOptions, restore_volumes_from_paths};

const MAX_INPUT_BYTES: usize = 1 << 20;
/// A restore needs data volumes plus parity; beyond a handful the extra files
/// only cost time.
const MAX_PARTS: usize = 8;

/// Split the input into parts, each `u16` length-prefixed (big endian). A
/// truncated prefix or an over-long length ends the split, so every input is
/// valid framing for *some* set and no byte string is wasted.
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
    if parts.is_empty() {
        return;
    }

    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    // The names are what tell restore which file is data and which is parity,
    // and a volume set is discovered by name, so they follow rar's own scheme
    // rather than being fuzzed themselves.
    let mut paths: Vec<PathBuf> = Vec::with_capacity(parts.len());
    for (index, part) in parts.iter().enumerate() {
        let extension = if index % 3 == 2 { "rev" } else { "rar" };
        let path = directory
            .path()
            .join(format!("set.part{}.{extension}", index + 1));
        if std::fs::write(&path, part).is_err() {
            return;
        }
        paths.push(path);
    }

    let options = RecoveryOptions {
        output_dir: Some(directory.path().to_path_buf()),
        overwrite_existing: true,
        verify_restored: true,
    };
    let _ = restore_volumes_from_paths(&paths, &options);
});
