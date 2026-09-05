# par3-rs

[![crates.io](https://img.shields.io/crates/v/par3-rs.svg)](https://crates.io/crates/par3-rs)
[![docs.rs](https://docs.rs/par3-rs/badge.svg)](https://docs.rs/par3-rs)

Reading PAR3 (Parity Volume Set 3.0) recovery files in pure Rust: packet
parsing, set inspection, and verification of the files a set protects.

**This is a work in progress.** It reads PAR3. It does not create PAR3, and it
does not repair anything. See [Scope](#scope) before depending on it.

```toml
[dependencies]
par3-rs = "0.1"
```

## Usage

```rust
use par3_rs::{Par3Set, Result, scan_packets_from_path, verify_set};
use std::path::Path;

fn main() -> Result<()> {
    let packets = scan_packets_from_path(Path::new("archive.par3"))?
        .into_iter()
        .map(|(_offset, packet)| packet)
        .collect();

    for set in Par3Set::from_packets(packets)? {
        for file in set.files() {
            println!("{} ({} bytes)", file.path(), file.size());
        }
        let report = verify_set(&set, Path::new("."))?;
        println!("{} of {} files complete",
            report.complete_count(), report.files().len());
    }
    Ok(())
}
```

## Scope

In:

- The two PAR3 hash functions: CRC-64/GO-ISO and 16-byte BLAKE3.
- Packet framing, and scanning a byte range for packets while skipping damage.
- Typed parsing and re-serialisation of Creator, Comment, Start, Data, External
  Data, all four Matrix kinds, Recovery Data, Recovery External Data, File,
  Directory and Root packets. Every other packet type is retained verbatim, so
  anything read writes back byte for byte.
- Grouping packets into input sets and resolving each set's files and
  directories into paths.
- Whole-file verification, with a mismatch narrowed down to the input blocks
  that failed.

Out, for this release:

- Creating PAR3 files.
- Recovery and repair, and the Galois-field arithmetic they need. Matrix and
  Recovery Data packets are parsed and kept, but nothing is computed from them.
- The sliding rolling-hash search that finds blocks whose position has moved.
- Verifying tail packing beyond each file's own whole-file hash.
- Incremental backups: a Start packet's parent set is exposed, never followed.
- Interpreting link and permission packets.
- "Par inside", where PAR3 packets live within the file they protect. Files with
  unprotected chunks are reported as unverifiable.
- Any command-line interface.

## The specification and the reference disagree

PAR3 has a published specification draft and a reference implementation that do
not match. Where they differ, this crate follows the reference implementation,
because that is what produced the files that exist. The differences that change
how bytes are read:

| Area | Specification draft | What this crate reads |
| --- | --- | --- |
| Galois field size | 2-byte field | 1 byte |
| Start packet | Begins with 8 random bytes | No random bytes; the older layout is detected by body length and preserved |
| InputSetID | First 8 bytes of the BLAKE3 of the Start body | Not derivable from anything stored; an opaque grouping key |
| File packet | No whole-file hash | 16-byte BLAKE3 of the file's protected data |
| Chunk descriptions | Per-chunk fingerprint | No per-chunk fingerprint |
| Cauchy matrix | Interleaved `x` values | `x_I = I` |
| External Data | Every input block | Full-size blocks only; blocks holding chunk tails are omitted |
| `PAR FFT\0` | Not specified | Written by the reference implementation, and parsed here |

## Damage is not an error

A `.par3` file exists to survive damage, so a packet whose header hash does not
match is treated as noise: it is skipped, and the scan resynchronises on the next
magic sequence. The error type describes input that cannot be interpreted at
all, or sets whose packets contradict each other — not bytes that are merely
corrupt.

## Untrusted input

There is no `unsafe` code. Allocation is bounded by explicit limits rather than
by lengths a packet claims, the directory walk is iterative and refuses cycles,
and File and Directory names that are empty, `.`, `..`, or that contain a path
separator are refused at parse time, so a set cannot direct a read outside the
directory it is verified against.

## Provenance

This is an independent, clean-room Rust implementation. The format was learned
from the
[Parity Volume Set Specification 3.0 draft](https://parchive.github.io/doc/Parity_Volume_Set_Specification_v3.0.html)
and by reading the reference implementation,
[par3cmdline](https://github.com/Parchive/par3cmdline), for the facts it settles
that the draft does not. No code from that project was copied.

The wire-format tests are pinned against `.par3` files that `par3cmdline` itself
produced; the exact commit, build recipe and command lines are recorded in
`tests/oracle_vectors.rs`.

Versioned API and migration notes are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/CHANGELOG.md).

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/LICENSE).
