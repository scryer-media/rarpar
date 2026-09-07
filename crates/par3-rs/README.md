# par3-rs

[![crates.io](https://img.shields.io/crates/v/par3-rs.svg)](https://crates.io/crates/par3-rs)
[![docs.rs](https://docs.rs/par3-rs/badge.svg)](https://docs.rs/par3-rs)

Reading, creating and repairing PAR3 (Parity Volume Set 3.0) recovery files in
pure Rust: packet parsing, set inspection, verification of the files a set
protects, the Cauchy Reed-Solomon arithmetic PAR3 recovery data is built from,
creating a complete set from a list of input files, and putting damaged and
missing files back from one.

**This is a work in progress.** The convenience APIs preserve default Cauchy
creation and repair. The incremental engine adds virtual sources, streaming
verification evidence, retained repair sessions, and low-rate FFT recovery.
Performance acceptance and the remaining advanced capabilities are still being
developed. See [Scope](#scope) before depending on this crate.

```toml
[dependencies]
par3-rs = "0.2"
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

## Creating a set

```rust
use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
use par3_rs::Result;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let base = Path::new("/srv/releases/2026-09");
    let files = [PathBuf::from("disc.iso"), PathBuf::from("notes/readme.txt")];

    let report = create(
        &InputSpec::new(base, &files),
        &base.join("disc.par3"),
        &CreateOptions::default()
            .with_recovery(RecoveryAmount::Percent(10))
            .with_comment("2026-09 release"),
    )?;

    println!("{} blocks of {} bytes, {} recovery blocks",
        report.block_count, report.block_size, report.recovery_count);
    for path in &report.files_written {
        println!("wrote {}", path.display());
    }
    Ok(())
}
```

With no explicit block size, `suggest_block_size` picks one the way the
reference implementation would. Each input file is read exactly once.

## Repairing a set

```rust
use par3_rs::repair::{RepairLimits, RepairOptions, plan_repair, repair_set};
use par3_rs::{Par3Set, Result, scan_packets_from_path};
use std::path::Path;

fn main() -> Result<()> {
    let base = Path::new("/srv/releases/2026-09");
    let packets = scan_packets_from_path(&base.join("disc.par3"))?
        .into_iter()
        .map(|(_offset, packet)| packet)
        .collect();
    let set = &Par3Set::from_packets(packets)?[0];

    // The dry run: what is wrong, and whether there is enough to fix it.
    let plan = plan_repair(set, base, &RepairLimits::default())?;
    if !plan.is_possible() {
        println!("{} more recovery blocks needed", plan.missing_recovery_blocks());
        return Ok(());
    }

    for file in repair_set(set, base, &RepairOptions::default())?.repaired() {
        println!("rebuilt {}", file.path());
    }
    Ok(())
}
```

Files that verify complete are never touched. Each rebuilt file is written under
a temporary name, checked against its File packet there, and only then moved
into place, over a backup of the damaged one (`<name>.1`, `.2`, …) unless
`RepairOptions::backup` is off. A rebuild that does not check out is left under
its temporary name and reported, and the file it was to replace is left alone.
Nothing is read whole into memory, at any size of file.

The temporary is created exclusively, so a link planted under its name before
the repair is refused rather than followed and truncated (a plain file left
there by an interrupted repair is replaced), and a set directory that has been
replaced by a link is refused before its file is rebuilt. That protects against
what was put in place before the repair started; the base directory itself, and
what happens to the tree while the repair is running, are the caller's.

## Trying it from a shell

`examples/par3rs.rs` drives all four of those from the command line, so the API
can be tried without writing a program first. It is an example rather than a
tool — crude argument parsing, plain-text output, no configuration — and it is
not official PAR3 tooling.

```sh
cargo run --example par3rs -- create ./data ./data/disc.par3 -r 10 disc.iso notes/readme.txt
cargo run --example par3rs -- list ./data/disc.par3 ./data/disc.vol0+1.par3
cargo run --example par3rs -- verify ./data ./data/disc.par3
cargo run --example par3rs -- repair ./data ./data/*.par3
```

It exits 0 when the set is complete, 1 when files are missing, damaged, or
beyond what the recovery blocks on hand can fix, and 2 when the command could
not be carried out at all.

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
- An inventory of the recovery blocks a set carries: which indices exist, which
  matrix each was computed with, and whether that matrix packet is present.
- Whole-file verification, with a mismatch narrowed down to the input blocks
  that failed.
- Arithmetic in both Galois fields PAR3 uses, GF(2^8) with `0x11D` and GF(2^16)
  with `0x1100B`: scalar, table-driven, portable, no `unsafe`.
- The Cauchy Reed-Solomon codec: a streaming encoder that computes a set's
  recovery blocks from its input blocks, and a streaming decoder that solves for
  lost input blocks from the recovery blocks that survived.
- Creating a set: choosing the block size, laying out the input blocks, packing
  chunk tails into shared blocks, computing the Cauchy code in either field,
  and writing the index file and power-of-two recovery volumes
  (`<stem>.par3`, `<stem>.vol0+1.par3`, `<stem>.vol1+2.par3`, …). For the same
  inputs and settings, the bytes match what the reference implementation writes.
- Repairing a set: deciding which input blocks were lost, reading the survivors
  and the tails packed beside them off the disk, solving for the rest with the
  recovery blocks the set carries, and writing every damaged or missing file
  back — including files inside directories that are themselves gone.

The incremental `Par3RepairSession` also provides:

- Chunked authenticated packet ingestion with lazy recovery and Data payloads.
- Source identity and generation contracts for disk, memory, and virtual input.
- Positioned streaming evidence, shared block aliases, packed tails, damage
  ranges, and contiguous verified prefixes.
- Retained assessments and recovery requirements per FFT cohort, with no
  source reads for unchanged reassessment or recovery-only merges.
- Explicit candidate placement using bounded CRC64 search and BLAKE3 checks.
- Byte-striped Cauchy and low-rate FFT repair, staged damaged files, cancellation,
  and shared allocation budgets (256 MiB total, up to 64 MiB retained by default).

Still unsupported:

- Repairing the recovery volumes themselves. A recovery block that does not
  parse is not available to a repair, and nothing puts it back.
- Sparse and explicit matrix execution, high-rate FFT, and automatic directory
  discovery. The original convenience repair API remains Cauchy-only.
- Checking a block of packed tails as a block. Each file's own tail is checked
  against the hashes in its chunk description; the block those tails share
  carries no checksum of its own — the reference implementation leaves tail
  blocks out of its External Data packets — and is never checked as a unit.
- Incremental backups: a Start packet's parent set is exposed, never followed.
- Interpreting link and permission packets, beyond keeping their bytes.
- "Par inside", where PAR3 packets live within the file they protect. Files with
  unprotected chunks are reported as unverifiable.
- Creating unprotected chunks, link or permission packets, and parent sets.
- Any command-line interface. `examples/par3rs.rs` demonstrates the API from a
  shell; it is not a tool, and nothing here is a supported front-end.

## Advanced standalone creation

`creation::CreationPlan::build` accepts virtual sources and explicit options for
Cauchy or low-rate FFT, capacity, starting recovery index, interleaving, aligned
or sliding deduplication, Data packets, and variable/uniform/size-limited volumes.
Inspect `requirements()` for block counts, codec geometry, exact output sizes,
and scratch bytes before calling `execute`. Deduplication windows and metadata
must fit the supplied allocation budget. Encoding uses a caller-selected scratch
directory. Destinations must be absent; output installation is exclusive.

The original `create` API and its byte-for-byte default output remain unchanged.
The new planner currently makes multiple source passes and uses scalar FFT
transforms; native performance parity has not been established.

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
| `PAR FFT\0` | Not specified | Low-rate Cantor-field execution follows the pinned reference appendix; GF16 uses polynomial `0x1002D`, distinct from Cauchy |

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
directory it is verified against. Creation refuses the same names on the way in,
component by component, so nothing this crate writes can fail to be read back.

The same limits bound *work*, not only memory, because a few kilobytes of
packets can otherwise ask for a great deal of both:

| Limit | Default | What it bounds |
| --- | --- | --- |
| `ScanLimits::max_packet_len` | 1 GiB | The largest packet a scan will read. |
| `ScanLimits::max_packets` | 1,000,000 | Packets one scan returns. |
| `ScanLimits::max_retained_bytes` | 4 GiB | Packet bodies one scan keeps. |
| `ScanLimits::max_failed_hash_passes` | 8 | Hashing spent on overlapping candidates that never check out, as a multiple of the input length. |
| `SetLimits::max_entries` | 1,000,000 | Files plus directories one set resolves to. |
| `SetLimits::max_depth` | 256 | Directory nesting the walk follows. |
| `SetLimits::max_path_bytes` | 64 MiB | Resolved path text, which a directory graph can expand exponentially. |
| `CodecLimits::max_buffer_bytes` | 1 GiB | Recovery rows, syndromes and the matrix a codec holds. |
| `CodecLimits::max_lost_blocks` | 4096 | Input blocks one decoder solves for at once; the inversion is cubic in this, and a set of tiny blocks can name thousands of them inside any memory budget. |
| `CreateLimits::max_block_size` | 1 GiB | The block size a create will use; one block is held while it is read, and every recovery row is one block wide. |
| `CreateLimits::max_files` | 1,000,000 | Input files one set protects. |
| `CreateLimits::max_path_bytes` | 64 MiB | Relative path text across all inputs. |
| `CreateLimits::max_tail_buffer_bytes` | 256 MiB | Blocks held while their chunk tails are still being filled. |
| `CreateLimits::codec` | `CodecLimits::default()` | The encoder the create runs. |
| `RepairLimits::max_input_blocks` | 65,536 | Input blocks a set may have for a repair to be attempted; the block ownership table has an entry per block. |
| `RepairLimits::max_tail_buffer_bytes` | 256 MiB | Blocks of packed chunk tails held while the files that write them are still being read. |
| `RepairLimits::codec` | `CodecLimits::default()` | The decoder the repair runs, which also caps the block size a repair will buffer. |

Chunk block ranges are validated whole against the set's block count when the
set is built, and verification narrows damage down only within the file it is
reading, so neither is steered by a length a packet chose. A repair builds its
block ownership table from the chunk descriptions before it opens a file, and
refuses a set whose descriptions contradict each other — two chunks claiming the
same bytes of one block, a tail that does not fit, an index past the end of the
set, or a block no file writes — rather than discovering it halfway through
writing over someone's data.

## Provenance

This is an independent, clean-room Rust implementation. The format was learned
from the
[Parity Volume Set Specification 3.0 draft](https://parchive.github.io/doc/Parity_Volume_Set_Specification_v3.0.html)
and by reading the reference implementation,
[par3cmdline](https://github.com/Parchive/par3cmdline), for the facts it settles
that the draft does not. No code from that project was copied.

The wire-format tests are pinned against `.par3` files that `par3cmdline` itself
produced — index files and recovery volumes alike; the exact commit, build
recipe and command lines are recorded in `tests/common/mod.rs`. The recovery
bytes are checked against the reference's own Cauchy construction, recomputed
from the input blocks in `tests/oracle_recovery.rs` with slow, longhand
arithmetic that lives in the test and is deliberately not the library's own.
`tests/oracle_codec.rs` then requires the library's encoder to reproduce those
same recovery blocks and its decoder to put back every input block that could
be lost. `tests/oracle_create.rs` rebuilds both reference archives from the same
input files and settings and requires every byte to match. `tests/repair.rs`
damages regenerated copies of those same input files — never the `.par3` bytes —
and requires each one to come back byte for byte.

Versioned API and migration notes are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/CHANGELOG.md).

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/LICENSE).
