# par3-rs

[![crates.io](https://img.shields.io/crates/v/par3-rs.svg)](https://crates.io/crates/par3-rs)
[![docs.rs](https://docs.rs/par3-rs/badge.svg)](https://docs.rs/par3-rs)

Read, verify, create and repair PAR3 recovery sets in Rust. It can also
verify and repair while the data is still arriving, and work within a fixed
memory budget.

```toml
[dependencies]
par3-rs = "0.7"
```

**Status:** a 0.x library, tested against the reference tool, par3cmdline.
Verifying and repairing are faster than the reference in the
[measured results](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/PERFORMANCE.md)
on x86-64 and ARM64. Creating FFT sets on ARM64 is still slower. This is
independent, clean-room software, not official Parchive tooling.

## Which API

- **Files on disk:** `scan_packets_from_path`, `Par3Set`, `verify_set`,
  `create::create` and `repair::repair_set`. The examples below use these.
- **Data still arriving, data that is not in files, or a memory limit:**
  `ingest::PacketScanner` and `Par3RepairSession`, reading through your own
  `source::SourceAccess`.
- **More control when creating** (codec, block layout, deduplication, volume
  sizes): `creation::CreationPlan`.
- **Protection embedded inside an archive:** `inside::{InsertionPlan,
  SelfRepairPlan}`, and `inside::rar5` for RAR5 (experimental).

Everything is synchronous and suits a blocking worker thread. Downloading,
scheduling and storage are up to the caller. The
[API documentation](https://docs.rs/par3-rs/latest/par3_rs/) has the
details, and [ENGINE.md](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/ENGINE.md)
describes the streaming engine.

## Verify files

The index file is usually enough to verify. To repair, load the recovery
volumes too, as in the next example.

```rust,no_run
use par3_rs::{
    Par3Set, Result, scan_packets_from_path, verify_set,
};
use std::path::Path;

fn main() -> Result<()> {
    let packets = scan_packets_from_path(Path::new("set.par3"))?
        .into_iter()
        .map(|(_, packet)| packet)
        .collect();

    for set in Par3Set::from_packets(packets)? {
        let report = verify_set(&set, Path::new("data"))?;
        println!("{} files complete", report.complete_count());
    }
    Ok(())
}
```

## Repair

Pass the recovery files you actually have. File names do not matter; the
packets inside them are checked.

```rust,no_run
use par3_rs::{Par3Set, Result, scan_packets_from_path};
use par3_rs::repair::{RepairOptions, repair_set};
use std::path::Path;

fn main() -> Result<()> {
    let base = Path::new("data");
    let carriers = ["set.par3", "set.vol0+1.par3"];
    let mut packets = Vec::new();
    for name in carriers {
        let path = Path::new(name);
        for (_, packet) in scan_packets_from_path(path)? {
            packets.push(packet);
        }
    }

    for set in Par3Set::from_packets(packets)? {
        let report = repair_set(
            &set, base, &RepairOptions::default(),
        )?;
        for file in report.repaired() {
            println!("{}: verified={}",
                file.path(), file.verified());
        }
        if !report.is_complete() {
            eprintln!("repair is incomplete");
        }
    }
    Ok(())
}
```

- Good files are left alone. A rebuilt file is checked before it replaces
  the damaged one.
- The damaged file is not kept unless you ask:
  `RepairOptions::default().with_backup(true)` renames it to `<name>.1`.
- Repair will not write through a symbolic link, or to a name the filesystem
  would confuse with another by case or Unicode form.
- An interrupted repair leaves its unfinished files in a
  `.par3-stage-<pid>-<n>` directory and lists them in
  `EngineError::RepairInterrupted`. A successful repair cleans up after
  itself.
- `scan_packets_from_path` reads each recovery file into memory. For large
  files or a strict memory limit, use the streaming API.

## Create

```rust,no_run
use par3_rs::create::{
    CreateOptions, InputSpec, RecoveryAmount, create,
};
use par3_rs::Result;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let base = Path::new("data");
    let files = [PathBuf::from("disc.iso")];
    let options = CreateOptions::default()
        .with_recovery(RecoveryAmount::Percent(10));
    let report = create(
        &InputSpec::new(base, &files),
        Path::new("set.par3"),
        &options,
    )?;
    println!("{} recovery blocks", report.recovery_count);
    Ok(())
}
```

`create` picks a block size if you give none, reads each file once, and
writes what the reference would write. With `CreationPlan`,
`requirements()` reports the block counts, output sizes and scratch space
before anything is written.

**Durability.** par3-rs never calls `fsync`. A crash right after a create or
repair can lose output that was reported as written. If you need it on disk,
sync the output paths the call returns, and their directories.

## Memory and limits

The streaming engine has default budgets:

- **256 MiB** of memory, shared, including what sessions keep.
- **64 MiB** kept per session.
- **32** open file handles.
- **1 TiB** of recovery files scanned in total.

When a request does not fit, the engine first narrows (fewer workers,
smaller batches) and only then refuses, with
`EngineError::ResourceLimit`. Its `cause()` says whether waiting can help:
`PeerContention` will fit once other work releases memory, while
`ExceedsLimit` and `Unmeasured` never will. `MemoryBudget::ledger()` shows
what the memory is being used for, and is safe to read from another thread
while a job runs.

The simpler APIs use their own limits (`ScanLimits`, `SetLimits`,
`CodecLimits`, `CreateLimits`, `RepairLimits`), with defaults documented on
each type. [ENGINE.md](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/ENGINE.md)
covers the rest: per-stage memory, checkpoints, continuing after a
shortfall, and how files are identified without rereading them.

## What it supports

- Cauchy recovery over GF(2⁸) and GF(2¹⁶), and low-rate FFT recovery,
  including sets of more than 65,536 blocks.
- Shared blocks, packed tails, repeated chunks, Data packets, and files that
  are only partly protected.
- Deduplication when creating.
- Recovery volumes of variable, uniform or limited size.
- Rebuilding a lost recovery file from a saved manifest.
- Protection embedded in ZIP, ZIP64 and 7z archives, without changing the
  archive's own members, and (experimental) in RAR5 archives and volume sets.

Not supported:

- Sparse matrices and high-rate FFT.
- Parent-set backups, restoring permissions or links, and protection nested
  inside protection.
- Finding the source directory automatically.
- Guessing missing set metadata or a recovery file's original byte order.
- RAR4 hosts for embedded protection, and RAR5 volume sets with encrypted
  headers.

Ordinary repair never removes embedded protection; that takes the explicit
`inside` APIs.

## The rarpar command

The `rarpar` CLI in this workspace has `par3 create`, `par3 verify`,
`par3 repair`, `par3 archive` (a 7z or ZIP archive protected in one pass),
the experimental `par3 inside` for RAR5, and PAR3 handling in `auto` mode.
Run as `par3`, it also accepts par3cmdline's command line for verifying,
listing and repairing (`v`, `l`, `r`, `vs`, `rs`); par3cmdline's create,
insert and delete commands are refused there.

## Compatibility with par3cmdline

Where the draft specification and par3cmdline disagree, this crate follows
par3cmdline:

- **Field size:** one byte, not the draft's two.
- **Start packet:** no leading random bytes. The older layout is still read.
- **InputSetID:** derived as par3cmdline derives it, from the file names,
  sizes, hashes, chunk layout and the Start packet. It cannot be recomputed
  from the stored bytes.
- **Metadata copies:** a recovery volume repeats its metadata packets as
  par3cmdline does; the index file has one copy.
- **File order and tail packing:** as par3cmdline does, for every
  deduplication mode.
- **Shared packets:** identical File or Directory packets are written once.
- **Comment:** written only when you give comment text.
- **File hash:** a 16-byte BLAKE3 hash of the protected chunks, which the
  draft does not have.
- **Chunks:** no per-chunk fingerprint.
- **Cauchy matrix:** `x_I = I`.
- **External Data:** full-size blocks only.
- **FFT:** follows the pinned appendix; GF16 uses `0x1002D`, Cauchy
  `0x1100B`. A set with one recovery block or a capacity of one records no
  field size.
- **ZIP64 embedding:** needs the ZIP size and offset sentinel fields set.

Two differences of its own:

- **Streaming-engine data volumes** store whole blocks rather than trimming
  each tail block. Index and recovery volumes are unaffected.
- **File names** are checked more strictly than either. A name is refused if
  any part is empty, `.` or `..`, or over 255 bytes; if it contains `\`,
  `:`, `?`, `*`, `"`, `<`, `>`, `|` or a control byte; if it is a Windows
  device name such as `CON`, `NUL` or `COM1`, with or without an extension;
  if it ends in a space or a dot; if the path is over 4096 bytes; or if it is
  absolute. Creating and repairing both refuse such a name, on every
  platform. A set that already contains one still reads and verifies.

The [interoperability record](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/INTEROPERABILITY.md)
has the tests against par3cmdline.

## Safety and provenance

Scanning skips corrupt packets and keeps going. Malformed sets,
contradictory metadata, running out of resources, and I/O failures are
errors. Path components that would escape the output directory are refused.

The only `unsafe` code is one Windows module that creates owner-only staging
directories and reads file identities; every other target forbids `unsafe`.

This is a clean-room implementation of the
[PAR3 draft](https://parchive.github.io/doc/Parity_Volume_Set_Specification_v3.0.html)
and of the format facts established by
[par3cmdline](https://github.com/Parchive/par3cmdline); no reference code was
copied. The FFT codec follows Lin, Al-Naffouri, Han and Chung (2016) and
Chen, Lin, Tang, Han and others (2026); full references are in
[ATTRIBUTION.md](https://github.com/scryer-media/rarpar/blob/main/ATTRIBUTION.md).

Changes by version are in [CHANGELOG.md](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/CHANGELOG.md).

## License

Apache-2.0 from version 0.5.1 onward. See
[LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/LICENSE).
Releases before 0.5.1 stay under GPL-3.0-or-later.
