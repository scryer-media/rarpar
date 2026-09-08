# par3-rs

[![crates.io](https://img.shields.io/crates/v/par3-rs.svg)](https://crates.io/crates/par3-rs)
[![docs.rs](https://docs.rs/par3-rs/badge.svg)](https://docs.rs/par3-rs)

Read, verify, create, and repair PAR3 recovery sets in Rust. Supports Cauchy and
low-rate FFT recovery, virtual sources, incremental verification, and repair
sessions that retain evidence as more data arrives.

**Status:** a 0.x library with reference interoperability tests. Verification and
repair exceed the reference's throughput aggregates in the measured
[native x86-64 and ARM64 results](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/PERFORMANCE.md)
with matched worker limits. Default ARM64 FFT creation still falls short.
See [Scope](#scope) for supported formats and exclusions. This is independent,
clean-room software, not official Parchive tooling.

```toml
[dependencies]
par3-rs = "0.3"
```

## Choose an API

- **Files on disk, default Cauchy sets:** use `scan_packets_from_path`,
  `Par3Set`, `verify_set`, `create::create`, and `repair::repair_set`.
- **Streaming or virtual input, FFT, or bounded memory:** use
  `ingest::PacketScanner` and `Par3RepairSession`. Supply bytes through
  `source::SourceAccess`; paths are optional.
- **Advanced creation:** use `creation::CreationPlan` to select a codec,
  interleaving, deduplication, Data packets, and recovery-volume layout.
- **Recovery carriers or embedded protection:** use `carrier::CarrierPlan`
  and `inside::{InsertionPlan, SelfRepairPlan}`.

See the [API documentation](https://docs.rs/par3-rs/latest/par3_rs/) and
[streaming engine contract](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/ENGINE.md).
The engine APIs are synchronous and fit blocking workers; the host owns
downloading, scheduling, persistence, and extraction policy.

## Verify files

An index normally contains enough metadata to verify protected files. To repair,
also load the available recovery volumes, as shown in the next example.

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

## Repair a Cauchy set

Supply the carriers that actually arrived. Filenames do not establish set
membership or recovery availability; authenticated packets do.

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

Clean files are left alone. Rebuilt files are staged and verified before
installation; backups are enabled by default. Inspect the report for incomplete
repairs. `plan_repair` is available for a separate assessment, but
`repair_set` performs its own analysis. Use a retained session to reuse evidence.

The convenience scanner reads each carrier into memory, and the legacy codec
retains whole recovery rows. Use the incremental engine for large carriers or
strict allocation budgets.
Its packet scanner reuses a bounded read-ahead stripe across packet boundaries;
both scanner buffers are charged to the allocation budget, and source-generation
checks still apply to cached bytes.

## Create a Cauchy set

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

This convenience API chooses the block size when none is supplied, reads each
input file once, and preserves the reference-compatible default output.

For advanced creation, inspect `CreationPlan::requirements()` before execution.
It reports block counts, recovery geometry, output sizes, and scratch space.
File and chunk hashes share one planning pass; sliding deduplication can read
additional candidate windows. Encoding reads sources again. Destinations must
be absent; execution uses a caller-selected scratch directory.

`execute` preserves file synchronization before installation. Standalone
creators can explicitly use `execute_with_durability` with
`CreationDurability::Buffered` to omit storage barriers. Both modes flush
application buffers and authenticate staged carriers; buffered output can be
lost after a crash. Neither mode promises atomic set installation across a
crash. Verification and repair retain their existing behavior.

## Streaming and resource limits

`PacketScanner` authenticates packets incrementally and keeps lazy references
to recovery and Data payloads. `Par3RepairSession` retains layout, evidence,
and assessment. Duplicate packets do not increase recovery availability.

Feed positioned decoded bytes to `evidence::StreamingVerifier`, then admit its
evidence to the session. Verified prefixes and unresolved file ranges support
extraction readiness. Unchanged assessments and recovery-only merges reuse
verification evidence. With read-free provider snapshots they perform no source
reads; unpinned non-Unix disk snapshots still hash content. Recovery requirements
identify the matrix, cohort, admissible indices, and deficit.

Source identities, generations, and published bytes must follow the
`SourceAccess` contract. Holes are unavailable bytes, never implicit zeroes.
Checkpoint replay also requires a digest preserved separately in trusted host
metadata. A digest computed from the replay blob does not establish trust.

Default engine budgets:

- **256 MiB** shared allocation accounting, including retained state.
- **64 MiB** retained state per session.
- **32** open engine handles, with shared leases across cloned options.
- **1 TiB** cumulative requested carrier-scanning bytes.

Set worker limits explicitly when running concurrent jobs. Clone the same
budgets to share ceilings, and use `DiskSourceAccess::with_options` to include
disk-provider handles. Provider storage and allocator overhead are outside
engine accounting; it is not a process-RSS limit. Out-of-order verification
drops incomplete hash work when its budget is exhausted, leaving those extents
unknown for later reading.

Windows scanning pins a read-only carrier handle, preventing repeated full-file
generation hashes after one acquisition hash. Retained packets keep that handle
alive; drop them before replacing or deleting carriers. All generation hashes
consume scan-work budget. Use `Par3RepairSession::validate_repair()` for dry-run readiness and
configured codec limits before staging output.

Cancellation, progress callbacks, stage timings, I/O counters, and typed
resource/I/O outcomes are available through `runtime`. Convenience APIs instead
use their own `ScanLimits`, `SetLimits`, `CodecLimits`, `CreateLimits`, and
`RepairLimits`; their defaults are documented on those types.

## Scope

The incremental engine supports:

- Cauchy over GF(2⁸) and GF(2¹⁶), and low-rate FFT with interleaved cohorts.
  Interleaving permits more than 65,536 total blocks within per-cohort limits.
- Shared blocks, packed and inline tails, repeated chunks, Data packets, and
  protected/unprotected file extents.
- Aligned or sliding deduplication during advanced creation, plus explicit
  candidate placement using CRC64 and BLAKE3 confirmation.
- Variable, uniform, or size-limited recovery volumes.
- Recovery-carrier reconstruction from a captured manifest, or an explicitly
  requested replacement when original packet order is unknown.
- Cauchy PAR-inside insertion and self-repair for supported ZIP, ZIP64, and 7z
  layouts, preserving existing archive member bytes and compression.

Packed tail blocks have no invented block checksum: each described tail is
verified against its own fingerprint. CRC64 localizes candidates; BLAKE3
establishes the required PAR3 integrity evidence.

Still outside scope:

- Sparse/explicit matrix execution and high-rate FFT.
- Parent-set backups, permission/link restoration, and recursive PAR-inside.
- Automatic source-directory discovery and arbitrary unprotected creation
  layouts beyond supported container insertion.
- Inferring an unknown carrier's original byte order or missing set metadata.

The workspace's `rarpar` CLI provides `par3 create`, `par3 verify`, `par3 repair`,
and PAR3 discovery/repair in `auto` mode. Install it from the workspace or use
its binary distribution; this crate remains a library. The `par3rs` example
demonstrates the older convenience APIs.

Ordinary repair does not silently remove embedded protection. Use the explicit
PAR-inside APIs; exact carrier restoration requires an authenticated manifest.
The convenience verifier reports unprotected chunks as unverifiable.

## Format compatibility

Where the draft specification and reference disagree, this crate follows the
reference. The deviations affecting interpretation are:

- **Field size:** one byte, rather than the draft's two-byte field.
- **Start packet:** no leading random bytes. The older layout is detected by
  body length and preserved.
- **InputSetID:** an opaque grouping key; it cannot be recomputed from stored
  bytes as the draft describes.
- **File hash:** a 16-byte BLAKE3 hash, absent from the draft, over protected
  chunks concatenated in file order. Unprotected bytes are omitted.
- **Chunks:** no per-chunk fingerprint from the draft layout.
- **Cauchy matrix:** `x_I = I`, rather than interleaved `x` values.
- **External Data:** full-size blocks only; packed tail blocks are omitted.
- **FFT:** low-rate Cantor-field semantics follow the pinned appendix.
  GF16 uses `0x1002D`, distinct from Cauchy's `0x1100B`.
- **Trivial FFT:** field size zero represents one-input copy recovery or
  capacity-one XOR, without transform tables.
- **ZIP64 insertion:** the pinned reference requires ZIP size/offset sentinel
  fields too; member count alone is insufficient. Corpus recipes normalize
  those original ZIP fields before official insertion.

The [interoperability record](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/INTEROPERABILITY.md)
documents reference verification and repair, including both fields, uneven
cohorts, more than 65,536 blocks, and embedded archive replacement.

## Input handling and provenance

Scanning skips corrupt packet candidates and resynchronizes. Malformed sets,
contradictory metadata, resource exhaustion, and I/O failure remain errors.
Parsed path components reject traversal names and separators, and set
construction bounds directory expansion and rejects cycles. These checks do
not replace control of the destination tree: callers must handle filesystem
links and concurrent changes according to the selected API's contract.

The crate forbids unsafe Rust; shared arithmetic dependencies use CPU-specific
kernels. It is a clean-room implementation of the
[PAR3 draft](https://parchive.github.io/doc/Parity_Volume_Set_Specification_v3.0.html)
and format facts established by
[par3cmdline](https://github.com/Parchive/par3cmdline). No reference code was
copied into the implementation. Official fixture provenance and creation
recipes are preserved in the repository; damage tests modify protected inputs
or model unavailable carrier ranges.

[API and migration notes](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/CHANGELOG.md).
Licensed **GPL-3.0-or-later**; see
[LICENSE](https://github.com/scryer-media/rarpar/blob/main/crates/par3-rs/LICENSE).
