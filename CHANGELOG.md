# Changelog

This file records user-visible `rarpar` CLI changes. Library API changes are
documented in each crate's own changelog so those notes ship with the crate.

## rarpar 0.5.1 (unreleased)

### CLI Changes

- `par verify` and `par repair` under the default smart placement no longer
  read a set that is already in place twice. The placement scan hashed every
  matching file in full, serially, before verification read it all again; a
  file already at its recorded name is now left to verification, and the
  remaining confirmations run in parallel. A clean eight-file 4 GiB verify
  went from 5.6 s to 0.6 s, the same as `--par-placement canonical`.

### Build Changes

- The crypto backend is now selected by an explicit feature rather than riding
  along with `runtime`. `crypto-aws-lc` forwards the AWS-LC backend to
  `par2-rs` and `unrar-rs` and is on by default; `crypto-rust` forwards the
  portable RustCrypto backends instead, for a build that must carry no C or
  assembly dependency. `runtime` forwards neither, so
  `--no-default-features --features runtime` now fails to compile — naming
  both features — instead of quietly resolving a backend.
- Every shipped artifact is still built with AWS-LC. The release and CI
  feature matrices name `crypto-aws-lc` explicitly, the release feature audit
  now requires all three packages to resolve it, and a new step reads the
  dependency graph of the exact feature list that was built and fails if
  `aws-lc-sys` is not in it.

### Library Versions

- `unrar-rs` 0.10.7 and `par2-rs` 0.10.4, for the backend feature scheme above
  and the placement scan fix;
  `unrar-rs` 0.10.7 also stops hashing a split streaming member with BLAKE2sp
  when no header names one.
  `par3-rs` and `reedsolomon-rs` are unchanged; `par3-rs` has no AWS-LC code
  path at all and gains no crypto feature.

## rarpar 0.5.0

### CLI Changes

- `par3 create` completes a recovery count or percentage to the whole rows that
  hold it when `--interleave` is set, so a request that is not a multiple of the
  cohort count no longer fails. `--first-recovery` names a row rather than a
  global recovery index for the same reason: an interleaved set takes a multiple
  of the cohort count, and anything else is refused as a command-line error
  naming that count instead of as an engine-state failure.
- A PAR3 operation refused because a name in the set breaks a name-safety rule
  now exits 3 (unsafe operation rejected) rather than 1. Creation raises it
  before it writes a byte of the set and repair before it writes a byte of any
  output, so nothing on disk has changed when it does.
- Keep repair dry runs read-only and reject layouts requiring explicit
  self-repair. Size CLI handle budgets for retained carrier collections, count
  only admitted carrier siblings, and expand inferred RAR cleanup members to
  their complete volume family.
- Retain authenticated PAR3 discovery packets across automatic repair and
  rediscovery, including renamed carriers. Defer PAR3 deficits until available
  PAR2 recovery has run, then reassess the affected sets.
- Reject overwrite plans leaving authenticated obsolete carriers and repair
  destinations that alias on the target filesystem. Apply Cauchy loss limits
  to repair dry runs and resolve cleanup membership against `-C`.
- Add `par3 create`, `par3 verify`, and `par3 repair`, using the bounded engine
  in `par3-rs` 0.4. Support FFT/interleaving, deduplication, Data packets,
  content placement, configurable volumes, dry-run creation plans, and explicit
  memory, worker, and repair-loss limits.
- Discover and repair PAR3 sets in `auto` before archive extraction. Handle
  independent copies and multiple sets, and preserve shared protection carriers
  during cleanup. Existing `par` commands continue to handle PAR2.
- Report file-coordinate damage, verified prefixes, cohort deficits, installed
  outputs, backups, and partial repair failures in human and JSON output.
- Keep creation durable by default, with an explicit buffered-write option.
  Embedded-container self-repair remains a library API.

### Libraries

- `unrar-rs` moves from 0.9.2 to 0.10.5. `rev` restores of a RAR3/RAR4 set no
  longer fail with `Bad file descriptor` when the missing volume is the set's
  last data volume, and they cost a fraction of the CPU they did: restoring a
  missing 1 MiB volume of the recovery fixture falls from about 3.0 s to 0.26 s
  on one core, byte-identical. A volume whose reader cannot report its length
  parses again, which 0.9.2's scan guard had broken for RAR4. Extraction gains
  BLAKE2sp hashing through the upstream `blake2s_simd` streaming state with
  runtime SSE4.1/AVX2 detection, cheaper RAR5 parallel-decoder literal replay,
  and a literal-run fix that keeps bounded progress when a pending filter holds
  the flush border. The parse-provenance flag, the incremental header prefixes,
  the shared KDF cache and the `Adaptive`/`Serial` decode modes are library APIs
  for streaming embedders; the binary keeps the unchanged `Auto` default and
  exposes no new option for them. See its
  [changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves from 0.9.1 to 0.10.2. The deferred short-block relocation
  sweep now reads only the bytes the scan cannot account for instead of
  byte-stepping the whole candidate once per open short length, so a damaged
  volume tail costs its own length rather than seconds; and the ordered
  canonical scan sizes its rolling buffer against the repair memory limit, so a
  set declaring a multi-gigabyte slice is scanned through a mapped window
  instead of aborting the process on an allocation it never reserved. `verify`
  and `repair` can also be cancelled while a very large candidate is being
  scanned. The extra-scan controls added in 0.10.0 are for the repairer API the
  CLI does not use. No API or option change reaches the binary. See its
  [changelog](crates/par2-rs/CHANGELOG.md).
- `par3-rs` is required at 0.4.2, the version the new `par3` commands are built
  against. It cuts and names an interleaved set's recovery carriers by row,
  bounds every repair stage's resident working set against an explicit memory
  budget, verifies large sources in a small admitted worker pool, prunes an FFT
  decode to the rows the caller reads, and refuses a set naming a path this
  platform could never write with `UnsafePath` rather than a generic
  engine-state error. See its [changelog](crates/par3-rs/CHANGELOG.md).
- `reedsolomon-rs` moves from 0.4.3 to 0.4.5. It carries the GF(2^8) region
  arithmetic and Cantor-field FFT primitives the PAR3 engine runs on, and a RAR3
  decoder that no longer clears and reallocates its syndrome and error-evaluator
  scratch on every call — the order-of-magnitude part of the `rev` restore
  saving above. See its [changelog](crates/reedsolomon-rs/CHANGELOG.md).

Every library the binary needs is now on crates.io at the version the workspace
carries, so the `[patch.crates-io]` block that stood in for the unpublished PAR3
engine and its arithmetic is gone. The CLI now names `unrar-rs`, `par2-rs` and
`par3-rs` by workspace path alongside the 0.10.5, 0.10.2 and 0.4.2 floors, so a
tagged binary is built from the tree it was cut from and the floors can no
longer drift silently behind the libraries beside them.

## rarpar 0.4.1

The 0.4.0 tag never produced a release: its build refused to link two
`aws-lc-sys` versions, because the copies of `par2-rs` and `unrar-rs` on
crates.io asked for incompatible ranges. 0.4.1 carries everything listed
under 0.4.0 below, with that conflict resolved and the RAR4 hardening added.

### Libraries

- `unrar-rs` moves from 0.9.0 to 0.9.2. RAR4 archives whose headers declare
  data that cannot exist now fail fast with `CorruptArchive` instead of
  hanging, panicking, or trying to decode gigabytes from a kilobyte; every
  reproducer the nightly fuzzing lane has saved since 2026-08-16 is covered.
  The checks run at header time or on paths the decoder reaches only once its
  input is exhausted, so legitimate archives pay nothing and the decode
  benches are unchanged within noise. `restore_volumes_from_paths` also
  restores missing volumes of a RAR5 set written with encrypted headers
  (`-hp`), which previously refused with "insufficient RAR5 recovery
  volumes". See its [changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves from 0.9.0 to 0.9.1: its optional `native-crypto` backend
  requires `aws-lc-sys` 0.45 rather than 0.44, matching `unrar-rs`. No API or
  behaviour change. See its [changelog](crates/par2-rs/CHANGELOG.md).
- `reedsolomon-rs` stays at 0.4.3.

## rarpar 0.4.0

### CLI Changes

- GPU acceleration is disabled on every platform. The `metal` and `wgpu`
  features are gone from the tool, `par create --backend metal` is no longer
  accepted, and the Apple Silicon release archive is CPU-only like every other
  archive. `--backend auto` still parses and resolves to the CPU path. The
  release feature audit now refuses any GPU feature request instead of
  admitting Metal on Apple Silicon.
- The VPCLMULQDQ CRC tier override the binary honours is renamed from
  `WEAVER_CRC32_VPCLMUL` to `RARPAR_CRC32_VPCLMUL`; values and semantics are
  unchanged and there is no alias. The `unrar-rs` runtime override knobs the
  binary inherits move from `WEAVER_*` to `UNRAR_RS_*` at the same time. A
  deployment that set the old names must rename them, which is why this is a
  minor release rather than a patch.
- A password named on the command line is now asserted on the archive after
  it opens, so members encrypted behind readable headers extract with it.
- RAR extraction goes through the `unrar-rs` 0.9.0 entry API. Output files are
  no longer preallocated to the member's declared size before extraction.

### Libraries

- `unrar-rs` moves from 0.5.5 to 0.9.0: the entry-handle extraction API, solid
  archives that refuse further extraction after an interrupted member instead
  of decoding wrong bytes, `volume_number` reported as absent when the format
  states nothing, and the `WEAVER_*` to `UNRAR_RS_*` knob rename. See its
  [changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves from 0.6.0 to 0.9.0: verification carried into repair without
  re-reading the payload, proven-slice verification, seeded-evidence scan
  settlement, and the CRC knob rename. See its
  [changelog](crates/par2-rs/CHANGELOG.md).
- `reedsolomon-rs` stays at 0.4.3.

### Dependencies

- Third-party crates move to their latest releases: `aws-lc-rs` 1.18.1 on
  `aws-lc-sys` 0.45, `cap-std` 4.0.3, `wgpu` 30.0.1, and the `wasmtime` test
  harness on 48, whose conformance test adopts wasmtime-wasi's `FsPerms`
  preopen API.

## rarpar 0.3.4

### Libraries

- `reedsolomon-rs` moves to 0.4.3, including guarded AVX512BMM capability
  detection for future SIMD dispatch work. See its
  [changelog](crates/reedsolomon-rs/CHANGELOG.md).
- `par2-rs` moves to 0.6.0. Repair scans now merge candidates before relocating
  unresolved short blocks, avoiding repeated relocation re-reads; its new
  `ScanDiagnostics` counters make that work observable. See its
  [changelog](crates/par2-rs/CHANGELOG.md).

## rarpar 0.3.3

### CLI Changes

- `par create` now warns on stderr for every zero-length input it excludes
  from the set (`skipping empty file (a PAR2 set cannot protect it): …`), on
  every noise level including `--quiet` — the same unconditional report
  `par2cmdline` gives, because an input the set will not protect is a warning,
  not progress chrome. `--json` reports the same list as the plan's
  `skipped_empty_files`. The exclusion itself is unchanged and matches the
  reference tool; details in the `par2-rs` changelog.

### Performance

- PAR2 creation now beats `par2cmdline-turbo` on every ARM class in the bench
  fleet: 1.22× on Cortex-A72 (was 0.54×), 1.10× on Neoverse V2 (was 0.77×),
  1.01× on Neoverse N1 (was 0.74×), and extends Zen 4 to 1.16× (>1 =
  `rarpar` faster), byte-identical sets throughout. The levers are a
  de-aliased, block-interleaved staging layout feeding sixteen-source CLMUL
  passes, a stripe-major banded pipeline with source hashing fused onto the
  encode bands, and a create-side kernel ladder correction on Zen 2; details
  in the `par2-rs` and `reedsolomon-rs` changelogs.
- Solid RAR4 archives no longer decode their first member twice (up to −33%
  wall on small solid PPMd archives); details in the `unrar-rs` changelog.

### Libraries

- `reedsolomon-rs` moves to 0.4.2. See
  [its changelog](crates/reedsolomon-rs/CHANGELOG.md).
- `unrar-rs` moves to 0.5.4. See
  [its changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves to 0.5.0 — a compatibility break, because bounding the
  packet inventory changed `scan_packets`'s return type and added a field to
  `Par2RepairerOptions`. See [its changelog](crates/par2-rs/CHANGELOG.md).

## rarpar 0.3.1

### CLI Changes

- Fixed a hang at 100% CPU when extracting RAR4 archives whose compressed
  payloads carry stacked delta+x86 VM filters (typical of compressed ELF
  binaries). Pre-existing since 0.2.4; details in the `unrar-rs` changelog.
- RAR4/RAR5 members whose filtered output straddles the declared member size
  now extract byte-identically to reference UnRAR (previously clamped a
  different way at decode time).
- The portable Linux musl builds — including the container image — now ship
  with the mimalloc allocator. This erases the musl allocator tax on
  allocation-heavy paths: the musl channel moves from ~5% slower than the
  glibc build to at or slightly ahead of it on the same hardware.

### Performance

- Encrypted RAR3/RAR4 extraction on x86-64 CPUs without SHA extensions flips
  from losing to reference UnRAR to beating it: 0.67–0.73× → 1.28–1.34× on
  Haswell (>1 = `rarpar` faster), from a rebuilt SHA-1 key-derivation path
  with runtime-dispatched SSSE3/AVX2 kernels. Hosts with SHA extensions were
  already ahead and are unchanged.
- PAR2 creation now beats `par2cmdline-turbo` outright on Zen 4 (1.13×) and
  Haswell (1.05×), while keeping `rarpar`'s write-and-revalidate commit.
- The published benchmark tables and charts were remeasured across all
  eleven machines on one workspace commit; per-class numbers are in
  [docs/benchmark.md](docs/benchmark.md).

### Libraries

- `reedsolomon-rs` moves to 0.4.1. See
  [its changelog](crates/reedsolomon-rs/CHANGELOG.md).
- `unrar-rs` moves to 0.5.1. See
  [its changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves to 0.4.1. See
  [its changelog](crates/par2-rs/CHANGELOG.md).
- `aws-lc-rs`/`aws-lc-sys` and the rest of the dependency tree were swept to
  current; the full workspace test matrix (1840 tests plus the slow-test
  corpus lanes) ran green on the swept tree.

## rarpar 0.3.0

### CLI Changes

- Added global `--par-placement smart|canonical`. `smart` remains the default
  and locates renamed or moved protected files by content. `canonical` limits
  PAR2 work to recorded paths and explicitly supplied search locations.
- Added the direct repair-compatible form
  `rarpar r [-B DIR] PARFILE [WILDCARD]`. The documented `rarpar par verify`
  and `rarpar par repair` commands remain the general interface.
- Explicit RAR discovery now probes only the selected archive's
  name-compatible siblings and recognizes extended old-style `.rNN`, `.sNN`
  through `.zNN`, numeric, and post-numeric volume names.
- In `auto`, volumes restored from `.rev` files remain beside their archive
  set. `--output` affects extracted payloads, not restored intermediate
  volumes.
- Relative archive paths are canonicalized before compatibility-mode set
  discovery, avoiding accidental sibling selection when the working directory
  changes.
- Header-encrypted multi-volume archives use their validated filename family
  to assemble sibling volumes when encrypted headers hide volume topology.
- Normal compatibility `x` and `e` extraction restores missing volumes from
  discovered `.rev` recovery files before extraction. Incremental `-vp` mode
  remains non-mutating and waits for later volumes through its continue/quit
  protocol.

### Libraries

- `reedsolomon-rs` moves to 0.3.0. See
  [its changelog](crates/reedsolomon-rs/CHANGELOG.md).
- `unrar-rs` moves to 0.4.0. See
  [its changelog](crates/unrar-rs/CHANGELOG.md).
- `par2-rs` moves to 0.3.0. See
  [its changelog](crates/par2-rs/CHANGELOG.md).
