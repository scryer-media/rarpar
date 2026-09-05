# Changelog

This file records user-visible `rarpar` CLI changes. Library API changes are
documented in each crate's own changelog so those notes ship with the crate.

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
