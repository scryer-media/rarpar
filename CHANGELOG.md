# Changelog

This file records user-visible `rarpar` CLI changes. Library API changes are
documented in each crate's own changelog so those notes ship with the crate.

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
  [its changelog](crates/weaver-reed-solomon/CHANGELOG.md).
- `unrar-rs` moves to 0.5.1. See
  [its changelog](crates/weaver-unrar/CHANGELOG.md).
- `par2-rs` moves to 0.4.1. See
  [its changelog](crates/weaver-par2/CHANGELOG.md).
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
  [its changelog](crates/weaver-reed-solomon/CHANGELOG.md).
- `unrar-rs` moves to 0.4.0. See
  [its changelog](crates/weaver-unrar/CHANGELOG.md).
- `par2-rs` moves to 0.3.0. See
  [its changelog](crates/weaver-par2/CHANGELOG.md).
