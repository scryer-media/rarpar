# Changelog


## 0.6.0

A breaking change to one field, made so an absent fact stops impersonating a
stated one.

### Changed

- **Breaking:** `RarVolumeFacts::volume_number` is now `Option<u32>`. RAR5
  states a volume number in the main header behind `MAIN_VOLNR` and RAR4
  states one only in an end record behind `VOLUME_NUMBER`; an old-numbering
  RAR4 set (`.rar`/`.rNN`) states nothing anywhere, and a RAR5 first volume
  routinely omits the field. Those volumes previously parsed as volume 0 —
  indistinguishable from a header that genuinely said 0 — which invited
  callers to adopt 0 as an identity the format never stated. `None` now means
  "the format stated nothing"; take an unnumbered volume's identity from the
  layout instead.

  Cache compatibility: facts encoded by pre-0.6 binaries carry a bare integer
  and decode as `Some(n)`. `None` encodes as nil, which pre-0.6 readers
  reject — they drop that cached row and re-parse the volume.

## 0.5.5

A correctness release from 0.5.4, plus a simpler way to extract a solid
member.

**Upgrade if you read RAR5 solid archives.** Versions 0.5.1 through 0.5.4 can
decode some of them wrongly. Extraction with `ExtractOptions::verify` set
reports the damage as a CRC or BLAKE2sp error, but with verification off the
wrong bytes are returned silently. 0.5.0 and earlier are unaffected.

### Fixed

- RAR5 members carrying filters could decode to the wrong bytes. Registering a
  filter returned the count of bytes already handed to the writer, and the
  serial decode loop assigned that back over its position in the member.
  Emission trails decoding by up to one write window, so every filter marker
  moved the position backwards — which then misplaced each later filter block
  and corrupted the output around it. Filter registration no longer returns a
  position at all, so nothing can overwrite it.

  Delta filters are what RAR emits for regular-stride binary content —
  uncompressed textures, bitmaps, PCM audio, game assets — so archives of that
  kind were the ones affected. The block-parallel decode path was never
  affected, which is why scalar decoding failed on more members than parallel
  decoding did on the same archive.

### Added

- `RarArchive::extract_member_solid_to_writer` extracts one member of a solid
  archive into a borrowed writer. It requires no `'static` bound, no `Send` or
  `Sync`, and no writer factory.

- `RarArchive::skip_member_solid` advances the solid decoder past a member
  without materialising it.

- `ExtractedMember::into_reader` returns an `ExtractedMemberReader`, reading
  from memory or streaming from the backing temporary file. A spooled member is
  no longer pulled into a `Vec` to be read, so it is not subject to the
  in-memory materialisation limit that `to_bytes` and `into_bytes` enforce.

### Runtime Behavior

- Filtered output is written whole, and the write counter advances, exactly as
  the reference implementation does. `UnpWriteData` clamps raw spans only, and
  advances its counter by the full span it was handed while the member is still
  under its declared size; filtered blocks go straight to the output. That
  counter supplies the file offset for the E8, E8E9 and ARM filters and the
  RAR4 virtual machine's `R[6]` register, so it tracks the reference exactly.

### Documentation

- The crate documentation and README lead with `extract_member` and
  `into_reader`, and cover writing a member straight into a caller's sink with
  `extract_member_streaming`. Solid and non-solid archives extract through the
  same calls; solidity determines only that members are read in ascending
  order.


## 0.5.4

This is a patch release from 0.5.3, internal only: no public item changed.

### Runtime Behavior

- RAR3 symbolic-link targets are bounded before decoding: a declared expanded
  size past the maximum path size is rejected up front, a missing expanded
  size is rejected before extraction, and oversized in-memory or
  tempfile-extracted link members are refused before materializing. Exactly
  `MAXPATHSIZE` is still admitted.

- Solid RAR4 archives no longer decode their first member twice. Solid
  dispatch is a decision about which decoder instance runs, not about state
  inheritance — inheritance is keyed on the member's own header flag inside
  the shared slot, where a non-solid member still gets a full reset
  mid-archive. Routing the (non-solid) first member of a solid archive to the
  plain path decoded it in a throwaway decoder and left the solid cursor at
  zero, so the next member re-decoded it from scratch: exactly one
  member-equivalent of redundant work per solid archive, measured at +33%
  wall on three-member PPMd fixtures. The archive-level flag is now folded
  into dispatch, which is the arrangement unrar gets for free from its single
  `Unpack` instance.
- The PPMd model keeps the previous decode's found-state symbol as a byte
  instead of re-validating the found state on every binary and escape decode:
  rescale and update relocate the found state but never change its symbol, so
  the symbol returned by decode N is exactly what decode N+1 needs. Restart
  re-seeds it from the restart-installed state. Decoded output is unchanged.

## 0.5.3

Stability patch from 0.5.2. No public item changed shape.

### Fixed

- **RAR3 recovery-volume restore no longer overflows a rayon worker's stack
  under fat LTO.** `restore_volumes_from_paths` reconstructed each byte
  column inside a `par_iter().map(..)` closure that built a fresh
  `Rar3RsCoder` (~22 KiB of GF tables) and ran a decode with ~12 KiB of scratch
  polynomials. With `lto = "fat"` / `codegen-units = 1` the optimizer inlines
  that closure into rayon's recursive splitting helper, so every recursion
  level carried a ~35 KiB frame and a default 2 MiB worker overflowed on a set
  of four 22 MiB volumes — an abort, not an error, so an embedder cannot
  contain it. A plain release build did not reproduce it, which is why it
  survived the crate's own tests. The per-column decode is now a
  `#[inline(never)]` leaf, and one boxed coder per rayon split is reused across
  its columns (the erasure pattern is identical for every column, which is the
  case the coder's cached locator polynomial exists for). Also markedly
  faster: the GF tables are built once per split rather than once per byte
  position.

### Added

- The `rar3_recovery_volumes_large` corpus set (four 1 MiB RAR 2.9-format
  volumes plus two `.rev`, `rar a -ma4 -m0 -v1m -rv2`) and a test that
  restores two missing volumes from it and checks them byte for byte against
  RARLAB's originals. The existing 1 KiB set decodes 1024 columns and cannot
  reach the recursion the fix above is about; this one decodes a million.

## 0.5.2

Security patch from 0.5.1. No public item changed shape.

### Fixed

- **Reject header-declared volume numbers above a sane ceiling instead of
  sizing an allocation with them.** RAR5 encodes the main header's volume
  number as an unbounded vint, and it was cast straight to `usize` and used to
  fill a dense volume vector one entry at a time. A 130-byte archive declaring
  volume 508_427_613_235_168_135 made `RarArchive::open` request roughly
  462,000 TiB before reading a single member byte — an allocation failure that
  aborts the process rather than unwinding, so a caller cannot contain it with
  `catch_unwind`. Availability only: no `unsafe` lies on that path. Found by
  the crate's `rar_headers` fuzz target; present since the first release.
  `RAR_MAX_VOLUME_NUMBER` (1 << 20) now bounds every header-declared volume
  number — RAR5 open, RAR5 incremental volume registration, and the RAR4/RAR14
  ENDARC number, the last already bounded by the format but routed through the
  same check so the invariant holds uniformly. Rejected rather than clamped:
  the reference implementation only ever displays this field, it never sizes a
  table with it. The ceiling cannot refuse a real set — 500 GiB of member data
  split into 512 KiB volumes is still under 1M parts.

## 0.5.1

This is a patch release from 0.5.0: additive and internal only, no public
item changed shape, staying inside the 0.5.x compatibility range.

### Runtime Behavior

- Fixed an infinite spin at 100% CPU on RAR4 archives whose compressed
  payloads carry stacked delta+x86 VM filters (typical of compressed ELF
  binaries): a head pending filter positioned ahead of the window made the
  output drain loop re-enter with byte-identical state forever. Pre-existing
  since 0.2.4. The drain now writes raw spans the way the reference
  implementation does and carries a no-progress guard, so it terminates by
  construction.
- RAR4 and RAR5 filtered output is now bounded at the write layer, matching
  the reference implementation exactly: emitted bytes are clamped while the
  written-size counter advances by the full span, so filtered blocks that
  straddle a member's declared end emit exactly the reference's bytes
  (previously clamped at decode time, which diverged on such archives). The
  decode bound is the declared size widened only by queued filter reach,
  hard-capped one dictionary past declared — archives without VM filters
  decode not one byte further than before, in both the serial and
  multi-threaded apply paths.
- RAR4 filter register sizing (`InitR[4]`) and cross-writer-version LZ state
  retention follow the reference implementation.

### Performance

- The RAR 2.9/3.x ("RAR29") key derivation — the dominant cost of opening
  encrypted RAR3/RAR4 archives — was rebuilt in three steps. The scalar
  SHA-1 fallback is fully unrolled to the reference tool's shape (1359
  instructions per block with zero branches, from ~2700 with ~400). On top
  of it, SSSE3 and AVX2 SHA-1 kernels ported from AWS-LC's perlasm
  implementation dispatch at runtime on x86-64 hosts without SHA extensions.
  The default vector tier is chosen by measurement, not ISA width: the SSSE3
  kernel outruns the AVX2 one on every no-SHA-NI part measured (Alder Lake
  and Haswell), so it is preferred, with the AVX2 kernel selectable by
  override for silicon that disagrees. Hosts with SHA extensions are
  unaffected — that path still wins outright and stays first.
  - Measured end to end on Haswell (Xeon E5-2666 v3) against reference
    UnRAR: the four encrypted RAR3/RAR4 extraction cases moved from
    0.67–0.73× to 1.28–1.34× (>1 = this crate is faster).
  - `WEAVER_UNRAR_SHA1_X86` selects within the vector module — `ssse3` and
    `avx2` force one tier so a single binary can A/B them (a named tier also
    stands the SHA-extension path down, so the A/B works on SHA-capable
    hosts), `0` stands the module down, and unknown values are ignored. The
    override widens *policy* only; the CPUID capability probe is never
    bypassed, so forcing a tier the CPU cannot execute stands the module down
    rather than issuing an undefined opcode. `WEAVER_UNRAR_SHA1_HW=0` keeps
    its existing whole-ladder meaning: plain scalar.
  - Digests are unchanged. The kernels are pinned by the RAR29 KDF
    known-answer vector under every override pin and by a multi-block
    differential of both vector kernels against the scalar path, with a
    deliberately corrupted-input negative control witnessed failing.
- BLAKE2sp member checksums on aarch64 use a group kernel arrangement,
  reducing checksum CPU on stored-payload archives.
- Further hot-path rounds landed on the no-AVX (SSSE3) and aarch64 tiers;
  per-machine results are in the workspace benchmark documentation, measured
  across eleven machines on this tree.

### Dependencies

- `aws-lc-rs` 1.16 → 1.18 and `aws-lc-sys` 0.42 → 0.44, converged on a
  single copy of the C library. The digest and HMAC surface this crate uses
  is byte-identical across the bump, and none of the upstream assembly this
  crate's hashes flow through changed on any architecture.

## 0.5.0

This release leaves the 0.4.x compatibility range because of one auto-trait
change; everything else is additive or internal.

### Migration

- `LzDecoder` is no longer `RefUnwindSafe`. The parallel LZ pipeline holds
  interior-mutable batch state, so code that placed an `LzDecoder` (or types
  containing it) across `std::panic::catch_unwind` must wrap it in
  `AssertUnwindSafe` or restructure. No other public item changed shape;
  additions are source-compatible.

### Runtime Behavior

- RAR5 LZ decoding runs a staged batch pipeline (block planning, staged
  input, bounded decode/apply overlap), replacing the worker-count-dependent
  batching that regressed low-core-count hosts, with a window-flush guard
  tied to unflushed dictionary bytes.
- RAR4 PPMd decode paths were restructured for measurable decode-time
  reduction on PPMd-heavy archives.
- Huffman, filter, window, and bitstream hot paths were tightened; benchmark
  charts in the README reflect the current tree across five platforms,
  including first AVX-512 (Zen 4) measurements.

### Documentation

- Benchmark charts regenerated with the relative-speed-ordered renderer and
  embedded with absolute URLs so crates.io and docs.rs render them; the crate
  changelog returned to the package after being dropped from 0.4.0's tree.

## 0.4.0

This is a minor release from 0.3.1.

### Public API

- `BitRead` adds `read_byte` and the hidden zero-padding helper used by range
  decoders. Both have defaults, so existing external implementations do not
  require changes.
- No existing archive, extraction, streaming-volume, or recovery API was
  intentionally removed.

### Runtime Behavior

- Recovery restoration is idempotent when every data volume is already present
  and valid, returning an empty restoration report instead of a corruption
  error.
- Solid archives now preserve decoder state from the first compressed member,
  whose per-file header cannot refer to a predecessor even though its state
  seeds later members.
- RAR4 PPMd uses validated arena spans and batched state access, tightening
  bounds handling while reducing repeated offset decoding.
- Byte-oriented range decoding now amortizes bitstream refills across
  consecutive unaligned byte reads.
- The Reed-Solomon dependency moves to 0.3.0.
