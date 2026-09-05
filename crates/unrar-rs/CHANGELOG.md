# Changelog


## 0.10.0

A parse result now says whether it came from the archive's Quick Open cache.
Until now a caller could only see that a *locator* was present, which says
nothing about provenance: `rar` writes a `QO` block holding file records and no
end-of-archive record, this crate refuses such a cache and walks the headers
physically, and the caller was left re-walking every locator-bearing volume to
find out what it had already been given.

### Added

- `ParsedHeaders::headers_from_quick_open` and
  `RarVolumeFacts::headers_from_quick_open` report where the returned headers
  came from: `true` only when the whole result was read out of the `QO` block,
  `false` for every physical walk — a cache that was present but rejected, an
  encrypted cache that could not be opened, a parse under
  `HeaderParseOptions { allow_quick_open: false }`, and every RAR4/RAR1.4
  volume, which has no such cache. Cache-derived headers stay
  non-authoritative, and a caller that routes bytes by them should re-parse
  with Quick Open disabled; it can now skip that second walk when the flag is
  `false`. `quick_open_offset.is_some()` is not a substitute — it reports a
  locator record, not provenance.

### Changed

- **Breaking.** `ParsedHeaders` and `RarVolumeFacts` are ordinary structs with
  all-public fields and no `#[non_exhaustive]`, so adding a field breaks any
  downstream code that builds one as a struct literal. Hence the minor bump
  rather than a patch. Nothing else about parsing changed: the same caches are
  accepted and the same ones refused.
- `RarVolumeFacts::headers_from_quick_open` decodes as `false` on facts a
  pre-0.10 binary serialized, and those binaries did consult the cache by
  default — so such a row can report a physical walk it never performed. A
  store that persists these facts across an upgrade should key entries by
  crate version and re-parse anything older.

## 0.9.2

Hardening against pathological RAR4 input found by the nightly fuzzing lane.
Every reproducer it saved since 2026-08-16 (18 inputs of 73 bytes to 1.6 KiB,
each declaring 2.5 MB to 4.2 GB of output) now fails fast with
`CorruptArchive` instead of hanging, panicking, or trying to decode gigabytes
from a kilobyte. Legitimate archives pay nothing for it: the checks run at
header time, or on paths the decoder only reaches once its input is already
exhausted, and the RAR4 LZ and PPMd decode benches are unchanged within noise.

### Fixed

- A RAR4 file header declaring a `packed_size` above `i64::MAX` made the
  volume scan seek *backwards* (the size was cast to `i64` for a relative
  seek), re-read the same header indefinitely, and grow the member list
  without bound; this was reachable from `RarArchive::open` alone. Every data
  skip is now a checked forward seek, each scan must strictly advance per
  header, and no volume yields more than `MAX_HEADERS_PER_VOLUME` headers.
- A RAR4 member whose data offset plus declared `packed_size` lies past the
  end of its volume is rejected when its header is read, unless the header
  says the data continues in the next volume. That is where most of the
  fuzzer's inputs now stop, before any decoder runs.
- The RAR4 LZ decoder could spin forever once its input ran out: the
  bit reader kept reporting bits remaining from a stale accumulator while
  refilling from nothing on every call. `bits_remaining()` no longer refills
  past end of input, and a decode round that neither consumes input nor
  produces output ends the member as corrupt.
- PPMd: the run-length counter overflowed `i32` after enough binary-context
  symbols and, with overflow checks on, panicked (it also feeds an array index,
  so a silent wrap was not benign); it saturates. A stream repeating the
  VM-code escape with no output is bounded by the filter queue's own limit,
  and a range decoder fed zeros past end of input fails after 64 of them
  instead of decoding symbols forever.
- The sliding window's invisible-byte accounting is a running total rather
  than a scan of every recorded range per symbol.

### Added

- `limits::MAX_HEADERS_PER_VOLUME`.
- The fuzz seed corpus under `fuzz/corpus/<target>/` carries the 18
  reproducers, and `tests/fuzz_corpus_regressions.rs` replays them. Both are
  excluded from the published crate together with the rest of `fuzz/**`.

## 0.9.1

A recovery-volume fix for header-encrypted sets.

### Fixed

- `restore_volumes_from_paths` now restores missing volumes of a RAR5 set
  written with `-hp` (encrypted headers). The volume-number probe required a
  readable main header to accept a data volume, and an encrypted one has none,
  so every present volume was counted as missing and the restore refused with
  "insufficient RAR5 recovery volumes". The layout name now places such a
  volume, and the `.rev` table's per-volume size and CRC32 still decide
  whether it is really present — a misnamed file is rejected, never trusted.
  The corpus gains `rar5_hp_recovery_volumes.*` (five 4 KiB volumes and two
  `.rev` files under the corpus HP password) from the `recovery_volumes`
  recipe, and the integration suite restores two missing parts of it.

## 0.9.0

Extraction is now reached the way the Rust archive ecosystem reaches it: take
a member handle from the archive, then say where its bytes go. The eight entry
points that came before are kept as deprecated wrappers over the same engines,
so nothing has to move today.

### Added

- `RarArchive::by_index`, `by_name` and `by_index_via` hand back an `Entry`.
  Taking one decodes nothing; it resolves the member and borrows the archive.
- `Entry` consumes itself into a destination: `copy_to` writes straight into a
  writer, `copy_to_volumes` splits the member across one writer per volume it
  spans, `unpack_to` and `unpack_in` write it to disk with the metadata the
  archive carries, `skip` advances past it, and `Read` serves it from a spool
  for callers that have no writer to hand. `index`, `info`, `name`, `size`
  and `is_dir` describe one entry; `with_progress` and `with_password` steer
  it. Every consuming call reports to the handler `with_progress` names: a
  start event, the running byte count as the destination receives it, and a
  completion event carrying the outcome.
- The per-volume writer is a plain generic. It needs neither `Box`, `Send`,
  nor `'static`, so a writer holding `&RefCell<_>` or `Rc<_>` is accepted.
- Extraction settings live on the archive: `set_verify`/`verify` and
  `set_restore_owners`/`restore_owners`, joining `set_password`. An `Entry`
  extracts under those settings, so no options value is threaded through a
  call chain.
- `ExtractOptions` gains `with_verify`, `with_password`, `with_restore_owners`
  and matching getters, and is `Clone` and `Debug`. The `Debug` form says
  whether a password is set and never prints it.
- Listing without building the whole metadata document: `len`, `is_empty`,
  `entries`, `entry_info` and `index_for_name`.
- `RarError::SolidStatePoisoned` reports a solid archive whose decoder was
  left mid-member. `RarError::MemberIndexOutOfRange` is what `by_index`
  raises for an index the archive does not list, and
  `RarError::VolumeProviderRequired` is what `copy_to_volumes` raises for a
  non-solid member taken without a provider; neither is a corruption report.

### Changed

- `RarError` is `#[non_exhaustive]`. A `match` over it outside this crate
  needs a wildcard arm; the crate's failure modes grow with the formats it
  recognises, and adding one should not be a breaking change.
- A solid member that fails partway — a decode error, or a writer that
  refuses — poisons the archive. Every later solid extraction raises
  `SolidStatePoisoned` until `reset_solid_state` clears it and extraction
  restarts from the first member. Before this, the carried-over dictionary was
  reused as if the interrupted member had completed, so the members after it
  could decode to plausible but wrong bytes. Non-solid members are unaffected.
- The `decompress`, `rar4` and `vint` modules are crate-private. An archive is
  read through `RarArchive` and its `Entry`; nothing outside this crate drove
  the decoders directly, and their surface was the crate's largest by a wide
  margin. `header` stays public — walking a RAR5 volume's headers without
  opening the archive is a real use, and its result type is public API.
- The decoder and RAR4 entry points that lost their last caller when those
  modules went private are still compiled, under one `#![allow(dead_code)]`
  per module tree (`decompress`, `rar4`). They are the 0.10.0 removal list:
  which of them is dead depends on the feature set, so removing them is a
  deliberate change rather than part of a visibility sweep.
- New non-default feature `unstable-internals` exposes `__internals`, which is
  what this crate's own bench and `probe_volumes` example reach for. It is not
  public API and carries no semver guarantee.

### Deprecated

- `extract_member`, `extract_by_name`, `extract_member_to_file`,
  `extract_member_streaming`, `extract_member_streaming_chunked`,
  `extract_member_solid_to_writer`, `extract_member_solid_chunked` and
  `skip_member_solid`. Each still behaves exactly as it did and calls the same
  engine the handle calls. They are removed in 0.10.0.

### Migration

Take a handle, then consume it. The archive holds the password, the
verification setting and the owner-restoration setting, so the
`ExtractOptions` value most call sites threaded through disappears.

- `extract_member(i, &options, progress)?.to_bytes()?` becomes
  `let mut bytes = Vec::new(); archive.by_index(i)?.copy_to(&mut bytes)?;`
  — or `read_to_end` on the entry when a `Read` is what the caller wants.
- `extract_by_name(name, &options, progress)?` becomes `archive.by_name(name)?`
  followed by the same consumption.
- `extract_member_to_file(i, &options, progress, path)?` becomes
  `archive.by_index(i)?.unpack_to(path)?`, or `.unpack_in(dir)?` to let the
  member's own sanitized name choose the file.
- `extract_member_solid_to_writer(i, &options, w)?` becomes
  `archive.by_index(i)?.copy_to(w)?`.
- `extract_member_streaming(i, &options, provider, w)?` becomes
  `archive.by_index_via(i, provider)?.copy_to(w)?`.
- `extract_member_streaming_chunked(i, &options, provider, factory)?` becomes
  `archive.by_index_via(i, provider)?.copy_to_volumes(factory)?`, and
  `extract_member_solid_chunked(i, &options, factory)?` becomes
  `archive.by_index(i)?.copy_to_volumes(factory)?`. The factory no longer has
  to return `Box<dyn Write>`: return the writer itself, and drop the
  `Rc<RefCell<_>>` or `Arc<Mutex<_>>` that boxing forced on a shared sink — a
  writer that borrows the sink is now accepted.
- `skip_member_solid(i, &options)?` becomes `archive.by_index(i)?.skip()?`.
- Options that were passed per call are set once instead: `options.verify`
  becomes `archive.set_verify(..)`, `options.password` becomes
  `archive.set_password(..)`, and `options.restore_owners` becomes
  `archive.set_restore_owners(..)`. A single entry can still override the
  password with `by_index(i)?.with_password(..)`.
- A `match` over `RarError` in another crate needs a wildcard arm.


## 0.8.0

A breaking release that removes every embedder-specific transport from the
crate. Host delegation of the two bulk primitives (AES-CBC decrypt and the
member CRC-32) now has exactly one shape — a pair of embedder-installed Rust
function pointers — and the crate no longer knows or cares whether the
embedder is a core wasm module, a WASI Preview 2 component, an Extism plugin,
or something else. The runtime escape hatches lose their former owner's name.

### Removed

- The raw wasm imports `host_aes_cbc_decrypt` and `host_crc32` that
  `crypto-host` / `crc-host` used to declare, together with the features
  that only selected their import namespace: `host-abi-extism`
  (`extism:host/user`) and the never-published `host-abi-component`. The
  guest-pointer ABI those imports encoded is a property of one particular
  embedding, not of RAR extraction; it now lives in
  `examples/wasm_extract_conformance.rs`, which is the reference embedding for
  a core module and is still driven end to end by the `wasmtime` harnesses in
  `tests/`.

### Changed

- `crypto-host` and `crc-host` delegate through the `hooks` module
  (`HostCryptoHooks`, `install_host_crypto_hooks`,
  `host_crypto_hooks_installed`, `clear_host_crypto_hooks`, `HostAesError`),
  which is present whenever either feature is enabled. The embedder installs
  the pair once at start-up and owns whatever transport sits behind it. The
  features stay wasm32-only in effect: on a native target they are accepted
  but inert, so feature unification in a mixed workspace cannot turn a native
  build into a delegating one. Every feature is additive; the crate builds
  with `--all-features`.
- The runtime override knobs are renamed from `WEAVER_*` to `UNRAR_RS_*`.
  Values and semantics are unchanged; there are no aliases.

  | 0.7.0                              | 0.8.0                           |
  |------------------------------------|---------------------------------|
  | `WEAVER_UNRAR_SHA1_HW`             | `UNRAR_RS_SHA1_HW`              |
  | `WEAVER_UNRAR_SHA1_X86`            | `UNRAR_RS_SHA1_X86`             |
  | `WEAVER_CRC32_VPCLMUL`             | `RARPAR_CRC32_VPCLMUL`          |
  | `WEAVER_RAR_DISABLE_PARALLEL`      | `UNRAR_RS_DISABLE_PARALLEL`     |
  | `WEAVER_RAR_SPOOL_THRESHOLD_BYTES` | `UNRAR_RS_SPOOL_THRESHOLD_BYTES`|
  | `WEAVER_RAR4_MT_THREADS`           | `UNRAR_RS_RAR4_MT_THREADS`      |
  | `WEAVER_RAR4_DEBUG_PPM`            | `UNRAR_RS_RAR4_DEBUG_PPM`       |
  | `WEAVER_RAR4_DEBUG_FILTERS`        | `UNRAR_RS_RAR4_DEBUG_FILTERS`   |
  | `WEAVER_RAR4_DEBUG_DUMP_PATH`      | `UNRAR_RS_RAR4_DEBUG_DUMP_PATH` |

  `RARPAR_CRC32_VPCLMUL` takes the workspace prefix because the CRC kernel it
  lives in is shared byte for byte with `par2-rs`, which renames it in the
  same release (0.9.0).
- `limits::WEAVER_MAX_MEMBER_DATA_SIZE` is renamed to
  `limits::MAX_MEMBER_DATA_SIZE`; the value is unchanged.

### Migration

- Native embedders (the default `crypto-aws-lc` or `crypto-rust` backends)
  are unaffected apart from the renames above.
- A wasm guest that built with `crypto-host` / `crc-host` and satisfied the
  raw imports from its runtime now declares those imports itself and installs
  hooks that forward to them — the `embedding` module in
  `examples/wasm_extract_conformance.rs` is a drop-in for the `host`
  namespace, and changing the `#[link(wasm_import_module = ...)]` string is
  all an Extism embedding needs. A component embedding installs hooks that
  forward to its generated imports and drops `host-abi-component` from its
  feature list.


## 0.7.0

A resource-hardening release that stops trusting an archive member's declared
expanded size as a reason to reserve disk blocks before any output is written.

### Changed

- **Breaking:** removed `RarArchive::preallocate_output_file`. It exposed the
  same eager physical-allocation policy that direct-to-file extraction used,
  and a caller could not apply it safely to an untrusted declared size before
  extraction had established how much output was actually available.

### Fixed

- Direct-to-file extraction no longer preallocates the member's declared
  expanded size. Truncated or malformed input now consumes disk space in
  proportion to bytes actually written instead of potentially reserving a
  large sparse member's full advertised size before extraction fails.


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
