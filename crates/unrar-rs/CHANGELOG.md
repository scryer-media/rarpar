# Changelog

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
