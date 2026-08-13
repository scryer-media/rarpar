# Changelog

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
