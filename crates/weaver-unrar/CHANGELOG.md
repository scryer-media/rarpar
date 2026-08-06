# Changelog

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
