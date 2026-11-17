# Reference source for segment reads and link inspection

This comparison uses RARLAB's **UnRAR 7.30 beta 2**, dated **2026-10-27** in
`version.hpp`, from the [official source archive](https://www.rarlab.com/rar/unrarsrc-7.3.2.tar.gz).
The archive SHA-256 is
`f61a1160d6e2ebbda2ad353c8e82f62ab4312f97fde23c6c2c982d25e0014f99`.
Line numbers below refer to that exact archive, not a moving mirror. Existing
UnRAR license restrictions and notices remain in force; this is a reader-only
change, not a RAR writer.

| Rust change | Reference source | Relationship |
| --- | --- | --- |
| `ArchiveSegmentReader::read` and `ChainedSegmentReader::read` bound in `u64` before converting the result to `usize` | `rdwrfn.cpp:81`, `ComprDataIO::UnpRead`; `rdwrfn.hpp:29` declares the wide packed counter | Preserves the same compare-before-narrowing principle. The defect was a Rust adapter cast on 32-bit targets, not an upstream UnRAR decoder defect. |
| `RarArchive::member_redirection` exposes existing parsed type and directory-target metadata | `arcread.cpp:1198-1215`, `FHEXTRA_REDIR`; `headers.hpp:109` | Additive borrowed access to already parsed semantics. It does not change the parser or equate a junction/directory target with a regular-file link. |
| `RarArchive::read_link_target` returns bounded target text without host extraction | `ulinks.cpp:73-110`, `ExtractUnixLink30` | Related reader responsibility, deliberately stricter API contract rather than literal behavior parity. |

## What the wide-length fix does

The previous Rust expression converted the remaining segment length to
`usize` before taking a minimum with the buffer length. On 32-bit targets,
including wasm32, values at or above 4 GiB can lose their high bits. At an
exact multiple of 4 GiB this asks the underlying reader for zero bytes, then
reports unexpected EOF. The replacement takes the minimum in `u64`; only a
count already bounded by the actual buffer is converted to `usize`.

The affected quantity is an individual packed segment's remaining length.
An archive's aggregate size, or an expanded member size above 4 GiB, is not
by itself sufficient to encounter this defect. Native 64-bit targets do not
truncate this counter. The change does not alter decompressor or CRC logic.
The boundary regression uses virtual segment metadata and a short real read;
it is not a completed multi-gigabyte archive test.

## Deliberate strict inspection policy

Reference `ExtractUnixLink30` bounds the packed target and reads it through
`UnpRead`. Its text path uses `SafeCharToWide` and `TruncateAtZero`, and its
hash update uses the first-NUL prefix (`strlen`). Do not describe it as the
new API's complete decoded-payload stored-CRC contract.

The new inspection API instead requires, for RAR3 Unix targets:

- known packed and expanded lengths within `min(max_bytes, 64 KiB)` before
  payload decoding, plus an actual output ceiling;
- a present payload CRC and the existing checksum-verifying decoder path;
- exact expanded length before and after materialization; and
- nonempty strict UTF-8 without any NUL byte.

In a solid archive a RAR3 target read consumes its member like an `Entry`
read: members are read in ascending order, an archive already poisoned by a
failed solid read is refused, and a target read that fails after its
member's decode began poisons the archive.

For RAR5, the target is existing header metadata: the raw target text the
header parser kept. The parser decodes the stored target as UnRAR's
`UtfToWide` does, ending at the first NUL or malformed UTF-8 sequence, so
it is the same target filesystem extraction uses; stored bytes past that
point are not seen by this API. The lossy convenience string is never used:
a member without raw target text (restored from an older metadata cache)
fails as corrupt. Header verification is not a claim of a separate payload CRC, nor
is a CRC a cryptographic authenticity guarantee. Unknown redirection types
are refused, while known directory/junction targets remain inspectable.
Returned paths are untrusted. Resolving targets within an archive, rejecting
traversal or aliases, deciding whether to allow links, and setting a lower
application limit are caller policies, not literal UnRAR parity claims.

## Legacy filesystem extraction

The existing filesystem extractor still calls its separate
`link_target_from_rar3_payload` path: first-NUL truncation, lenient text
compatibility and its existing prefix-CRC policy are retained. The new
strict text API does not replace that path or prohibit native filesystem
link extraction.

One existing bound is intentionally enforced more strongly: all RAR4 solid
link-payload branches, including both encrypted-reader routes, now wrap the
writer when a link-output ceiling was requested. Ordinary decoding with no
such ceiling delegates to the original solid decoder. Do not summarize this
as every aspect of filesystem behavior being unchanged.
