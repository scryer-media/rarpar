# Changelog

## 0.2.0

An inventory of the recovery data a set carries, the Galois-field arithmetic and
the Cauchy Reed-Solomon codec that recovery data is built from, and an oracle
suite that pins both against the reference implementation. The crate still
writes no `.par3` file and repairs no damaged one: the codec computes and solves
the code, and nothing yet plans a set, builds packets, decides what was lost or
writes a file back.

### Added

- `gf`: `Field`, `Gf8` and `Gf16` — table-driven arithmetic in the two binary
  Galois fields PAR3 uses, with `mul`, `inv`, and the region operations
  `mul_acc` and `mul_into` a codec spends its time in. GF(2^16) symbols are
  little-endian 16-bit words, as the reference implementation reads them.
  Constructors take the generator polynomial a Start packet declares and refuse
  one that is not primitive, because the log tables both fields are built on
  need the element two to reach every value; `gf::for_set` builds the field a
  parsed `GaloisField` names. Scalar and portable: no `unsafe`, no SIMD, no new
  dependencies.
- `cauchy`: `Encoder` and `Decoder`, the streaming Cauchy Reed-Solomon codec.
  The encoder takes input blocks in any order, once each, zero-pads a short one
  the way the reference pads a block holding a chunk tail, and returns the
  recovery blocks. The decoder is told which input blocks are lost and which
  recovery blocks are on hand, accumulates a syndrome per chosen row over the
  surviving blocks, and solves an `n × n` system over the lost columns alone —
  never the whole `input_blocks × recovery_blocks` matrix.
- `cauchy`: `Geometry`, which validates that a set's block counts have a Cauchy
  matrix at all. The row and column values collide unless
  `input_blocks + first_recovery + recovery_blocks <= 2^w`, so GF(2^8) takes 251
  input blocks with 5 recovery blocks and refuses 252 with 5.
- `cauchy`: `default_field`, the reference implementation's rule for choosing
  between the two fields, and `element`, one matrix element on its own.
- `cauchy`: `CodecLimits`, in the style of `ScanLimits` and `SetLimits`, bounding
  the recovery rows, syndromes and matrix a codec allocates from numbers a
  `.par3` file chose. `Encoder::with_limits` and `Decoder::with_limits` take one.
- `error`: `Par3Error::UnsupportedField`, `CodecGeometry`, `CodecBlock`,
  `InsufficientRecovery`, `SingularSystem` and `CodecLimitExceeded`, for the
  ways a field or a codec geometry can be unusable. A hostile geometry is an
  error at construction, never a panic and never an allocation.
- `set`: `RecoveryBlock` and `Par3Set::recovery_blocks`, the set's recovery
  blocks sorted by index and then by matrix hash, one per matrix and index and
  deduplicated — the reference implementation repeats its vital packets across
  recovery volumes so that any one volume can be read alone, and identical copies
  of a recovery block collapse into one entry. A block index selects a row of the
  Matrix packet the block names, so a set holding two matrices legitimately holds
  a block 0 for each. Each block reports the Matrix packet it names and whether
  that packet is present.
- `set`: `Par3Set::foreign_recovery_packets`, for Recovery Data packets that name
  some other Root packet. An incremental backup's child set shares its parent's
  InputSetID lineage but not its Root, so such packets are neither this set's
  recovery data nor damage; they are kept aside rather than dropped.
- `set`: `Par3Set::conflicting_recovery_packet_count`, for Recovery Data packets
  left out of the inventory because two or more of them claimed one matrix and
  index without agreeing on the bytes. None of them is listed — nothing stored
  says which is right — but the set still assembles, so a junk recovery packet
  appended to a file costs the caller that recovery block and not the file
  listing.
- `set`: `Par3Set::recovery_block_checksums` and
  `Par3Set::recovery_block_checksum`, mapping Recovery External Data packets by
  Matrix packet hash and recovery block index the way External Data packets are
  mapped by input block index, and `RecoveryBlock::matches_checksum` to check a
  block against one.

### Changed

- **Breaking:** `Par3Set::recovery_packets` is gone, replaced by
  `Par3Set::recovery_blocks` for the set's own recovery data and
  `Par3Set::foreign_recovery_packets` for packets written against another Root.
  Between them they hold every Recovery Data packet the set kept, each exactly
  once — only packets excluded as contradictory are dropped, and those are
  counted. Keeping the flat list as well would have meant retaining every
  recovery block twice, and a recovery block is as large as an input block.
- The `CauchyMatrixPacket` documentation now states the reference
  implementation's construction exactly — `inv(I ^ (MAX - R))`, applied to
  little-endian field symbols over zero-padded input blocks — instead of
  describing it loosely.
- The README, the crate documentation and the Matrix and Recovery Data packet
  documentation no longer say that the Galois-field arithmetic is unimplemented
  and that recovery is out of scope. They now draw the line where it actually
  falls: the arithmetic and the codec are here, and creating a `.par3` file and
  repairing a damaged one are not.

### Tests

- The oracle suite now covers the recovery volumes as well as the index files:
  their packet layout, their round-trip, assembling a set from the volumes alone
  or from a volume truncated mid-packet, and the recovery inventory.
- `tests/oracle_recovery.rs` recomputes every recovery block in both the GF(2^8)
  and the GF(2^16) oracle archive from the regenerated input blocks, using
  scalar Galois-field arithmetic that lives in the test alone, and asserts the
  result byte for byte against what the reference wrote. It also asserts that
  the published specification's `x_I = I + 1` column numbering does *not*
  reproduce those bytes, so the deviation is pinned rather than incidental.
- `tests/oracle_codec.rs` requires the library's own encoder to reproduce those
  same five recovery blocks byte for byte, and its decoder to rebuild every
  input block that can be lost and still recovered: all fifteen loss patterns of
  the GF(2^8) archive, and every single loss plus two hundred sampled larger
  ones of the GF(2^16) archive. The longhand arithmetic in
  `tests/oracle_recovery.rs` stays where it is, as the independent standard.
- `tests/codec.rs` round-trips random data through geometries the two oracle
  archives do not cover — odd block sizes, blocks of one field symbol, non-zero
  first recovery indices, and input counts at the edge of what each field can
  address — and checks that the order input blocks arrive in does not change the
  result.

## 0.1.0

First release. A reading foundation for PAR3: it parses packets, assembles input
sets, and verifies the files a set protects. It does not create PAR3 files and
does not repair anything — see the README for the full scope.

### Added

- `hash`: CRC-64/GO-ISO (`rolling_hash`, `RollingHasher`, `quick_rolling_hash`)
  and 16-byte BLAKE3 (`fingerprint`, `FingerprintHasher`).
- `packet`: the 48-byte header, `PacketType` for all seventeen reserved
  signatures, and typed parse plus re-serialisation for Creator, Comment, Start,
  Data, External Data, Cauchy / Sparse Random / Explicit / FFT Matrix, Recovery
  Data, Recovery External Data, File, Directory and Root. Unrecognised and
  uninterpreted types are retained as `PacketBody::Opaque`, so every packet
  written back is byte-identical to the packet read.
- `scan`: `scan_packets` and friends, which find packets in any byte range,
  verify each header hash, skip damaged packets by resynchronising on the next
  magic sequence, and bound their work with `ScanLimits` — including
  `ScanLimits::max_failed_hash_passes`, which caps the hashing a hostile input
  can provoke by packing overlapping candidate headers that never check out.
- `set`: `Par3Set`, which groups packets by InputSetID, deduplicates them, and
  resolves the Root packet's tree into `Par3File` and `Par3Directory` entries
  with `/`-joined paths, under `SetLimits` — including
  `SetLimits::max_path_bytes`, which meters the path text a directory graph
  expands into rather than only counting entries. Every chunk's whole block
  range — not only its first index — is validated against the Root packet's
  block count, so verification can walk a range without re-checking it.
- `verify`: `verify_file`, `verify_file_at_path` and `verify_set`, which check
  files against their File packet's fingerprint and narrow a mismatch down to
  input blocks using the set's External Data checksums. Localisation stops at
  the end of the file being checked: blocks that begin past it are absent rather
  than wrong, and are left to be read off the reported sizes.
