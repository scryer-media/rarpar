# Changelog

## 0.3.0 (unreleased)

- Pin Windows packet carriers with budgeted read-only sharing locks to avoid
  full-file generation hashes inside scan and payload loops. Charge fallback
  generation hashing to the cumulative work budget.
- Expose `Par3RepairSession::validate_repair` so dry runs and execution share
  readiness, ordinary-repair layout support, and configured Cauchy loss/handle checks.
- Add bounded incremental packet ingestion, virtual source access, positioned
  BLAKE3 verification evidence, retained repair sessions, cancellation, and
  shared memory, handle, and scan-work budgets.
- Support low-rate FFT and interleaved recovery, shared and deduplicated blocks,
  packed tails, Data packets, content placement, and selective reconstruction.
- Add advanced creation, recovery-carrier reconstruction, and explicit staged
  ZIP/ZIP64/7z insertion and self-repair. Existing convenience creation defaults
  remain Cauchy-based.
- Reuse the GF8 and FFT primitives in `reedsolomon-rs` 0.4.5. Verify Data payloads
  against protected-extent fingerprints before admission, validate FFT field
  geometry, and bound Cauchy loss counts before solver allocation.
- Enable the published advanced reference corpus and document the synchronous
  host contract, interoperability, and native verification/repair performance.

This minor version introduces the advanced public engine contract. Consumers
should review the README and ENGINE.md when moving from the 0.2 convenience APIs.

## 0.2.0

An inventory of the recovery data a set carries, the Galois-field arithmetic and
the Cauchy Reed-Solomon codec that recovery data is built from, creating a
complete PAR3 set from a list of input files, repairing one, and an oracle suite
that pins all of it against the reference implementation.

### Added

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
  `.par3` file chose, and — since the solve is cubic in the number of lost
  blocks, and a set of two-byte blocks can name thousands of them inside any
  memory budget — the lost blocks one decoder will solve for
  (`max_lost_blocks`, 4096 by default). `Encoder::with_limits` and
  `Decoder::with_limits` take one.
- `error`: `Par3Error::UnsupportedField`, `CodecGeometry`, `CodecBlock`,
  `InsufficientRecovery`, `SingularSystem` and `CodecLimitExceeded`, for the
  ways a field or a codec geometry can be unusable. A hostile geometry is an
  error at construction, never a panic and never an allocation.

- `create`: `create`, which writes an index file and its recovery volumes for
  files under a base directory. It plans the whole set from the file sizes
  alone — block size, chunk map, tail packing, block count, Galois field,
  recovery count — then reads each input exactly once, hashing it, checksumming
  its input blocks and feeding the Cauchy encoder as the bytes go past. Given
  the same inputs and settings, every byte of every file it writes matches what
  the reference implementation writes, the Creator text aside;
  `tests/oracle_create.rs` rebuilds both oracle archives and requires it.
- `create`: `CreateOptions` and `RecoveryAmount`, for the block size (or
  `None` to take the suggested one), the recovery amount as a block count or a
  percentage, the Creator text, an optional comment, and whether an existing
  file may be replaced. Nothing is written until every target has been checked,
  so a refusal to overwrite leaves the directory untouched.
- `create`: `InputSpec`, naming the files a set protects relative to one base
  directory, plus any directories that hold no protected file. Every name is
  checked component by component against the rules the reader enforces, so
  nothing this crate writes can fail to be read back.
- `create`: `CreateReport`, which says what was built: the InputSetID, the block
  size after any rounding, the input and recovery block counts, the field, how
  many chunk tails were packed behind an earlier one, and every file written
  with the index first.
- `create`: `suggest_block_size`, the reference implementation's rule for
  choosing a block size from a set of file sizes.
- `create`: `CreateLimits`, in the same style, bounding the block size, the
  number of input files, the bytes of path text, the blocks held while their
  chunk tails are still filling, and the codec.
- `error`: `Par3Error::CreateInput`, `CreateLimitExceeded` and `FileIo`, for an
  input a set cannot be built from, a set that would exceed `CreateLimits`, and
  anything the file system refused, named by path.

- `repair`: `repair_set`, which puts a set's protected files back from whatever
  survives. It verifies every file, works out which input blocks were lost —
  those of a missing file, those that failed their checksum, the block behind
  every damaged chunk tail, and everything a truncation took away — solves for
  them with the recovery blocks the set carries, and writes each damaged or
  missing file back. Files that verify complete are never touched. Everything
  streams: a file is read a block at a time and written a block at a time, so
  nothing costs the size of a file.
- `repair`: `plan_repair` and `RepairPlan`, the dry run. It reports the
  verification, the input blocks that would have to be rebuilt, the recovery
  blocks that would be spent, how many the set has, and which files would be
  written — and a set with more losses than recovery blocks is a plan, not an
  error, so a caller can say how many more blocks would be needed
  (`missing_recovery_blocks`).
- `repair`: `RepairOptions`, for whether the damaged file is kept. With `backup`
  on, the default, it is renamed to `<name>.1`, or `.2`, and so on up to the
  first free number, the way the reference implementation does it; with it off
  nothing is deleted either — the rebuilt file is renamed over the damaged one,
  which replaces it in one step. Each rebuild is written under a temporary name,
  checked against its File packet there, and only then moved into place, so a
  rebuild that does not check out costs nothing that was still there. The
  temporary is created exclusively — a link planted under its name is refused,
  never followed — and a set directory replaced by a link is refused before its
  file is rebuilt.
- `repair`: `RepairReport` and `RepairedFile`, saying what was written, where the
  damaged file was kept, whether each rebuild checked out, and how the whole set
  verified afterwards.
- `repair`: `RepairLimits`, in the same style, bounding the input blocks a set
  may have, the bytes held for blocks of packed chunk tails that are still
  filling, and the decoder.
- `error`: `Par3Error::UnrepairableSet` and `RepairLimitExceeded`, for a set
  whose own packets do not describe a layout to repair from — two chunks
  claiming the same bytes of one input block, a tail that does not fit, a block
  no file writes, a file that cannot be checked at all, or recovery data
  computed with a matrix this crate does not implement — and for a repair that
  would exceed `RepairLimits`.

- `verify`: `FileVerdict::Damaged::damaged_tail_blocks` and
  `FileVerdict::damaged_tail_blocks`, the input blocks holding a chunk tail that
  did not match. This is the damage `damaged_chunks` names, expressed in the
  blocks a codec works in: a tail block may hold several tails from several
  files, and one wrong tail spoils all of it. An inline tail lives in the File
  packet and occupies no block, so it never appears here.

- `examples/par3rs.rs`: a std-only example front-end with `create`, `verify`,
  `repair` and `list` subcommands, so the API can be tried from a shell without
  writing a program first. It is a demonstration, not a tool, and not official
  PAR3 tooling.

### Changed

- **Breaking:** `Par3Set::recovery_packets` is gone, replaced by
  `Par3Set::recovery_blocks` for the set's own recovery data and
  `Par3Set::foreign_recovery_packets` for packets written against another Root.
  Between them they hold every Recovery Data packet the set kept, each exactly
  once — only packets excluded as contradictory are dropped, and those are
  counted. Keeping the flat list as well would have meant retaining every
  recovery block twice, and a recovery block is as large as an input block.
- **Breaking:** `FileVerdict::Damaged` is now `#[non_exhaustive]` as well as the
  enum, because it gained a field. Match it with a trailing `..`.
- `verify_file_at_path` no longer reads the file into memory. It hashes the file
  in fixed-size pieces, and narrows a mismatch down by reading one region at a
  time, so its working set is `min(block_size, file_size)` plus a fixed 64 KiB
  whatever the file's length. The verdicts are unchanged, and
  `tests/repair.rs` requires them to equal `verify_file`'s on the same bytes for
  every damage case.
- The `CauchyMatrixPacket` documentation now states the reference
  implementation's construction exactly — `inv(I ^ (MAX - R))`, applied to
  little-endian field symbols over zero-padded input blocks — instead of
  describing it loosely.
- The README, the crate documentation and the Matrix and Recovery Data packet
  documentation no longer say that the Galois-field arithmetic is unimplemented
  and that recovery is out of scope. They now draw the line where it actually
  falls: reading, verifying, creating and repairing a set built with the
  reference implementation's default settings are all here, and what is not is
  listed one item at a time.

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
- `tests/corpus_sets.rs` holds the library to the eight PAR3 sets in the
  repository's test corpus — `gf8_packed`, `gf16_blocks`, `gf16_by_recovery`,
  `index_only`, `tree`, `tiny_inline`, `auto_block` and `large_stream` — every
  one of them written by the reference implementation, and hydrated from the
  published, signed corpus rather than committed. Each set is read and compared
  with the shape the reference recorded, its inputs are verified whole, it is
  created again from those inputs and matched byte for byte across every index
  and volume file, and damage made in memory on copies of the inputs is
  repaired back to them from the reference's own volumes. `tiny_inline` and
  `auto_block` were written without `-s`, so re-creating them holds
  `suggest_block_size` to the block size the reference chose; `index_only` pins
  the refusal to repair a set that carries no recovery data, and that the
  refusal writes nothing. The tests skip where the corpus has not been
  hydrated.

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
