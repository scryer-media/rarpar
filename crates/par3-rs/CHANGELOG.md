# Changelog

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
  with `/`-joined paths, under `SetLimits`.
- `verify`: `verify_file`, `verify_file_at_path` and `verify_set`, which check
  files against their File packet's fingerprint and narrow a mismatch down to
  input blocks using the set's External Data checksums.
