# weaver-unrar test fixtures

Binary fixtures live in Git LFS. `.gitattributes` at the repo root routes
`crates/weaver-unrar/tests/fixtures/**/*.{rar,rev,exe,bin,mkv,wav}` through the
LFS filter; anything added here under a different extension needs a new pattern
before it will be stored correctly.

Tests soft-skip when a fixture is absent, so a checkout without LFS payloads
still runs the suite. A skip prints `skipping test: <set> fixtures not present`.

`Cargo.toml` sets `exclude = ["tests/fixtures/**"]`, so none of this ships in
the published crate.

## Generators

| Script | Produces | Needs |
| --- | --- | --- |
| `generate_edge_cases.sh` | most `rar4_*` / `rar5_*` edge-case sets | `rar:latest`, `rar:4` |
| `generate_generated_matrix.sh` | `generated_matrix_*` multi-volume matrix | `rar:latest`, `rar:4`, ffmpeg |
| `generate_encrypted.sh` | `*_enc_*` / `*_hp_*` sets | `rar:latest`, `rar:4` |
| `generate_stored_layout.sh` | the stored-layout sets listed below | `rar:latest` |

The `rar:latest` image is RARLAB rar **7.20**. It dropped `-ma4` and `-vn`, so
it can no longer write RAR4 archives or old-style (`.r00`, `.r01`) volume
names; those come from the `rar:4` image (rar 6.24).

## Imported corpora

Fixtures whose provenance is another repository, kept byte-identical to their
source so they stay comparable.

### From the Scryer e2e release gate

Copied verbatim from `scryer-media/e2e/testdata/`. Verified byte-identical by
SHA-256 at import. All eight are single-volume archives exercising decode paths
(solid, nested, unicode, header encryption) rather than cross-volume layout.

| Fixture | e2e source |
| --- | --- |
| `rar4/rar4_hp_large.rar` | `testdata/rar4-encrypted/archive.rar` |
| `rar4/rar4_solid.rar` | `testdata/rar4-solid/archive.rar` |
| `rar5/rar5_nested_2deep.rar` | `testdata/nested-rar/archive.rar` |
| `rar5/rar5_nested_3deep.rar` | `testdata/nested-3deep/archive.rar` |
| `rar5/rar5_nested_5deep.rar` | `testdata/nested-5deep/archive.rar` |
| `rar5/rar5_solid.rar` | `testdata/rar5-solid/archive.rar` |
| `rar5/rar5_solid_encrypted.rar` | `testdata/rar5-solid-encrypted/archive.rar` |
| `rar5/rar5_unicode_cjk.rar` | `testdata/unicode-filenames/archive.rar` |

The e2e corpus also holds multi-volume sets (`rar4-multivolume`,
`rar5-multivolume`, `par2-multivolume`, `rar5-solid-multivolume`). None were
imported: every one is a **compressed** member at 20–31 MiB per volume, so they
add no stored-layout coverage that the sets below do not already give at a
thousandth of the size.

`e2e` is a read-only release gate. Import from it; never write to it.

### Other upstreams

- `rar4/old-rar-provenance.md` — junrar RAR 1.5 / 2.0 oracle archives.
- `test_read_format_*` — libarchive's RAR test corpus.
- `ssokolow_*` — ssokolow's RAR sample collection (SFX, locked, AV headers).

## Stored-layout coverage

Sets driven by `tests/stored_layout_fixtures.rs` against
`src/stored_layout.rs`. "Recipe" is the `rar` invocation; see the generator
scripts for the surrounding setup.

| Set | Shape it exercises | Recipe |
| --- | --- | --- |
| `rar4/rar4_mv_store.part1..5.rar` | RAR4 multi-volume store, one member over 5 volumes. `compression_version = 20`, so split parts reuse `FILE_CRC` for the **packed** CRC32 and only the final part states the whole-member value. | no checked-in generator; shape reconstructed from the headers as `rar a -ma4 -m0 -ep1 -v64k … originals/binary.bin` (262 144 B) |
| `rar5/rar5_mv_store_long.part01..27.rar` | Long chain: 27 volumes, so logical offsets are real prefix sums. First part 1855 B, middle 1854 B, last 947 B — non-uniform at both ends. | `rar a -m0 -v2k` on a 48 KiB blob |
| `rar5/generated_matrix_rar5_store_plain.part1..7.rar` | Quick-open service data (`QO`) on every volume of a plain stored set: envelope bytes that must not perturb the member mapping. | `rar a -m0 -ep1 -v160k` (`generate_generated_matrix.sh`) |
| `rar5/rar5_mv_store_rr.part1..6.rar` | Recovery record (`RR`) on every volume, ~1 KiB per volume — large enough that an envelope sum that ignored it would be obviously wrong. | `rar a -m0 -rr5p -v4k` on a 16 KiB blob |
| `rar5/rar5_multifile_lz.rar` | Mixed archive: `-m3` stores what it cannot shrink, so two stored members stay direct-eligible while one compressed member is demoted with exact packed/unpacked counts. | `rar a -m3 -ep1` (`generate_edge_cases.sh`) |
| `rar5/rar5_store_blake2.rar` + `rar5/rar5_store_crc32_control.rar` | The `-htb` pair: identical members, differing only in the hash switch. Establishes that BLAKE2 **replaces** the CRC32. | `rar a -m0 -htb` / `rar a -m0` |
| `rar5/rar5_mv_store_blake2.part1..6.rar` | `-htb` across a split chain: non-final parts state a packed BLAKE2sp and no packed CRC32. | `rar a -m0 -htb -v1k` on a 4 KiB blob |
| `rar5/rar5_enc_mv_store.part1..5.rar` | Encrypted multi-volume store: demoted to `Encrypted`, chain facts still intact. | `rar a -m0 -v55k -ep1 -ptestpass123` (`generate_encrypted.sh`) |
| `rar5/rar5_recovery_volumes.part01..10.rar` | Header volume numbers (0-based) against filename part numbers (1-based). | no checked-in generator; shape reconstructed from the headers as `rar a -m0 -v1k -rv2 … payload.bin` (8192 B), which also emits the two `.rev` recovery volumes |

### Empirical finding: `-htb` writes BLAKE2 only

RARLAB rar 7.20 with `-htb` writes a BLAKE2sp digest and **no** `Data-CRC32` —
the switch selects a hash type, it does not add one. `rar5_store_blake2.rar`
and its CRC32 twin `rar5_store_crc32_control.rar` pin this down: same members,
same stored layout, and the only difference in the parsed facts is
`data_crc32: None, data_blake2_hash: Some(_)` against
`data_crc32: Some(_), data_blake2_hash: None`.

Across a split chain the same holds per part: non-final parts carry
`packed_blake2_hash` and no `packed_crc32`, and the final part carries the
whole-member BLAKE2sp and no CRC32.

So `IneligibilityReason::Blake2OnlyNoCrc32` is a state real archives reach, not
a defensive branch — BLAKE2sp only accepts bytes in order, so nothing in a
`-htb` archive can verify an out-of-order direct-store write.

### Known gap

No fixture uses old-style RAR volume names (`archive.rar`, `archive.r00`,
`archive.r01`). Those would give a filename/volume-number relationship that is
not a constant offset, which is the harder case for modal-delta reconciliation.
A genuine one cannot be faked by renaming — RAR4's main header carries a
`MHD_NEWNUMBERING` flag that records which scheme was used — and rar 7.20 has
no `-vn`, so producing one needs a rar 6.x binary.

## Content rule

Fixture member names are invented. Use `Silver.Horizon`-style titles, never
real media names.
