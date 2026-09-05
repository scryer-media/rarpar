# unrar-rs test fixtures

Binary fixtures are part of the repository's **test corpus**: every file here
has an entry in `test-corpus/sources.json` (digest, size, and provenance —
which generator on which pinned writer, or which pinned upstream commit under
which license), and the corpus is published as a signed, content-addressed
object set hydrated by `cargo run -p xtask -- test-corpus fetch --profile …`.
The UnRAR fixtures are bundled by format era: `rar12` (RAR 1.5 / 2.0),
`rar34` (RAR 3.x / 4.x — the `rar4/` directory) and `rar57` (RAR 5.x / 7.x —
the `rar5/` directory), each with `originals/`. See `docs/test-corpus.md`.
Until the first published corpus is pinned in `test-corpus/lock.json`, Git LFS
remains the transport (`.gitattributes` routes the listed binary extensions
through the LFS filter).

Tests soft-skip when a fixture is absent, so a checkout without the payloads
still runs the suite. A skip prints `skipping test: <set> fixtures not present`.

`Cargo.toml` sets `exclude = ["tests/fixtures/**"]`, so none of this ships in
the published crate.

## Generators

**Every fixture here has a recipe.** Nothing in this directory is inherited: a
file is either written by one of the recipes below on the shared pinned
toolchain in `bench/rarpar-bench/config/toolchains.json`, or imported
byte-identically from a public upstream at a pinned commit. Build the images
once with `cargo run --locked -p xtask -- bench toolchains build`, then produce
the whole corpus with:

```console
cargo run --locked -p xtask -- test-corpus generate --jobs 4
```

That is the only supported way to regenerate: it runs the recipes in the right
order, fetches the upstream imports, refuses a tree that is not exactly the
ledger's path set, and refreshes `test-corpus/sources.json`. `--only <recipe>`
runs one of them while you iterate, but a corpus revision is a full run.

The recipes are Go, in `bench/rarpar-bench/internal/testcorpus`, so they run
wherever the harness does — Windows included; the only external processes they
start are the pinned Docker images. `--only` names one of the units below.

| Recipe | Produces | Toolchain |
| --- | --- | --- |
| `inputs` | `originals/binary.bin`, `originals/test_clip.mkv` | `ffmpeg-7.1-ubuntu2404` (the ramp needs none) |
| `edge_cases` | most `rar4_*` / `rar5_*` edge-case sets, both `*_tiny_volumes` sets, and the `originals/` inputs | `rarlab-7.20`, `rarlab-6.24` |
| `core_sets` | `*_store`, `*_lz`, `*_hp_store`, `*_hp_lz`, `*_mv_store`, `*_mv_video`, `rar4_lz_solid_mv` | `rarlab-7.20`, `rarlab-6.24` |
| `encrypted` | the four `*_enc_*` sets per format | `rarlab-7.20`, `rarlab-6.24` |
| `recovery_volumes` | `rar3_recovery_volumes.*`, `rar3_recovery_volumes_large.*`, `rar5_recovery_volumes.*` and `rar5_hp_recovery_volumes.*`, `.rar` and `.rev` | `rarlab-6.24`, `rarlab-7.20` |
| `large_sets` | the ~85 MB video-member sets: `*_solid`, `*_hp_large`, `rar5_solid_encrypted`, `rar5_unicode_cjk`, `rar5_nested_{2,3,5}deep` | `ffmpeg-7.1-ubuntu2404`, `rarlab-7.20`, `rarlab-6.24` |
| `generated_matrix` | `generated_matrix_*` multi-volume matrix | `rarlab-7.20`, `rarlab-6.24`, `ffmpeg-7.1-ubuntu2404` |
| `stored_layout` | the stored-layout sets listed below | `rarlab-7.20` |
| `ppmd_solid` | `rar4_ppm_solid_restart`, `rar4_ppm_solid_mv` (PPMd correctness) | `rarlab-6.24` |
| `ppmd_perf` | deterministic RAR4 order-16 PPMd performance and classic-volume corpora (`generate_ppmd_perf.py`, the one recipe still a script) | `rarlab-6.24` |

`rarlab-7.20` is RARLAB rar **7.20**. It dropped `-ma4` and `-vn`, so it can no
longer write RAR4 archives or old-style (`.r00`, `.r01`) volume names; those
come from `rarlab-6.24` (rar 6.24).

Regeneration is **shape-reproducible, not byte-reproducible** (rar stamps times
into headers and encryption draws random salts), so re-running a generator is
always a corpus revision: refresh `test-corpus/sources.json`, publish, and pin.
What *is* fixed is everything the suites read — member names and sizes, volume
counts, the payload prefixes the PPMd and solid-LZ tests pin — so a regenerated
corpus still passes the suites with different bytes.

**Every RAR fixture here is written by a pinned RARLAB `rar` image or imported
unmodified from a public upstream, and there is no third option.** The UnRAR
license permits unrar's code, and knowledge of it, to be used to *read* RAR
archives, never to create them, so a hand-assembled container is not something
this corpus may hold — and a shape RARLAB's writer cannot emit is a shape the
corpus does not carry. Never use `unrar` — the binary or its source — to author,
stamp or complete a fixture. (PAR2, Matroska and the plain inputs are open
formats and follow the ordinary pinned-toolchain rules.)

`rar4/rar4_hp_long_password.rar` is the one thing here that is **not** corpus
content: the test that reads it is `#[ignore]`d, and it has no ledger entry, so
the `edge_cases` recipe writes it only under
`RARPAR_FIXTURES_LONG_PASSWORD=1`.

## RAR4 PPMd performance corpus

`rar4/rar4_ppm_order16_32m.rar` is generated by
`generate_ppmd_perf.py`. It contains one deterministic 33,554,432-byte
base64-like text member and is compressed with
`rar a -ma4 -m5 -mc16:16t+ -md4m -ep`. The fixed writer is RARLAB rar 6.24,
because later releases cannot create RAR4 archives; by default it comes from the
pinned `rarpar-bench-rarlab:6.24` image, and `--rar-bin` runs a local 6.24
binary instead. The script prints both archive and decompressed-payload SHA-256
values — SHA-256 because `tests/integration.rs` pins the payload as a SHA-256
known-answer vector and Python has no BLAKE3 in its standard library; the corpus
ledger records the archive's BLAKE3 digest like every other object's.

## RAR4 PPMd classic volumes

`rar4_ppm_oldmv.rar` through `rar4_ppm_oldmv.r02` contain the first 262,144
bytes of the same deterministic payload. They exercise PPMd decoding across
classic volume boundaries. `--all` writes them together with the order-16
corpus at their ledger paths, which is what `test-corpus generate` runs:

```console
python3 generate_ppmd_perf.py --all
```

The decompressed payload's digest is not repeated here: `tests/integration.rs`
pins it (`test_rar4_ppmd_classic_multivolume_payload`), and one place to update
is enough.

## RAR4 PPMd correctness corpus

The `ppmd_solid` recipe writes the two fixtures the PPMd *decoder* is held to,
as opposed to the performance corpora above:

- `rar4_ppm_solid_restart.rar` — one 1 600 000-byte member under a small PPMd
  heap, so the sub-allocator restarts several times mid-stream. The payload is
  base64 of the byte sequence Python's `random.seed(20260704)` produces through
  `getrandbits(8)`; `tests/integration.rs` pins its length, its ASCII-ness and
  its first sixteen bytes.
- `rar4_ppm_solid_mv.rar` — three solid PPMd members, so the range coder's
  registers have to survive a member boundary. `tests/integration.rs` pins each
  member's exact length and its first 24 bytes, which is why the word salad the
  script writes starts from a fixed opening phrase and is cut to an exact
  length.

Both are also imported by `bench/rarpar-bench/config/corpus.json` under a pinned
digest, so regenerating them moves those pins:
`cargo run --locked -p xtask -- test-corpus bench-pins` prints the new values.

## The large video-member sets

The `large_sets` recipe writes the eight single-volume archives that exercise
decode paths — solid, nested, unicode, header encryption — rather than
cross-volume layout, plus their ~85 MB member from the pinned encoder.

| Fixture | Shape it exercises |
| --- | --- |
| `rar4/rar4_solid.rar`, `rar5/rar5_solid.rar` | Solid, members `sample.mkv`, `file1.txt`, `file2.txt`: reaching a later member decodes the earlier ones |
| `rar4/rar4_hp_large.rar`, `rar5/rar5_hp_large.rar` | `-hp` over a member far larger than the dictionary, under `e2e-test-password` |
| `rar5/rar5_solid_encrypted.rar` | Solid `-p`: file data encrypted, headers readable, two members |
| `rar5/rar5_unicode_cjk.rar` | One member whose name is CJK (`映画テスト.mkv`) |
| `rar5/rar5_nested_{2,3,5}deep.rar` | A RAR holding a RAR, that deep, with the clip at the bottom |

These eight were imported verbatim from the Scryer e2e release gate before they
had a recipe. They now have one, so nothing depends on that private repository.
The generated three-deep chain differs from the imported one in exactly one way:
the import's innermost container was a 7-Zip archive, and 7-Zip is not in the
pinned toolchain, so the generated chain is RAR at every level. No suite reads
the nested sets, so nothing turns on it.

## Imported corpora

Fixtures whose provenance is another repository, kept byte-identical to their
source so they stay comparable. Every one is public and is re-fetched at its
pinned commit by `test-corpus generate`; the corpus has no private upstream.

### Other upstreams

Pinned by commit, path, digest and license in `test-corpus/sources.json`; the
publish workflow re-fetches every public one and requires byte identity.

- `rar4/old-rar-provenance.md` — junrar RAR 1.5 / 2.0 oracle archives
  (junrar/junrar, UnRAR license). Immutable imports: no RARLAB writer is, or
  can be, assigned to them.
- `test_read_format_*` — libarchive's RAR test corpus (libarchive/libarchive,
  BSD-2-Clause; stored uuencoded upstream).
- `ssokolow_*` — ssokolow's RAR sample collection (ssokolow/rar-test-files,
  CC0-1.0; the SFX stubs inside are freely redistributable RARLAB code).

## Stored-layout coverage

Sets driven by `tests/stored_layout_fixtures.rs` against
`src/stored_layout.rs`. "Recipe" is the `rar` invocation; see the generator
scripts for the surrounding setup.

| Set | Shape it exercises | Recipe |
| --- | --- | --- |
| `rar4/rar4_mv_store.part1..5.rar` | RAR4 multi-volume store, one member over 5 volumes. `compression_version = 20`, so split parts reuse `FILE_CRC` for the **packed** CRC32 and only the final part states the whole-member value. | `rar a -ma4 -m0 -v64k` on `originals/binary.bin` (262 144 B) (`core_sets`) |
| `rar5/rar5_mv_store_long.part01..27.rar` | Long chain: 27 volumes, so logical offsets are real prefix sums. First part 1855 B, middle 1854 B, last 947 B — non-uniform at both ends. | `rar a -m0 -v2k` on a 48 KiB blob |
| `rar5/generated_matrix_rar5_store_plain.part1..7.rar` | Quick-open service data (`QO`) on every volume of a plain stored set: envelope bytes that must not perturb the member mapping. | `rar a -m0 -ep1 -v176k` (`generated_matrix`) |
| `rar5/rar5_mv_store_rr.part1..6.rar` | Recovery record (`RR`) on every volume, ~1 KiB per volume — large enough that an envelope sum that ignored it would be obviously wrong. | `rar a -m0 -rr5p -v4k` on a 16 KiB blob |
| `rar5/rar5_multifile_lz.rar` | Mixed archive: `-m3` stores what it cannot shrink, so two stored members stay direct-eligible while one compressed member is demoted with exact packed/unpacked counts. | `rar a -m3 -ep1` (`edge_cases`) |
| `rar5/rar5_store_blake2.rar` + `rar5/rar5_store_crc32_control.rar` | The `-htb` pair: identical members, differing only in the hash switch. Establishes that BLAKE2 **replaces** the CRC32. | `rar a -m0 -htb` / `rar a -m0` |
| `rar5/rar5_mv_store_blake2.part1..6.rar` | `-htb` across a split chain: non-final parts state a packed BLAKE2sp and no packed CRC32. | `rar a -m0 -htb -v1k` on a 4 KiB blob |
| `rar5/rar5_enc_mv_store.part1..5.rar` | Encrypted multi-volume store, one member over 5 volumes, with a plaintext size that is already block-aligned — the case an exact chain-sum equality passes by luck. | `rar a -m0 -v55k -ep1 -ptestpass123` (`encrypted`) |
| `rar5/rar5_enc_mv_store_pair.part01..09.rar` | Encrypted (`-p`) multi-volume store with **two** members over 9 volumes: two CBC streams with different IVs, one volume carrying the tail of one member and the head of the next, and both sides of the padding rule (20 001 B needs a 15-byte tail, 12 288 B needs none). Parts are not individually block-aligned, so a range's preceding cipher block routinely lives in the previous volume. | `rar a -m0 -ptestpass123 -v4k` on 20 001 B + 12 288 B blobs |
| `rar5/rar5_enc_store_pair.rar` | The same two members in one volume: the only place the 15-byte tail padding is directly visible as packed bytes past the member's declared end. | `rar a -m0 -ptestpass123` on the same blobs |
| `rar4/rar4_enc_mv_store.part1..5.rar` | RAR4 encrypted multi-volume store: no `FHEXTRA_CRYPT` record, an 8-byte per-file salt instead, and the same `align16` chain rule. | `rar a -ma4 -m0 -v55k -ep1 -ptestpass123` (`encrypted`) |
| `rar5/rar5_recovery_volumes.part01..10.rar` | Header volume numbers (0-based) against filename part numbers (1-based). | `rar a -m0 -v1k -rv2` on an 8 192-byte `payload.bin`, which also emits the two `.rev` recovery volumes (`recovery_volumes`) |

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

### Empirical findings: what `-p` does to a stored chain

Measured across `rar5_enc_store*`, `rar5_enc_mv_*`, `generated_matrix_rar5_store_enc`
and `rar4_enc_*`, all written by RARLAB rar (7.20 for RAR5, 6.24 for RAR4).

1. **One CBC stream per member, padded once.** A member's packed sizes sum to
   `align16(unpacked_size)`, never to `unpacked_size` — 1 172 084 B of payload
   occupies 1 172 096 packed bytes, 290 B occupies 304. This holds for RAR4 as
   well as RAR5.
2. **Split parts are not individually block-aligned.** A 262 144 B member over
   five volumes splits 56 058 / 56 057 / 56 057 / 56 057 / 37 915 — none of
   which is a multiple of 16. The CBC chain therefore runs unbroken across
   volume boundaries, and the cipher block preceding an interior offset is
   often in the previous volume (sometimes straddling the boundary itself).
3. **Every part of a member states the same crypt record**, byte for byte:
   same version, KDF count, salt, IV and password-check value. Different
   *members* of one archive share the salt and check value but get their own
   IV.
4. **The hash-MAC flag is per part, and `rar` sets it on the final part only.**
   `enc_flags & 0x0002` is clear on every non-final part and set on the last —
   because only the last part's checksum is the whole member's. Treating that
   flag as a per-member constant, or folding it into "the parts agree about
   encryption", would misjudge every real encrypted split chain.

## Multi-member multi-volume extraction

Sets driven by `tests/integration.rs`, for the one thing every other
multi-volume fixture here cannot show: a member that does not start in the
set's first volume. With a single member starting in volume 0, addressing
volumes by the set's numbering and by the member's own first volume look
identical, and a streaming path that confuses the two still passes.

| Set | Shape it exercises | Recipe |
| --- | --- | --- |
| `rar5/rar5_mv_store_pair.part01..09.rar` | Plain multi-volume store, two members over 9 volumes, the second starting in volume 5. The plaintext twin of `rar5_enc_mv_store_pair` — same members, same volume size, same member boundary — which is what shows the volume-addressing defect it was found through has nothing to do with encryption. | `rar a -m0 -v4k` on 20 001 B + 12 288 B blobs |
| `rar5/rar5_mv_solid_pair.part01..09.rar` | The same pair as one solid (`-s -m5`) stream, second member again starting in volume 5. Reaching it decodes the first member first, so the skipped member's volumes are addressed too. | `rar a -m5 -s -v4k` on the same blobs |

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
