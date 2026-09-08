# Incremental engine interoperability evidence

All reference runs below use official `par3cmdline` commit
`2971702e501f1350b1c7b9d11369af9157d6ed56`. The local oracle runs Linux x86-64
under emulation on macOS ARM64. These are correctness checks, not native
throughput measurements. Official reference-created fixture provenance remains
in `tests/fixtures/advanced/README.md` and `test-corpus/sources.json`.

## SIMD and worker creation checks, 2026-09-07

`tests/creation_engine.rs::export_reference_interoperability_cases` generates
additional large inputs from the BLAKE3 XOF of the UTF-8 bytes
`PAR3 native worker interoperability inputs v1`. Each input contains the full
blocks below followed by 37 bytes stored as an inline tail. This nonrepeating
input prevents successful repair from relying on duplicate source blocks.

| Case | Field | Full blocks | Capacity per cohort | Cohorts | Damaged block indices | Equations used by reference |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| `wide-fft8` | Cantor GF8 | 120 | 128 | 1 | 3, 61, 119 | 3 |
| `wide-fft16` | Cantor GF16 | 300 | 64 | 1 | 3, 137, 299 | 3 |
| `wide-interleaved` | Cantor GF8 | 301 | 128 | 3 | 0, 1, 2, 298, 299, 300 | 6 |

All cases use 1,024-byte blocks, automatic SIMD selection, two admitted engine
workers, six recovery rows beginning at index zero, and uniform three-row
volumes. The uneven case pads each cohort to 101 inputs and loses two real
blocks in each cohort. Its recovery surplus cannot move between cohorts.

For each case, the reference first verified the complete set. The test driver
then XORed byte 13 of each listed input block with `0x71`, leaving PAR3 carriers
untouched. Reference repair explicitly reported the equation count above.
Repaired input bytes equalled the original bytes held in the host driver's
memory, and a subsequent reference verification reported every file correct.
No original copy was placed where reference file discovery could use it.

| Case | Input bytes | SHA-256 of original and repaired input |
| --- | ---: | --- |
| `wide-fft8` | 122917 | `2ddcf04be6484007344e2ffee1d3e75d64198e670aff74fffe511990b32bb61d` |
| `wide-fft16` | 307237 | `a8f7e2b17a966e99a1ee2cb19b75b4ed73e0399f82920810b30a6c726204f0df` |
| `wide-interleaved` | 308261 | `5d1ab9bace03ff3246f162de3476ae74e3865c628ea165f81a7802c3f5ee2ce0` |

These comparison digests supplement the reference's own PAR3 verification;
they do not replace required PAR3 fingerprints in engine evidence.

## Embedded replacement checks, 2026-09-07

`tests/inside_engine.rs::export_replacement_archives_for_reference_validation`
exports replacements made without an original carrier manifest. It omits the
official archive's recovery packet through an unavailable range, preserves the
remaining authenticated packets, and explicitly requests the missing equation.
The authenticated gap and protected coordinates remain fixed. Ordinary tests
also repair protected-data damage with a missing optional Creator packet.

The pinned reference accepted all three replacements with `par3 vs`. XORing
protected byte 100 with `0x80` and running `par3 rs -S0` then consumed one
recovery equation in each archive and restored the complete replacement digest.

| Format | Replacement bytes | SHA-256 before damage and after reference repair |
| --- | ---: | --- |
| ZIP | 2643 | `0e02305e5ab00997e8f1c0a44b54ab5d8bb31cb9f5a88e611a05617b97e74109` |
| ZIP64 | 5656335 | `863ea588cfd53f0622ffc4c5f3c35489ef49fdb293d1d82cb5a77262bff320f3` |
| 7z | 1969 | `ca37a65afe9e79bffb50dee888effa45c55f08a4a5eb0380bb2e1ea530348509` |

Export with `PAR3_REPLACEMENT_ORACLE_OUTPUT` naming an absent directory and
Nextest's ignored test filter `test(export_replacement_archives_for_reference_validation)`.
The recorded output was `/tmp/par3-reference.mGh8NL/replacements-20260907`,
with `Zip/inside.zip`, `Zip64/inside64.zip`, and `SevenZip/inside.7z`.
These are explicit replacement carriers, not byte-exact restoration claims
about an unknown original manifest, and are not official-reference fixtures.

## Large logical block count, 2026-09-08

The exporter now includes `many-blocks`: 65,539 full 64-byte blocks, three
interleaved cohorts, and one XOR recovery equation per cohort. Its input is the
BLAKE3 XOF of `PAR3 interleaved logical block boundary v1`. The ordinary creation
test damages byte 13 of blocks 0, 32,767, and 65,537 with `0x80` and restores
the full input through the public session API. This exceeds the per-codec field
geometry globally while keeping each cohort within its own supported geometry.

Local creation and repair passed. The pinned reference also verified the
generated set, repaired the same three damaged blocks with `par3 r -S0 set.par3`,
and reported all files correct on a subsequent `par3 v set.par3`. It explicitly
reported 65,536 surviving input blocks out of 65,539 and consumed three recovery
equations. Only the protected input bytes were damaged; all carriers remained
unchanged, and no clean input copy was available to reference file discovery.

The original and repaired 4,194,496-byte input both have SHA-256
`0e35f01462cc94e846d8b862b3c1cac400d484113e4bdd508a9a21de57a3e83b`.
The authorized local run used `rarpar-par3-engine-oracle` with the generated set
under `/tmp/par3-reference.mGh8NL/created-boundary-20260908/many-blocks`. Raw logs
were `/tmp/par3-boundary-reference-before.log`,
`/tmp/par3-boundary-reference-repair.log`, and
`/tmp/par3-boundary-reference-after.log`. These are correctness results under
emulation, not native throughput evidence or official-reference fixture bytes.

## Reproduction

Create a fresh empty output directory, then export through the public library:

```sh
PAR3_ENGINE_ORACLE_OUTPUT=/absolute/path/to/empty/output \
  rtk proxy cargo nextest run --locked -p par3-rs --test creation_engine \
  --run-ignored only -E 'test(export_reference_interoperability_cases)' \
  --no-fail-fast
```

In each `wide-*` directory, run the pinned reference's `par3 v set.par3`, apply
only the input damage described above, then run `par3 r -S0 set.par3` and
`par3 v set.par3`. Check both successful exit status and explicit clean-file
verification, along with the input digest. The exporter refuses existing case
directories. It also exports the earlier small Cauchy, FFT, deduplication, and
Data cases; those do not replace the wide cases' equation-use checks.

The recorded local run used the existing `rarpar-par3-engine-oracle` container
and `/tmp/par3-reference.mGh8NL/created-workers-20260907-v2`. Each case's
`verify-before.log`, `repair.log`, and `verify-after.log`, plus the root
`interop-results.json`, held the raw results. Those temporary files are not
durable fixture provenance. Library-created packets are not added to the
official-reference fixture corpus.

Automated tests separately cover reference-created FFT repair, pure arithmetic
scalar/SIMD equivalence, supplied-pool isolation, cancellation, and allocation
ceilings. The combined host lifecycle and diagnostics are covered by
`tests/weaver_consumer.rs` and `tests/diagnostics.rs`. Required native
ARM64/x86-64 end-to-end performance comparisons remain outstanding; these
results do not claim Weaver production readiness.
