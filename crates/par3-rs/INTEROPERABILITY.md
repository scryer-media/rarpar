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
ceilings. Required native ARM64/x86-64 end-to-end performance comparisons,
complete stage diagnostics, and the remaining integration acceptance still
apply; these results do not claim Weaver production readiness.
