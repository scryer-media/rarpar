# Fuzzing

Two crates parse attacker-supplied containers — `unrar-rs` reads RAR, `par2-rs`
reads PAR2 — and both are reached by ordinary users pointing the tool at a file
someone else made. That is the whole threat model, and it is why fuzzing here is
a standing job rather than something run before a release.

## Targets

Five, split by what fails rather than by crate. A parser target proves the
headers cannot crash the reader; it says nothing about what those headers then
drive, which is where the arithmetic lives.

| Target | Crate | What it reaches |
| --- | --- | --- |
| `rar_headers` | `unrar-rs` | `RarArchive::open`: signatures, header chains, volume discovery. |
| `rar_extract` | `unrar-rs` | Decompression — RAR4 and RAR5 LZ, PPMd, the filter VM, stored and solid layouts. Bounded to 32 members per input so one pathological archive cannot spend the run. |
| `rar_recovery_restore` | `unrar-rs` | `restore_volumes_from_paths`: reconstructing missing volumes from `.rev` parity. This is the path that aborted an embedder with a stack overflow before 0.5.3 — well-formed headers, wrong arithmetic behind them. |
| `par2_packets` | `par2-rs` | `scan_packets_from_path`: the packet scanner. |
| `par2_verify_repair` | `par2-rs` | Slice verification against real files plus repair *planning* — exponents, slice counts and memory reservations computed from attacker-controlled numbers. Repair is not executed: its cost is set by those same numbers, so a fuzzer would spend the run reconstructing one input. |

`rar_recovery_restore` and `par2_verify_repair` need a *set* of files rather
than one blob, so their input is length-prefixed: a `u16` big-endian length,
that many bytes, repeated. A truncated or over-long prefix simply ends the
split, so every byte string is valid framing for some set and nothing is
wasted. The framing is explicit rather than `arbitrary`-derived so a crash
artifact stays readable and a minimiser can shrink each part independently.

## Seeds and dictionaries

Both formats are almost entirely structure — a signature, then typed headers
whose lengths have to agree — so a mutator starting from nothing spends its
whole budget failing the first check. Every target therefore ships:

- **A seed corpus**, committed under `crates/<crate>/fuzz/corpus/<target>/`.
  These are real archives produced by the pinned RARLAB writers and
  par2cmdline-turbo, copied from the test corpus; they are seeds, not fixtures,
  and they are not in `test-corpus/sources.json`. `cargo fuzz run <target>`
  picks the same directory up locally, so a developer reproducing a CI finding
  starts where CI started.
- **A dictionary** (`crates/<crate>/fuzz/*.dict`) of format tokens: signatures,
  header types, packet types, filter names, plausible field widths. These come
  from the published format documentation, never from reading unrar's source.

`.clusterfuzzlite/build.sh` packages both for every target
(`<target>_seed_corpus.zip` and `<target>.dict` in `$OUT`).

## Jobs

| Workflow | Trigger | Budget | Sanitizer |
| --- | --- | --- | --- |
| `cflite-pr.yml` | pull requests touching either crate or the fuzz config | 600 s, `code-change` | address |
| `cflite-batch.yml` → `batch (address)` / `batch (undefined)` | nightly 02:41 UTC, or dispatch | 3600 s each, `batch` | address, undefined |
| `cflite-batch.yml` → `coverage` | after the batch jobs | 600 s | coverage |
| `cflite-batch.yml` → `prune` | after coverage | 600 s | — |

The pull-request lane is a regression check on the change itself. The deep
search is the nightly job.

**Why two sanitizers.** They answer different questions: ASan finds the memory
error, UBSan finds the arithmetic that would have caused one on a different
target — an overflowing length computation, a bad shift, an unaligned
reference. Rust catches many of these in debug builds, but these crates ship
release with overflow checks off, which is exactly the gap UBSan covers. A
finding from one does not make the other redundant, so the matrix does not
`fail-fast`.

**Why coverage and prune.** Without a coverage report the budget is spent on
faith: a target whose coverage has been flat for a month is either finished or
stuck behind a check it cannot satisfy, and those want opposite responses.
Pruning keeps the accumulated corpus minimal so the next run spends its budget
on new ground rather than re-executing thousands of inputs that reach nothing
new.

**Why nightly.** These formats' interesting states are several correct headers
deep, so a run's value keeps rising with its budget long before it plateaus, and
each night's corpus makes the next night start further in. Weekly also meant a
build breakage could sit undetected for six days — which is how the last one was
found.

## Running one locally

```sh
# nightly is required: -Zsanitizer
cargo +nightly fuzz run rar_extract

# reproduce a specific artifact
cargo +nightly fuzz run rar_extract fuzz/artifacts/rar_extract/crash-<hash>

# minimise it before filing
cargo +nightly fuzz tmin rar_extract fuzz/artifacts/rar_extract/crash-<hash>
```

Run from the crate directory (`crates/unrar-rs` or `crates/par2-rs`), not the
workspace root — each crate's `fuzz/` is its own workspace.
