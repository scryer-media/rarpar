# rarpar

[![License](https://img.shields.io/badge/license-GPL--3.0--or--later%20AND%20UnRAR--restriction-blue)](#license)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/scryer-media/rarpar/badge)](https://scorecard.dev/viewer/?uri=github.com/scryer-media/rarpar)

`rarpar` is a command-line tool for RAR archives and PAR2/PAR3 recovery sets,
written in Rust. Point it at an archive, a recovery file, or a messy download
folder, and it works out what is there, repairs what it can, rebuilds missing
volumes, and extracts with every byte checked.

It is built on library crates in this repository that are published on
crates.io. The CLI itself ships as release binaries and source, not on
crates.io.

`rarpar` is not an official RAR, PAR2 or PAR3 tool. It ships no binaries
named `unrar`, `rar`, `par2` or `par2repair`, and it cannot create or modify
RAR archives.

## What it does

- Finds RAR, REV, PAR2 and PAR3 sets in a file or folder.
- Verifies and repairs PAR2 and PAR3 sets before extracting.
- Creates PAR2 sets (`par create`) and PAR3 sets (`par3 create`).
- Rebuilds missing RAR volumes from `.rev` files.
- Extracts RAR archives, including encrypted ones, with integrity checks on.
- Compresses, decompresses, tests and lists `.xz` files on several threads.
- Can delete the source files after a successful extraction, to the trash by
  default.
- Reports in JSON for scripts.
- Accepts UnRAR's command shape, including `-vp` for archives still
  downloading.

## Speed

How many times faster than the reference tools a whole `rarpar` run is
(2.0× is half the time). The references are RARLAB's UnRAR and
par2cmdline-turbo 1.4.0.

| CPU | Arch | Instruction set | unrar (binary) | unrar (text) | par2 (heavy) |
|---|---|---|---:|---:|---:|
| AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 2.5× | 1.8× | 3.3× |
| Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 2.0× | 1.5× | 2.5× |
| Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 1.6× | 1.4× | 3.0× |
| Intel Xeon Platinum 8124M (Skylake-SP) | x86-64 | AVX-512 | 1.6× | 1.3× | 2.3× |
| AMD Ryzen 5 3600 (Zen 2) † | x86-64 | AVX2 | 1.6× | 1.5× | 1.6× |
| Intel Xeon E5-2666 v3 (Haswell) | x86-64 | AVX2 | 1.6× | 1.3× | 2.3× |
| Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.2× | 1.4× | 1.6× |
| Apple M5 Max † | arm64 | NEON | 1.3× | 1.5× | 7.8× |
| Arm Cortex-A72 | arm64 | NEON | 2.0× | 1.6× | 1.3× |
| Arm Neoverse N1 | arm64 | NEON | 2.9× | 1.7× | 1.8× |
| Arm Neoverse V2 | arm64 | NEON | 3.1× | 1.8× | 2.0× |

- **unrar (binary)** is extracting stored media, with and without encryption.
- **unrar (text)** is extracting compressed data, including PPMd.
- **par2 (heavy)** is the two heavy repairs.
- † From an older release (`rarpar` 0.3.3), awaiting a re-measure. The other
  rows measure `rarpar` 0.8.0 and 0.8.1.
- The Apple PAR2 figure is against par2cmdline-turbo's macOS arm64 build,
  which is much slower than its Linux and Windows builds.

Encrypted extraction gains the most, up to 11.9×. A few cases are at or just
below parity, among them PAR2 verify on the Intel machines and stored media on
Denverton.

PAR3, against par3cmdline 0.0.1 on Alder Lake and Denverton: creating is
4.6×–7.6× faster, verifying 5.2×–5.8×, repairing 6.3×–8.6×.

Release builds run on the CPU only; the GPU options of the PAR2 library are
not turned on. Every case, chart, method and version is in
[docs/benchmark.md](docs/benchmark.md).

## Install

With Homebrew:

```bash
brew install scryer-media/rarpar/rarpar
```

Or download the archive for your platform from GitHub Releases and put
`rarpar` on your `PATH`. Archives include a manpage and shell completions
under `share/`, signed checksums and build provenance; Linux comes in GNU and
musl builds. [Release verification](.github/release-signing/verification.md)
shows how to check them.

From source:

```bash
cargo install --locked --path tools/rarpar
```

## Quick start

Do everything for a download (`rarpar auto` is the same):

```bash
rarpar ~/Downloads/some-release
```

See what it would do, without changing anything:

```bash
rarpar inspect --json ~/Downloads/some-release
```

Extract somewhere else, then move the sources to the trash:

```bash
rarpar auto --output ~/Extracted --delete-sources ~/Downloads/some-release
```

`--permanent-delete` deletes instead of using the trash, and
`rarpar cleanup --dry-run` shows what cleanup would remove.

## Commands

```bash
rarpar rar list archive.part1.rar
rarpar rar extract archive.part1.rar ./out
rarpar rar restore-volumes archive.part1.rar archive.part1.rev

rarpar par verify release.par2
rarpar par repair release.par2
rarpar par create ./release/release --recovery-percent 5 part01.rar part02.rar

rarpar par3 create release.par3 part01.rar part02.rar -s 1048576 -r 5
rarpar par3 verify release.par3
rarpar par3 repair release.par3

rarpar xz compress data.tar
rarpar xz decompress data.tar.xz ./out
tar -c ./release | rarpar xz compress > release.tar.xz
```

Pipes work without temporary files: `par verify --name` checks a file as it
streams in, `par3 create -` and `xz compress --sidecar` make a recovery set
from a stream, and `xz` reads and writes standard input and output.

The [command reference](docs/cli.md) covers every command, including PAR3
options, recovery sets written alongside an archive, file placement, and
folder scanning limits.

## Passwords

```bash
rarpar --password-file passwords.txt ./release
rarpar --password-env RAR_PASSWORD ./release
rarpar --password-fd 3 ./release 3< passwords.txt
```

Files and descriptors hold one password per line. If none works and you are
at a terminal, `rarpar` asks, with the input hidden. Passwords are never
printed or written to JSON.

## Cleanup

Cleanup only removes files it used: the RAR volumes, their `.rev` files, and
the PAR2 and PAR3 files for that set. It leaves `.nfo`, `.sfv`, samples,
subtitles and anything else alone.

## UnRAR-compatible mode

Programs that expect UnRAR can call `rarpar` the same way:

```bash
rarpar x archive.part1.rar /dest/
rarpar t archive.rar
rarpar l archive.rar
```

`x`, `e`, `t`, `l` and `lb` work, with the common switches. `-vp` waits for
each volume while a set is still downloading. See
[docs/rarpar-compatibility.md](docs/rarpar-compatibility.md).

## Crates

- [`unrar-rs`](crates/unrar-rs): reads and extracts RAR archives.
- [`par2-rs`](crates/par2-rs): creates, verifies and repairs PAR2 sets.
- [`par3-rs`](crates/par3-rs): creates, verifies and repairs PAR3 sets.
- [`reedsolomon-rs`](crates/reedsolomon-rs): the recovery math they share.
- [`tools/rarpar`](tools/rarpar): this command.

## Development

Test files live in a separate signed store, not in Git
([docs/test-corpus.md](docs/test-corpus.md)). After cloning:

```bash
git config core.hooksPath .githooks
cargo run --locked -p xtask -- test-corpus hydrate --profile unrar --profile par2
```

The checks CI runs:

```bash
cargo fmt --check --all
cargo clippy --locked --workspace --all-targets --features unrar-rs/unstable-internals -- -D warnings
cargo nextest run --locked --workspace --lib --bins --examples --no-fail-fast --features unrar-rs/unstable-internals
```

More in `docs/`: [publishing](docs/publishing.md),
[packaging](docs/packaging.md), [fuzzing](docs/fuzzing.md), and the
[technology radar](docs/technology-radar.md). Changes by version are in
[CHANGELOG.md](CHANGELOG.md).

## License

- `rarpar` is GPL-3.0-or-later, with a section 7 permission to combine it
  with `unrar-rs` ([tools/rarpar/LICENSE](tools/rarpar/LICENSE)). It includes
  `unrar-rs` by default, so an ordinary build, `cargo install` or release
  archive carries the UnRAR restriction too. Release archives include one
  `LICENSE` file with the full terms.
- `unrar-rs` is Apache-2.0 plus the UnRAR licence restriction, from 0.11.0 on.
  Its RAR engine was developed from RARLAB's UnRAR source, and the restriction
  still governs that code ([LICENSE](crates/unrar-rs/LICENSE)).
- `par2-rs` (from 0.10.11), `par3-rs` (from 0.5.1) and `reedsolomon-rs`
  (from 0.4.10) are Apache-2.0. The par2-rs tests adapted from par2cmdline's
  GPL-2.0-or-later suite stay GPL-3.0-or-later and are not published with
  the crate. `reedsolomon-rs` includes GF(2¹⁶) kernels ported from
  [ParPar](https://github.com/animetosho/ParPar), which its author released as
  public domain or CC0.

Earlier releases of the library crates stay under
GPL-3.0-or-later (`unrar-rs` with the UnRAR restriction).

The UnRAR restriction covers `unrar-rs` and `rarpar` only, never the PAR2,
PAR3 or Reed-Solomon crates. That is why those are published with an SPDX
licence expression, while `unrar-rs` and `rarpar` use a licence file: the
restriction has no SPDX form.

Papers and borrowed algorithms are credited in [ATTRIBUTION.md](ATTRIBUTION.md).
