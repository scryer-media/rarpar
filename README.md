# rarpar

`rarpar` is a smart RAR/PAR2 command-line tool written in Rust. Point it at an
archive, a PAR2 file, or a messy download directory and it will discover what is
there, repair what can be repaired, restore recovery volumes when possible, and
extract the archive with verification enabled.

It is built on reusable archive and parity crates that live in this workspace
and are published on crates.io. The CLI is distributed as a binary release
and source build, not as a crates.io package.

`rarpar` is not an official RAR or PAR2 utility. It does not ship binaries named
`unrar`, `rar`, `par2`, or `par2repair`, and it does not provide RAR archive
writing, compression, or modification APIs.

## What It Does

- Discovers RAR, REV, and PAR2 sets from paths, headers, magic bytes, and
  bounded directory scans.
- Verifies and repairs PAR2 sets before extraction.
- Creates PAR2 recovery sets with validated, atomically committed output
  (`par create`).
- Restores missing RAR volumes from `.rev` recovery volumes when available.
- Extracts RAR archives with integrity checks enabled.
- Handles encrypted archives through secure password sources or a hidden
  interactive prompt.
- Can delete consumed source files after successful extraction, using the OS
  trash by default.
- Provides JSON inspection/reporting for automation.
- Supports an UnRAR-compatible command shape, including `-vp` incremental
  extraction.

## Performance

Deterministic end-to-end runs from the 43-case `rarpar-bench` corpus — one
warmup, seven measured runs, byte-validated output — against reference
UnRAR and `par2cmdline-turbo 1.4.0`, using shipped-style portable release
builds rather than benchmark-only binaries.

Each cell is the **geometric mean** of `reference wall time / rarpar wall
time` over that workload class, so `2.0×` means `rarpar` finished in half the
time.

| CPU | Arch | Instruction set | unrar (binary) | unrar (text) | par2 (heavy) |
|---|---|---|---:|---:|---:|
| AMD EPYC 9R14 (Zen 4) | x86-64 | GFNI + AVX-512 | 2.7× | 1.7× | 2.3× |
| Intel Xeon Platinum 8488C (Sapphire Rapids) | x86-64 | GFNI + AVX-512 | 2.1× | 1.4× | 1.9× |
| Intel Core i5-1240P (Alder Lake) | x86-64 | GFNI + AVX2 | 1.7× | 1.3× | 2.3× |
| Intel Xeon Platinum 8124M (Skylake-SP) | x86-64 | AVX-512 | 1.5× | 1.2× | 1.8× |
| AMD Ryzen 5 3600 (Zen 2) | x86-64 | AVX2 | 1.6× | 1.5× | 1.6× |
| Intel Xeon E5-2666 v3 (Haswell) | x86-64 | AVX2 | 1.5× | 1.2× | 1.9× |
| Intel Atom C3538 (Denverton) | x86-64 | SSSE3 (no AVX) | 1.2× | 1.3× | 1.4× |
| Apple M5 Max | arm64 | NEON | 1.3× | 1.4× | 7.2× |
| Arm Cortex-A72 | arm64 | NEON | 2.3× | 1.6× | 1.2× |
| Arm Neoverse N1 | arm64 | NEON | 3.1× | 1.7× | 1.5× |
| Arm Neoverse V2 | arm64 | NEON | 3.8× | 1.8× | 1.5× |

**unrar (binary)** is store-mode extraction — uncompressible media payloads,
including the encrypted and BLAKE2sp variants; this is the dominant
real-world shape by data volume. **unrar (text)** is compressed extraction
across the LZ and PPMd decode paths, including compressed machine code and
the encrypted compressed cases; it includes PPMd, an archaic RAR4 mode that
is deliberately left unoptimized and still trails the reference decoder on
x86-64. **par2 (heavy)**
is the two heavy-repair cases. The Apple row is the CPU lane; the optional
Metal lane is charted in the deep dive.

The class geomeans above blend quiet cases with `rarpar`'s widest wins:
**encrypted extraction runs 1.2×–13.4×** depending on silicon and shape
(encrypted store-mode, the dominant large-release shape, reaches 6.0×–13.4×
on Arm), inside classes that average lower. Per-case charts for every machine
are in the [benchmark deep dive](docs/benchmark.md).

One caveat travels with this table: the macOS PAR2 figure is measured against
upstream's published macOS arm64 reference binary, which is much slower than
the same version's Linux and Windows builds. The deep dive explains it.

Known weaker shapes remain: RAR4 PPMd and dense compressible-text archives
trail the reference decoder, and PAR2 generation still trails
`par2cmdline-turbo` on most machines — it is now ahead on Zen 4 and Haswell —
because `rarpar` flushes and re-validates every written recovery volume
before commit, which the reference tool does not do. `rarpar` verifies
repaired and extracted output rather than trusting timing-only success.

Release builds use AWS-LC-backed native crypto and CPU execution only, which
keeps startup behavior consistent across supported platforms; `rarpar`
deliberately does not enable optional GPU backends from its underlying PAR2
library.

**Per-case charts for all machines, the full methodology, and the
versions these numbers were measured with are in
[docs/benchmark.md](docs/benchmark.md).**

## Install

With Homebrew:

```bash
brew tap scryer-media/rarpar
brew install rarpar
```

One-shot install:

```bash
brew install scryer-media/rarpar/rarpar
```

From a release archive, download the `rarpar` binary for your platform from
GitHub Releases and place it on your `PATH`.

Release archives include a `rarpar(1)` manpage and shell completions under
`share/`. Homebrew installs those automatically.

Linux direct archives are available in GNU and musl forms. The portable musl
archives are also the inputs used to build the CPU-only container image.

With Docker or another OCI runtime:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work \
  ghcr.io/scryer-media/rarpar:latest ./release
```

The container image is CPU-only by design and carries the same manpage,
completions, README, and license notices as the Docker-focused release archive.

From source:

```bash
cargo install --locked --path tools/rarpar
```

Or build a local release binary:

```bash
cargo build --locked --release -p rarpar
./target/release/rarpar --help
```

## Quick Start

Run the smart workflow on a file or directory:

```bash
rarpar ~/Downloads/some-release
```

That is equivalent to:

```bash
rarpar auto ~/Downloads/some-release
```

Inspect what `auto` would do without mutating files:

```bash
rarpar inspect --json ~/Downloads/some-release
```

Extract under a specific output directory:

```bash
rarpar auto --output ~/Extracted ~/Downloads/some-release
```

Delete consumed source files only after successful verified extraction:

```bash
rarpar auto --delete-sources ~/Downloads/some-release
```

By default cleanup moves files to the OS trash/recycle bin. Irreversible
deletion requires an explicit extra flag:

```bash
rarpar auto --delete-sources --permanent-delete ~/Downloads/some-release
```

Preview cleanup without deleting anything:

```bash
rarpar cleanup --dry-run ~/Downloads/some-release
```

## Explicit Commands

RAR operations:

```bash
rarpar rar list archive.part1.rar
rarpar rar test archive.part1.rar
rarpar rar extract archive.part1.rar ./out
rarpar rar restore-volumes archive.part1.rar archive.part1.rev
```

PAR2 operations:

```bash
rarpar par verify release.par2
rarpar par repair release.par2
rarpar par create ./release/release --block-size 1048576 \
  --recovery-percent 5 part01.rar part02.rar
```

`par create` takes one OUTPUT path or stem followed by one or more explicit
FILE inputs. Directories, recursion, and file-list expansion are rejected. If omitted,
`--base-path` defaults to OUTPUT's parent, and input names are recorded relative
to that directory. Use `--block-size` or `--block-count` to choose source-block
sizing, then select recovery with `--recovery-percent` or the exact, long-only
`--recovery-count`. Recovery blocks begin at `--first-exponent`; volumes use the
variable scheme by default and can be selected as `uniform` with
`--volume-scheme`, then split with `--volume-count`. `--memory-mib` sets the
creator's bounded planning/working budget.

Creation honors the global safety/reporting flags:

```bash
rarpar --dry-run --json par create ./release/release \
  --block-count 256 --recovery-count 16 \
  part01.rar part02.rar
rarpar --overwrite par create ./release/release --recovery-percent 10 \
  part01.rar part02.rar
```

Dry-run produces a creation-specific plan report and does not write PAR2 files.
Human progress is rate-limited and goes to stderr; JSON mode emits one final
structured creation report on stdout. Add `--quiet` to suppress human output.

Automation that already emits a PAR2-command-shaped repair invocation can use
the compatibility form directly. This form accepts repair mode, `-B` as a
separate or joined base-directory option, the PAR2 file, and an optional data
wildcard:

```bash
rarpar r -B ./release ./release/release.par2 "*.rar"
```

The explicit `rarpar par ...` commands remain the general-purpose interface.

PAR2 placement defaults to `smart`, which can locate renamed or moved data by
content. For a conventional expected-path-only verification or repair, use:

```bash
rarpar par verify --par-placement canonical release.par2
rarpar auto --par-placement canonical ./release
```

Explicit RAR selection recognizes modern `partNN` names and old-style `.r00`,
`.s00`, and numeric volume sequences. Discovery probes only name-compatible
siblings for an explicitly selected multi-volume archive. During `auto`, RAR
volumes restored from `.rev` files stay beside the source set; `--output`
controls extracted payload placement, not those intermediate volumes.

Discovery controls are global:

```bash
rarpar --no-recursive inspect ./release
rarpar --max-depth 4 --max-files 5000 ./downloads
```

Directory inputs recurse by default with a maximum depth of 8 and a maximum of
20,000 files. Symlink directories are not traversed.

## Passwords

`rarpar` never prints passwords and does not include them in JSON output.

Use one or more non-interactive password sources:

```bash
rarpar --password-file passwords.txt ./release
RAR_PASSWORD='correct horse battery staple' rarpar --password-env RAR_PASSWORD ./release
rarpar --password-fd 3 ./release 3< passwords.txt
```

`--password-file` and `--password-fd` read newline-separated candidates.
`--password-env` reads one candidate from the named environment variable. If no
non-interactive candidate works and stdin/stderr are TTYs, `rarpar` prompts with
hidden input only when a password is needed.

Use `-p-` in UnRAR-compatible mode to disable prompting.

## Cleanup Safety

Cleanup is intentionally narrow. Automatic cleanup only considers files
positively identified as consumed source files for an extracted set:

- RAR volumes used for extraction
- Restored or repaired RAR volumes used for extraction
- `.rev` recovery volumes for that set
- PAR2 files used for that set

It does not delete unrelated sidecar files such as `.nfo`, `.sfv`, samples,
subtitles, or PAR2-protected data files. Standalone `cleanup` validates expected
outputs before deleting anything for a set.

## UnRAR-Compatible Mode

Tools that expect an UnRAR-shaped command can call the `rarpar` binary directly.
`rarpar` accepts these command forms:

```bash
rarpar x archive.part1.rar /dest/
rarpar e archive.rar /dest/
rarpar t archive.rar
rarpar l archive.rar
rarpar lb archive.rar
```

Supported compatibility switches include `-y`, `-ai`, `-idp`, `-scf`, `-tsm-`,
`-mlp`, `-vp`, `-o+`, `-o-`, `-or`, `-p-`, `-pPASSWORD`, `-om`, `-om1`, `-om-`,
and `-riN[:S]`.

`-vp` keeps the archive open, waits for later volumes, and prints the
incremental prompt expected by UnRAR-compatible callers. `rarpar` intentionally
does not print an UnRAR banner and does not claim to be official UnRAR.

Normal `x` and `e` extraction uses sibling `.rev` recovery files to restore
missing volumes before extraction. The incremental `-vp` path does not mutate
the archive set; it waits for each later volume instead.

## Workspace Packages

- `crates/reedsolomon-rs`: Reed-Solomon finite-field kernels shared by
  RAR recovery and PAR2 repair. Licensed GPL-3.0-or-later.
- `crates/unrar-rs`: RAR reading, probing, extraction, and recovery only.
  Licensed GPL-3.0-or-later with the additional UnRAR source-code restriction.
- `crates/par2-rs`: PAR2 packet loading, creation, verification,
  placement-aware repair, and post-repair verification. Licensed
  GPL-3.0-or-later.
- `tools/rarpar`: the standalone CLI. Source is GPL-3.0-or-later. Normal
  binary builds link `unrar-rs`, so binary distribution also carries the
  additional UnRAR source-code restriction.

## Development

The binary test fixtures are the **test corpus**: a signed, content-addressed
object set on R2, described by the ledger in `test-corpus/` and hydrated with
`xtask` (see [docs/test-corpus.md](docs/test-corpus.md)). Until the first
published corpus is pinned in `test-corpus/lock.json`, Git LFS remains the
transport. After cloning:

```bash
git lfs install
git lfs pull
git config core.hooksPath .githooks
```

Once a corpus is pinned, hydrate what you need instead of `git lfs pull`:

```bash
cargo run --locked -p xtask -- test-corpus fetch --profile unrar --profile par2
```

The versioned pre-commit hook runs `gitleaks` and blocks staged machine-local
usernames or home-directory paths.

Common validation commands:

```bash
cargo fmt --check --all
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --no-fail-fast
```

Release and crates.io publishing automation lives under `.github/workflows/`.
Publishing notes are in `docs/publishing.md`.
Linux packaging layout notes are in `docs/packaging.md`.
Versioned CLI and library migration notes are in [CHANGELOG.md](CHANGELOG.md).

## License

The workspace is GPL-3.0-or-later, with the UnRAR restriction carried wherever
`unrar-rs` is used:

- `reedsolomon-rs`, `par2-rs`, and `rarpar` source are
  GPL-3.0-or-later.
- `unrar-rs` is GPL-3.0-or-later with the additional UnRAR source-code
  restriction documented in `crates/unrar-rs/LICENSE`.
- `rarpar` binary releases link `unrar-rs` and therefore carry that
  additional restriction too. Release archives include `LICENSE`,
  `LICENSE.GPL-3.0-or-later`, and `LICENSE.unrar-rs`.

The additional restriction applies to the RAR extraction and recovery code in
`unrar-rs` and to `rarpar` binaries that include it. It does not apply to
the PAR2 or Reed-Solomon crates.
