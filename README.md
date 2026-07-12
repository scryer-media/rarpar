# rarpar

`rarpar` is a smart RAR/PAR2 command-line tool written in Rust. Point it at an
archive, a PAR2 file, or a messy download directory and it will discover what is
there, repair what can be repaired, restore recovery volumes when possible, and
extract the archive with verification enabled.

It is built on reusable archive and parity crates that live in this workspace
and are intended to be publishable on crates.io. The CLI is distributed as a
binary release and source build, not as a crates.io package.

`rarpar` is not an official RAR or PAR2 utility. It does not ship binaries named
`unrar`, `rar`, `par2`, or `par2repair`, and it does not provide RAR archive
writing, compression, or modification APIs.

## What It Does

- Discovers RAR, REV, and PAR2 sets from paths, headers, magic bytes, and
  bounded directory scans.
- Verifies and repairs PAR2 sets before extraction.
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

`rarpar` uses the same RAR and PAR2 engines benchmarked in Weaver. These are
selected warm-cache median results from shipped-style release builds with
verified output, not benchmark-only binaries. They are shape-specific; archive
content, storage, and CPU features matter. Release builds use AWS-LC-backed
native crypto, with Metal repair on Apple Silicon and `wgpu` repair in direct
Linux and Windows builds. Every GPU-capable build falls back to CPU when a
suitable device or driver is unavailable.

RAR extraction, compared with the reference RAR extraction utility:

| Platform | Workload | Reference | Weaver engine | Result |
|---|---|---:|---:|---|
| Apple M5 Max | RAR7 video, 4.9 GB, 4.6 GB dictionary | 8.6 s | **5.8 s** | ~1.5x faster |
| Apple M5 Max | RAR5 encrypted, AES-256 | 0.41 s | **0.25 s** | ~1.6x faster |
| Core Ultra 9 285H | RAR7 video, 4.9 GB, `-m3` | 17.7 s | **13.5 s** | ~1.3x faster |
| Core Ultra 9 285H | RAR5 encrypted, AES-256 | 0.83 s | **0.52 s** | ~1.6x faster |
| Ryzen 5 3600, Windows | RAR7 video, 4.94 GB, `-m3` | **13.5 s** | 13.6 s | parity |
| Ryzen 5 3600, Windows | Store-mode BLAKE2sp verify, 4.94 GB | 3.48 s | **1.80 s** | ~1.9x faster |

PAR2 verification and repair, compared with `par2cmdline-turbo 1.4.0`:

| Platform | Workload | turbo | Weaver engine | Result |
|---|---|---:|---:|---|
| Apple M5 Max | 4 GB set, 1 MB slices, 407 missing | 112 s wall / 1622 s CPU | **28.5 s / 338 s** | ~3.9x faster |
| Apple M5 Max | 2 GB set, 32,768 slices, 3,000 missing | 457 s wall / 6507 s CPU | **95 s / 1288 s** | ~4.8x faster |
| Apple M5 Max | Verify clean 1 GB set | 2.43 s | **0.09 s** | ~27x faster |
| Core Ultra 9 285H | 4 GB set, 1 MB slices, 407 missing | 12.1 s | **8.1 s** | ~1.5x faster |
| Core Ultra 9 285H | Verify clean 1 GB set | 0.66 s | **0.37 s** | ~1.8x faster |
| Ryzen 5 3600, Windows | Verify clean 1 GB set | 1.70 s | **0.30 s** | ~5.7x faster |

### GPU Backends

Apple Silicon archives enable Weaver's Metal GF(2^16) repair tier for PAR2.
Intel macOS archives are CPU-only. Direct Linux GNU, direct Linux musl, and
Windows archives enable the portable `wgpu` tier; they need a compatible host
graphics driver and fall back to CPU when no suitable device is available.
Docker images are deliberately CPU-only and contain neither GPU backend nor
graphics-driver requirements.

The Apple Silicon repair engine attempts Metal when
`outputs * sources * region_bytes` is at least 256 MiB; below that, the CPU path
avoids GPU setup/upload overhead. Set
`WEAVER_GF16_METAL=1` to force the Metal path or `WEAVER_GF16_METAL=0` to
disable it. Once a Metal session engages, it runs the streaming repair chunks
until completion or a GPU error, and any failed chunk is redone on the CPU.
Repaired files are still read back and PAR2 verified before install.

These numbers compare the same damaged PAR2 sets on an Apple M5 Max. `turbo` is
`par2cmdline-turbo 1.4.0`; `Weaver CPU` is the all-core NEON path; `Weaver Metal`
is the GPU path shipped in Apple Silicon archives:

| Platform | Workload | turbo | Weaver CPU | Weaver Metal | Result |
|---|---|---:|---:|---:|---|
| Apple M5 Max | 512 MB set, 64 KiB slices, 1,400 missing | 78.1 s | 8.96 s | **4.10 s** | ~19x faster than turbo |
| Apple M5 Max | 76 MB set, 400 missing | 3.71 s | 0.62 s | **0.40 s** | ~9x faster than turbo |

Raw Metal GF16 throughput in the Weaver benchmark was about **1.26 TB/s** versus
about **62 GB/s** for the all-core NEON path; at this point the larger Apple
Silicon repairs are mostly I/O-bound.

Known weaker shapes remain: compressible-text RARs, RAR4 PPMd, Windows
store-mode write-to-disk, and single-file/many-slice PAR2 repair on x86.
`rarpar` verifies repaired and extracted output rather than trusting timing-only
success.

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

Linux direct archives are available in GNU and musl forms, both with `wgpu`
acceleration and CPU fallback. The separate `linux-*-docker` archives are
CPU-only musl binaries used to build the container image; they are not selected
by Homebrew.

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
```

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

## Workspace Packages

- `crates/weaver-reed-solomon`: Reed-Solomon finite-field kernels shared by
  RAR recovery and PAR2 repair. Licensed GPL-3.0-or-later.
- `crates/weaver-unrar`: RAR reading, probing, extraction, and recovery only.
  Licensed GPL-3.0-or-later with the additional UnRAR source-code restriction.
- `crates/weaver-par2`: PAR2 packet loading, verification, placement-aware
  repair, and post-repair verification. Licensed GPL-3.0-or-later.
- `tools/rarpar`: the standalone CLI. Source is GPL-3.0-or-later. Normal
  binary builds link `weaver-unrar`, so binary distribution also carries the
  additional UnRAR source-code restriction.

## Development

This repository uses Git LFS for binary fixture corpora. After cloning:

```bash
git lfs install
git lfs pull
git config core.hooksPath .githooks
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

## License

The workspace is GPL-3.0-or-later, with the UnRAR restriction carried wherever
`weaver-unrar` is used:

- `weaver-reed-solomon`, `weaver-par2`, and `rarpar` source are
  GPL-3.0-or-later.
- `weaver-unrar` is GPL-3.0-or-later with the additional UnRAR source-code
  restriction documented in `crates/weaver-unrar/LICENSE`.
- `rarpar` binary releases link `weaver-unrar` and therefore carry that
  additional restriction too. Release archives include `LICENSE`,
  `LICENSE.GPL-3.0-or-later`, and `LICENSE.weaver-unrar`.

The additional restriction applies to the RAR extraction and recovery code in
`weaver-unrar` and to `rarpar` binaries that include it. It does not apply to
the PAR2 or Reed-Solomon crates.
