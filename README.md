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

## Install

With Homebrew:

```bash
brew install scryer-media/rarpar/rarpar
```

From a release archive, download the `rarpar` binary for your platform from
GitHub Releases and place it on your `PATH`.

Release archives include a `rarpar(1)` manpage and shell completions under
`share/`. Homebrew installs those automatically.

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
- `tools/rarpar`: the standalone CLI. Licensed GPL-3.0-or-later; normal builds
  link `weaver-unrar`, so binary distribution must also account for that
  dependency's additional restriction.

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

The workspace is GPL-3.0-or-later, with one package-specific addition:

- `weaver-reed-solomon`, `weaver-par2`, and the `rarpar` CLI source are
  GPL-3.0-or-later.
- `weaver-unrar` is GPL-3.0-or-later with the additional UnRAR source-code
  restriction documented in `crates/weaver-unrar/LICENSE`.

In short, the additional restriction applies to the RAR extraction and recovery
code in `weaver-unrar`; it does not apply to the PAR2 or Reed-Solomon crates.
