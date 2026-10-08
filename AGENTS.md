# AGENTS Instructions

This repository contains a standalone GPL tool and publishable crates for RAR
and PAR2 workflows.

## Commands

- Always pass `--locked` to Cargo commands after `Cargo.lock` exists.
- For broad test sweeps, use Cargo's `--no-fail-fast`.

## Scope

- Reusable libraries live under `crates/`.
- CLI applications live under `tools/`.
- Keep edits scoped to the package being changed unless the task explicitly
  requires a workspace-wide update.

## Licensing And Release

- PRs must carry prospective version bumps for changed publishable crates and
  CLI behavior, with matching internal dependency requirements, lockfile, and
  changelog entries. Use an existing appropriate unreleased version when one
  already covers the change; never leave new behavior at an already-published
  version. Record the version impact explicitly for documentation/CI-only PRs.
  Preparing these PR changes is authorized; publication, tags, and deployment
  still require a separate explicit operator instruction.
- `reedsolomon-rs` and `par3-rs` source are Apache-2.0.
- `par2-rs` and `rarpar` source are GPL-3.0-or-later. `par2-rs` stays GPL
  while its test suite carries cases adapted from par2cmdline's
  GPL-2.0-or-later unit tests.
- `unrar-rs` is Apache-2.0 plus the unRAR restriction; its RAR engine is
  developed from RARLAB's unRAR source code, which remains governed by the
  unRAR license restriction documented in `crates/unrar-rs/LICENSE`. The
  combination has no SPDX expression, so the manifest uses `license-file`.
- Never bring GPL-licensed code, or a translation of it, into an Apache-2.0
  crate.
- `rarpar` carries a GPLv3 section 7 permission to combine with `unrar-rs`
  (`tools/rarpar/LICENSE`); binary distributions link `unrar-rs` and must
  preserve the unRAR restriction notice.
- Never bypass signed commit or signed tag requirements.
- Run the repo release script if one exists; do not hand-roll releases.

## RAR/PAR2 Rules

- `unrar-rs` is read/extract/recovery-only.
- Do not add archive writer, archive builder, compressor, or modify-RAR APIs.
- Standard crypto must use `aws-lc-rs` or `aws-lc-sys` directly in the
  default feature set of every crate and in every shipped `rarpar` artifact.
  The `crypto-rust` feature is the supported opt-out for library consumers
  that cannot carry a C or assembly dependency; it must never be the default,
  never be selected by the release matrix, and never change the AWS-LC code
  path.
- Local crypto ports are allowed only for UnRAR-specific legacy algorithms that
  AWS-LC does not provide.
- `rarpar` must not claim to be official RAR, UnRAR, or PAR2 tooling.
- Do not ship binaries named `unrar`, `rar`, `par2`, or `par2repair`.

## PAR3 Rules

- `par3-rs` 0.x parses, inspects, verifies, creates and repairs PAR3 sets built
  with the reference implementation's default settings: a Cauchy matrix over
  GF(2^8) or GF(2^16), chunk tails packed into shared blocks, and power-of-two
  recovery volumes. Everything beyond that — repairing the recovery volumes
  themselves, the FFT, sparse and explicit matrices, deduplication and Data
  packets, permission and link packets, incremental parent sets, the sliding
  search for moved or renamed files, a command-line interface — is out of scope
  until a deliberate, separately planned step widens it: update the README and
  crate docs in the same change, and keep the "what does not work yet"
  statements accurate.
- Where the PAR3 specification draft and the `par3cmdline` reference
  implementation disagree, follow the reference: it produced the files that
  exist. Record any newly found difference in the deviation table in the crate's
  README and `lib.rs`.
- The crate is clean-room. Read the reference implementation for format facts;
  do not copy its code or its comments.
- PAR3 fixture bytes come only from official `par3cmdline` runs. Never
  hand-assemble or bit-edit a PAR3 packet, in a test or anywhere else; produce
  damage cases in memory by flipping bytes of regenerated inputs.
