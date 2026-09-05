# AGENTS Instructions

This repository contains standalone GPL tools and publishable crates for RAR
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

- `reedsolomon-rs`, `par2-rs`, `par3-rs`, and `rarpar` source are
  GPL-3.0-or-later.
- `unrar-rs` is GPL-3.0-or-later; its RAR engine is developed from RARLAB's
  unRAR source code, which remains governed by the unRAR license restriction
  documented in `crates/unrar-rs/LICENSE`.
- `rarpar` carries a GPLv3 section 7 permission to combine with `unrar-rs`
  (`tools/rarpar/LICENSE`); binary distributions link `unrar-rs` and must
  preserve the unRAR restriction notice.
- Never bypass signed commit or signed tag requirements.
- Run the repo release script if one exists; do not hand-roll releases.

## RAR/PAR2 Rules

- `unrar-rs` is read/extract/recovery-only.
- Do not add archive writer, archive builder, compressor, or modify-RAR APIs.
- Standard crypto must use `aws-lc-rs` or `aws-lc-sys` directly.
- Local crypto ports are allowed only for UnRAR-specific legacy algorithms that
  AWS-LC does not provide.
- `rarpar` must not claim to be official RAR, UnRAR, or PAR2 tooling.
- Do not ship binaries named `unrar`, `rar`, `par2`, or `par2repair`.

## PAR3 Rules

- `par3-rs` 0.1 is read-only: parsing, set inspection, and verification. The
  crate is intended to grow into a full PAR3 implementation (creation and
  repair), but each widening of scope is a deliberate, separately planned step:
  update the README and crate docs in the same change, and keep the "what does
  not work yet" statements accurate.
- Where the PAR3 specification draft and the `par3cmdline` reference
  implementation disagree, follow the reference: it produced the files that
  exist. Record any newly found difference in the deviation table in the crate's
  README and `lib.rs`.
- The crate is clean-room. Read the reference implementation for format facts;
  do not copy its code or its comments.
- PAR3 fixture bytes come only from official `par3cmdline` runs. Never
  hand-assemble or bit-edit a PAR3 packet, in a test or anywhere else; produce
  damage cases in memory by flipping bytes of regenerated inputs.
