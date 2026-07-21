# Contributing to rarpar

## Scope

- Keep changes focused. Exclude unrelated cleanup, dependency churn,
  formatting, generated files, and refactors.
- Follow existing ownership boundaries and patterns. Add abstractions only when
  they remove meaningful complexity or duplication.
- Preserve public behavior unless changing it is the stated goal. Update tests
  and documentation for intentional behavior changes.
- Keep public APIs small, documented, and covered by contract tests.
- Do not bump versions, publish, tag, or alter release artifacts unless a
  maintainer explicitly requests it.
- Use the versioned hooks, satisfy signature requirements, and disclose
  validation gaps in the pull request.

## Pull Request Process

1. Open the pull request against `main`.
2. A maintainer will review it and respond with feedback on the request and its
   implementation.
3. If the request is accepted for potential adoption, a maintainer will name
   the release branch and direct you to retarget the pull request to it. Do not
   choose or create a release branch yourself.

## Correctness And Safety

- Identify formats from signatures, packets, and archive metadata before
  trusting filenames.
- Base final results on content and verify repaired or extracted output.
  Metadata and cached scan state are optimization hints, not proofs.
- Preserve member order, volume order, and solid-archive semantics.
- Never print, serialize, log, or unnecessarily retain passwords.
- Validate all required outputs before deleting sources. Permanent deletion
  requires explicit user intent.
- Keep discovery bounded and do not follow directory symlinks by default.
- `weaver-unrar` is read, extract, and recovery only. Do not add RAR writing,
  compression, construction, or modification.
- Use AWS-LC for standard cryptography. Local implementations are limited to
  RAR-specific legacy algorithms unavailable in AWS-LC.
- Preserve runtime CPU dispatch and CPU fallbacks. Do not add host-specific
  `target-cpu` release flags or require a GPU for correctness.
- Do not claim that `rarpar` is official RAR, UnRAR, or PAR2 software.

## Local Validation

Use `xtask` for repository-specific checks. List the current commands with:

```bash
cargo run --locked -p xtask -- --help
cargo run --locked -p xtask -- docs --check
```

For feature, target, or packaging changes, run the applicable `feature-audit`
or `package-root` command shown by `--help`. These checks complement the
affected Cargo tests.

## Tests And Fixtures

- Add regression coverage for bug fixes and test relevant failure paths,
  especially corrupt, incomplete, encrypted, destructive, and platform-specific
  behavior.
- Run the affected tests before review. Treat current CI as the source of truth
  for required commands, platforms, and features; disclose anything not run.
- Performance claims require reproducible workloads, equivalent work, verified
  output, and enough measurements to support the claim.
- Prefer small, deterministic synthetic fixtures with documented generation.
  Sourced fixtures require known provenance and redistribution rights.
- Store binary fixtures through Git LFS and verify they are excluded from
  crates.io packages.
- Do not commit personal downloads, private data, credentials, ordinary media
  collections, or archives of uncertain origin.

## AI-Assisted Contributions

- The human submitter must understand and review every change and personally
  run claimed validation. AI cannot review itself or fabricate test results.
- Disclose substantive AI assistance and describe the human verification.
- Ground format behavior in specifications, tests, and validated reference
  behavior, not a model's memory of RAR or PAR2.
- Verify the origin and license of suggested material. Do not provide AI
  services with secrets, private data, restricted fixtures, or unpublished
  security reports.
- AI tools must not bypass hooks, signing, branch protections, or safety checks.
  Publishing and destructive actions require explicit maintainer authorization
  and human supervision.

## Licensing

- `weaver-reed-solomon`, `weaver-par2`, and `rarpar` source are
  GPL-3.0-or-later.
- `weaver-unrar` is GPL-3.0-or-later plus the UnRAR source-code restriction in
  `crates/weaver-unrar/LICENSE`.
- Distributed `rarpar` binaries link `weaver-unrar` and carry its restriction.
- Do not move restricted RAR implementation code into PAR2 or Reed-Solomon
  code.
- Contributions must be original or license-compatible with the destination;
  third-party code and test data require clear origin and licensing.
