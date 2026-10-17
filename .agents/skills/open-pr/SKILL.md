---
name: open-pr
description: Open, push to, or report on a pull request in rarpar. Runs the preflight a mergeable PR needs (one PR per version, a version bump for every changed library crate and for the CLI, internal dependency floors, changelog headings, README dependency lines, lockfile, fmt, clippy, tests, semver-checks, package) and writes the PR body. Use whenever a PR is to be opened, pushed, updated or called ready.
---

# Opening a pull request in rarpar

Write every PR as if it were already released. The moment it merges, `main`
must publish by dispatching `publish-crates` with nothing else to edit: the
workflow publishes every library whose manifest version crates.io does not
have yet, and fails on a manifest below the newest published version. Each
step here exists because skipping it has already cost a release.

The workspace has four libraries on crates.io (`reedsolomon-rs`, `unrar-rs`,
`par2-rs`, `par3-rs`) and the `rarpar` CLI, which is released from signed
`rarpar-v<version>` tags as GitHub releases, not on crates.io.

## 1. One PR per version

- `gh pr list --repo scryer-media/rarpar --state open`. If a PR for the next
  version is open, this work goes onto its branch as more commits. Never open
  a second PR for the same version, and never open a PR whose base is another
  PR's branch. A CLI bump that a library change needs rides in the same PR.
- Branches use `feature/…`, `bugfix/…` or `hotfix/…`, cut from `main`, in a
  worktree under `.worktrees/`.
- Open the PR only when the maintainer asked for one. Agents do not push
  otherwise.

## 2. Versions

- Published is what the registry says, nothing else: not a changelog heading,
  not a tag, not a review bot.
  - A library: `curl -s https://crates.io/api/v1/crates/<crate> | jq -r .crate.max_version`
  - The CLI: `gh release list --repo scryer-media/rarpar --limit 1`
- Each changed crate's version is its published version plus one step. If
  `main` already carries an unpublished version above published, use it;
  never bump twice before a release, and never give two PRs different
  prospective versions.
- Which step for a library: `cargo semver-checks -p <crate>` against its
  published baseline. A breaking change on 0.x is a minor bump; anything else
  is a patch bump.
- Every crate whose code changed is bumped: its `Cargo.toml` `version`, the
  requirement every sibling names it by (`version = "x.y.z"`, a caret floor,
  never `=`), and `Cargo.lock` (`cargo update -p <crate> --offline`). Confirm
  `cargo metadata --locked --format-version 1 >/dev/null` passes.
- A library change the CLI ships also bumps `tools/rarpar`.
- A docs- or CI-only PR states its version impact ("none") in the body.

## 3. Changelogs

- Each library's section in `crates/<crate>/CHANGELOG.md` is headed
  `## <version>`; the CLI's in the root `CHANGELOG.md` is `## rarpar <version>`.
- Never `(unreleased)` or `Unreleased`:
  `grep -rn -i unreleased CHANGELOG.md crates/*/CHANGELOG.md` must print
  nothing. An existing `(unreleased)` heading for a version the registry
  already has is fixed in the same PR.
- Every change has a bullet under its crate's one heading. A later commit on
  the same PR adds bullets; it does not add a heading.

## 4. README and docs

- Each crate's README dependency lines name its current major.minor:
  `grep -n ' = "\| version = "' crates/*/README.md`. A minor bump changes
  every `<crate> = "0.x"` and `{ version = "0.x", … }` line.
- A new or renamed feature, default, flag or public type is reflected in the
  crate README, `docs/` and the CLI help in the same PR. A PAR3 scope change
  also updates the "what does not work yet" statements.

## 5. Local gates

Run what CI runs, with `--locked`, before pushing:

```sh
cargo fmt --check --all
cargo clippy --locked --workspace --all-targets --features unrar-rs/unstable-internals -- -D warnings
cargo run --locked -p xtask -- test-corpus hydrate --profile unit --profile par3
cargo nextest run --locked --workspace --lib --bins --examples --no-fail-fast --features unrar-rs/unstable-internals
cargo semver-checks -p <each bumped library>
cargo package --locked -p <each bumped library>
```

- Then the changed crate's own lane from `.github/workflows/ci.yml`
  (`par2-tests`, `par3-tests`, `unrar-tests`, `crypto-rust-backend`), with the
  corpus profile that lane hydrates.
- A CLI change also runs `cargo run --locked -p xtask -- docs --check`.
- A change to `unsafe` code runs its selectors from
  `docs/unsafe-validation.md`, and that inventory is kept current.
- Never add a package size budget to CI or the publish workflow.

## 6. Commit

- Every commit is SSH-signed. If signing fails, stop and leave the change
  staged; never `--no-gpg-sign`.
- No `Co-Authored-By` or other attribution trailers.
- Conventional subject: `feat(scope): …`, `fix(scope): …`, `!` for breaking.

## 7. PR title and body

Title: the crate, its version and what it does, for example
`unrar-rs 0.12.0: keep typed causes on reader, provider and block-header errors`.

Body sections, in this order, leaving out any that would be empty:

- **Changes**: one subsection per crate (`### unrar-rs`, `### rarpar`).
- **Breaking changes**: what a consumer must change, if anything.
- **Merge order**: anything that has to publish or merge first.
- **Version impact**: each crate and the CLI, old → new, or "none".
- **Verification**: each command from step 5 and its result.
- **Follow-ups**: work left for later. Follow-ups live in the body; do not
  open GitHub issues without the maintainer's approval.

## 8. After every push

- Do not enable auto-merge unless the maintainer asks.
- Read the review comments:
  `gh api repos/scryer-media/rarpar/pulls/<n>/comments --paginate`.
  Fix each finding on this branch, or reply with the reason it is wrong, then
  resolve the thread.
- A code-scanning alert on the PR is fixed, or dismissed with a written reason
  when it is a false positive.
- The PR is ready only when every job, `ci-complete` included, is green on the
  head and every correctness, safety or version finding is fixed and replied
  to. Pure wording nits may be deferred with a reply.

## 9. After merge

Publishing and tagging need the maintainer's instruction. Libraries: Actions →
`publish-crates` on `main`, `dry_run` on, then off. The CLI: a signed
`rarpar-v<version>` tag on its `release-<version>` branch. See
`docs/publishing.md`.
