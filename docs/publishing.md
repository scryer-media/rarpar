# Publishing

Initial external package version: `0.1.0`.

Publish order:

1. `weaver-reed-solomon`
2. `weaver-unrar`
3. `weaver-par2`

`rarpar` is a CLI binary and is not published to crates.io.

Patch releases may publish a single library crate when only that crate changed.
Use the dependency order above for coordinated multi-crate releases.

Before publishing:

```text
rtk cargo fmt --check --all
rtk cargo clippy --locked --workspace --all-targets -- -D warnings
rtk cargo test --locked --workspace --no-fail-fast
rtk cargo package --locked -p weaver-reed-solomon
rtk cargo package --locked --no-verify -p weaver-unrar
rtk cargo package --locked --no-verify -p weaver-par2
rtk cargo package --locked --list -p weaver-reed-solomon
rtk cargo package --locked --list -p weaver-unrar
rtk cargo package --locked --list -p weaver-par2
```

Use `.github/workflows/publish-crates.yml` for real crates.io publishing. The
workflow accepts `package=all` for coordinated releases or one publishable crate
name for a patch release. The `all` path publishes in the order above so each
downstream package can be verified by `cargo publish` after its internal
dependency is visible in the crates.io index.

## Fixture Policy

Crates.io packages include tests, examples, benches, and fixture files unless
the crate manifest excludes them. Git LFS keeps the repository manageable, but
it does not automatically keep files out of the `.crate` upload.

The large local fixture corpora stay in this repository for parity and
regression testing, but they are excluded from published library packages:

- `crates/weaver-unrar/tests/fixtures/**`
- `crates/weaver-par2/tests/fixtures/**`

Before publishing, check the package output and file lists. The expected package
sizes should stay in the low MiB/KiB range, not hundreds of MiB.

Verify repository metadata before the first publish.

## GitHub Actions

- `rust-toolchain.toml` pins the repo to Rust `1.96.0`; workflows specify the
  same toolchain explicitly for action compatibility.
- `.github/workflows/ci.yml` runs formatting, clippy, workspace tests, and
  package-content checks on pull requests, pushes to `main`, and manual runs.
  It also validates generated manpages, shell completions, and the future Linux
  package-root layout. Native build lanes use `sccache`, Linux `mold`,
  path-prefix remapping, and `--no-install-recommends` native dependency
  installs.
- `.github/workflows/release.yml` builds release archives for Linux GNU, Linux
  musl, macOS Apple Silicon, macOS Intel, and Windows, then creates or updates
  a GitHub Release. It runs on tags matching `rarpar-v*` and supports manual
  dispatch against an existing tag. It validates that the tag version matches
  every workspace package, validates generated manpages/completions, smoke-tests
  each native binary, and uploads build logs plus `sccache` stats as workflow
  artifacts. Release archives include `share/` manpage and completion files.
  Linux GNU builds also upload package-root inspection artifacts for future
  distro packaging work, but GitHub Releases receive only `rarpar-*.tar.gz`,
  `rarpar-*.zip`, and `SHA256SUMS`. When `TAP_PUSH_TOKEN` is available, the
  release job updates
  `scryer-media/homebrew-rarpar` with a single portable Homebrew formula that
  selects the macOS archive for the current architecture and, on Linux,
  prefers the GNU/glibc archive when glibc is new enough, falling back to the
  musl archive otherwise.
- `.github/workflows/publish-crates.yml` publishes crates to crates.io in the
  selected package mode. It is manual-only and defaults to dry-run/preflight
  mode. Use `package=all` for coordinated releases or a specific package name
  for patch releases. Set `dry_run` to `false` to publish. Real publishing
  runs exact package/list/size checks immediately before each crate, retries
  failures, and waits for each published crate version to appear in the
  crates.io index before continuing.

Release builds intentionally avoid `target-cpu` and other CPU-specific compile
flags so acceleration comes from runtime dispatch instead of host-specific
artifact lanes. Linker and reproducibility flags, such as `mold`, `lld-link`,
and `--remap-path-prefix`, are allowed.

Required repository configuration:

- `CARGO_REGISTRY_TOKEN`: crates.io token with publish access to the three
  library packages. The publish workflow reads it from
  `secrets.CARGO_REGISTRY_TOKEN`.
- `crates-io` environment: recommended for required reviewer protection around
  the real publish job.
- `TAP_PUSH_TOKEN`: GitHub token that can push to
  `scryer-media/homebrew-rarpar`. The release workflow skips the tap update
  when this secret is absent.
- Release workflow access to the standard GitHub-hosted runner labels in
  `.github/workflows/release.yml`.
- GitHub Actions cache access for `sccache` lanes. Cache saves are restricted
  to trusted repository events for pull-request CI and to release/publish jobs
  running in this repository.

Publish note: downstream crates can depend on same-version workspace crates that
are not in the public registry yet. CI still runs the full workspace build/test
suite. For a first coordinated release of a new shared version, dry-run
preflight cannot run exact `cargo package` checks for downstream crates until
their same-version dependencies exist in the registry; it checks manifest
fixture excludes instead. The protected real publish workflow performs the exact
downstream package file-list and archive-size checks immediately before each
publish, after the upstream crate has reached the crates.io index.
