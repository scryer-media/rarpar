# Publishing

Initial external package version: `0.7.0`.

Publish order:

1. `weaver-reed-solomon`
2. `weaver-unrar`
3. `weaver-par2`
4. `rarpar`

Before publishing:

```text
rtk cargo fmt --check --all
rtk cargo clippy --locked --workspace --all-targets -- -D warnings
rtk cargo test --locked --workspace --no-fail-fast
rtk cargo package --locked -p weaver-reed-solomon
rtk cargo package --locked --list -p weaver-unrar
rtk cargo package --locked --list -p weaver-par2
rtk cargo package --locked --list -p rarpar
```

Use `.github/workflows/publish-crates.yml` for real crates.io publishing. The
workflow publishes in the order above so each downstream package can be verified
by `cargo publish` after its internal dependency is visible in the crates.io
index.

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

- `rust-toolchain.toml` pins the repo to Rust `1.96.0`; workflows use that
  file instead of repeating a separate toolchain version.
- `.github/workflows/ci.yml` runs formatting, clippy, workspace tests, and
  package-content checks on pull requests, pushes to `main`, and manual runs.
  Native build lanes use `sccache`, Linux `mold`, path-prefix remapping, and
  `--no-install-recommends` native dependency installs.
- `.github/workflows/release.yml` builds release archives for Linux GNU, Linux
  musl, macOS Apple Silicon, macOS Intel, FreeBSD x86_64, and Windows, then
  creates or updates a GitHub Release. It runs on tags matching `rarpar-v*` and
  supports manual dispatch against an existing tag. It validates that the tag
  version matches every workspace package, smoke-tests each native binary, and
  uploads build logs plus `sccache` stats as workflow artifacts. GitHub Releases
  receive only `rarpar-*.tar.gz`, `rarpar-*.zip`, and `SHA256SUMS`.
- `.github/workflows/publish-crates.yml` publishes crates to crates.io in the
  dependency order above. It is manual-only and defaults to dry-run/preflight
  mode. Set `dry_run` to `false` to publish. Real publishing retries failures
  and waits for each upstream crate version to appear in the crates.io index
  before publishing dependents.

Release builds intentionally avoid `target-cpu` and other CPU-specific compile
flags so acceleration comes from runtime dispatch instead of host-specific
artifact lanes. Linker and reproducibility flags, such as `mold`, `lld-link`,
and `--remap-path-prefix`, are allowed.

Required repository configuration:

- `CARGO_REGISTRY_TOKEN`: crates.io token with publish access to all four
  packages. The publish workflow reads it from
  `secrets.CARGO_REGISTRY_TOKEN`.
- `crates-io` environment: recommended for required reviewer protection around
  the real publish job.
- Release workflow access to the standard GitHub-hosted runner labels in
  `.github/workflows/release.yml`, plus permission to run
  `vmactions/freebsd-vm@v1` for the FreeBSD x86_64 archive.
- GitHub Actions cache access for `sccache` lanes. Cache saves are restricted
  to trusted repository events for pull-request CI and to release/publish jobs
  running in this repository.

Initial publish note: before the first crates.io publish, downstream crates
cannot be fully package-verified against the public registry because their
same-version internal dependencies are not published yet. CI still runs the full
workspace build/test suite and validates downstream package file lists; the
protected publish workflow lets `cargo publish` perform the full verification as
each upstream crate reaches the crates.io index.
