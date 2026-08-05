# Benchmarking rarpar

`bench/rarpar-bench` creates repeatable, content-validated RAR and PAR2
workloads. It is a Go harness invoked through `xtask`; it does not change
rarpar's normal CLI behavior or use the repository's test-fixture corpus.

## Corpus

The corpus begins with deterministic synthetic payload bytes. Its source lock
pins each archive writer and the PAR2 generator by URL, SHA-256, Docker image
identity, and platform. Docker is needed only to build those generators and
materialize a corpus.

Use an empty directory outside source control. `target/bench` is the normal
local location:

```sh
cargo run --locked -p xtask -- bench toolchains validate
cargo run --locked -p xtask -- bench toolchains build
cargo run --locked -p xtask -- bench corpus generate --out target/bench/corpus
cargo run --locked -p xtask -- bench corpus verify --root target/bench/corpus
```

Generation refuses to replace a non-empty corpus directory. Each case stores
only its archive/parity source material, a manifest, and expected extracted
file hashes. The temporary original payload is independently extracted and
verified before it is discarded.

## Runs

Create and retain a plan before measuring. The default plan has one warmup and
five measured samples in deterministic order.

```sh
cargo run --locked -p xtask -- bench plan create \
  --corpus target/bench/corpus \
  --out target/bench/plan.json \
  --lane cpu

cargo run --locked -p xtask -- bench run \
  --corpus target/bench/corpus \
  --plan target/bench/plan.json \
  --candidate target/release/rarpar \
  --machine workstation-a \
  --out target/bench/run-cpu
```

For a comparative run, provide both a RAR reference executable and a PAR2
reference executable. Their labels are supplied as benchmark metadata; they
are not hard-coded into reports.

```sh
cargo run --locked -p xtask -- bench run \
  --corpus target/bench/corpus \
  --plan target/bench/plan.json \
  --candidate target/release/rarpar \
  --reference-rar /path/to/rar-reference \
  --reference-par2 /path/to/par2-reference \
  --reference-label reference \
  --machine workstation-a \
  --out target/bench/run-comparison
```

Every sample uses a byte-copied private staging directory. Successful output
is checked against expected paths, sizes, and SHA-256 values. A failed stage
is retained below the run output for inspection; successful stages are removed.
Passwords are written only to a private staged file for the encrypted case and
never enter plans, manifests, logs, reports, or SVGs.

For a source-built candidate, make the source identity explicit. The harness
runs the existing feature audit before measuring and records the checkout
revision separately from release-binary runs:

```sh
cargo run --locked -p xtask -- bench run \
  --corpus target/bench/corpus --plan target/bench/plan.json \
  --candidate target/release/rarpar --out target/bench/run-source \
  --source-manifest tools/rarpar/Cargo.toml \
  --source-target aarch64-apple-darwin
```

## Evidence And Charts

Build a report and render static charts from a completed comparative run:

```sh
cargo run --locked -p xtask -- bench report \
  --input target/bench/run-comparison/raw.json \
  --out target/bench/report.json
cargo run --locked -p xtask -- bench render \
  --input target/bench/report.json \
  --out target/bench/charts
```

The renderer writes separate RAR and PAR2 SVGs when comparable samples exist,
plus `chart-summary.json`. SVGs are static, accessible, dark-mode aware, and
contain provenance metadata without timestamps or local paths. A matched report
input always produces identical SVG bytes.

Only compare reports with the same corpus digest, plan, execution lane, binary
identity, and backend behavior. The report deliberately omits unmatched,
failed, or insufficient samples rather than inventing a relative-speed claim.

`rarpar` benchmark plans use CPU execution. Docker CPU runs use the same
CPU-only policy as direct release builds.
