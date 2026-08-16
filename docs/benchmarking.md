# Benchmarking rarpar

`bench/rarpar-bench` creates repeatable, content-validated RAR and PAR2
workloads. It is a Go harness invoked through `xtask`; it does not change
rarpar's normal CLI behavior or use the repository's test-fixture corpus.

## Corpus

The corpus begins with deterministic synthetic payload bytes. Its source lock
pins each archive writer and the PAR2 generator by URL, BLAKE3 digest, Docker
image identity, and platform. Docker is needed only to build those generators and
materialize a corpus.

`toolchains build` resolves every original distribution archive before Docker
starts. Each archive is fetched from the public tool mirror first — the
content-addressed `tools/<kind>/blake3/<digest>/` objects on R2, whose Sigstore
bundles must verify under the publish workflow's exact identity and whose
provenance must agree with the lock — and falls back to RARLAB or GitHub only
when the mirror does not hold it or cannot be reached; a mirrored object that
does not verify is an error, never a fallback. Either way the bytes must match
the BLAKE3 digest in `config/toolchains.json` before anything uses them. The image is
then built from a temporary context holding only the Dockerfile and that
verified archive, so the build itself downloads no tool. Set
`RARPAR_TOOL_MIRROR_BASE` (or `--mirror-base URL`) to the mirror's public read
base; leave it unset to go straight to the official URLs. `cosign` must be
installed whenever a mirror base is set, since every mirrored object's signature
is verified. `toolchains resolve` does the resolving alone, printing kind, name,
digest and origin per archive without building any image.

The same lock is the generator toolchain of the repository's test corpus
(`docs/test-corpus.md`): its writer set carries RAR 6.24 and 7.20 for that
reason alongside the benchmark's own writers, and `bench payload video
--profile ffmpeg-video --target-bytes BYTES --out PATH` exposes the pinned
encoder so the fixture generators take their MKV inputs from it instead of
carrying an ffmpeg command line. The two corpora share nothing else — not a
manifest, an output, or a regeneration schedule.

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

The default RAR extraction suite covers archives produced by locked RAR 3.93,
4.20, 5.00, 6.24, and 7.23 writers. It includes stored and compressed data,
single and multi-volume layouts, solid streams, data-only and header
encryption, recovery volumes, and four RAR4 PPMd workloads. RAR 7.x still
writes the RAR5 container format; the workload labels preserve the writer
version so results do not imply a distinct RAR7 container format.

RAR 7's compression algorithm version 1 requires dictionaries above 4 GiB and
is not part of the routine performance corpus. Large-dictionary compatibility
fixtures belong in a separate corpus with explicit memory and disk
requirements.

The PAR2 suite covers generation, verification, and repair. Generation stages
a 256 MiB RAR5 multi-volume input set, creates a fresh recovery set with the
declared slice size and recovery percentage, and validates the result with the
reference verifier outside the timed operation. This keeps generation results
comparable while ensuring each generated set protects the intended inputs.

## Runs

Create and retain a plan before measuring. The default plan has one warmup and
five measured samples in deterministic order. Candidate/reference pairs
alternate which subject runs first to reduce order bias. The plan records
`canonical` PAR2
placement by default: rarpar verifies the paths recorded in the PAR2 set,
without its optional content-based relocation scan. This is the comparable lane
for conventional PAR2 tools. Use `--par2-placement smart` to measure rarpar's
relocated-file workflow instead; do not compare those reports as the same
operation.

```sh
cargo run --locked -p xtask -- bench plan create \
  --corpus target/bench/corpus \
  --out target/bench/plan.json \
  --lane cpu \
  --par2-placement canonical

cargo run --locked -p xtask -- bench run \
  --corpus target/bench/corpus \
  --plan target/bench/plan.json \
  --candidate target/release/rarpar \
  --machine workstation-a \
  --out target/bench/run-cpu
```

For a comparative run, provide both a RAR reference executable and a PAR2
reference executable. The raw evidence records their supplied label, version,
and SHA-256; relative charts use the canonical UnRAR and par2cmdline-turbo
reference roles.

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

## Multi-host Full Suite

For repeatable cross-machine evidence, copy the committed template to the
ignored operator inventory and replace every example hostname, SSH identity,
binary path, and host directory with real values:

```sh
cp bench/rarpar-bench/config/hosts.example.json \
  bench/rarpar-bench/config/hosts.local.json
$EDITOR bench/rarpar-bench/config/hosts.local.json
cargo run --locked -p xtask -- bench all-hosts
```

`all-hosts` runs configured hosts in parallel by default (`--jobs N` limits the
concurrency). On each host it runs `go test ./...`, verifies the configured
corpus, creates the full plan, measures the configured direct candidate and
reference executables, and writes the report and SVG charts. It never builds or
replaces a corpus or candidate binary: provision those inputs first. The host
output directory must not already exist, so prior evidence and failed staging
directories are never overwritten. Every remote path is required to be an
absolute POSIX path; `path` supplies the complete remote `PATH` when a
non-interactive SSH session needs explicit Go or Cargo locations.

The local inventory is intentionally ignored because it can identify private
hosts and SSH key locations. The key remains outside the repository; the
inventory only names its local path. SSH uses batch mode, supports optional
per-host ports and additional OpenSSH options, and leaves host-key verification
under the operator's normal SSH policy.

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
