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

## PAR3 Suite

`rarpar-bench par3` compares the shipped `rarpar` CLI with the pinned
`par3cmdline` reference on create, verify and repair. It measures the CLI
because that is what ships, the same way the PAR2 suite drives `rarpar par`.
If you pass `--engine-perf PATH`, it also runs the `par3-rs` `engine_perf`
example once per set and durability as an untimed stage breakdown, selecting
the durability with `PAR3_BENCH_CREATE_DURABILITY` and
`PAR3_BENCH_REPAIR_DURABILITY` (`durable` or `buffered`; older builds ignore
the repair variable). Nothing from that pass goes into the timing tables.

```sh
cd bench/rarpar-bench
go build -o target/rarpar-bench ./cmd/rarpar-bench

# The matrix the profile runs; it builds and runs nothing.
target/rarpar-bench par3 matrix --profile full

# Build the reference from the pinned archive in config/toolchains.json
# (mirror first, then upstream; BLAKE3-verified either way). Needs CMake.
target/rarpar-bench par3 build-reference --out target/par3-reference

# Smoke run, about a minute.
target/rarpar-bench par3 run --profile smoke \
  --reference target/par3-reference/build/par3cmd/par3 \
  --candidate ../../target/release/rarpar \
  --work target/p3 --out target/par3-smoke \
  --ops create,verify,verify-damaged,repair --repeats 3

# Re-render the Markdown from a saved results.json.
target/rarpar-bench par3 report --input target/par3-smoke/results.json
```

### Sets

Each set is a deterministic generated dataset plus one codec configuration.
The same inputs and damage are produced on every host:

| set | data | block | input / recovery | codec | damage |
|---|---|---|---|---|---|
| `a-gf16` | 1 GiB | 1 MiB | 1024 / 103 | Cauchy GF(2^16) | 50 lost blocks |
| `a-gf8` | 1 GiB | 8 MiB | 128 / 13 | Cauchy GF(2^8) | 6 lost blocks |
| `a-fft` | 1 GiB | 1 MiB | 1024 / 103 | FFT | 50 lost blocks |
| `b-gf16` | 300 MiB, many files | 1 MiB | 300 / 30 | Cauchy GF(2^16) | 10 lost blocks in 5 of 10 files |
| `c-gf16` | 1.5 GiB | 32 KiB | 49152 / 4916 | Cauchy GF(2^16) | 2000 lost blocks |
| `c-fft` | 1.5 GiB | 32 KiB | 49152 / 4916 | FFT | 2000 lost blocks |
| `smoke-*` | 8 MiB | 16-128 KiB | 65-514 / 7-52 | GF8, GF16, FFT | 6-30 lost blocks |

`--profile full` runs sets A, B and C and then the smoke sets.
`--profile smoke` runs only the three smoke sets. Use `--set ID` (repeatable) to narrow either profile.

### Rows and protocol

The rows are the reference (single-threaded), `rarpar-w1` and `rarpar-w8`. Use
`--workers` to choose different worker counts. `--kernel-variant
NAME:VAR=value[,VAR=value]` adds a `rarpar` row with extra environment
variables. The env-gated kernel pins on main are currently no-ops for PAR3;
the flag is plumbing for when they exist.

Every `rarpar` create and repair row runs twice: once durable, which is the
default (no flag, one fsync per output), and once buffered (`--buffered`, no
fsync). The durable row is listed first and labelled `durable (default)`; the
buffered row is named `rarpar-wN-buffered`. Both carry ratios against the
single reference row, whose durability column reads `none (never syncs)`.
Verify rows write nothing and run once. `--durability durable` drops the
buffered rows; durable is always required. The suite probes
`rarpar par3 <op> --help` for `--buffered` as a whole token. When the help
prints but lacks it, which is the case for `par3 repair` today, the suite skips
that op's buffered row and says so in the report notes. When the help itself
fails (a timeout, a non-zero exit, a start failure, or a quarantine), the run
stops with that error rather than guessing. `par3 matrix --profile full` prints
the rows per op.

Each variant gets the warmups, then the measured repeats, and the variant order
alternates on every repeat. Each table cell is the median with the range,
`median [min–max]`, for wall time, user+sys CPU, and peak RSS. Ratios compare
medians against the reference, so below 1.000 means `rarpar` used less. Use
`--pin-cpus 0-7` to confine every timed process to that CPU range (Linux
`taskset`, Windows affinity). It takes one CPU or an inclusive range within
CPUs 0-63; a list such as `0,2` is refused because the Windows mask cannot
apply it. A matrix that would hold two rows with the same name, such as
`--workers 1,1`, is refused too. `--iocount` adds an untimed `strace -f -c` pass on
Linux and reports block and syscall counts.

Repair runs against a fresh copy of the damaged tree each time. A repair row
passes only when the repaired files hash back to the originals. The
"left behind" column lists the backup files each tool writes.

### Peak RSS

Peak RSS is a required field of every row (`max_rss_bytes` in `results.json`
and `runs.jsonl`). Every table shows it next to wall and CPU, with the
ours/reference RSS ratio. The harness reads it from the child itself:

| platform | source | equivalent tool output |
|---|---|---|
| macOS | `wait4` rusage `ru_maxrss`, already bytes | `/usr/bin/time -l` "maximum resident set size" |
| Linux | `wait4` rusage `ru_maxrss`, KiB scaled to bytes | `/usr/bin/time -v` "Maximum resident set size" |
| Windows | `K32GetProcessMemoryInfo` `PeakWorkingSetSize` on a handle opened at start and held across exit | (`Process.PeakWorkingSet64` reads null after exit, so it is not used) |

A process that exits without a peak RSS is a harness bug, not a missing value:
the row fails as `harness-missing-rss` (for the reference too; it is never
turned into a DNF), and `par3 report` refuses a `results.json` whose ok rows
lack the field. Only rows that never finished, such as a DNF or a timeout, may
have no RSS.

### Timeouts and reference DNF

Every run has a per-run timeout, `--timeout`, now 20 minutes by default (it
was longer before). The limit applies to `rarpar` rows too, so on a slow host
raise it, or a large set's `rarpar` rows fail as `timeout`. A `rarpar` row that
times out stays failed and is not retried on its remaining warmups and
repeats. `--reference-timeout` sets a different limit for the reference only.

A reference run is **DNF** for exactly these failure classes, recorded with
the exit code (or the timeout) and the last line it printed:

- `timeout`: it exceeded its timeout and was killed, with its whole process
  group (an interrupt or SIGTERM to `par3 run` kills the running process
  group the same way before the harness exits);
- `signal`: it was killed by a signal;
- `exit-N`: it exited non-zero;
- `no-carriers`, `truncated-carriers`, `unreadable-carriers`: a create exited 0
  but wrote no recovery files, fewer recovery blocks than asked for, or files
  that do not parse.

The suite carries on: the rest of that reference row is skipped, every
`rarpar` row still runs, and the run never fails because of it. Ratios against
a DNF reference show `-`.

Every other reference failure fails the run: `start-failed` (the binary would
not start), `reference-nondeterministic` (its create did not reproduce its own
canonical set byte for byte, which would make every identity verdict
meaningless), `repair-mismatch` (its repair did not restore the original
bytes) and `harness-missing-rss`.

Verify and repair need a canonical recovery set, normally written by an untimed
reference create. If that create is DNF (one of the classes above; any other
failure stops the set), `rarpar` (durable, most workers) writes
the canonical set instead, the reference still verifies and repairs it, the
identity verdicts are skipped, and the report says where the set came from.

### Identity verdicts

Every create row is compared with the reference's set for the same inputs:

- `identical`: byte-identical files.
- `payloads-only`: every recovery block's payload matches, but packet metadata
  differs.
- `DIFFERENT`: the recovery payloads differ.

Today's CLI sets are `DIFFERENT` by design. They carry a different `Creator`
and `InputSetID`, write each packet once per volume where the reference writes
it twice, and order the inputs differently. As a result the recovery
coefficients differ too. For sets with 129-255 input blocks, `rarpar` and the
reference also choose GF(2^8) versus GF(2^16) at different thresholds. This is
recorded rather than failed: each tool's create is still verified by itself
and repaired back to the original bytes. The report says which packet types
and counts differ.

### Reference caveats

- **macOS.** Upstream `par3cmdline` does not build on macOS. On macOS,
  `build-reference` applies
  `internal/par3bench/patches/par3cmdline-2971702e-macos.patch`, a bench-only
  port that is labelled in its header, and fetches a pinned `sse2neon.h` on
  arm64. Linux arm64 gets the same patch, since upstream's x86-only SIMD
  flags fail there; its Darwin hunks are guarded, so Linux code paths are
  unchanged. Linux x86-64 and Windows build or use the unmodified source. The
  patch digest is recorded in `reference.json` and in the results.
- **Work-path length.** The reference stores pointers into its list of
  recovery file names, then reallocates the list once it outgrows 1 KiB. It
  reopens the volumes through those dangling pointers and fails with
  "Failed to open Recovery File". It turns the output path into an absolute
  path first, so only the total length of the absolute volume paths matters,
  and a relative `--work` does not help. FFT sets always reach this path, and
  so do Cauchy sets too large to hold in memory. The failure is
  nondeterministic, so `par3 run` and `fleet plan` warn per set, with the
  path length and the number of characters to cut, and then run anyway; if the
  reference fails, its rows are DNF as above. Keep `--work` short, for example
  `/bench/p3` or `C:\p3`.
- **Windows.** The fleet uses the official `windows/par3.exe` from the pinned
  archive, verified by digest, instead of building it.

### Windows Defender

The suite hashes both binaries at startup and again before every batch. A
binary that refuses to start (a Defender block), disappears, or changes on
disk stops the run as `binary-quarantined`, with the path and what happened.
The harness never adds exclusions and never retries around it. Restore the
binary, or ask the host owner to allow it, then rerun.

Known false positive: Defender flags the `par3-rs` `engine_perf.exe` example
as `Trojan:Win64/AsyncRAT.C!MTB` and quarantines it. `engine_perf.exe` is only
used by a manual `par3 run --engine-perf PATH`; the fleet neither ships nor
runs it. The operator-approved handling is a path-scoped Defender exclusion,
added by hand by the host owner, on the bench work directory that holds
`engine_perf.exe`: the directory you build it into (cargo's
`target\release\examples`) or copy it into before passing it as `PATH`. Do not
widen it beyond that directory. No automation in this repository touches
Defender settings, and none may.

### Output

`--out` receives `results.json` (schema `rarpar-par3-bench-v1`; the
durability, DNF, timeout and canonical-source fields were added without
changing any existing field, so the schema name stays v1), `runs.jsonl`
(one line per process, warmups included) and `report.md`. Generated datasets
and the reference's canonical sets are cached under `--work`; delete it to
reclaim the space. `--keep-stages` keeps the per-run directories for
inspection.

### Storage targets and engine rows

`--target NAME=DIR` (repeatable, instead of `--work`) runs every row on every
target, interleaved, so a remote mount and its local control come from one
run. Each record carries the target's mount (filesystem, mount options,
`--target-meta NAME:key=value` facts the harness cannot see) and, on Linux NFS
mounts, the per-run delta of `/proc/self/mountstats` (READ, WRITE, COMMIT and
metadata ops, bytes, RTT). `--engine-workers 8` adds timed `engine_perf` rows
that report the engine's disk-work counters (opens, read/write calls and
bytes, fsyncs); `--engine-variant NAME:VAR=V` adds rows with `PAR3_BENCH_*`
switches, for example `wff-off:PAR3_BENCH_WHOLE_FILE_FIRST=0` for single-pass
disk verification. `--rows engine` keeps only those rows. `--drop-caches`
drops the page cache before every timed run (Linux, root). Engine rows have no
reference ratio.

### Network-mount rig

`bench/nfs` is a compose project: a kernel nfsd server exporting one `async`
and one `sync` export, and a privileged Linux client with the pinned Rust
toolchain that builds the tree under test from a read-only source mount and
runs the suite on three targets: `local` (the client's volume), `nfs-async`
and `nfs-sync`. Run it from `bench/rarpar-bench`:

```sh
rarpar-bench nfs run --context desktop-linux --label run1 \
  --env NFS_VERS=4.1 --env NFS_ACTIMEO=0 \
  -- --profile full --set a-gf16 --engine-workers 8 --repeats 3
rarpar-bench nfs down --context desktop-linux
```

Mount options are client environment variables (`NFS_VERS`, `NFS_PROTO`,
`NFS_RSIZE`, `NFS_WSIZE`, `NFS_HARD`, `NFS_ACTIMEO`, `NFS_CLIENT_SYNC`,
`NFS_NCONNECT`, `NFS_EXTRA_OPTS`) and are recorded in every row with the
server type and export mode. `--service bench-client-lowmem` runs in a client
whose memory limit (`RIG_LOWMEM_LIMIT`, default 768m) is below the largest
set file, so a second read pass cannot come from the page cache. `--env
RIG_EXT4=8G` adds a `local-ext4` target, a fresh loop-mounted ext4 image of
that size: a local filesystem without file clones. Evidence goes
to `target/bench/nfs/<label>/`, with the host's load average sampled into
`host-load.jsonl`. The cache volume keeps builds and datasets between runs;
`nfs down --volumes` removes it.

Server and client share one kernel, so the client turns NFS LOCALIO off
before mounting (else I/O would bypass the protocol) and restores it after.
The network is a container bridge with no real latency, and the exports sit
on the same virtual disk as the local control: the rig shows protocol cost
(extra round trips, commits, cache behaviour), not a NAS's disks or a WAN.
Compare NFS rows with local rows from the same run only.

`--env RIG_RATE_MBPS=80` throttles the client's link to that many MB/s each
way inside the client's network namespace (a token bucket on its interface,
and one on an IFB device its inbound traffic is redirected through), so the
server is unchanged. After mounting, the client writes a 1 GiB file to the
async export, drops the page cache, reads it back with `dd` and records the
measured rates in `rig.json` and in every NFS target's metadata.

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
