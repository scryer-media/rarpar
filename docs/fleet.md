# Fleet benchmarking

`rarpar-bench fleet` runs a whole cross-machine benchmark round from one
non-interactive command. It spawns every configured host in parallel — local SSH
machines and EC2 instances — runs the standard protocol on each, collects
results as hosts finish, tears cloud hosts down with verification, and renders
charts plus a fleet summary on the orchestrating machine.

It is the productized form of the per-round shell scripts that produced the
recorded evidence rounds. Everything those scripts learned the hard way is
encoded in the tool, not left to the operator.

## Setup

```sh
cp bench/fleet.example.toml bench/fleet.toml     # bench/fleet.toml is gitignored
$EDITOR bench/fleet.toml
```

`bench/fleet.example.toml` documents every key. Replace all of it: hostnames,
users, ports, key paths, staging directories, corpus paths, oracle URLs and
digests, the release tag under test, and the AWS account.

The config holds **no secrets**. Authentication is either

- `auth = "key"` with `key_path` pointing at a private key, or
- `auth = "askpass"` with `askpass_script` pointing at a helper that reads the
  secret from your own environment at call time.

A `password`, `secret`, or `token` key in the file is rejected by validation.

## One-command usage

```sh
# Read exactly what would happen. No side effects at all.
rarpar-bench fleet plan --config bench/fleet.toml

# Dry check: also download, verify and stage every bundle here. No fleet host
# is contacted and nothing is launched.
rarpar-bench fleet plan --config bench/fleet.toml --stage

# Run the whole round.
rarpar-bench fleet run --config bench/fleet.toml

# Narrow it.
rarpar-bench fleet run --config bench/fleet.toml --machine nas-atom --suite macro-rar
```

`fleet run` is non-interactive from start to finish. It:

1. **Verifies the candidates, then preflights, fail-fast.** Every release
   bundle's asset and the release's `SHA256SUMS` are downloaded and the asset's
   sha256 is checked first (see
   [Candidates: the published release](#candidates-the-published-release)); a
   missing asset or `SHA256SUMS`, or a mismatch, stops the round before any
   credential check, host probe or launch. With cloud machines it then checks
   AWS credentials — an expired session is reported with remediation before
   anything is built or launched — then validates the whole parallel launch
   against the account vCPU quota (cross-checked against
   `describe-instance-types`), then discovers this machine's public IPv4 by DNS
   for the session security group. Local hosts are probed over their own
   configured endpoint, and host-path oracles are proven present and
   digest-matched.
2. **Stages bundles.** A release bundle stages the verified `rarpar`
   (`rarpar.exe` for a Windows host) as published, and only the pure-Go harness
   is cross-compiled here, with CGO off (`rarpar-bench`, or `rarpar-bench.exe`
   for a Windows bundle). Nothing in the fleet builds a candidate from source,
   and nothing in it runs in a container. A prebuilt bundle is copied from a
   local directory as it is. Every bundle carries a `BUILDINFO.json` with the
   release it staged, tree revisions, dirty-file counts, binary digests, and
   the codegen policy.
3. **Spawns everything in parallel.** EC2 instances launch concurrently against a
   session security group scoped to your address and an ephemeral keypair, with
   `DeleteOnTermination`, terminate-on-shutdown, and a deadman shutdown inside
   the instance. SSH never runs on port 22: the security group opens only the
   configured ports (`fleet.aws.ssh_ingress_port`, default 22022, per-machine
   overridable via `connection.port`) and user-data relocates each instance's
   sshd there at boot — including on socket-activated Ubuntu, where
   `ssh.socket` owns the listener. Local hosts get their staging directory
   prepared.
4. **Runs each host fully detached.** The bundle and a generated self-contained
   run script go up by tar-over-ssh; the script is started with
   `setsid`/`nohup` and needs no further orchestrator contact. On the host it
   does: quiet-load gate → warmup pass (discarded) → timed repeats → perf
   diagnostic pass → evidence tarball + inventory manifest + `DONE` sentinel.
   An oracle whose vendor publishes no binary for the platform is compiled
   here, on the host, never on the orchestrator: UnRAR on Linux arm64 before
   the first suite (see
   [The UnRAR oracle on Linux arm64](#the-unrar-oracle-on-linux-arm64)),
   par3cmdline at the start of the PAR3 suite, and XZ Utils in the lzma-turbo
   suite.
5. **Collects as hosts finish.** Each host is polled for its sentinel; on DONE
   the tarball is pulled and verified against the manifest, then cloud hosts are
   terminated and the teardown is verified resource by resource. A slow or hung
   host never blocks another.
6. **Renders and summarises.** SVGs per platform label into the run directory
   (never the repository's docs), plus `fleet-summary.json` and
   `fleet-summary.txt` with per-host status, durations, cost math from the
   launch/terminate stamps, teardown evidence, and failures.

Everything lands under `<results_root>/<run-id>/`:

```
plan.json plan.txt          what the run intended to do
run-state.json              live state; the resume path reads this
release-cache/<tag>/        SHA256SUMS and the verified release assets
run-<machine>.sh            the exact script that ran on each host
bundles/<machine>/          what was shipped, with BUILDINFO.json
hosts/<machine>/results/    the verified evidence
charts/<platform-label>/    rendered SVGs
fleet-summary.json/.txt     the round
```

## Candidates: the published release

A machine's rarpar is the published release asset for its platform, run
natively on the host. It is never built for the round.

```toml
[machines.bundle]
source = "release"        # the default
tag = "rarpar-v0.7.0"     # or version = "0.7.0"
go_os = "linux"           # linux | darwin | windows
go_arch = "amd64"         # amd64 | arm64
flavor = "musl-direct"    # Linux only: musl-direct (default) | gnu-direct
```

`go_os`, `go_arch` and, on Linux, `flavor` pick one asset of the release:

| Host | Asset | Binary |
| --- | --- | --- |
| Linux x86_64 / arm64 | `rarpar-<tag>-linux-<x86_64\|arm64>-<flavor>.tar.gz` | `rarpar` |
| macOS x86_64 / arm64 | `rarpar-<tag>-darwin-<x86_64\|arm64>.tar.gz` | `rarpar` |
| Windows x86_64 / arm64 | `rarpar-<tag>-windows-<x86_64\|arm64>.zip` | `rarpar.exe` |

`musl-direct` is the statically linked musl build and `gnu-direct` the glibc
build. When `build_target` is set it must be the asset's Rust target, so a
mismatch is a config error rather than a mislabelled chart. A `powershell` host needs
`go_os = "windows"`, and `go_os = "windows"` needs a `powershell` host.

How the asset is checked:

- `SHA256SUMS` is fetched from
  `https://github.com/scryer-media/rarpar/releases/download/<tag>/SHA256SUMS`
  on every run. A line that is not a `<sha256>  <file>` entry fails the
  round rather than being skipped.
- The asset is downloaded once per (tag, platform), however many machines
  share it, into `<run dir>/release-cache/<tag>/<platform>/`. It is hashed
  as it streams and kept only if its sha256 is the one `SHA256SUMS` lists.
  A cached copy is hashed again before it is reused.
- Downloads come from GitHub and nowhere else: a redirect to any host other
  than `github.com` or GitHub's asset hosts is refused.
- Only the binary at the archive root is unpacked. The tarballs also carry a
  bash completion named `rarpar`, which is never taken for the binary. An
  archive member that would escape the cache directory, a root binary that
  appears twice, or one that is not a regular file is refused.
- A missing asset, a missing `SHA256SUMS` or a mismatch stops the round
  before any credential check, host probe or launch.
- The machine's `release` record in `run-state.json` and the bundle's
  `BUILDINFO.json` hold the provenance: tag, release URL, platform, Rust
  target, asset name, URL, size and sha256, the `SHA256SUMS` URL and digest,
  and the unpacked binary's digest and size. The staged binary is checked
  against that digest once more when the bundle is assembled.

The release's cosign signature (`SHA256SUMS.sigstore.json`) is not verified;
the check rests on HTTPS to GitHub and the digest match.

Two things a release bundle cannot do:

- `crc-probe` and `yenc-micro` measure weaver's own binaries, which no rarpar
  release publishes. With a release bundle they are a config error; run them
  from a prebuilt bundle.
- The release binaries are built without forced frame pointers or debug info.
  The perf pass still runs, but its frame-pointer call graphs
  (`--call-graph fp`) stop early inside `rarpar`. For full call graphs, use a
  prebuilt bundle built with frame pointers in a spot test.

**Dry check.** `rarpar-bench fleet plan --config bench/fleet.toml --stage`
prints the plan, then downloads and verifies every release asset and
assembles every bundle exactly as `fleet run` would, under
`<results_root>/<run-id>/` (never `bundle_cache`). It records the result in
`stage-state.json`, never `run-state.json`, so `fleet collect` and
`fleet teardown` cannot mistake it for a round, and it refuses a run id that
already has a `run-state.json`. It contacts no fleet host, checks no
credential and launches nothing. Oracles are resolved as in a round, so an
`official-binary` oracle, and the source tarball of an `unrar-portable-onhost`
oracle, is downloaded unless `--no-fetch` is given.

**Prebuilt, for dev spot tests.** `source = "prebuilt"` with `path` set to an
absolute local directory stages that directory as it is: early development
spot tests only, never a measured round. The plan flags every prebuilt
machine as a dev spot test. The directory must hold `rarpar-bench` and
`rarpar` (`.exe` names for a Windows host) plus the binaries of any suite
that needs them, such as `crc_probe`.

## Resume

If a host was still running when you stopped watching, or its collection failed:

```sh
rarpar-bench fleet collect --config bench/fleet.toml --run-id e2e-20260813T211255Z
```

Hosts already collected are skipped; only stragglers and failures are re-entered.

## Cloud teardown

Teardown is part of a host being finished, not a best-effort extra: terminate,
wait, then confirm the instance state, that the root volume is gone
(`DeleteOnTermination`), that no volumes remain attached, and that no ENIs
remain. The shared security group and keypair are deleted after the last cloud
host and confirmed `NotFound`.

To sweep strays from an interrupted run:

```sh
rarpar-bench fleet teardown --config bench/fleet.toml --run-id <id>
rarpar-bench fleet teardown --config bench/fleet.toml        # sweep by prefix only
```

`--dry-run-aws` exercises every AWS code path except the API mutations. Reads
(`sts get-caller-identity`, `describe-*`) still run live, so a dry run genuinely
validates credentials, account, instance types, quota arithmetic, and the
teardown logic.

## Adding a machine

Append a `[[machines]]` block. The mandatory decisions:

| Field | What it decides |
| --- | --- |
| `kind` | `local-ssh` (a machine you own) or `aws-ec2` (launched and destroyed per run; `ec2.access` = `ssh` or `ssm`) |
| `platform_label` | Names the SVGs and the report machine label. Must be unique — a collision overwrites another machine's charts |
| `suites` | `macro-rar`, `macro-par2`, `macro-par3`; `crc-probe` and `yenc-micro` from a prebuilt bundle only |
| `capabilities.perf` | `linux-perf`, `samply`, or `none`. Decides which diagnostic pass runs; `linux-perf` also runs the macro-par3 perf pass (`perf.par3_ops`) |
| `capabilities.no_pgrep` | Set on busybox-class appliances; the load gate falls back to `ps -ef \| grep` |
| `bundle.source` | `release` (the default: the published release asset, with `tag` or `version`) or `prebuilt` (stage a local directory; dev spot tests only) |
| `oracles.*` | `host-path`, `official-binary`, or `source-build` |

Then:

```sh
rarpar-bench fleet plan --config bench/fleet.toml --machine <new-name> --stage
rarpar-bench fleet run  --config bench/fleet.toml --machine <new-name> --suite macro-rar
```

Start with `fleet plan --stage`: it proves the release publishes an asset for
the machine's platform, verifies it and assembles the bundle without touching
the host. Then run one macro suite, narrowed with `[machines.run].cases`, to
prove the transport, the bundle, the sentinel, and the collection path before
you spend an hour of macro suite on a host that turns out to be missing an
oracle.

### Rules the tool enforces so you do not have to remember them

- **The candidate is the published release, checked before anything runs.**
  Each machine runs its platform's release asset, verified against the
  release's `SHA256SUMS`. Nothing in the fleet builds a candidate from source
  or runs one in a container.
- **Never build an oracle the vendor publishes a binary for.** `source-build`
  requires a recorded `reason`, a pinned source, and one of two audited
  recipes. Each is refused on every platform its vendor publishes a binary
  for, and each compiles natively on the host during the run, never on the
  orchestrator and never in a container. `unrar-portable-onhost` builds UnRAR
  on Linux arm64 only (see
  [The UnRAR oracle on Linux arm64](#the-unrar-oracle-on-linux-arm64)).
  `par3cmdline-onhost` builds par3cmdline on Linux and macOS (see
  [PAR3 suite on the fleet](#par3-suite-on-the-fleet)). The removed
  `unrar-portable` recipe, which compiled UnRAR in a container on the
  orchestrating machine, is refused with a pointer to `unrar-portable-onhost`.
- **Hosts run natively.** `fleet.defaults.lane` must be `cpu` or `metal`;
  `docker-cpu` is refused.
- **Explicit `user@host:port` from the machine's own config entry.** ssh_config
  aliases are rejected; an alias that resolved to the wrong user has
  mis-authenticated a whole round.
- **tar-over-ssh for every transfer.** Some hosts have the sftp subsystem
  disabled, and macOS `openrsync` silently ignores `-e`.
- **A short ControlPath** under `/tmp`, because the default `%r@%h:%p` template
  overruns the 104-byte unix socket path limit.
- **Quiet-load gating before every timed pass**, by process name *and* loadavg.
  Either check alone lies: a name check catches another operator's bench before
  loadavg reacts, and loadavg catches housekeeping that owns no matching name.
- **Machines get access details only from their own config entry.** Coordination
  between concurrent operators is by sentinel files and process-name matching,
  never by discovering how another session connects.
- **A deadman on every cloud host**, at least as long as the cost cap, so the
  cost cap fires first and the deadman is only ever the backstop.

### Failures versus warnings

A host is only *failed* when its measured evidence is compromised — a corpus
that does not verify, a suite that did not run, a report that was not written.
A diagnostic pass that could not run is recorded as a **warning** instead: the
timed numbers stand, and the summary says what was missed. A host without
`perf`, for instance, warns `perf-missing`, and a macro-par3 perf pass that
fell short warns `par3-perf-incomplete`.

Both lists travel in the host manifest and appear in `fleet-summary.json`.

### Gotcha worth knowing

The process-name gate has no expiry, by design — it will not measure next to
another bench. A *stuck* process matching one of the names (0% CPU, never
exiting) therefore blocks that host until the orchestrator's
`host_timeout_minutes` abandons it. The host's `run.log` says exactly which name
it is waiting on. Clear the process, or drop that name from
`quiet_load_process_names` for the run.

## The UnRAR oracle on Linux arm64

RARLAB publishes no Linux arm64 UnRAR. rarlab.com/download.htm lists none,
and the only Linux ARM entries on rarlab.com/rar_add.htm are
`unrar-4.1.3-armv4l.tar.gz` and `unrar-5.5.0-arm.gz`. The second is UnRAR
5.5.0 from 2017: an ELF 32-bit ARM EABI5 binary, dynamically linked against
`/lib/ld-linux-armhf.so.3`. An AArch64-only server core cannot execute it,
and it predates RAR 7. So a Linux arm64 host's `rar` oracle is the one UnRAR
the fleet builds, and the host builds it itself. Every other host runs
RARLAB's own binary.

```toml
[machines.oracles.rar]
policy = "source-build"
reason = "RARLAB publishes no Linux arm64 UnRAR: rarlab.com/download.htm lists none, and the only Linux ARM entries on rarlab.com/rar_add.htm are unrar-4.1.3-armv4l.tar.gz and unrar-5.5.0-arm.gz, an UnRAR 5.5.0 (2017) ELF 32-bit ARM EABI5 binary dynamically linked against /lib/ld-linux-armhf.so.3, which an AArch64-only server core cannot execute and which predates RAR 7"
url = "https://www.rarlab.com/rar/unrarsrc-7.2.3.tar.gz"
sha256 = "3995af0aa32b1505a566da053725551a1f0698dc42b2fdf7ba7d65db0d004e33"
recipe = "unrar-portable-onhost"
# binary_sha256 = "<64 hex>"      # optional: hold later runs to one binary
version = "unrar 7.2.3 (portable on-host build)"
```

- **The orchestrator compiles nothing.** It downloads the source tarball,
  refuses it unless its sha256 matches the pin, and ships it in the bundle.
  `fleet plan --stage` does the same; with `--no-fetch` the tarball must
  already be in the cache.
- **The host builds it at run start**, after `environment.txt` records the
  quiet box and before `binaries.txt` hashes the binaries, by running
  `rarpar-bench fleet build-unrar`. That checks the shipped tarball against
  the pin again and unpacks it. It refuses to build if the stock makefile
  carries `-march`, `-mcpu`, `-mtune` or `native` outside a comment line. It
  runs the stock makefile with its stock `CXXFLAGS` and `LDFLAGS`, setting
  only `CXX=g++`, and removes `CPPFLAGS`, `CFLAGS`,
  `CXXFLAGS`, `LDFLAGS`, `LIBS`, `MAKEFLAGS`, `MFLAGS`, `GNUMAKEFLAGS` and
  `MAKEFILES` from make's environment, so none of them can carry a flag from
  the host into the build. The result links dynamically against the host's
  glibc, the one it was built on: a static glibc link cannot back UnRAR's
  wide-character console output, and such a binary crashes on a null pointer
  inside `fputws` the first time it prints. It refuses a result that is not
  an ELF executable for the host's architecture, one that is killed by a
  signal or does not print UnRAR's banner when run with no arguments (the
  suites' identity probe), and one whose sha256 differs from `binary_sha256`
  when that is set. Only then does it install
  `unrar-reference/unrar` in the run's staging directory, the path every
  suite uses. It first deletes any binary an earlier build left there, so a
  refused build leaves none. The quiet-load gate before the first suite waits
  out the build's load.
- **Evidence.** `results/unrar-build.json` records the source URL and
  digest, the makefile digest, the flag audit, the make arguments, the
  removed variables, the make and compiler versions, the binary digest and
  whether a pin held it, the ELF machine, the shared libraries it names and
  the banner from the start check.
  `results/unrar-build.log` holds the full build output.
- **A failed build fails the host** as `unrar-build`. Every run that needs
  the oracle then stops at its missing-binary check before it runs a case.
- **Host requirements.** make, g++, and the libc and libstdc++ development
  files. EC2 user-data installs `build-essential` when this recipe is
  selected; a local host must already have them.
- **Pinning the binary.** The digest depends on the host's compiler, so a run
  without `binary_sha256` records the digest and does not check it. Review
  `results/unrar-build.json`, then set `binary_sha256` to hold later runs to
  that binary.
- **Refusals.** The recipe needs `bundle.go_arch = "arm64"` on a Linux host
  and is refused anywhere else, since RARLAB publishes the binary there. It
  needs the `url` and `sha256` of an `unrarsrc-*.tar.gz`.

## PAR3 suite on the fleet

Add `macro-par3` to a machine's `suites` and give it a `par3` oracle. The
bundle then carries `toolchains.json`, and the host runs `rarpar-bench par3 run`
before the corpus suites' perf pass. Evidence goes to `<results>/par3/`
(`results.json`, `runs.jsonl`, `report.md`), and logs go to
`par3-run.stdout.log` and `par3-run.stderr.log` (`par3-run.log` on Windows).
The suite itself is documented in
[benchmarking.md](benchmarking.md#par3-suite).

```toml
[machines.oracles.par3]
policy = "source-build"
reason = "par3cmdline publishes no release and no Linux binary; the tree ships only windows/par3.exe"
recipe = "par3cmdline-onhost"     # built on the host from the pinned archive

[machines.par3]
profile = "full"                  # or "smoke"
# sets = ["a-gf16", "c-gf16"]     # default: every set in the profile
# ops = ["create", "verify", "repair"]
workers = [1, 8]
warmups = 1
repeats = 5
pin_cpus = "0-7"
work = "/bench/p3"                # keep it short, see below
timeout_minutes = 20              # per run, rarpar rows too; a reference over it is DNF
# reference_timeout_minutes = 60  # default 0: the reference uses timeout_minutes
```

- **Buffered rows.** Every `rarpar` create and repair runs buffered, one
  `rarpar-wN` row per worker count, and the bench never passes `--fsync`:
  durability is a consumer concern, not a PAR3 one. The reference gets one
  row. The harness probes each candidate's `par3 <op> --help`: a build that
  lists `--buffered` (0.6.x and earlier) gets it, one that lists only
  `--fsync` (0.7.0 and later) is buffered when run plain, and one that lists
  neither runs the plain command and says so in the report notes. A
  `par3.durability` key is a config error.
- **Repair rows.** Each worker count also gets a repair-only
  `rarpar-wN-backup` row. `rarpar-wN` repairs in place with no backup;
  `rarpar-wN-backup` keeps a numbered `.1` of every file it repairs, as the
  reference does, so it is the row that is like for like with the reference
  on bytes written. Each row's switch comes from the candidate's
  `par3 repair --help` (`--backup` after 0.7.0, `--no-backup` for 0.7.0 and
  earlier); see [benchmarking.md](benchmarking.md#rows-and-protocol). A
  PAR-inside set keeps its one compatible `rs` row. In the text plan, the
  macro-par3 step reads "buffered rarpar rows only (never --fsync): per
  worker count rarpar-wN for every op, repairing in place with no backup,
  and the repair row rarpar-wN-backup, which keeps a numbered .1 as the
  reference does (like for like on bytes written)" and gives the per-run
  timeout, and the machine's `par3` block lists the variants and the rows
  each op produces; `--json` carries the same rows under `par3.rows`.
- **PAR2 rows.** The fleet profile's posting-shape Cauchy sets also run
  `par2-rs`, and `par2cmdline-turbo` when the machine has the `par2` oracle,
  which the run script passes to `par3 run` as `--par2`; see
  [benchmarking.md](benchmarking.md#fleet-profile). The PAR2-against-PAR3
  charts are drawn from these suite results by `par3 versus-render`.
- **Perf pass.** On a `linux-perf` machine, `par3 run` runs the untimed
  [perf pass](benchmarking.md#linux-perf-pass) itself, after each covered
  op's timed runs: `stat_repeats` perf stat runs of every reference and
  `rarpar` row of the `par3_ops` ops, each on a fresh stage, and one
  perf record at `record_frequency` of every `rarpar` row on each set in
  `par3_record_sets`:

  ```toml
  [machines.perf]
  stat_repeats = 3
  record_frequency = 499
  par3_ops = ["repair"]            # the default with macro-par3; [] turns the pass off
  par3_record_sets = ["a-gf16"]    # plain sets this machine selects; default none
  ```

  Every op added to `par3_ops` costs `stat_repeats` more untimed runs per
  row and plain set. Both keys are checked when the config loads: each op
  must be one the machine's macro-par3 run measures, each record set a plain
  (not PAR-inside) set it selects, listed once; record sets need `par3_ops`,
  and either key needs `capabilities.perf = "linux-perf"` and the macro-par3
  suite. The plan's `perf` line says what runs under perf per suite, and a
  step after the macro-par3 step names the sets, the rows, the record sets
  and an upper bound on the untimed runs; `--json` carries the keys as
  `protocol.perf_par3_ops` and `protocol.perf_par3_record_sets`. Evidence
  goes to `<results>/perf/par3/`. A pass that was skipped, had a perf run
  fail, or ran nothing writes `INCOMPLETE.txt` there, and the host warns
  `par3-perf-incomplete`, as it does when that directory is empty; neither
  fails the host. The corpus suites' perf work runs only when one of them is
  selected: a machine that runs macro-par3 alone records only
  `perf --version` and `kernel.perf_event_paranoid` in the corpus perf step.
- **Timeouts.** `timeout_minutes` (default 20, lower than before) applies to
  `rarpar` rows too; raise it on slow hosts. `reference_timeout_minutes`
  gives the reference its own limit (0 = the same).
- **Reference failures** that mean "did not finish" (timeout, signal, non-zero
  exit, missing, short or unreadable recovery files) are recorded as DNF with
  the exit code and stderr line, and the PAR3 section carries on. A reference
  that would not start, did not reproduce its own canonical set, or repaired
  wrongly fails the section; see
  [benchmarking.md](benchmarking.md#timeouts-and-reference-dnf).

- **Linux and macOS hosts** use `recipe = "par3cmdline-onhost"`, because
  par3cmdline publishes no release and no Linux binary; the tree ships only
  windows/par3.exe. The host runs `par3 build-reference`, which builds the
  commit `internal/par3bench/reference.go` pins, so the reference is compiled natively and never
  emulated. It needs CMake and a C compiler; EC2 user-data installs
  `build-essential` and `cmake` when this recipe is selected. This recipe
  takes no `url` or `sha256`.
- **Windows hosts** use `policy = "official-binary"` with the pinned archive's
  `windows/par3.exe` (`archive_member`, `binary_sha256`); see the example
  config. `par3cmdline-onhost` is refused on Windows, and so is
  `[machines.par3].iocount`.
- **Work path.** `fleet plan` checks `[machines.par3].work`, which defaults to
  `<scratch>/p3`, against the reference's file-name limit. An over-long path
  is a plan warning with the character count, and preflight logs it; neither
  refuses, because the reference bug is nondeterministic and a failure only
  costs DNF rows. The run deletes the work directory afterwards.
- **Defender.** A quarantined or blocked binary stops the PAR3 section as
  `binary-quarantined`. The harness reports it and does not work around it.
  Defender misflags the `par3-rs` `engine_perf.exe` example as
  `Trojan:Win64/AsyncRAT.C!MTB`. The fleet neither ships nor runs it; it only
  matters for a manual `par3 run --engine-perf`. See the Windows section below.

```sh
rarpar-bench fleet plan --config bench/fleet.toml --suite macro-par3
rarpar-bench fleet run  --config bench/fleet.toml --suite macro-par3
```

Public write-ups name hosts by core type only, for example "Zen 4" or
"Graviton 4", never by machine name. `platform_label` should follow the same
rule.

## Turbo suites on the fleet

`lzma-turbo` and `sevenz-turbo` run the lzma-turbo and sevenz-turbo Go
harnesses (`bench/lzma-turbo-bench`, `bench/sevenz-turbo-bench` in their own
repositories) against their own oracles. Name the checkouts in `[fleet]` and
add the suites to a machine:

```toml
[fleet]
lzma_turbo_path = "/path/to/lzma-turbo"
sevenz_turbo_path = "/path/to/sevenz-turbo"

[[machines]]
suites = ["lzma-turbo", "sevenz-turbo"]

[machines.turbo]
lzma_profile = "fleet"            # quick | full | fleet
sevenz_profile = "fleet"
# lzma_only = ["decode"]          # the harness's --only selectors
# sevenz_only = ["lzma2"]
# lzma_repeats = 0                # 0 = the profile's
# sevenz_repeats = 0
# pin_cpus = "0-7"                # sevenz --pin-cpus
timeout_minutes = 60              # per case
# sevenz_fixtures_image = "<account>.dkr.ecr.<region>.amazonaws.com/sevenz-turbo-fixtures:fleet-7zz2604-x86_64"
```

Unlike the rarpar suites, the candidates are built **on the host**. Both
harnesses record the checkout's rustc and lockfile as provenance, the lzma
harness refuses a binary whose embedded commit is not the checkout's clean
HEAD, and lzma's fixtures come from `cargo xtask` in that checkout. So the
bundle carries, per suite, a `git bundle` of the checkout's HEAD commit, a
`.commit` sidecar, and the harness cross-compiled with CGO off. The build
refuses a dirty checkout. A machine that runs only turbo suites still stages
its platform's rarpar release asset, though neither suite runs it, and its
`[machines.bundle]` sets the Go target.

On the host, the run script:

1. installs rustup 1.29.1 from its pinned, digest-checked installer under the
   run root with no default toolchain, so each checkout's `rust-toolchain.toml`
   installs exactly its own compiler;
2. fetches the official 7-Zip 26.04 Linux release (digest-checked) as the
   `7zz` oracle;
3. for `lzma-turbo`: clones the bundle, verifies the commit, builds XZ Utils
   5.8.4 from its pinned tarball (static), runs `toolchain --build`,
   `fixtures`, then `run --profile <lzma_profile>` into `results/lzma-turbo/`;
4. for `sevenz-turbo`: clones the bundle, verifies the commit, builds
   `decode-bench` twice (`aws-lc-rs` and `native-crypto`), generates the
   fixture corpus with the official `7zz` (or pulls it, below), records the
   toolchain, then `run --profile <sevenz_profile>` into
   `results/sevenz-turbo/`.

Setup logs live under `results/turbo/`. Each stage that fails records a
`fail` marker and skips the rest of that suite; the other suite and the
manifest still run. The host needs `build-essential`, `cmake`, `pkg-config`,
`git`, `curl`, `xz-utils` and `perl`; EC2 user-data installs them.

### Sevenz fixture image

Writing the sevenz `fleet` corpus (about 21 GB, mostly `7zz a`) takes about
24 minutes of every host's setup. On an `aws-ec2` machine,
`turbo.sevenz_fixtures_image` caches it in ECR instead:

- **Pull.** The orchestrator mints an ECR token for the image's region at
  staging, and the host fetches the image in-region with
  `rarpar-bench corpus fetch` (digest-verified). The harness's `fixtures` step
  still runs over the pulled corpus: it keeps every source and archive whose
  recipe and oracle provenance match, rewrites anything that does not, and the
  run raises `warn sevenz-fixtures-image-stale` when it had to rewrite
  something, so a stale tag is visible rather than silently slow.
- **Seed.** When the tag is absent (the preflight says so) or the fetch
  fails, the host generates the corpus as before and, after the run,
  publishes it with `rarpar-bench corpus push` (a tar staged on the run
  volume, so size `ec2.volume_gb` for twice the corpus). A failed push raises
  `warn sevenz-fixtures-push` and leaves the results alone.

The archives' provenance is the `7zz` build that wrote them, which differs
per architecture, so tag one image per profile, `7zz` version and
architecture (`fleet-7zz2604-x86_64`, `fleet-7zz2604-aarch64`) and change the
tag when any of them changes. The repository must exist (`aws ecr
create-repository`); the layer is an uncompressed tar, so each image stores about the corpus size. `corpus
push` accepts a root holding a rarpar `corpus.json` or a sevenz-turbo
`fixtures.json` (`sevenz-turbo-bench/fixtures/1`) and nothing else.

Budget the session for the profile. The sevenz `fleet` profile is the full
corpus at three repeats and runs for hours on a 16-thread host; set
`ec2.max_hours`, `ec2.deadman_minutes`, `fleet.aws.max_session_hours` and
`fleet.host_timeout_minutes` accordingly, or narrow with `sevenz_only`.
Only Linux hosts run these suites: a Windows host, or one whose
`bundle.go_os` is not `linux` (a macOS host's is `darwin`), is refused.

## Network-mount rig

Remote-filesystem rows do not run on the fleet. They come from the local
compose rig, `rarpar-bench nfs run`, which runs the PAR3 suite on kernel NFS
exports and a local control in one run; see
[benchmarking.md](benchmarking.md#network-mount-rig).

## EC2 over SSM

`access = "ssh"` is the default: the run uses a temporary keypair, a security
group, and SSH on `fleet.aws.ssh_ingress_port`. Use `access = "ssm"` when SSH
into EC2 is unreliable from the orchestrating network:

```toml
[fleet.aws]
ssm_bucket = "your-transfer-bucket"           # scripts and tarballs travel here
instance_profile = "your-ssm-instance-profile" # AmazonSSMManagedInstanceCore + bucket access

[[machines]]
kind = "aws-ec2"
[machines.ec2]
access = "ssm"
spot = true                                    # optional, SSM only
```

- No keypair, security group, or ingress rule is created. The instance gets
  the instance profile and nothing else.
- Every script runs through `AWS-RunShellScript`. The script is uploaded to
  `s3://<bucket>/<prefix>/<run>/<machine>/`, which the host fetches, deletes
  and runs. Bundles and results move as tar objects under the same prefix,
  and each object is deleted after its transfer.
- User-data leaves snapd running: the SSM agent on Ubuntu cloud images is a
  snap, and disabling snapd would cut the only channel to the instance. The
  host's AWS CLI also comes from `snap install aws-cli --classic`. The SSH
  path still disables snapd.
- `corpus_source` is refused with SSM. Use the generated PAR3 data or a
  prebuilt corpus in the bundle.
- Preflight checks the bucket (`s3api head-bucket`) and the profile
  (`iam get-instance-profile`) read-only. `--dry-run-aws` stops before
  launch, exactly as it does for SSH.

## Known limits

- The on-host UnRAR build (`unrar-portable-onhost`) has not yet compiled
  UnRAR on a live Linux arm64 host. Its checks are unit-tested around a
  stand-in `make`, and the builder has run on RARLAB's real 7.2.3 source
  tarball with that stand-in. Treat its first run as bring-up.
- The Windows runner has never been executed (see below).
- The SSM access mode is implemented and unit-tested but has not been run
  against a live account yet. Treat its first run as bring-up.
- The Windows transport is implemented and unit-tested but has not run against
  a live host (see below).
- The turbo suites' host-side flow (rustup, checkout build, oracle fetch and
  build, harness run) is unit-tested from the generated script but has not run
  on a live host yet. Treat the first run as bring-up.
- The macro-par3 perf pass is unit-tested against a stub `perf` and from the
  generated script, but has not run under a real `perf` on a live host yet.
  Treat its first run as bring-up.

## Windows hosts

Implemented and unit-tested, but **unvalidated: it has never run against a live
Windows host.** Treat the first Windows run as bring-up, not evidence. See the
TODO at the top of `internal/fleet/windows.go` for what bring-up must confirm.

The host needs Windows OpenSSH (sshd with its default sftp subsystem) and
Windows PowerShell 5.1. It needs no `sh` and no `tar`:

- **Control commands** (probe, mkdir, existence checks, the oracle check,
  reading the `DONE` sentinel, cleanup) are short PowerShell scripts sent as
  `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -EncodedCommand <base64>`. Base64 has nothing cmd.exe or PowerShell
  interprets, so there is no quoting layer. A script too long for cmd.exe's
  command-line limit is refused rather than truncated.
- **Uploads.** The bundle and the run script are zipped locally, sent with
  `scp -P <port>` (same key, known-hosts file and multiplexing as ssh) to
  `/C:/...`, and unpacked with `Expand-Archive`.
- **The run** is the uploaded `run.ps1` *file*, never an inline command string,
  because quoting a script through ssh → cmd.exe → PowerShell truncates it
  silently. It starts through `Win32_Process.Create`, so it is outside the
  sshd session's job object and survives the connection closing. Its output
  goes to `run.log`.
- **Evidence** is `results.zip`, built on the host with
  `System.IO.Compression.ZipFile` and fetched by scp. Locally, backslash entry
  names are normalised and entries that would escape the destination are
  refused; the inventory manifest is verified as on POSIX hosts.
- **Preflight** probes Windows hosts too (OS caption, `NUMBER_OF_PROCESSORS`,
  CPU load) and checks host-path oracles with `Get-FileHash`.
- **Paths.** Windows host paths must be absolute and must not contain a double
  quote, `%` or a line break, because the detached start passes them through a
  cmd.exe command line.
- `capabilities.perf` must be `none`.

The generated PowerShell is pinned by golden files in
`bench/rarpar-bench/internal/fleet/testdata/windows/`; regenerate them with
`go test ./internal/fleet -run Golden -update` and review the diff. The POSIX
transport is unchanged.

**Defender.** Defender flags the `par3-rs` `engine_perf.exe` example as
`Trojan:Win64/AsyncRAT.C!MTB`, a false positive. The fleet neither ships nor
runs `engine_perf.exe`; it is used only by a manual
`rarpar-bench par3 run --engine-perf PATH` on the host. The operator-approved
handling is a path-scoped Defender exclusion, added by hand by the host owner,
on the bench work directory that holds `engine_perf.exe` (cargo's
`target\release\examples` where it was built, or the directory it was copied
into for `--engine-perf`), and no wider. Nothing in the fleet tooling touches
Defender settings, and nothing may; a quarantine still surfaces as
`binary-quarantined`.
