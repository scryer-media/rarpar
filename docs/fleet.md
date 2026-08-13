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
digests, and the AWS account.

The config holds **no secrets**. Authentication is either

- `auth = "key"` with `key_path` pointing at a private key, or
- `auth = "askpass"` with `askpass_script` pointing at a helper that reads the
  secret from your own environment at call time.

A `password`, `secret`, or `token` key in the file is rejected by validation.

## One-command usage

```sh
# Read exactly what would happen. No side effects at all.
rarpar-bench fleet plan --config bench/fleet.toml

# Run the whole round.
rarpar-bench fleet run --config bench/fleet.toml

# Narrow it.
rarpar-bench fleet run --config bench/fleet.toml --machine nas-atom --suite crc-probe
```

`fleet run` is non-interactive from start to finish. It:

1. **Preflights, fail-fast.** With cloud machines it checks AWS credentials
   *first* — an expired session is reported with remediation before anything is
   built or launched — then validates the whole parallel launch against the
   account vCPU quota (cross-checked against `describe-instance-types`), then
   discovers this machine's public IPv4 by DNS for the session security group.
   Local hosts are probed over their own configured endpoint, and host-path
   oracles are proven present and digest-matched.
2. **Builds bundles.** Either staged from a prebuilt directory or built in the
   recorded container recipe (musl, `crt-static`, no `-march`/`-mcpu`/`-mtune`
   anywhere, aws-lc built in-container, Go with CGO off). Every bundle carries a
   `BUILDINFO.json` with tree revisions, dirty-file counts, binary digests, and
   the codegen policy.
3. **Spawns everything in parallel.** EC2 instances launch concurrently against a
   session security group scoped to your address and an ephemeral keypair, with
   `DeleteOnTermination`, terminate-on-shutdown, and a deadman shutdown inside
   the instance. Local hosts get their staging directory prepared.
4. **Runs each host fully detached.** The bundle and a generated self-contained
   run script go up by tar-over-ssh; the script is started with
   `setsid`/`nohup` and needs no further orchestrator contact. On the host it
   does: quiet-load gate → warmup pass (discarded) → timed repeats → perf
   diagnostic pass → evidence tarball + inventory manifest + `DONE` sentinel.
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
run-<machine>.sh            the exact script that ran on each host
bundles/<machine>/          what was shipped, with BUILDINFO.json
hosts/<machine>/results/    the verified evidence
charts/<platform-label>/    rendered SVGs
fleet-summary.json/.txt     the round
```

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
| `kind` | `local-ssh` (a machine you own) or `aws-ec2` (launched and destroyed per run) |
| `platform_label` | Names the SVGs and the report machine label. Must be unique — a collision overwrites another machine's charts |
| `suites` | `crc-probe`, `yenc-micro`, `macro-rar`, `macro-par2` |
| `capabilities.perf` | `linux-perf`, `samply`, or `none`. Decides which diagnostic pass runs |
| `capabilities.no_pgrep` | Set on busybox-class appliances; the load gate falls back to `ps -ef \| grep` |
| `bundle.source` | `docker` (build the recipe) or `prebuilt` (stage a directory) |
| `oracles.*` | `host-path`, `official-binary`, or `source-build` |

Then:

```sh
rarpar-bench fleet plan --config bench/fleet.toml --machine <new-name>
rarpar-bench fleet run  --config bench/fleet.toml --machine <new-name> --suite crc-probe
```

Start with `crc-probe`: it is short, needs no corpus, and proves the transport,
the bundle, the sentinel, and the collection path before you spend an hour of
macro suite on a host that turns out to be missing an oracle.

### Rules the tool enforces so you do not have to remember them

- **Never rebuild an oracle where an official binary exists.** `source-build`
  requires a recorded `reason`, a pinned source tarball digest, and one of the
  audited recipes. `unrar-portable` uses the stock makefile and stock
  `CXXFLAGS`, sets only `CXX` and a static link, and refuses to build if the
  makefile has acquired a `-march`/`-mcpu`/`-mtune` of its own.
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
timed numbers stand, and the summary says what was missed. `perf stat` output on
Intel hybrid (P-core + E-core) CPUs, for instance, defeats the harness's
counter parser while the measurements themselves are perfectly good.

Both lists travel in the host manifest and appear in `fleet-summary.json`.

### Gotcha worth knowing

The process-name gate has no expiry, by design — it will not measure next to
another bench. A *stuck* process matching one of the names (0% CPU, never
exiting) therefore blocks that host until the orchestrator's
`host_timeout_minutes` abandons it. The host's `run.log` says exactly which name
it is waiting on. Clear the process, or drop that name from
`quiet_load_process_names` for the run.

## Known limits

- `bundle.build_host` accepts a machine name but only `"local"` is implemented.
  A remote build host is refused at build time with a message telling you to
  build there yourself and use `bundle.source = "prebuilt"`.
- The Windows runner has never been executed (see below).

## Windows hosts

Schema-complete and implemented, but **unvalidated**: no Windows host has run it
yet. The runner uploads a `.ps1` and executes the *file* — PowerShell is never
driven by an inline command string, because quoting a script through
ssh → cmd.exe → powershell truncates it silently. `capabilities.perf` must be
`none`. Treat the first Windows run as bring-up, not evidence. See the TODO at
the top of `internal/fleet/windows.go`.
