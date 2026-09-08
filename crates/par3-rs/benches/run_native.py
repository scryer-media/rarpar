#!/usr/bin/env python3
"""Matched native PAR3 measurements in a newly created, caller-selected directory.

Uses taskset and GNU time on Linux, or native time on macOS without CPU
pinning. Requires a release engine_perf example; pass the pinned reference
for matched comparisons. Without it, only Rust-created sets are exercised,
which supplies no independent interoperability or reference-throughput evidence.
Does not manage services, change CPU policy, or drop system caches. All
generated inputs and output artifacts stay under --output.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import threading
import time


MIB = 1 << 20
CASES = {
    # codec, block bytes, block count, recovery, damaged blocks, interleave, MiB
    "cauchy-gf8": ("cauchy", 256 << 10, 128, 16, 8, 0, 256),
    "cauchy-gf16": ("cauchy", 64 << 10, 512, 32, 16, 0, 256),
    "fft-gf8": ("fft", 256 << 10, 128, 32, 16, 0, 256),
    "fft-gf16": ("fft", 64 << 10, 512, 64, 32, 0, 256),
    "fft-uneven": ("fft", 64 << 10, 515, 63, 30, 2, 256),
    "cauchy-heavy": ("cauchy", 256 << 10, 512, 256, 192, 0, 64),
    "fft-heavy": ("fft", 256 << 10, 512, 256, 192, 0, 64),
    "large-block-small-budget": ("cauchy", 4 << 20, 8, 4, 2, 0, 8),
    "many-small-files": ("cauchy", 64 << 10, 16, 8, 4, 0, 256),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--reference", type=Path, help="pinned reference; omit for Rust-only measurements")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--workers", default="1,4")
    parser.add_argument("--cpus", help="Linux CPU affinity list; default 0,2,4,6")
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    system = platform.system()
    if system not in ("Linux", "Darwin"):
        parser.error("only Linux and macOS measurements are supported")
    if system == "Darwin" and args.cpus is not None:
        parser.error("macOS does not support taskset CPU pinning")
    if system == "Linux" and args.cpus is None:
        args.cpus = "0,2,4,6"
    args.engine = args.engine.resolve(strict=True)
    if args.reference:
        args.reference = args.reference.resolve(strict=True)
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    cpus = args.cpus.split(",") if args.cpus else None
    worker_limit = len(cpus) if cpus else (os.cpu_count() or 1)
    records = []

    def run(label, command, cwd, workers, metadata):
        env = os.environ.copy()
        env.update(OMP_NUM_THREADS=str(workers), OMP_DYNAMIC="FALSE", OMP_THREAD_LIMIT=str(workers))
        log = cwd / (label + ".log")
        rss = cwd / (label + ".resource.json")
        if system == "Linux":
            invocation = ["taskset", "-c", ",".join(cpus[:workers]), "/usr/bin/time", "-f",
                          '{"max_rss_kib":%M,"user_seconds":%U,"system_seconds":%S}',
                          "-o", str(rss), *map(str, command)]
        else:
            invocation = ["/usr/bin/time", "-l", "-p", *map(str, command)]
        start = time.perf_counter()
        with log.open("w") as stream:
            child = subprocess.Popen(invocation, cwd=cwd, env=env, stdout=stream,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            expired = threading.Event()

            def expire():
                if child.poll() is None:
                    expired.set()
                    # Only this invocation's newly created process group.
                    os.killpg(child.pid, signal.SIGKILL)

            timer = threading.Timer(300, expire)
            timer.start()
            try:
                returncode = child.wait()
            finally:
                timer.cancel()
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            if expired.is_set():
                raise subprocess.TimeoutExpired(invocation, 300)
        record = dict(metadata, label=label, wall_seconds=time.perf_counter() - start,
                      exit_code=returncode, command=list(map(str, command)),
                      log=str(log.relative_to(root)), workers=workers,
                      load_average=os.getloadavg(), platform=system,
                      cpu_affinity=cpus[:workers] if cpus else None)
        if system == "Darwin":
            text = log.read_text()
            resident = re.findall(r"^\s*(\d+)\s+maximum resident set size\s*$", text, re.MULTILINE)
            user = re.findall(r"^user\s+([0-9.]+)\s*$", text, re.MULTILINE)
            kernel = re.findall(r"^sys\s+([0-9.]+)\s*$", text, re.MULTILINE)
            if not resident or not user or not kernel:
                raise RuntimeError(f"missing macOS resource measurements: {log}")
            rss.write_text(json.dumps({"max_rss_kib": int(resident[-1]) / 1024,
                                       "user_seconds": float(user[-1]),
                                       "system_seconds": float(kernel[-1])}) + "\n")
        # GNU time emits an extra diagnostic on nonzero exit; retain it in file.
        resource_lines = [s for s in rss.read_text().splitlines() if s.startswith("{")]
        record.update(json.loads(resource_lines[-1]))
        record["engine_metrics"] = [json.loads(s) for s in log.read_text().splitlines() if s.startswith("{")]
        records.append(record)
        with (root / "results.jsonl").open("a") as stream:
            stream.write(json.dumps(record) + "\n")
        print(json.dumps({k: record[k] for k in ("case", "workers", "label", "wall_seconds", "exit_code")}), flush=True)
        if returncode:
            raise RuntimeError(f"{label} failed: {log.read_text()[-3000:]}")
        return record

    for name in args.cases.split(","):
        codec, block, count, recovery, damage, interleave, memory = CASES[name]
        for workers in map(int, args.workers.split(",")):
            if workers < 1 or workers > worker_limit:
                raise ValueError("worker count exceeds available CPUs or affinity list")
            case = root / f"{name}-w{workers}"
            case.mkdir()
            data = case / "original"
            data.mkdir()
            if name == "many-small-files":
                for n in range(256):
                    (data / f"file{n:04}.bin").write_bytes(hashlib.shake_256(f"par3 native benchmark v1 file {n}".encode()).digest(4096))
            else:
                (data / "input.bin").write_bytes(hashlib.shake_256(b"par3 native benchmark v1 input").digest(block * count))
            expected = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in data.glob("*.bin")}
            (case / "input-sha256.json").write_text(json.dumps(expected, indent=2) + "\n")
            settings = dict(case=name, codec=codec, block_size=block, block_count=count,
                            recovery=recovery, damage=damage, interleave=interleave,
                            memory_mib=memory, source_bytes=sum(p.stat().st_size for p in data.glob("*.bin")))
            try:
                for repetition in range(args.repetitions):
                    trial = case / f"trial{repetition}"
                    trial.mkdir()
                    meta = dict(settings, repetition=repetition)
                    rs, ref, scratch = [trial / s for s in ("rust", "reference", "scratch")]
                    for directory in (rs, ref, scratch):
                        directory.mkdir()
                    cap = 1 << (math.ceil(recovery / (interleave + 1)) - 1).bit_length()
                    reference_create = [args.reference, "c", f"-m{memory}M", f"-s{block}",
                                        f"-c{recovery}", f"-e{8 if codec == 'fft' else 1}",
                                        f"-B{data}", ref / "set.par3", *sorted(data.glob("*.bin"))]
                    if codec == "fft":
                        reference_create[2:2] = [f"-cm{cap * (interleave + 1)}", f"-i{interleave}"]
                    commands = [("rust-create", [args.engine, "create", data, rs, scratch, workers, memory, codec, block, recovery, interleave])]
                    if args.reference:
                        commands.append(("reference-create", reference_create))
                    if repetition % 2:
                        commands.reverse()
                    for label, command in commands:
                        run(label, command, trial, workers, meta)
                    # Matched runs use official carriers; standalone runs use Rust output.
                    carriers = ref if args.reference else rs
                    if args.reference:
                        run("reference-verifies-rust", [args.reference, "v", "-S0", f"-m{memory}M", f"-B{data}", rs / "set.par3"], trial, workers, meta)
                    verify_commands = [
                        ("rust-verify", [args.engine, "verify", data, carriers, scratch, workers, memory]),
                    ]
                    if args.reference:
                        verify_commands.append(("reference-verify", [args.reference, "v", "-S0", f"-m{memory}M", f"-B{data}", ref / "set.par3"]))
                    if repetition % 2:
                        verify_commands.reverse()
                    for label, command in verify_commands:
                        run(label, command, trial, workers, meta)
                    run("rust-scan", [args.engine, "scan", data, carriers, scratch, workers, memory], trial, workers, meta)
                    run("rust-reassess", [args.engine, "reassess", data, carriers, scratch, workers, memory], trial, workers, meta)
                    if name != "many-small-files":
                        run("rust-placement", [args.engine, "placement", data, carriers, scratch, workers, memory], trial, workers, meta)
                    damaged = trial / "damaged"
                    shutil.copytree(data, damaged)
                    targets = sorted(damaged.glob("*.bin"))
                    if len(targets) == 1:
                        with targets[0].open("r+b") as stream:
                            for n in range(damage):
                                stream.seek((n * count // damage) * block + 13)
                                value = stream.read(1)
                                stream.seek(-1, 1)
                                stream.write(bytes([value[0] ^ 0x80]))
                    else:
                        for target in targets[:damage * 16]:
                            with target.open("r+b") as stream:
                                value = stream.read(1)
                                stream.seek(0)
                                stream.write(bytes([value[0] ^ 0x80]))
                    ref_damaged = trial / "reference-damaged"
                    if args.reference:
                        shutil.copytree(damaged, ref_damaged)
                    repaired = trial / "repaired"
                    repaired.mkdir()
                    repair_commands = [
                        ("rust-repair", [args.engine, "repair", damaged, carriers, repaired, workers, memory]),
                    ]
                    if args.reference:
                        repair_commands.append(("reference-repair", [args.reference, "r", "-S0", f"-m{memory}M", f"-B{ref_damaged}", ref / "set.par3"]))
                    if repetition % 2:
                        repair_commands.reverse()
                    for label, command in repair_commands:
                        run(label, command, trial, workers, meta)
                    for filename, digest in expected.items():
                        for directory in ((ref_damaged, repaired) if args.reference else (repaired,)):
                            target = directory / filename
                            if directory == repaired and not target.exists():
                                target = damaged / filename  # clean files must remain unstaged
                            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                                raise RuntimeError(f"repair hash mismatch: {target}")
                    if len(targets) > 1 and len(list(repaired.glob("*.bin"))) != damage * 16:
                        raise RuntimeError("clean files were staged during selective repair")
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                (case / "FAILURE.txt").write_text(str(error) + "\n")
                print(f"FAILED {name} w{workers}: {error}", flush=True)
    (root / "run.json").write_text(json.dumps({"cases": args.cases, "repetitions": args.repetitions,
                                                "workers": args.workers, "cpus": args.cpus,
                                                "platform": system, "engine": str(args.engine),
                                                "reference": str(args.reference) if args.reference else None}, indent=2) + "\n")
    if list(root.glob("*/FAILURE.txt")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
