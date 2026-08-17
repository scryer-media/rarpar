#!/usr/bin/env python3
"""Generate the deterministic large RAR4 PPMd performance corpora.

Two sets come out of here: the 32 MiB order-16 member
(``rar4/rar4_ppm_order16_32m.rar``) and the classic-volume set
(``rar4/rar4_ppm_oldmv.rar`` plus ``.r00``/``.r01``/``.r02``). ``--all`` writes
both at their ledger paths, which is what ``xtask test-corpus generate`` runs.

The writer is RARLAB rar 6.24: current rar releases no longer write RAR4
archives, and 6.24 is the last one that also still has ``-vn`` for classic
volume names. By default it comes from the pinned ``rarpar-bench-rarlab:6.24``
image (bench/rarpar-bench/config/toolchains.json); ``--rar-bin`` (or ``RAR_BIN``)
runs a local 6.24 binary instead, which is how this script was originally
driven.

The generated payload is deterministic and temporary; only the RAR fixtures are
retained.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


PAYLOAD_SIZE = 32 * 1024 * 1024
PAYLOAD_NAME = "ppmd-order16-32m.txt"
FIXED_MTIME = 1_700_000_000
SEED = b"rarpar/unrar-rs deterministic RAR4 PPMd order-16 corpus v1"

FIXTURE_DIR = Path(__file__).resolve().parent
# Image tag as pinned in bench/rarpar-bench/config/toolchains.json.
DEFAULT_IMAGE = "rarpar-bench-rarlab:6.24"

# The classic-volume set: the first 262 144 bytes of the same payload over
# 64 KiB volumes with old-style (.rar/.r00/.r01) names.
OLDMV_PAYLOAD_SIZE = 262_144
OLDMV_PAYLOAD_NAME = "ppmd-oldmv.txt"
OLDMV_VOLUME_SIZE = "64k"

# The grouped-solid set: four deterministic members under `-s2`, so member 2
# is a MID-ARCHIVE RESET POINT (per-file solid flag clear while the archive
# flag is set). This is the shape that distinguishes "solid dispatch picks
# the decoder instance" from "solid drives the reset": the reset must key on
# the per-file flag inside the shared slot, and the group leaders must still
# prime the chain for their group (see member_is_solid in archive/member.rs).
S2_GROUP_MEMBERS = 4
S2_GROUP_MEMBER_SIZE = 524_288
S2_GROUP_PAYLOAD_STEM = "ppmd-s2grp"


def write_payload(path: Path, payload_size: int = PAYLOAD_SIZE) -> str:
    # SHA-256 twice over, and deliberately: the payload stream is base64 over a
    # fixed SHA-256 counter sequence, which is what the checked-in fixture bytes
    # are; and the digest reported for it is the SHA-256 known-answer vector
    # tests/integration.rs pins. The corpus ledger digests the *archives* with
    # BLAKE3; Python has no BLAKE3 in its standard library, and moving either of
    # these would move the fixture or the pinned answer for no gain.
    digest = hashlib.sha256()
    written = 0
    counter = 0
    with path.open("wb") as output:
        while written < payload_size:
            block = hashlib.sha256(SEED + counter.to_bytes(8, "little")).digest()
            encoded = base64.b64encode(block) + b"\n"
            encoded = encoded[: payload_size - written]
            output.write(encoded)
            digest.update(encoded)
            written += len(encoded)
            counter += 1
    os.utime(path, (FIXED_MTIME, FIXED_MTIME))
    return digest.hexdigest()


def require_rar_624(rar_bin: Path) -> None:
    result = subprocess.run(
        [rar_bin],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if "RAR 6.24" not in result.stdout:
        raise SystemExit(f"{rar_bin} is not the required RARLAB rar 6.24")


def rar_arguments(
    archive_name: str,
    payload_name: str,
    volume_size: str | None,
    old_volume_names: bool,
) -> list[str]:
    """The `rar` argument vector, without the executable."""
    command = ["a", "-idq", "-ma4", "-m5", "-mc16:16t+", "-md4m", "-ep", "-o+"]
    if volume_size:
        command.append(f"-v{volume_size}")
    if old_volume_names:
        command.append("-vn")
    command.extend([archive_name, payload_name])
    return command


def build_set(
    run_rar,
    work_dir: Path,
    archive_name: str,
    payload_name: str,
    payload_size: int,
    destination: Path,
    volume_size: str | None = None,
    old_volume_names: bool = False,
) -> tuple[str, list[Path]]:
    """Write one archive set into `destination`'s directory, replacing it."""
    payload = work_dir / payload_name
    payload_sha256 = write_payload(payload, payload_size)
    run_rar(work_dir, rar_arguments(archive_name, payload_name, volume_size, old_volume_names))
    payload.unlink()

    stem = archive_name[: -len(".rar")] if archive_name.endswith(".rar") else archive_name
    produced = sorted(
        path
        for path in work_dir.iterdir()
        if path.is_file() and path.name.startswith(stem)
    )
    if not produced:
        raise SystemExit(f"rar produced no output for {archive_name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    for stale in sorted(destination.parent.glob(f"{stem}.*")):
        stale.unlink()
    written = []
    for path in produced:
        target = destination.parent / path.name
        shutil.copyfile(path, target)
        path.unlink()
        written.append(target)
    return payload_sha256, written


def build_s2_group_set(
    run_rar,
    work_dir: Path,
    destination: Path,
) -> tuple[list[str], list[Path]]:
    """Write the 4-member `-s2` grouped-solid archive at `destination`."""
    payload_names = []
    payload_hashes = []
    for index in range(S2_GROUP_MEMBERS):
        name = f"{S2_GROUP_PAYLOAD_STEM}{index}.txt"
        # Distinct per-member streams: extend the seed with the member index
        # (write_payload hashes SEED || counter; vary the counter start).
        payload = work_dir / name
        digest = hashlib.sha256()
        written = 0
        counter = index * 1_000_000
        with payload.open("wb") as output:
            while written < S2_GROUP_MEMBER_SIZE:
                block = hashlib.sha256(SEED + counter.to_bytes(8, "little")).digest()
                encoded = base64.b64encode(block) + b"\n"
                encoded = encoded[: S2_GROUP_MEMBER_SIZE - written]
                output.write(encoded)
                digest.update(encoded)
                written += len(encoded)
                counter += 1
        os.utime(payload, (FIXED_MTIME, FIXED_MTIME))
        payload_names.append(name)
        payload_hashes.append(digest.hexdigest())

    command = ["a", "-idq", "-ma4", "-m5", "-s2", "-mc16:16t+", "-md4m", "-ep", "-o+"]
    command.append(destination.name)
    command.extend(payload_names)
    run_rar(work_dir, command)
    for name in payload_names:
        (work_dir / name).unlink()

    produced = work_dir / destination.name
    if not produced.is_file():
        raise SystemExit(f"rar produced no output for {destination.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()
    shutil.copyfile(produced, destination)
    produced.unlink()
    return payload_hashes, [destination]


def local_runner(rar_bin: Path):
    def run(work_dir: Path, command: list[str]) -> None:
        subprocess.run([str(rar_bin), *command], cwd=work_dir, check=True)

    return run


def docker_runner(docker: str, image: str):
    def run(work_dir: Path, command: list[str]) -> None:
        subprocess.run(
            [
                docker,
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-v",
                f"{work_dir}:/work",
                "-w",
                "/work",
                image,
                *command,
            ],
            check=True,
        )

    return run


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rar-bin",
        type=Path,
        default=os.environ.get("RAR_BIN"),
        help="path to a local RARLAB rar 6.24 executable (default: the pinned Docker image)",
    )
    parser.add_argument("--docker", default="docker", help="Docker executable")
    parser.add_argument(
        "--image",
        default=DEFAULT_IMAGE,
        help=f"pinned RAR 6.24 image (default: {DEFAULT_IMAGE})",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="write both the order-16 corpus and the classic-volume set at their ledger paths",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=FIXTURE_DIR / "rar4" / "rar4_ppm_order16_32m.rar",
    )
    parser.add_argument("--payload-size", type=int, default=PAYLOAD_SIZE)
    parser.add_argument("--payload-name", default=PAYLOAD_NAME)
    parser.add_argument(
        "--volume-size",
        help="optional RAR volume size such as 64k",
    )
    parser.add_argument(
        "--old-volume-names",
        action="store_true",
        help="use classic .rar/.r00 volume names",
    )
    args = parser.parse_args()

    if args.rar_bin is not None:
        rar_bin = Path(args.rar_bin).resolve()
        require_rar_624(rar_bin)
        run_rar = local_runner(rar_bin)
    else:
        run_rar = docker_runner(args.docker, args.image)

    if args.all:
        with tempfile.TemporaryDirectory() as tmp:
            hashes, written = build_s2_group_set(
                run_rar, Path(tmp), FIXTURE_DIR / "rar4" / "rar4_ppm_s2groups.rar"
            )
        for index, digest in enumerate(hashes):
            print(f"rar4_ppm_s2groups member {index} payload sha256: {digest}")
        for path in written:
            print(f"wrote {path}")
        sets = [
            (
                "rar4_ppm_order16_32m.rar",
                PAYLOAD_NAME,
                PAYLOAD_SIZE,
                FIXTURE_DIR / "rar4" / "rar4_ppm_order16_32m.rar",
                None,
                False,
            ),
            (
                "rar4_ppm_oldmv.rar",
                OLDMV_PAYLOAD_NAME,
                OLDMV_PAYLOAD_SIZE,
                FIXTURE_DIR / "rar4" / "rar4_ppm_oldmv.rar",
                OLDMV_VOLUME_SIZE,
                True,
            ),
        ]
    else:
        output = args.output.resolve()
        sets = [
            (
                output.name,
                args.payload_name,
                args.payload_size,
                output,
                args.volume_size,
                args.old_volume_names,
            )
        ]

    with tempfile.TemporaryDirectory(prefix="rarpar-ppmd-perf-") as temp_dir:
        work_dir = Path(temp_dir)
        for archive_name, payload_name, payload_size, destination, volume_size, old_names in sets:
            payload_sha256, written = build_set(
                run_rar,
                work_dir,
                archive_name,
                payload_name,
                payload_size,
                destination,
                volume_size,
                old_names,
            )
            print(f"payload_size={payload_size}")
            print(f"payload_sha256={payload_sha256}")
            for path in written:
                archive_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                print(f"archive_sha256={archive_sha256}")
                print(f"archive={path}")


if __name__ == "__main__":
    main()
