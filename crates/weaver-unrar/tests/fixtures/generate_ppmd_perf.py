#!/usr/bin/env python3
"""Generate the deterministic large RAR4 PPMd performance fixture.

Requires the RARLAB rar 6.24 executable because current rar releases no longer
write RAR4 archives. The generated payload is temporary; only the RAR fixture
is retained in Git LFS.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


PAYLOAD_SIZE = 32 * 1024 * 1024
PAYLOAD_NAME = "ppmd-order16-32m.txt"
FIXED_MTIME = 1_700_000_000
SEED = b"rarpar/unrar-rs deterministic RAR4 PPMd order-16 corpus v1"


def write_payload(path: Path) -> str:
    digest = hashlib.sha256()
    written = 0
    counter = 0
    with path.open("wb") as output:
        while written < PAYLOAD_SIZE:
            block = hashlib.sha256(SEED + counter.to_bytes(8, "little")).digest()
            encoded = base64.b64encode(block) + b"\n"
            encoded = encoded[: PAYLOAD_SIZE - written]
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rar-bin",
        type=Path,
        default=os.environ.get("RAR_BIN"),
        required="RAR_BIN" not in os.environ,
        help="path to the RARLAB rar 6.24 executable (or set RAR_BIN)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parent / "rar4" / "rar4_ppm_order16_32m.rar",
    )
    args = parser.parse_args()
    rar_bin = args.rar_bin.resolve()
    output = args.output.resolve()
    require_rar_624(rar_bin)
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="rarpar-ppmd-perf-") as temp_dir:
        payload = Path(temp_dir) / PAYLOAD_NAME
        payload_sha256 = write_payload(payload)
        output.unlink(missing_ok=True)
        subprocess.run(
            [
                rar_bin,
                "a",
                "-idq",
                "-ma4",
                "-m5",
                "-mc16:16t+",
                "-md4m",
                "-ep",
                "-o+",
                output,
                payload,
            ],
            check=True,
        )

    archive_sha256 = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"payload_size={PAYLOAD_SIZE}")
    print(f"payload_sha256={payload_sha256}")
    print(f"archive_sha256={archive_sha256}")
    print(f"archive={output}")


if __name__ == "__main__":
    main()
