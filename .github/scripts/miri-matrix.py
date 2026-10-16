#!/usr/bin/env python3
"""Turn the live Nextest selections into one Miri job per portable unsafe test.

Usage: miri-matrix.py GITHUB_OUTPUT PACKAGE=LISTING.json [PACKAGE=LISTING.json ...]

Each listing is the JSON from `cargo miri nextest list` for one package, run
with that package's filter (see the `unsafe-miri-plan` job in ci.yml). The
selection is checked against the prefixes each package may contribute and the
tests it must keep, so a renamed module fails discovery instead of quietly
shrinking the lane.
"""

import json
import sys
from pathlib import Path

# Module prefixes each package's filter may select, and tests that must stay
# selected. Keep these in step with the filters in ci.yml and with
# docs/unsafe-validation.md.
POLICY = {
    "unrar-rs": {
        "prefixes": (
            "decompress::lz::window::tests::",
            "decompress::lz::block_reader::tests::",
        ),
        # Exhaustive sweeps too slow to interpret; Memcheck and ASan run them.
        "excluded": ("copy_matrix_matches_reference",),
        "required": {
            "short_match_copy_never_writes_past_the_match",
            "test_copy_overlapping",
            "test_copy_wraps_source_and_dest",
            "narrow_peeks_match_checked_model_at_every_offset",
        },
    },
    "reedsolomon-rs": {
        "prefixes": ("fft::tests::",),
        "required": {
            "row_banks_are_zeroed_aligned_rows",
            "known_zero_steps_at_par3_shapes",
            "transforms_match_direct_polynomial_evaluation_and_round_trip",
        },
    },
}

tests = []
for argument in sys.argv[2:]:
    package, _, path = argument.partition("=")
    policy = POLICY.get(package)
    if policy is None or not path:
        raise SystemExit(f"unknown package or missing listing: {argument!r}")
    listing = json.loads(Path(path).read_text())
    selected = [
        name
        for suite in listing["rust-suites"].values()
        for name, case in suite["testcases"].items()
        if case["filter-match"]["status"] == "matches" and not case["ignored"]
    ]
    names = {name.rsplit("::", 1)[-1] for name in selected}
    if (
        not selected
        or len(selected) != len(set(selected))
        or not policy["required"].issubset(names)
        or any(not name.startswith(policy["prefixes"]) for name in selected)
        or any(word in name for name in selected for word in policy.get("excluded", ()))
    ):
        raise SystemExit(
            f"Miri discovery for {package} lost required unsafe tests "
            "or selected unrelated tests"
        )
    tests.extend({"package": package, "test": name} for name in sorted(selected))
    print(f"{package}: {len(selected)} Miri jobs")

with Path(sys.argv[1]).open("a") as output:
    output.write("matrix=" + json.dumps({"include": tests}) + "\n")
    output.write(f"count={len(tests)}\n")
print(f"Scheduled {len(tests)} separate Miri jobs")
