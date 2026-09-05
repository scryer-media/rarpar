#!/usr/bin/env python3
"""Render ClusterFuzzLite findings as SARIF for GitHub code scanning.

Why this exists instead of `output-sarif: true`
-----------------------------------------------
CIFuzz can write a SARIF file itself, but the one it writes is not a report
of the run. Its batch runner fuzzes every target in turn without stopping at
the first bug, then serialises *one* result: whichever target it walked last
(`infra/cifuzz/run_fuzzers.py`, `run_fuzz_targets`, marked upstream with
"TODO: Handle multiple crashes"). Target order comes from `os.walk`, so which
target that is depends on the filesystem. With five targets in this
repository, a `rar_extract` timeout followed by a clean `par2_verify_repair`
run produces an empty SARIF. Its rule table also has no entry for timeouts or
Rust panics, so those it does report land under a generic "no-crashes" rule.

What CIFuzz does get right is the artifact tree: every reproducible finding is
copied to `<workspace>/out/artifacts/<target>/<sanitizer>/<testcase>` next to a
`<testcase>.summary` holding the full libFuzzer log for that unit, and those
are what the `crashes-<target>` run artifacts contain. This script walks that
tree and emits one SARIF result per testcase, so a night with findings in two
targets reports two findings, and a clean night uploads an empty run, which
is how code scanning learns that an earlier alert is fixed.

No fingerprint is written. Code scanning computes one from rule and location
when the SARIF carries none, and that is the right key here: the same site
found again on the next night through a different input is one alert, while
two timeouts in different loops are two. libFuzzer's own DEDUP_TOKEN is the
wrong key for that; for every timeout it is the alarm handler's three frames,
identical for all of them.

Stdlib only: this runs on the batch runner after the fuzzing container has
exited, and nothing may be installed there.

Usage
-----
    cflite_sarif.py --artifacts out/artifacts --output cflite.sarif \
        [--source-prefix /src/rarpar/] [--summary-path "$GITHUB_STEP_SUMMARY"]

The exit status is 0 whether or not findings exist; the SARIF upload is the
report, and a non-zero status here would only hide it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

TOOL_NAME = "ClusterFuzzLite"
TOOL_URI = "https://google.github.io/clusterfuzzlite/"

# The stack frame format shared by libFuzzer and the sanitizers:
#   #12 0x556f9a660f0a in rar_extract::_::__libfuzzer_sys_run /src/rarpar/crates/unrar-rs/fuzz/fuzz_targets/rar_extract.rs:40:25
# Frames without debug info end in a module+offset instead of a path and do
# not match, which is what we want: they carry no location to report.
_FRAME_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<function>.+?)\s+"
    r"(?P<path>/\S+?):(?P<line>\d+)(?::(?P<column>\d+))?\s*$"
)

# `thread '<unnamed>' panicked at /src/rarpar/crates/unrar-rs/src/decompress/ppmd/model.rs:871:13:`
# Rust prints this before the sanitizer sees the abort, and it names the exact
# site, which is more precise than any frame in the trace that follows.
_PANIC_RE = re.compile(
    r"panicked at (?P<path>\S+?):(?P<line>\d+)(?::(?P<column>\d+))?:?\s*$",
    re.MULTILINE,
)

_TIMEOUT_RE = re.compile(r"ERROR: libFuzzer: timeout after (?P<seconds>\d+) seconds")
# The detail is itself parenthesised, e.g. `(malloc(4194304000))`, so it runs
# to the end of the line rather than to the first closing bracket.
_OOM_RE = re.compile(r"ERROR: libFuzzer: out-of-memory(?: \((?P<detail>.+)\))?\s*$", re.MULTILINE)
_DEADLY_SIGNAL_RE = re.compile(r"ERROR: libFuzzer: deadly signal")
_SANITIZER_RE = re.compile(
    r"ERROR: (?:Address|Memory|Undefined(?:Behavior)?|Leak|Thread)Sanitizer: "
    r"(?P<kind>[A-Za-z][A-Za-z0-9_-]*)"
)
_DEDUP_RE = re.compile(r"^DEDUP_TOKEN:\s*(?P<token>.+?)\s*$", re.MULTILINE)

# Rule ids are the classification the message text reports. Anything the
# sanitizer names that is not listed here is passed through as its own rule
# (e.g. `stack-buffer-overflow`) with a generic description, so a new class
# of finding is never silently folded into an old one.
_RULES = {
    "timeout": {
        "shortDescription": "Fuzz target exceeded the per-unit time limit",
        "fullDescription": (
            "libFuzzer's alarm fired on a single input. In this repository that "
            "has meant an unbounded decode loop or a header scan that stops "
            "making progress; it can also be an arithmetic-overflow panic that "
            "the slower sanitizer build did not reach before the alarm."
        ),
        "level": "error",
    },
    "out-of-memory": {
        "shortDescription": "Fuzz target exceeded the memory limit",
        "fullDescription": (
            "libFuzzer's RSS limit was exceeded on a single input, typically a "
            "declared size that was allocated before being checked against the "
            "bytes actually present."
        ),
        "level": "error",
    },
    "panic": {
        "shortDescription": "Rust panic",
        "fullDescription": (
            "The fuzz target panicked. The fuzzers build with debug assertions "
            "and overflow checks on, so this includes arithmetic overflow that "
            "a release build would wrap silently."
        ),
        "level": "error",
    },
    "deadly-signal": {
        "shortDescription": "Fuzz target aborted",
        "fullDescription": (
            "The process died on a signal without a sanitizer report or a Rust "
            "panic message; the full log is in the run's crashes artifact."
        ),
        "level": "error",
    },
    "crash": {
        "shortDescription": "Unclassified fuzzing failure",
        "fullDescription": (
            "A reproducer was saved but the summary matched no known failure "
            "signature; read the log in the run's crashes artifact."
        ),
        "level": "error",
    },
}


@dataclass
class Location:
    path: str
    line: int
    column: Optional[int] = None


@dataclass
class Finding:
    target: str
    sanitizer: str
    testcase: str
    rule_id: str
    detail: str
    location: Optional[Location]
    dedup_token: Optional[str]
    frames: list[str] = field(default_factory=list)


def _relativise(path: str, source_prefix: str) -> Optional[str]:
    """Map a container path to a repo-relative one, or None if it is not ours.

    Paths under the source prefix are the checkout; anything else (the
    libFuzzer runtime under /src/llvm-project, registry crates under /rust,
    the toolchain under /rustc) is not a location code scanning can show.
    """
    if not path.startswith(source_prefix):
        return None
    rel = path[len(source_prefix):].lstrip("/")
    return rel or None


def classify(summary: str) -> tuple[str, str]:
    """Return (rule_id, detail) for one libFuzzer unit log."""
    match = _TIMEOUT_RE.search(summary)
    if match:
        return "timeout", f"timeout after {match.group('seconds')} s"
    match = _OOM_RE.search(summary)
    if match:
        detail = match.group("detail")
        return "out-of-memory", f"out-of-memory ({detail})" if detail else "out-of-memory"
    match = _SANITIZER_RE.search(summary)
    if match:
        kind = match.group("kind").lower()
        return kind, kind
    panic = _PANIC_RE.search(summary)
    if panic:
        return "panic", f"panic at {panic.group('path')}:{panic.group('line')}"
    if _DEADLY_SIGNAL_RE.search(summary):
        return "deadly-signal", "deadly signal"
    return "crash", "unclassified"


def locate(summary: str, source_prefix: str) -> tuple[Optional[Location], list[str]]:
    """Pick the location to report and the project frames that justify it.

    A panic message names the exact site, so it wins. Otherwise the innermost
    frame with a path inside the checkout is used: for a timeout that is the
    deepest project function the sampler could symbolise, which is the loop
    that did not terminate or its nearest caller.
    """
    project_frames: list[str] = []
    innermost: Optional[Location] = None
    for line in summary.splitlines():
        frame = _FRAME_RE.match(line)
        if not frame:
            continue
        rel = _relativise(frame.group("path"), source_prefix)
        if rel is None:
            continue
        project_frames.append(f"{frame.group('function')} {rel}:{frame.group('line')}")
        if innermost is None:
            column = frame.group("column")
            innermost = Location(rel, int(frame.group("line")), int(column) if column else None)

    panic = _PANIC_RE.search(summary)
    if panic:
        rel = _relativise(panic.group("path"), source_prefix)
        if rel is not None:
            column = panic.group("column")
            return Location(rel, int(panic.group("line")), int(column) if column else None), project_frames

    return innermost, project_frames


def read_findings(artifacts: Path, source_prefix: str) -> list[Finding]:
    """Walk <artifacts>/<target>/<sanitizer>/<testcase>[.summary]."""
    findings: list[Finding] = []
    if not artifacts.is_dir():
        return findings
    for target_dir in sorted(p for p in artifacts.iterdir() if p.is_dir()):
        for sanitizer_dir in sorted(p for p in target_dir.iterdir() if p.is_dir()):
            for testcase in sorted(p for p in sanitizer_dir.iterdir() if p.is_file()):
                if testcase.suffix == ".summary":
                    continue
                summary_path = testcase.with_name(testcase.name + ".summary")
                summary = summary_path.read_text(errors="replace") if summary_path.is_file() else ""
                rule_id, detail = classify(summary)
                location, frames = locate(summary, source_prefix)
                dedup = _DEDUP_RE.search(summary)
                findings.append(
                    Finding(
                        target=target_dir.name,
                        sanitizer=sanitizer_dir.name,
                        testcase=testcase.name,
                        rule_id=rule_id,
                        detail=detail,
                        location=location,
                        dedup_token=dedup.group("token") if dedup else None,
                        frames=frames,
                    )
                )
    return findings


def _rule(rule_id: str) -> dict:
    spec = _RULES.get(
        rule_id,
        {
            "shortDescription": f"Sanitizer report: {rule_id}",
            "fullDescription": (
                f"The sanitizer reported `{rule_id}`; the full report is in the "
                "run's crashes artifact."
            ),
            "level": "error",
        },
    )
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": spec["shortDescription"]},
        "fullDescription": {"text": spec["fullDescription"]},
        "helpUri": TOOL_URI,
        "defaultConfiguration": {"level": spec["level"]},
        "properties": {"tags": ["fuzzing", "security"]},
    }


def _message(finding: Finding) -> str:
    lines = [
        f"`{finding.target}` ({finding.sanitizer}): {finding.detail}.",
        f"Reproducer `{finding.testcase}` is in this run's `crashes-{finding.target}` "
        "artifact alongside the full libFuzzer log.",
    ]
    if finding.frames:
        shown = finding.frames[:6]
        lines.append("Project frames, innermost first: " + "; ".join(shown) + ".")
    return " ".join(lines)


def build_sarif(findings: Iterable[Finding], run_url: Optional[str] = None) -> dict:
    findings = list(findings)
    rules: dict[str, dict] = {}
    results = []
    for finding in findings:
        rules.setdefault(finding.rule_id, _rule(finding.rule_id))
        rule_index = list(rules).index(finding.rule_id)
        location = finding.location or Location(".clusterfuzzlite/build.sh", 1)
        region = {"startLine": location.line}
        if location.column:
            region["startColumn"] = location.column
        result = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index,
            "level": rules[finding.rule_id]["defaultConfiguration"]["level"],
            "message": {"text": _message(finding)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location.path, "uriBaseId": "%SRCROOT%"},
                        "region": region,
                    }
                }
            ],
            "properties": {
                "fuzzTarget": finding.target,
                "sanitizer": finding.sanitizer,
                "testcase": finding.testcase,
            },
        }
        if finding.dedup_token:
            result["properties"]["dedupToken"] = finding.dedup_token
        results.append(result)

    run = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "informationUri": TOOL_URI,
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "columnKind": "utf16CodeUnits",
    }
    if run_url:
        run["properties"] = {"runUrl": run_url}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def render_step_summary(findings: list[Finding]) -> str:
    if not findings:
        return "### ClusterFuzzLite findings\n\nNone: every target ran to its budget without a reportable unit.\n"
    rows = ["### ClusterFuzzLite findings", "", "| Target | Kind | Location | Reproducer |", "|---|---|---|---|"]
    for f in findings:
        where = f"`{f.location.path}:{f.location.line}`" if f.location else "(no project frame)"
        rows.append(f"| `{f.target}` | {f.detail} | {where} | `{f.testcase}` |")
    rows.append("")
    rows.append("Reproducers and full logs are in the `crashes-<target>` artifacts of this run.")
    return "\n".join(rows) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifacts", type=Path, default=Path("out/artifacts"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-prefix",
        default="/src/rarpar/",
        help="path of the checkout inside the fuzzing container; frames under it become repo-relative",
    )
    parser.add_argument("--run-url", default=None)
    parser.add_argument("--summary-path", type=Path, default=None, help="append a Markdown table here (GITHUB_STEP_SUMMARY)")
    args = parser.parse_args(argv)

    findings = read_findings(args.artifacts, args.source_prefix)
    sarif = build_sarif(findings, run_url=args.run_url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(sarif, indent=2) + "\n")

    summary = render_step_summary(findings)
    print(summary, end="")
    if args.summary_path:
        with args.summary_path.open("a") as handle:
            handle.write(summary)
    print(f"wrote {len(findings)} finding(s) to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
