#!/usr/bin/env python3
"""Decide which workspace members a change can affect, for CI lane gating.

Why this is a script and not a `case` statement
-----------------------------------------------
The `changes` job used to sort paths into two buckets, "crates" and "rarpar",
and every library lane keyed on the first. A one-line fix in one crate then
paid for the complete unrar-rs suite, the par2-rs suite, both wasm harnesses
and the platform matrix, none of which could observe it. Two buckets were also
the wrong shape once the workspace held crates that do not depend on each
other: a change to one of them cannot break the other, and the lanes should
know that.

The right unit is the workspace member, and the right question is "which
members' *build inputs* changed". That is decided from three sources:

1. Paths. A file under a member's manifest directory is that member's. A
   handful of repository-level files are mapped explicitly below: the CI
   workflow itself, the workspace manifest and toolchain pin affect everyone;
   the corpus manifest affects the crates that hydrate it; and so on.
2. `Cargo.lock`. A lockfile diff is resolved to package names, and a member is
   affected when one of those packages is in its transitive dependency set as
   `cargo metadata` reports it (all dependency kinds, all targets — tests and
   build scripts are inputs too). A bump of a dependency two crates share
   reaches both; a bump of one only a single crate uses reaches that crate.
3. Fan-out. A member is affected when any workspace member in its dependency
   set is: rarpar rebuilds when unrar-rs changes, and so does par2-rs, whose
   tests use unrar-rs. This is the same closure as item 2, so the two agree
   by construction.

Everything not matched by a rule is ignored: a Markdown file outside the
documented locations changes nothing that Rust compiles.

The output is one boolean per member, named without the `-rs` suffix
(`unrar`, `par2`, ...), plus two aggregates the workflow keys its shared lanes
on: `crates` (any publishable library crate under `crates/`) and `rust` (any
member at all). The set of names the workflow declares is fixed (`KNOWN`), so
a crate that does not exist on this branch still yields `false` rather than
an undefined output.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import pathlib
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

# Output names the workflow declares. Members outside this list still get an
# output, but the workflow has no lane for them; the summary says so.
KNOWN = ("reedsolomon", "unrar", "par2", "par3", "rarpar", "xtask")

# Repository-level paths that are nobody's manifest directory. Globs are
# matched with fnmatch against the repository-relative path, where `*` also
# crosses `/` (everything under a directory is that directory's).
#
# ALL: inputs to every build. The workflow itself is here because a change to
# the lanes has to be exercised by the lanes; xtask is here because every lane
# hydrates the corpus through it, so a broken xtask breaks lanes that do not
# otherwise depend on it.
GLOBAL_PATHS = (
    ".github/workflows/ci.yml",
    ".github/scripts/*",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".cargo/*",
    "xtask/*",
)

# Paths that reach a named set of members. Names are member package names.
# `LIBRARY_CRATES` is expanded at classification time to every member whose
# manifest lives under `crates/`.
LIBRARY_CRATES = "<library crates>"
PATH_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # The corpus manifest, lock and its publish workflow: consumed by the
    # crates whose fixture suites hydrate from it. The rarpar CLI suite does
    # too, but reaches it through fan-out from these.
    ("test-corpus/*", ("unrar-rs", "par2-rs")),
    (".github/workflows/test-corpus-publish.yml", ("unrar-rs", "par2-rs")),
    # Packaging inputs: the package-content lane keys on `crates`.
    (".github/workflows/publish-crates.yml", (LIBRARY_CRATES,)),
    (".gitattributes", (LIBRARY_CRATES,)),
    (".gitleaks.toml", (LIBRARY_CRATES,)),
    (".githooks/*", (LIBRARY_CRATES,)),
    # The CLI's own release, docs and benchmark surfaces.
    (".github/workflows/release.yml", ("rarpar",)),
    ("README.md", ("rarpar",)),
    ("docs/*", ("rarpar",)),
    ("bench/rarpar-bench/*", ("rarpar",)),
)

LOCKFILE = "Cargo.lock"


@dataclass
class Member:
    name: str
    id: str
    directory: str  # repository-relative manifest directory, no trailing slash
    closure: frozenset[str] = field(default_factory=frozenset)  # package ids

    @property
    def output_name(self) -> str:
        return self.name[: -len("-rs")] if self.name.endswith("-rs") else self.name

    @property
    def is_library_crate(self) -> bool:
        return self.directory.startswith("crates/")


@dataclass
class Classification:
    # member name -> reasons it is affected (empty set: not affected)
    reasons: dict[str, set[str]]
    ignored: list[str]
    members: dict[str, Member]

    def affected(self, name: str) -> bool:
        return bool(self.reasons.get(name))

    def outputs(self) -> dict[str, bool]:
        out = {name: False for name in KNOWN}
        for member in self.members.values():
            out[member.output_name] = self.affected(member.name)
        out["crates"] = any(
            self.affected(m.name) for m in self.members.values() if m.is_library_crate
        )
        out["rust"] = any(self.affected(m.name) for m in self.members.values())
        return out


def load_members(metadata: Mapping) -> dict[str, Member]:
    root = pathlib.PurePosixPath(metadata["workspace_root"])
    by_id = {pkg["id"]: pkg for pkg in metadata["packages"]}
    members: dict[str, Member] = {}
    for member_id in metadata["workspace_members"]:
        pkg = by_id[member_id]
        manifest = pathlib.PurePosixPath(pkg["manifest_path"])
        directory = manifest.parent.relative_to(root).as_posix()
        members[pkg["name"]] = Member(pkg["name"], member_id, directory)

    edges: dict[str, list[str]] = {
        node["id"]: [dep["pkg"] for dep in node.get("deps", [])]
        for node in metadata["resolve"]["nodes"]
    }
    for member in members.values():
        seen = {member.id}
        stack = [member.id]
        while stack:
            for dep in edges.get(stack.pop(), []):
                if dep not in seen:
                    seen.add(dep)
                    stack.append(dep)
        member.closure = frozenset(seen)
    return members


LockEntry = tuple[str, str, str | None]  # (name, version, source); path packages have no source


def lock_packages(text: str) -> dict[LockEntry, str | None]:
    """Every `[[package]]` entry of a lockfile, keyed by identity, valued by checksum."""
    if not text:
        return {}
    data = tomllib.loads(text)
    return {
        (p["name"], p["version"], p.get("source")): p.get("checksum")
        for p in data.get("package", [])
    }


def changed_lock_entries(old_lock: str, new_lock: str) -> set[LockEntry]:
    """Lock entries added, removed, or re-hashed between the two lockfiles.

    Identity carries the source on purpose: the workspace's own `par2-rs` and
    the registry `par2-rs` that `rarpar` may build against are different
    packages with the same name and version, and a change to one is not a
    change to the other. A removed entry is reported too; nothing depends on
    it any more, so it reaches nobody — right, since the member that dropped
    it changed its manifest and is affected by path.
    """
    old, new = lock_packages(old_lock), lock_packages(new_lock)
    return {
        key for key in old.keys() | new.keys()
        if key not in old or key not in new or old[key] != new[key]
    }


def _matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/*"):
        return path.startswith(pattern[:-1])
    return fnmatch.fnmatchcase(path, pattern)


def classify(
    changed_files: Iterable[str],
    metadata: Mapping,
    old_lock: str = "",
    new_lock: str = "",
) -> Classification:
    members = load_members(metadata)
    by_id = {m.id: m for m in members.values()}
    library = [m.name for m in members.values() if m.is_library_crate]
    reasons: dict[str, set[str]] = {name: set() for name in members}
    ignored: list[str] = []

    def hit(names: Iterable[str], reason: str) -> None:
        for name in names:
            if name == LIBRARY_CRATES:
                hit(library, reason)
            elif name in reasons:
                reasons[name].add(reason)
            else:
                raise SystemExit(f"path rule names unknown member {name!r}")

    lock_changed = False
    for path in changed_files:
        path = path.strip()
        if not path:
            continue
        matched = False
        if any(_matches(path, g) for g in GLOBAL_PATHS):
            hit(members.keys(), f"global input `{path}`")
            matched = True
        for member in members.values():
            if path.startswith(member.directory + "/"):
                hit([member.name], f"`{path}`")
                matched = True
        for pattern, names in PATH_RULES:
            if _matches(path, pattern):
                hit(names, f"`{path}`")
                matched = True
        if path == LOCKFILE:
            lock_changed = True
            matched = True
        if not matched:
            ignored.append(path)

    if lock_changed:
        changed = changed_lock_entries(old_lock, new_lock)
        identity = {
            pkg["id"]: (pkg["name"], pkg["version"], pkg.get("source"))
            for pkg in metadata["packages"]
        }
        for member in members.values():
            hits = sorted(
                {
                    identity[pid][0]
                    for pid in member.closure
                    if pid != member.id and identity[pid] in changed
                }
            )
            if hits:
                reasons[member.name].add(f"`{LOCKFILE}`: {', '.join(hits)}")
        # A lockfile edit that resolves nothing differently (cargo rewrites
        # the file on a format bump) reaches nobody, which is right.

    # Fan-out: a member is affected when any member in its closure is. One
    # pass suffices because closures are transitive.
    direct = {name for name, why in reasons.items() if why}
    for member in members.values():
        for pid in member.closure:
            dep = by_id.get(pid)
            if dep is not None and dep.name != member.name and dep.name in direct:
                reasons[member.name].add(f"depends on `{dep.name}`")

    return Classification(reasons, ignored, members)


def render_outputs(outputs: Mapping[str, bool]) -> str:
    return "".join(f"{key}={'true' if value else 'false'}\n" for key, value in outputs.items())


def render_summary(result: Classification, outputs: Mapping[str, bool], changed: list[str]) -> str:
    lines = ["### Change classification", "", "| output | value | why |", "| --- | --- | --- |"]
    for member in result.members.values():
        why = "; ".join(sorted(result.reasons[member.name])) or "—"
        lines.append(f"| `{member.output_name}` | `{str(result.affected(member.name)).lower()}` | {why} |")
    for key in ("crates", "rust"):
        lines.append(f"| `{key}` | `{str(outputs[key]).lower()}` | aggregate |")
    unknown = [m.output_name for m in result.members.values() if m.output_name not in KNOWN]
    if unknown:
        lines += ["", f"Members with no declared lane: {', '.join(f'`{u}`' for u in unknown)}"]
    if result.ignored:
        lines += ["", "Changed files affecting no member:"]
        lines += [f"- `{p}`" for p in result.ignored]
    lines += ["", "Changed files:"] + [f"- `{p}`" for p in changed]
    return "\n".join(lines) + "\n"


def all_true(metadata: Mapping) -> Classification:
    members = load_members(metadata)
    return Classification({name: {"manual run"} for name in members}, [], members)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--changed-files", type=pathlib.Path, help="one repository-relative path per line")
    parser.add_argument("--old-lock", type=pathlib.Path, help="Cargo.lock at the comparison base (may be missing)")
    parser.add_argument("--new-lock", type=pathlib.Path, help="Cargo.lock at the compared head (default: ./Cargo.lock)")
    parser.add_argument("--metadata", type=pathlib.Path, help="`cargo metadata --all-features --format-version 1` output; runs cargo when omitted")
    parser.add_argument("--all", action="store_true", help="mark every member affected (manual runs)")
    parser.add_argument("--github-output", type=pathlib.Path)
    parser.add_argument("--step-summary", type=pathlib.Path)
    args = parser.parse_args(argv)

    if args.metadata:
        metadata = json.loads(args.metadata.read_text())
    else:
        metadata = json.loads(
            subprocess.check_output(["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"])
        )

    if args.all:
        changed: list[str] = []
        result = all_true(metadata)
    else:
        if args.changed_files is None:
            parser.error("--changed-files is required without --all")
        changed = [line.strip() for line in args.changed_files.read_text().splitlines() if line.strip()]
        old_lock = args.old_lock.read_text() if args.old_lock and args.old_lock.exists() else ""
        new_path = args.new_lock or pathlib.Path(LOCKFILE)
        new_lock = new_path.read_text() if new_path.exists() else ""
        result = classify(changed, metadata, old_lock, new_lock)

    outputs = result.outputs()
    rendered = render_outputs(outputs)
    summary = render_summary(result, outputs, changed)
    if args.github_output:
        with args.github_output.open("a") as fh:
            fh.write(rendered)
    if args.step_summary:
        with args.step_summary.open("a") as fh:
            fh.write(summary)
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
