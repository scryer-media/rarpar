#!/usr/bin/env python3
"""Tests for ci_changes.py against a synthetic workspace graph.

The graph mirrors the real one's shape: reedsolomon-rs at the bottom,
unrar-rs and par2-rs above it (par2-rs uses unrar-rs in its tests), par3-rs
standing alone, and the rarpar CLI building against a *registry* unrar-rs
rather than the workspace one, as it does between releases.
"""

import pathlib
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import ci_changes  # noqa: E402

ROOT = "/work"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def _pkg(name, version, directory=None):
    if directory is None:
        return {
            "id": f"{REGISTRY}#{name}@{version}",
            "name": name,
            "version": version,
            "source": REGISTRY,
            "manifest_path": f"/registry/{name}-{version}/Cargo.toml",
        }
    return {
        "id": f"path+file://{ROOT}/{directory}#{name}@{version}",
        "name": name,
        "version": version,
        "source": None,
        "manifest_path": f"{ROOT}/{directory}/Cargo.toml",
    }


PACKAGES = {
    "reedsolomon-rs": _pkg("reedsolomon-rs", "0.4.3", "crates/reedsolomon-rs"),
    "unrar-rs": _pkg("unrar-rs", "0.10.0", "crates/unrar-rs"),
    "par2-rs": _pkg("par2-rs", "0.9.1", "crates/par2-rs"),
    "par3-rs": _pkg("par3-rs", "0.1.0", "crates/par3-rs"),
    "rarpar": _pkg("rarpar", "0.4.1", "tools/rarpar"),
    "xtask": _pkg("xtask", "0.4.3", "xtask"),
    "blake3": _pkg("blake3", "1.8.7"),
    "crc-fast": _pkg("crc-fast", "1.6.0"),
    "unrar-rs@registry": _pkg("unrar-rs", "0.9.2"),
}

EDGES = {
    "reedsolomon-rs": [],
    "unrar-rs": ["reedsolomon-rs", "crc-fast"],
    "par2-rs": ["reedsolomon-rs", "unrar-rs", "crc-fast"],
    "par3-rs": ["blake3"],
    "rarpar": ["unrar-rs@registry", "crc-fast"],
    "xtask": ["rarpar"],
    "blake3": [],
    "crc-fast": [],
    "unrar-rs@registry": ["crc-fast"],
}

MEMBERS = ["reedsolomon-rs", "unrar-rs", "par2-rs", "par3-rs", "rarpar", "xtask"]


def metadata(members=MEMBERS):
    return {
        "workspace_root": ROOT,
        "workspace_members": [PACKAGES[m]["id"] for m in members],
        "packages": list(PACKAGES.values()),
        "resolve": {
            "nodes": [
                {"id": PACKAGES[k]["id"], "deps": [{"pkg": PACKAGES[d]["id"]} for d in deps]}
                for k, deps in EDGES.items()
            ]
        },
    }


def lock(**overrides):
    """A lockfile with one entry per package; overrides replace an entry's checksum."""
    entries = []
    for key, pkg in PACKAGES.items():
        block = f'[[package]]\nname = "{pkg["name"]}"\nversion = "{pkg["version"]}"\n'
        if pkg["source"]:
            block += f'source = "{pkg["source"]}"\n'
            block += f'checksum = "{overrides.get(key, "sha-" + key)}"\n'
        entries.append(block)
    return "\n".join(entries)


def affected(result):
    return sorted(name for name in result.members if result.affected(name))


class PathClassification(unittest.TestCase):
    def test_leaf_crate_reaches_only_its_dependents(self):
        result = ci_changes.classify(["crates/unrar-rs/src/lib.rs"], metadata())
        # par2-rs uses the workspace unrar-rs; rarpar builds the registry one.
        self.assertEqual(affected(result), ["par2-rs", "unrar-rs"])
        self.assertIn("depends on `unrar-rs`", result.reasons["par2-rs"])

    def test_standalone_crate_reaches_nobody_else(self):
        result = ci_changes.classify(["crates/par3-rs/src/packet/mod.rs"], metadata())
        self.assertEqual(affected(result), ["par3-rs"])
        outputs = result.outputs()
        self.assertTrue(outputs["par3"])
        self.assertTrue(outputs["crates"])
        self.assertFalse(outputs["unrar"])
        self.assertFalse(outputs["rarpar"])

    def test_bottom_crate_fans_out_through_the_graph(self):
        result = ci_changes.classify(["crates/reedsolomon-rs/src/gf.rs"], metadata())
        self.assertEqual(affected(result), ["par2-rs", "reedsolomon-rs", "unrar-rs"])

    def test_cli_reaches_xtask_only(self):
        result = ci_changes.classify(["tools/rarpar/src/main.rs"], metadata())
        self.assertEqual(affected(result), ["rarpar", "xtask"])
        outputs = result.outputs()
        self.assertFalse(outputs["crates"])
        self.assertTrue(outputs["rust"])

    def test_workflow_and_workspace_files_reach_everyone(self):
        for path in (".github/workflows/ci.yml", "Cargo.toml", "rust-toolchain.toml", ".cargo/config.toml", "xtask/src/corpus.rs", ".github/scripts/ci_changes.py"):
            with self.subTest(path=path):
                result = ci_changes.classify([path], metadata())
                self.assertEqual(affected(result), sorted(MEMBERS))

    def test_corpus_reaches_its_consumers(self):
        result = ci_changes.classify(["test-corpus/manifest.json"], metadata())
        self.assertEqual(affected(result), ["par2-rs", "unrar-rs"])

    def test_docs_reach_the_cli(self):
        result = ci_changes.classify(["docs/usage.md", "README.md"], metadata())
        self.assertEqual(affected(result), ["rarpar", "xtask"])

    def test_unrelated_files_are_ignored_and_reported(self):
        result = ci_changes.classify(["AGENTS.md", ".github/workflows/security.yml", ""], metadata())
        self.assertEqual(affected(result), [])
        self.assertEqual(result.ignored, ["AGENTS.md", ".github/workflows/security.yml"])
        self.assertFalse(result.outputs()["rust"])

    def test_directory_prefix_is_exact(self):
        # `crates/unrar-rs-extra/...` must not be attributed to unrar-rs.
        result = ci_changes.classify(["crates/unrar-rs-extra/src/lib.rs"], metadata())
        self.assertEqual(affected(result), [])


class LockfileClassification(unittest.TestCase):
    def classify_lock(self, old, new):
        return ci_changes.classify(["Cargo.lock"], metadata(), old, new)

    def test_unchanged_lock_reaches_nobody(self):
        self.assertEqual(affected(self.classify_lock(lock(), lock())), [])

    def test_private_dependency_reaches_its_one_user(self):
        result = self.classify_lock(lock(), lock(blake3="sha-new"))
        self.assertEqual(affected(result), ["par3-rs"])
        self.assertIn("`Cargo.lock`: blake3", result.reasons["par3-rs"])

    def test_shared_dependency_reaches_every_user(self):
        result = self.classify_lock(lock(), lock(**{"crc-fast": "sha-new"}))
        self.assertEqual(affected(result), ["par2-rs", "rarpar", "unrar-rs", "xtask"])

    def test_registry_twin_is_not_the_workspace_crate(self):
        # The registry unrar-rs that rarpar builds against was re-hashed; the
        # workspace unrar-rs is untouched and its suite need not run.
        result = self.classify_lock(lock(), lock(**{"unrar-rs@registry": "sha-new"}))
        self.assertEqual(affected(result), ["rarpar", "xtask"])

    def test_added_and_removed_entries(self):
        removed = lock().replace(
            '[[package]]\nname = "blake3"\nversion = "1.8.7"\n'
            f'source = "{REGISTRY}"\nchecksum = "sha-blake3"\n',
            "",
        )
        # blake3 gone from the old lock: it is new in the head lock, par3-rs gets it.
        self.assertEqual(affected(self.classify_lock(removed, lock())), ["par3-rs"])
        # blake3 gone from the new lock: the head's graph no longer resolves
        # it, so its entry reaches nobody (par3-rs, which dropped it, is
        # affected by its manifest edit, not by the lock).
        md = metadata()
        for node in md["resolve"]["nodes"]:
            if node["id"] == PACKAGES["par3-rs"]["id"]:
                node["deps"] = []
        result = ci_changes.classify(["Cargo.lock"], md, lock(), removed)
        self.assertEqual(affected(result), [])

    def test_missing_old_lock_counts_every_entry_as_new(self):
        result = self.classify_lock("", lock())
        self.assertEqual(affected(result), ["par2-rs", "par3-rs", "rarpar", "unrar-rs", "xtask"])


class Outputs(unittest.TestCase):
    def test_declared_outputs_are_always_present(self):
        result = ci_changes.classify(["crates/unrar-rs/src/lib.rs"], metadata(members=[m for m in MEMBERS if m != "par3-rs"]))
        outputs = result.outputs()
        self.assertEqual(set(ci_changes.KNOWN) | {"crates", "rust"}, set(outputs))
        self.assertFalse(outputs["par3"])

    def test_all_marks_everyone(self):
        result = ci_changes.all_true(metadata())
        self.assertEqual(affected(result), sorted(MEMBERS))
        self.assertTrue(all(result.outputs().values()))

    def test_rendering(self):
        rendered = ci_changes.render_outputs({"unrar": True, "par2": False})
        self.assertEqual(rendered, "unrar=true\npar2=false\n")

    def test_summary_lists_reasons_and_ignored_paths(self):
        result = ci_changes.classify(["crates/par2-rs/src/lib.rs", "AGENTS.md"], metadata())
        summary = ci_changes.render_summary(result, result.outputs(), ["crates/par2-rs/src/lib.rs", "AGENTS.md"])
        self.assertIn("| `par2` | `true` | `crates/par2-rs/src/lib.rs` |", summary)
        self.assertIn("| `unrar` | `false` | — |", summary)
        self.assertIn("Changed files affecting no member:\n- `AGENTS.md`", summary)


class CommandLine(unittest.TestCase):
    def test_end_to_end_writes_github_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / "metadata.json").write_text(__import__("json").dumps(metadata()))
            (tmp / "changed.txt").write_text("crates/par3-rs/src/lib.rs\nCargo.lock\n")
            (tmp / "old.lock").write_text(lock())
            (tmp / "new.lock").write_text(lock(**{"crc-fast": "sha-new"}))
            out = tmp / "output.txt"
            summary = tmp / "summary.md"
            rc = ci_changes.main([
                "--changed-files", str(tmp / "changed.txt"),
                "--old-lock", str(tmp / "old.lock"),
                "--new-lock", str(tmp / "new.lock"),
                "--metadata", str(tmp / "metadata.json"),
                "--github-output", str(out),
                "--step-summary", str(summary),
            ])
            self.assertEqual(rc, 0)
            self.assertEqual(
                out.read_text(),
                textwrap.dedent(
                    """\
                    reedsolomon=false
                    unrar=true
                    par2=true
                    par3=true
                    rarpar=true
                    xtask=true
                    crates=true
                    rust=true
                    """
                ),
            )
            self.assertIn("### Change classification", summary.read_text())


if __name__ == "__main__":
    unittest.main()
