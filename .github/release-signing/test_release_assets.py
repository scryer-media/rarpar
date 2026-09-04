"""Offline release policy tests. External verifiers and GitHub are mocked."""

import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_assets as release


TAG = "rarpar-v1.2.3"
REPO = "scryer-media/rarpar"
COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parents[2]


class AssetsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "build"
        self.assets = self.root / "assets"
        self.source.mkdir()
        for i, name in enumerate(release.archives(TAG)):
            platform = self.source / str(i)
            platform.mkdir()
            (platform / name).write_bytes(name.encode())
            (platform / "build.log").write_text("build log")
        release.collect(self.source, self.assets, TAG)
        (self.assets / release.BUNDLE).write_text("mock signature bundle")
        (self.assets / release.PROVENANCE).write_text("mock signed provenance")
        expected = release.validate_files(self.assets, TAG)
        uri = f"git+https://github.com/{REPO}@refs/tags/{TAG}"
        self.statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [{"name": n, "digest": {"sha256": h}} for n, h in expected.items()],
            "predicate": {
                "builder": {"id": release.BUILDER},
                "invocation": {"configSource": {
                    "uri": uri, "entryPoint": release.WORKFLOW, "digest": {"sha1": COMMIT},
                }},
                "materials": [{"uri": uri, "digest": {"sha1": COMMIT}}],
            },
        }
        self.calls = []

    def verifier(self, *args):
        self.calls.append(args)
        if args[0] == "cosign":
            self.assertEqual(args[args.index("--certificate-identity") + 1],
                             f"https://github.com/{REPO}/{release.WORKFLOW}@refs/tags/{TAG}")
            self.assertEqual(args[args.index("--certificate-oidc-issuer") + 1],
                             "https://token.actions.githubusercontent.com")
            self.assertIn("--new-bundle-format=true", args)
            return ""
        self.assertEqual(args[:2], ("slsa-verifier", "verify-artifact"))
        self.assertEqual(args[2:10], tuple(str(self.assets / n) for n in release.archives(TAG)))
        self.assertEqual(args[args.index("--builder-id") + 1], release.BUILDER)
        self.assertEqual(args[args.index("--source-uri") + 1], f"github.com/{REPO}")
        self.assertEqual(args[args.index("--source-tag") + 1], TAG)
        return (json.dumps(self.statement) + "\n") * 8

    def verify(self):
        with patch.object(release, "run", side_effect=self.verifier):
            release.verify(self.assets, REPO, TAG, COMMIT)

    def test_complete_set_and_all_verifier_arguments(self):
        self.verify()
        self.assertEqual(len(self.calls), 2)

    def test_collect_missing_duplicate_and_unexpected(self):
        first = next(self.source.rglob("*.tar.gz"))
        for kind in ("missing", "duplicate", "unexpected"):
            with self.subTest(kind=kind):
                source = self.root / kind
                shutil.copytree(self.source, source)
                if kind == "missing":
                    (source / first.relative_to(self.source)).unlink()
                else:
                    shutil.copy(first, source / (first.name if kind == "duplicate" else "extra.zip"))
                with self.assertRaises(ValueError):
                    release.collect(source, self.root / (kind + "-out"), TAG)

    def test_reject_symlink(self):
        (self.source / "alias.zip").symlink_to(next(self.source.rglob("*.tar.gz")))
        with self.assertRaises(ValueError):
            release.collect(self.source, self.root / "out", TAG)

    def test_tampered_archive(self):
        (self.assets / release.archives(TAG)[0]).write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()
        self.assertFalse(self.calls)

    def test_missing_or_extra_asset(self):
        for name in release.asset_names(TAG):
            with self.subTest(name=name):
                path = self.assets / name
                data = path.read_bytes()
                path.unlink()
                with self.assertRaises(ValueError):
                    self.verify()
                path.write_bytes(data)
        (self.assets / "extra.zip").write_bytes(b"unexpected")
        with self.assertRaises(ValueError):
            self.verify()

    def test_malformed_checksum_manifests(self):
        path = self.assets / release.CHECKSUMS
        original = path.read_bytes()
        for bad in (original + original, original.replace(b"  rarpar", b"  ../rarpar"),
                    b"not checksums", b"", original.replace(b"\n", b"\r\n")):
            with self.subTest(bad=bad[:30]):
                path.write_bytes(bad)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_wrong_provenance_policy(self):
        original = copy.deepcopy(self.statement)
        mutations = [
            lambda s: s["subject"].pop(),
            lambda s: s["subject"].append(s["subject"][0]),
            lambda s: s["subject"][0].update(name="extra.zip"),
            lambda s: s["subject"][0]["digest"].update(sha256="0" * 64),
            lambda s: s["predicate"]["builder"].update(id="untrusted"),
            lambda s: s["predicate"]["invocation"]["configSource"].update(uri="git+https://github.com/other/repo@refs/tags/" + TAG),
            lambda s: s["predicate"]["invocation"]["configSource"].update(uri=f"git+https://github.com/{REPO}@refs/tags/rarpar-v1.2.4"),
            lambda s: s["predicate"]["invocation"]["configSource"].update(digest={"sha1": "b" * 40}),
            lambda s: s["predicate"]["invocation"]["configSource"].update(entryPoint="other.yml"),
            lambda s: s["predicate"].update(materials=[]),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.statement = copy.deepcopy(original)
                mutate(self.statement)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_crypto_failures_stop_verification(self):
        for tool in ("cosign", "slsa-verifier"):
            with self.subTest(tool=tool):
                def failing(*args):
                    if args[0] == tool:
                        raise subprocess.CalledProcessError(1, args)
                    return self.verifier(*args)
                with patch.object(release, "run", side_effect=failing):
                    with self.assertRaises(subprocess.CalledProcessError):
                        release.verify(self.assets, REPO, TAG, COMMIT)

    def test_empty_verified_output_rejected(self):
        with patch.object(release, "run", return_value=""):
            with self.assertRaises(ValueError):
                release.verify(self.assets, REPO, TAG, COMMIT)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        AssetsTests.setUp(self)
        self.remote = None
        self.remote_files = {}
        self.gh_calls = []
        self.verifications = []
        self.bad_download = False
        self.addCleanup(patch.stopall)
        patch.object(release, "release_metadata", side_effect=lambda *_: copy.deepcopy(self.remote)).start()
        patch.object(release, "run", side_effect=self.gh).start()
        patch.object(release, "verify", side_effect=self.check_assets).start()

    # These tests isolate publication control; AssetsTests covers the verifier.
    def check_assets(self, directory, repository, tag, commit):
        self.verifications.append(directory)
        release.validate_files(directory, tag)

    def gh(self, *args):
        self.gh_calls.append(args)
        self.assertEqual(args[:2], ("gh", "release"))
        command = args[2]
        if command == "create":
            self.assertIn("--draft", args)
            self.assertIn("--verify-tag", args)
            self.remote = {"tag_name": TAG, "draft": True, "assets": []}
        elif command == "upload":
            self.assertTrue(self.remote["draft"])
            self.assertTrue(self.verifications)
            for name in release.asset_names(TAG):
                self.remote_files[name] = (self.assets / name).read_bytes()
            self.remote["assets"] = [{"name": n} for n in self.remote_files]
        elif command == "download":
            destination = Path(args[args.index("--dir") + 1])
            for name, data in self.remote_files.items():
                (destination / name).write_bytes(data)
            if self.bad_download:
                (destination / release.archives(TAG)[0]).write_bytes(b"tampered")
        elif command == "delete-asset":
            self.assertTrue(self.remote["draft"])
            del self.remote_files[args[4]]
        elif command == "edit":
            self.assertIn("--draft=false", args)
            self.assertGreaterEqual(len(self.verifications), 2)
            self.remote["draft"] = False
        else:
            self.fail(f"unexpected GitHub command {args}")
        return ""

    def seed(self, draft):
        self.remote_files = {n: (self.assets / n).read_bytes() for n in release.asset_names(TAG)}
        self.remote = {"tag_name": TAG, "draft": draft,
                       "assets": [{"name": n} for n in self.remote_files]}

    def test_new_release_verifies_download_before_publishing(self):
        self.assertTrue(release.finalize(self.assets, REPO, TAG, COMMIT))
        self.assertEqual([c[2] for c in self.gh_calls], ["create", "upload", "download", "edit"])

    def test_failed_download_verification_leaves_draft(self):
        self.bad_download = True
        with self.assertRaises(ValueError):
            release.finalize(self.assets, REPO, TAG, COMMIT)
        self.assertTrue(self.remote["draft"])
        self.assertNotIn("edit", [c[2] for c in self.gh_calls])

    def test_failed_local_verification_cannot_mutate(self):
        with patch.object(release, "verify", side_effect=ValueError("invalid signature")):
            with self.assertRaises(ValueError):
                release.finalize(self.assets, REPO, TAG, COMMIT)
        self.assertFalse(self.gh_calls)

    def test_retry_repairs_incomplete_draft(self):
        self.seed(True)
        del self.remote_files[release.BUNDLE]
        self.remote_files["obsolete.zip"] = b"old"
        self.remote["assets"] = [{"name": n} for n in self.remote_files]
        self.assertTrue(release.finalize(self.assets, REPO, TAG, COMMIT))
        self.assertEqual([c[2] for c in self.gh_calls], ["delete-asset", "upload", "download", "edit"])

    def test_published_release_is_only_read_even_if_rebuild_differs(self):
        self.seed(False)
        (self.assets / release.archives(TAG)[0]).write_bytes(b"different rebuild")
        self.assertFalse(release.finalize(self.assets, REPO, TAG, COMMIT))
        self.assertEqual([c[2] for c in self.gh_calls], ["download"])

    def test_incomplete_published_release_is_never_repaired(self):
        self.seed(False)
        self.remote["assets"].pop()
        with self.assertRaises(ValueError):
            release.finalize(self.assets, REPO, TAG, COMMIT)
        self.assertFalse(self.gh_calls)


class MetadataTests(unittest.TestCase):
    def test_explicit_null_release_means_missing(self):
        response = json.dumps({"data": {"repository": {"release": None}}})
        with patch.object(release, "run", return_value=response):
            self.assertIsNone(release.release_metadata(REPO, TAG))

    def test_drafts_and_published_releases_are_loaded_by_id(self):
        for draft in (True, False):
            responses = [json.dumps({"data": {"repository": {"release": {"databaseId": 42}}}}),
                         json.dumps({"tag_name": TAG, "draft": draft, "assets": []})]
            with self.subTest(draft=draft), patch.object(release, "run", side_effect=responses) as mock:
                self.assertEqual(release.release_metadata(REPO, TAG)["draft"], draft)
                self.assertEqual(mock.call_args.args, ("gh", "api", f"repos/{REPO}/releases/42"))

    def test_api_errors_are_not_missing_releases(self):
        with patch.object(release, "run", side_effect=subprocess.CalledProcessError(1, "gh")):
            with self.assertRaises(subprocess.CalledProcessError):
                release.release_metadata(REPO, TAG)
        for response in ({"data": {"repository": None}}, {"errors": [{"message": "forbidden"}]}):
            with patch.object(release, "run", return_value=json.dumps(response)):
                with self.assertRaises(ValueError):
                    release.release_metadata(REPO, TAG)


class WorkflowTests(unittest.TestCase):
    def test_release_policy(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertIn('tags:\n      - "rarpar-v*"', workflow)
        for forbidden in ("ghcr.io", "docker/", "packages: write", "oci-verify", "always()", "!cancelled()"):
            self.assertNotIn(forbidden, workflow)
        jobs = dict(re.findall(r"^  ([a-z-]+):\n(.*?)(?=^  [a-z-]+:\n|\Z)",
                               workflow.split("jobs:\n", 1)[1], re.M | re.S))
        self.assertEqual(set(jobs), {"release-trust", "preflight", "build", "collect", "archive-provenance", "deploy"})
        for job, needs in {"preflight": "release-trust", "build": "release-trust, preflight",
                           "collect": "build", "archive-provenance": "collect",
                           "deploy": "collect, archive-provenance"}.items():
            self.assertIn(f"    needs: [{needs}]", jobs[job])
            self.assertNotRegex(jobs[job], re.compile(r"^    if:", re.M))
        self.assertIn("merge-multiple: false", jobs["collect"])
        self.assertIn("upload-assets: false", jobs["archive-provenance"])
        self.assertIn("generator_generic_slsa3.yml@v2.1.0", jobs["archive-provenance"])
        self.assertIn("--directory release-assets", jobs["deploy"])
        self.assertIn("steps.finalize.outputs.published == 'true'", jobs["deploy"])
        self.assertIn("commit -S", jobs["deploy"])
        self.assertIn("verify-commit HEAD", jobs["deploy"])
        self.assertEqual(sorted(re.findall(r"- platform: (\S+)", jobs["build"])), sorted(release.PLATFORMS))


if __name__ == "__main__":
    unittest.main()
