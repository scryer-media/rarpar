"""Offline release policy tests. External verifiers and GitHub are mocked."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_assets as release


TAG = "rarpar-v1.2.3"
REPO = "scryer-media/rarpar"
COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parents[2]
RELEASE_SCRIPTS = ROOT / ".github/scripts/release"
BUILD_JOBS = {"build-linux": "linux-", "build-macos": "darwin-", "build-windows": "windows-"}
AWS_LC_ENV = {
    "CARGO_INCREMENTAL": '"0"',
    "AWS_LC_SYS_USE_SYSTEM": '"0"',
    "AWS_LC_SYS_STATIC": '"1"',
    "AWS_LC_SYS_SMALL": '"0"',
    "AWS_LC_SYS_CMAKE_BUILDER": '"0"',
}
_spec = importlib.util.spec_from_file_location("confirm_native_code",
                                               RELEASE_SCRIPTS / "confirm_native_code.py")
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)


def workflow_jobs(path):
    workflow = (ROOT / path).read_text()
    return dict(re.findall(r"^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)",
                           workflow.split("jobs:\n", 1)[1], re.M | re.S))


def env_block(text, indent):
    """The KEY: value pairs of the first `env:` block at this indent."""
    match = re.search(rf"^{indent}env:\n((?:{indent}  .*\n|\s*#.*\n)+)", text, re.M)
    return dict(re.findall(rf"^{indent}  ([A-Za-z0-9_]+): (.*)$", match.group(1), re.M)) if match else {}


def matrix_rows(job):
    rows = re.findall(r"- platform: (\S+)\n(.*?)(?=\n {10}- platform: |\n    [a-z]|\Z)", job, re.S)
    return {platform: dict(re.findall(r"^ {12}([a-z_]+): (.*)$", body, re.M)) for platform, body in rows}


def cflags(target):
    return target.replace("-", "_")


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


class NativeCodeTests(unittest.TestCase):
    """confirm_native_code.py against build outputs shaped like real ones."""

    CRATE = "/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.45.0"
    JITTER = ("base", "gcd", "health", "noise", "sha3", "timer")

    def build_output(self, compiler="cc", ordinary=("-O3",), jitter=("-O3", "-O0"), tail=(),
                     header=("Building with: CC",), link=True, windows=False, extra=(),
                     crate=CRATE):
        def debug(text):
            # How Rust's {:?} prints an argument.
            return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

        def quote(path):
            return debug("C:" + path.replace("/", "\\") if windows else path)

        def running(flags, source):
            words = [debug(compiler), *(debug(flag) for flag in (*flags, *extra, *tail)),
                     '"-o"', quote("/out/x.o"), '"-c"', quote(f"{crate}/aws-lc/{source}")]
            return "running: " + " ".join(words)

        lines = [f"cargo:warning={line}" for line in header]
        lines += [running(ordinary, f"crypto/fipsmodule/f{i}.c") for i in range(120)]
        lines += [running(ordinary, "generated-src/linux-x86_64/crypto/fipsmodule/x.S")]
        lines += [running(("-O0",), "tests/compiler_features_tests/c11.c")]
        lines += [running(jitter, f"third_party/jitterentropy/jitterentropy-library/src/jitterentropy-{name}.c")
                  for name in self.JITTER]
        lines += ['running: "cc" "-O0" "-o" "/out/flag_check.o" "-c" "/out/flag_check.c"']
        if link:
            lines += ["cargo:rustc-link-lib=static=aws_lc_0_45_0_crypto", "cargo:link_kind=static"]
        return "\n".join(lines) + "\n"

    def errors(self, output, target="x86_64-unknown-linux-musl"):
        return native.check_aws_lc_build(output, target)[0]

    def test_release_shaped_builds_pass(self):
        self.assertEqual(self.errors(self.build_output()), [])
        # sccache in front of the compiler, as in the CI lanes.
        output = self.build_output(compiler="sccache").replace('"sccache" ', '"sccache" "musl-gcc" ')
        self.assertEqual(self.errors(output), [])
        # clang-cl: cc passes -O2 and the cl dialect's /O2 comes from CFLAGS;
        # aws-lc-sys swaps CFLAGS' optimisation flags for -Od on jitterentropy.
        output = self.build_output(compiler="C:\\Program Files\\LLVM\\bin\\clang-cl.exe",
                                   ordinary=("-O2", "/O2"), jitter=("-O2", "-Od", "-Od"), windows=True)
        errors, summary = native.check_aws_lc_build(output, "x86_64-pc-windows-msvc")
        self.assertEqual(errors, [])
        self.assertIn("120 C sources at O2", summary)
        self.assertIn("jitterentropy at Od", summary)
        # aws-lc-sys passes its crate directory to clang-cl in 8.3 short form.
        output = self.build_output(compiler="clang-cl", ordinary=("-O2", "/O2"),
                                   jitter=("-O2", "-Od", "-Od"), windows=True,
                                   crate="C:/RUNNER~1/CARGO~1/registry/src/INDEXC~1.IO-/AWS-LC~1.0")
        errors, summary = native.check_aws_lc_build(output, "aarch64-pc-windows-msvc")
        self.assertEqual(errors, [])
        self.assertIn("120 C sources at O2", summary)
        self.assertIn("jitterentropy at Od", summary)

    def test_an_optimisation_flag_in_cflags_overrides_jitterentropy(self):
        errors = self.errors(self.build_output(tail=("-O3",)))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("6 jitterentropy AWS-LC C sources were compiled at O3, not O0", errors[0])

    def test_ordinary_sources_below_the_release_level_fail(self):
        errors = self.errors(self.build_output(ordinary=("-O2",)))
        self.assertTrue(any("120 ordinary AWS-LC C sources were compiled at O2, not O3" in e for e in errors), errors)

    def test_builder_link_and_assembly_failures(self):
        cases = {
            "not built from source by the aws-lc-sys cc builder": self.build_output(header=("Building with: CMake",)),
            "did not link AWS-LC statically": self.build_output(link=False),
            "-DOPENSSL_NO_ASM=1": self.build_output(extra=("-DOPENSSL_NO_ASM=1",)),
            "/DOPENSSL_SMALL=1": self.build_output(extra=("/DOPENSSL_SMALL=1",)),
            "Size-optimized AWS-LC build enabled": self.build_output(header=(
                "Building with: CC",
                "Size-optimized AWS-LC build enabled. Applying OPENSSL_SMALL and disabling AVX-512 assembly.")),
            "records no compiler commands": "cargo:warning=Building with: CC\ncargo:link_kind=static\n"
                                            "cargo:rustc-link-lib=static=aws_lc_0_45_0_crypto\n",
        }
        for message, output in cases.items():
            with self.subTest(message):
                self.assertTrue(any(message in e for e in self.errors(output)), self.errors(output))

    def test_windows_requires_clang_cl_and_jitterentropy_base(self):
        output = self.build_output(compiler="cl.exe", ordinary=("-O2",), jitter=("-O2", "-Od"), windows=True)
        errors = self.errors(output, "aarch64-pc-windows-msvc")
        self.assertEqual(errors, ["AWS-LC was compiled with cl, not clang-cl"])
        output = self.build_output().replace("jitterentropy-base.c", "jitterentropy-other.c")
        self.assertIn("the build output records no jitterentropy-base.c compile", self.errors(output))

    def test_dependency_graph_and_binary_markers(self):
        tree = "rarpar v0.8.0\n├── aws-lc-rs v1.18.1\n│   └── aws-lc-sys v0.45.0\n"
        self.assertEqual(native.check_dependency_graph(tree, "x86_64-apple-darwin"), [])
        self.assertEqual(len(native.check_dependency_graph(tree, "aarch64-unknown-linux-musl")), 1)
        self.assertEqual(native.check_dependency_graph(tree + "├── mimalloc v0.1.48\n",
                                                       "aarch64-unknown-linux-musl"), [])
        self.assertEqual(len(native.check_dependency_graph("rarpar v0.8.0\n", "x86_64-apple-darwin")), 1)
        binary = b"\0SHA256 block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>\0"
        self.assertEqual(native.check_binary(binary, "x86_64-unknown-linux-gnu"), [])
        self.assertEqual(len(native.check_binary(binary, "x86_64-unknown-linux-musl")), 1)
        self.assertEqual(native.check_binary(binary + b"mimalloc: warning: ", "x86_64-unknown-linux-musl"), [])
        self.assertEqual(len(native.check_binary(b"mimalloc: warning: ", "x86_64-unknown-linux-musl")), 1)


    def test_mimalloc_must_be_built_without_huge_pages(self):
        source = ("/opt/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libmimalloc-sys-0.1.49/"
                  "c_src/mimalloc/v3/src/static.c")

        def output(*flags):
            words = " ".join(f'"{flag}"' for flag in ("musl-gcc", "-O3", *flags, "-o", "/out/static.o", "-c", source))
            return f"running: {words}\n"

        self.assertEqual(native.check_mimalloc_build(output("-DMI_DEFAULT_ALLOW_THP=0")), [])
        # A later define wins, as it does for the compiler.
        self.assertEqual(native.check_mimalloc_build(output("-DMI_DEFAULT_ALLOW_THP=1",
                                                            "-DMI_DEFAULT_ALLOW_THP=0")), [])
        for flags, value in ((("-DNDEBUG",), "not set"), (("-DMI_DEFAULT_ALLOW_THP=0", "-DMI_DEFAULT_ALLOW_THP=1"), "1")):
            with self.subTest(flags):
                errors = native.check_mimalloc_build(output(*flags))
                self.assertEqual(len(errors), 1, errors)
                self.assertIn(f"last value: {value}", errors[0])
        self.assertIn("records no compile", native.check_mimalloc_build("cargo:rustc-link-lib=static=mimalloc\n")[0])


class WorkflowTests(unittest.TestCase):
    def test_release_policy(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertIn('tags:\n      - "rarpar-v*"', workflow)
        for forbidden in ("ghcr.io", "docker/", "packages: write", "oci-verify", "always()", "!cancelled()"):
            self.assertNotIn(forbidden, workflow)
        jobs = dict(re.findall(r"^  ([a-z-]+):\n(.*?)(?=^  [a-z-]+:\n|\Z)",
                               workflow.split("jobs:\n", 1)[1], re.M | re.S))
        self.assertEqual(set(jobs), {"release-trust", "preflight", *BUILD_JOBS, "collect",
                                     "archive-provenance", "deploy"})
        for job, needs in {"preflight": "release-trust",
                           **dict.fromkeys(BUILD_JOBS, "release-trust, preflight"),
                           "collect": ", ".join(BUILD_JOBS), "archive-provenance": "collect",
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
        platforms = []
        for job, prefix in BUILD_JOBS.items():
            # One build job per operating system: its rows are that system's,
            # and nothing in it asks which system it runs on.
            rows = re.findall(r"- platform: (\S+)", jobs[job])
            self.assertTrue(rows and all(row.startswith(prefix) for row in rows), (job, rows))
            for marker in ("runner.os", "RUNNER_OS"):
                self.assertNotIn(marker, jobs[job])
            platforms += rows
        self.assertEqual(sorted(platforms), sorted(release.PLATFORMS))

    def test_release_scripts_exist(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        scripts = sorted(set(re.findall(r"\.github/scripts/release/[\w.-]+", workflow)))
        self.assertTrue(scripts)
        for script in scripts:
            self.assertTrue((ROOT / script).is_file(), script)
            if script.endswith(".sh"):
                # The build jobs run these by path.
                self.assertTrue(os.access(ROOT / script, os.X_OK), f"{script} is not executable")

    def test_release_native_code_policy(self):
        jobs = workflow_jobs(".github/workflows/release.yml")
        for job in BUILD_JOBS:
            env = env_block(jobs[job], "    ")
            for key, value in AWS_LC_ENV.items():
                self.assertEqual(env.get(key), value, (job, key))
            self.assertEqual(env.get("CC_ENABLE_DEBUG_OUTPUT"), '"1"', job)
            self.assertNotIn("CFLAGS", env, job)
            self.assertNotIn("CXXFLAGS", env, job)
            rows = matrix_rows(jobs[job])
            self.assertTrue(rows, job)
            build_step = jobs[job].split("- name: Build rarpar\n", 1)[1]
            build_step = build_step.split("\n      - ", 1)[0] + "\n"
            if job == "build-windows":
                # The target is also the host on the Windows runners, so
                # job-wide per-target flags would reach the xtask steps' host
                # build, where ring forces GNU clang on aarch64 and rejects the
                # cl dialect. The flags live on the build step only.
                for key in env:
                    self.assertFalse(key.startswith(("CFLAGS_", "CXXFLAGS_")), (job, key))
                flag_env = env_block(build_step, "        ")
            else:
                flag_env = env
            for platform, row in rows.items():
                target = row["target"]
                features = row["features"].split(",")
                self.assertNotIn("crypto-rust", features, platform)
                self.assertIn("crypto-aws-lc", features, platform)
                # mimalloc replaces musl's allocator; nothing else takes it.
                self.assertEqual("musl-allocator" in features, target.endswith("-musl"), platform)
                for name in ("CFLAGS", "CXXFLAGS"):
                    flags = flag_env.get(f"{name}_{cflags(target)}", "").strip('"').split()
                    self.assertIn("-DNDEBUG" if "-" in flags[0] else "/DNDEBUG", flags, (platform, name))
                    if job == "build-windows":
                        self.assertEqual(flags, ["/O2", "/DNDEBUG", "/Gy", "/Gw"], platform)
                    else:
                        # The cc crate appends CFLAGS last: a level here would
                        # override jitterentropy's -O0.
                        self.assertFalse([f for f in flags if f.startswith("-O")], (platform, flags))
                        self.assertEqual("-mno-outline-atomics" in flags,
                                         target == "aarch64-unknown-linux-musl", platform)
            build = jobs[job].index("- name: Build rarpar")
            script = "confirm-native-code.ps1" if job == "build-windows" else "confirm-native-code.sh"
            self.assertGreater(jobs[job].index(f".github/scripts/release/{script}"), build, job)
        windows = env_block(jobs["build-windows"], "    ")
        self.assertEqual(windows.get("AWS_LC_SYS_PREBUILT_NASM"), '"0"')
        self.assertEqual(windows.get("CC_x86_64_pc_windows_msvc"), "clang-cl")
        self.assertEqual(windows.get("CXX_x86_64_pc_windows_msvc"), "clang-cl")

    def test_ci_target_checks_build_what_the_release_builds(self):
        release_jobs = workflow_jobs(".github/workflows/release.yml")
        ci_jobs = workflow_jobs(".github/workflows/ci.yml")
        workflow_env = env_block((ROOT / ".github/workflows/ci.yml").read_text(), "")
        for key, value in AWS_LC_ENV.items():
            self.assertEqual(workflow_env.get(key), value, key)
        for job in ("platform-tests-windows", "target-checks-windows"):
            env = env_block(ci_jobs[job], "    ")
            self.assertEqual(env.get("AWS_LC_SYS_PREBUILT_NASM"), '"0"', job)
            self.assertEqual(env.get("CC_x86_64_pc_windows_msvc"), "clang-cl", job)
            self.assertEqual(env.get("CXX_x86_64_pc_windows_msvc"), "clang-cl", job)
        release_rows, ci_rows = {}, {}
        for build_job, checks_job in (("build-linux", "target-checks-linux"),
                                      ("build-macos", "target-checks-macos"),
                                      ("build-windows", "target-checks-windows")):
            release_env = env_block(release_jobs[build_job], "    ")
            release_rows.update(matrix_rows(release_jobs[build_job]))
            ci_rows.update(matrix_rows(ci_jobs[checks_job]))
            step = ci_jobs[checks_job].split("- name: Build the release binary\n", 1)[1]
            step_env = env_block(step.split("\n      - name:", 1)[0], "        ")
            self.assertEqual(step_env.get("CC_ENABLE_DEBUG_OUTPUT"), '"1"', checks_job)
            if build_job == "build-windows":
                # Windows keeps its C flags on the build step (see
                # test_release_native_code_policy).
                build = release_jobs[build_job].split("- name: Build rarpar\n", 1)[1]
                release_env = env_block(build.split("\n      - ", 1)[0] + "\n", "        ")
            release_flags = {k: v for k, v in release_env.items() if "FLAGS_" in k}
            self.assertTrue(release_flags, build_job)
            self.assertEqual({k: v for k, v in step_env.items() if "FLAGS_" in k}, release_flags, checks_job)
            self.assertIn(".github/scripts/release/confirm_native_code.py", ci_jobs[checks_job], checks_job)
        self.assertEqual(sorted(ci_rows), sorted(release.PLATFORMS))
        for platform, row in ci_rows.items():
            self.assertEqual((row["target"], row["features"]),
                             (release_rows[platform]["target"], release_rows[platform]["features"]), platform)

    def run_release_profile(self, manifest):
        return subprocess.run([sys.executable, "-B", str(RELEASE_SCRIPTS / "release_profile.py"), str(manifest)],
                              capture_output=True, text=True)

    def test_release_profile_reaches_the_build(self):
        result = self.run_release_profile(ROOT / "Cargo.toml")
        self.assertEqual(result.returncode, 0, result.stderr)
        settings = result.stdout.splitlines()
        for setting in settings:
            self.assertRegex(setting, r"^profile\.release\.[a-z-]+=(?:'[^']*'|true|false|[+-]?\d+)$")
        # The symbol-table checks in build-linux and build-macos assume it.
        self.assertIn("profile.release.strip=true", settings)

    def test_release_profile_refuses_what_it_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "Cargo.toml"
            manifest.write_text('[workspace]\n\n[profile.release] # shipped\nlto = "fat"\ndebug = 0\n')
            result = self.run_release_profile(manifest)
            self.assertEqual(result.stdout.splitlines(), ["profile.release.lto='fat'", "profile.release.debug=0"])
            for body in ('[profile.release]\nlto = "fat"\n[profile.release.package.foo]\nopt-level = 1\n',
                         '[profile]\nrelease.lto = "fat"\n',
                         'profile.release.lto = "fat"\n',
                         '[profile.release]\nlto = ["fat"]\n',
                         '[workspace]\nmembers = []\n'):
                manifest.write_text(body)
                result = self.run_release_profile(manifest)
                self.assertNotEqual(result.returncode, 0, body)
                self.assertEqual(result.stdout, "", body)


if __name__ == "__main__":
    unittest.main()
