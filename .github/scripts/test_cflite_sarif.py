"""Tests for cflite_sarif.py.

The summaries here are cut down from real `.summary` logs the batch lane
saved (the timeout one is `timeout-8014be61` from the 2026-08-31 run); only
the lines the renderer reads are kept.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cflite_sarif  # noqa: E402

PREFIX = "/src/rarpar/"

TIMEOUT_SUMMARY = """\
INFO: Running with entropic power schedule (0xFF, 100).
artifact_prefix='/tmp/tmpatevcqqf/'; Test unit written to /tmp/tmpatevcqqf/timeout-8014be61447a8b6e83f58b47b9ae391668897a67
==116== ERROR: libFuzzer: timeout after 35 seconds
    #0 0x556f9a62c831 in __sanitizer_print_stack_trace (build-out/rar_extract+0x435831)
    #1 0x556f9ad3de58 in fuzzer::PrintStackTrace() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:5
    #2 0x556f9ad2191b in fuzzer::Fuzzer::AlarmCallback() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:304:5
    #3 0x7fde4f56e41f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f) (BuildId: 9753720502573b97dbac595b61fd72c2df18e078)
    #4 0x556f9a7ca8fa in <unrar_rs::decompress::ppmd::model::Model>::decode_char_result (build-out/rar_extract+0x5d38fa)
    #10 0x556f9ab42003 in <unrar_rs::archive::RarArchive>::extract_member_with_link_policy /src/rarpar/crates/unrar-rs/src/archive/member.rs:4543:35
    #11 0x556f9ab323c7 in <unrar_rs::archive::RarArchive>::extract_member /src/rarpar/crates/unrar-rs/src/archive/member.rs:4050:14
    #12 0x556f9a660f0a in rar_extract::_::__libfuzzer_sys_run /src/rarpar/crates/unrar-rs/fuzz/fuzz_targets/rar_extract.rs:40:25
    #13 0x556f9a665025 in rust_fuzzer_test_input /rust/registry/src/index.crates.io-1949cf8c6b5b557f/libfuzzer-sys-0.4.13/src/lib.rs:276:60

DEDUP_TOKEN: __sanitizer_print_stack_trace--fuzzer::PrintStackTrace()--fuzzer::Fuzzer::AlarmCallback()
SUMMARY: libFuzzer: timeout
"""

PANIC_SUMMARY = """\
thread '<unnamed>' panicked at /src/rarpar/crates/unrar-rs/src/decompress/ppmd/model.rs:871:13:
attempt to add with overflow
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
==42== ERROR: libFuzzer: deadly signal
    #0 0x55d0 in __sanitizer_print_stack_trace (build-out/rar_extract+0x435831)
    #5 0x55d1 in <unrar_rs::decompress::ppmd::model::Model>::decode_bin_symbol /src/rarpar/crates/unrar-rs/src/decompress/ppmd/model.rs:871:13
    #6 0x55d2 in rar_extract::_::__libfuzzer_sys_run /src/rarpar/crates/unrar-rs/fuzz/fuzz_targets/rar_extract.rs:40:25
DEDUP_TOKEN: abort--decode_bin_symbol--decode_char_result
SUMMARY: libFuzzer: deadly signal
"""

OOM_SUMMARY = """\
==7== ERROR: libFuzzer: out-of-memory (malloc(4194304000))
    #0 0x1 in __sanitizer_print_stack_trace (build-out/rar_headers+0x1)
    #4 0x2 in alloc::raw_vec::RawVec<u8>::grow_one /rustc/abc/library/alloc/src/raw_vec.rs:10:1
    #5 0x3 in unrar_rs::rar4::parse_rar4_headers /src/rarpar/crates/unrar-rs/src/rar4/mod.rs:193:9
SUMMARY: libFuzzer: out-of-memory
"""

ASAN_SUMMARY = """\
==9== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60 at pc 0x1 bp 0x2 sp 0x3
READ of size 4 at 0x60 thread T0
    #0 0x1 in par2_rs::packet::parse /src/rarpar/crates/par2-rs/src/packet.rs:77:5
DEDUP_TOKEN: parse--verify
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/rarpar/crates/par2-rs/src/packet.rs:77:5 in par2_rs::packet::parse
"""


class ClassifyTests(unittest.TestCase):
    def test_timeout(self):
        self.assertEqual(cflite_sarif.classify(TIMEOUT_SUMMARY), ("timeout", "timeout after 35 s"))

    def test_panic_wins_over_deadly_signal(self):
        rule, detail = cflite_sarif.classify(PANIC_SUMMARY)
        self.assertEqual(rule, "panic")
        self.assertIn("model.rs:871", detail)

    def test_out_of_memory(self):
        self.assertEqual(
            cflite_sarif.classify(OOM_SUMMARY), ("out-of-memory", "out-of-memory (malloc(4194304000))")
        )

    def test_sanitizer_kind_is_passed_through(self):
        self.assertEqual(cflite_sarif.classify(ASAN_SUMMARY), ("heap-buffer-overflow", "heap-buffer-overflow"))

    def test_deadly_signal_without_panic(self):
        summary = "==1== ERROR: libFuzzer: deadly signal\nSUMMARY: libFuzzer: deadly signal\n"
        self.assertEqual(cflite_sarif.classify(summary), ("deadly-signal", "deadly signal"))

    def test_unknown(self):
        self.assertEqual(cflite_sarif.classify("nothing useful"), ("crash", "unclassified"))


class LocateTests(unittest.TestCase):
    def test_timeout_uses_innermost_project_frame(self):
        location, frames = cflite_sarif.locate(TIMEOUT_SUMMARY, PREFIX)
        self.assertEqual(location.path, "crates/unrar-rs/src/archive/member.rs")
        self.assertEqual((location.line, location.column), (4543, 35))
        # The runtime and registry frames are not project frames.
        self.assertEqual(len(frames), 3)
        self.assertTrue(all("llvm-project" not in f and "/rust/registry" not in f for f in frames))

    def test_panic_site_beats_frames(self):
        location, _ = cflite_sarif.locate(PANIC_SUMMARY, PREFIX)
        self.assertEqual(location.path, "crates/unrar-rs/src/decompress/ppmd/model.rs")
        self.assertEqual(location.line, 871)

    def test_no_project_frames(self):
        location, frames = cflite_sarif.locate("==1== ERROR: libFuzzer: deadly signal\n", PREFIX)
        self.assertIsNone(location)
        self.assertEqual(frames, [])

    def test_prefix_outside_checkout_is_ignored(self):
        location, _ = cflite_sarif.locate(OOM_SUMMARY, PREFIX)
        self.assertEqual(location.path, "crates/unrar-rs/src/rar4/mod.rs")
        self.assertEqual(location.line, 193)


class TreeTests(unittest.TestCase):
    def _write(self, root: Path, target: str, sanitizer: str, name: str, summary: str):
        directory = root / target / sanitizer
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_bytes(b"\x00")
        (directory / (name + ".summary")).write_text(summary)

    def test_every_target_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "rar_extract", "address", "timeout-aaaa", TIMEOUT_SUMMARY)
            self._write(root, "rar_extract", "address", "crash-bbbb", PANIC_SUMMARY)
            self._write(root, "par2_packets", "address", "crash-cccc", ASAN_SUMMARY)
            # Something CIFuzz did not write, in the shape of a stray file.
            (root / "notes.txt").write_text("ignored")
            findings = cflite_sarif.read_findings(root, PREFIX)
        self.assertEqual(
            [(f.target, f.testcase, f.rule_id) for f in findings],
            [
                ("par2_packets", "crash-cccc", "heap-buffer-overflow"),
                ("rar_extract", "crash-bbbb", "panic"),
                ("rar_extract", "timeout-aaaa", "timeout"),
            ],
        )

    def test_missing_summary_is_still_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "rar_headers" / "address"
            directory.mkdir(parents=True)
            (directory / "timeout-dddd").write_bytes(b"\x00")
            findings = cflite_sarif.read_findings(root, PREFIX)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "crash")
        self.assertIsNone(findings[0].location)

    def test_absent_root_is_empty(self):
        self.assertEqual(cflite_sarif.read_findings(Path("/nonexistent/for/this/test"), PREFIX), [])


class SarifTests(unittest.TestCase):
    def _findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for target, name, summary in (
                ("rar_extract", "timeout-aaaa", TIMEOUT_SUMMARY),
                ("rar_extract", "crash-bbbb", PANIC_SUMMARY),
                ("rar_headers", "oom-eeee", OOM_SUMMARY),
            ):
                directory = root / target / "address"
                directory.mkdir(parents=True, exist_ok=True)
                (directory / name).write_bytes(b"\x00")
                (directory / (name + ".summary")).write_text(summary)
            return cflite_sarif.read_findings(root, PREFIX)

    def test_one_result_per_finding_with_rules_and_locations(self):
        sarif = cflite_sarif.build_sarif(self._findings())
        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), 3)
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(sorted(rule_ids), ["out-of-memory", "panic", "timeout"])
        for result in run["results"]:
            self.assertEqual(rule_ids[result["ruleIndex"]], result["ruleId"])
            loc = result["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uriBaseId"], "%SRCROOT%")
            self.assertFalse(loc["artifactLocation"]["uri"].startswith("/"))
            self.assertIn("crashes-", result["message"]["text"])
            # Code scanning keys alerts on rule + location when no fingerprint
            # is given; libFuzzer's DEDUP_TOKEN would merge every timeout.
            self.assertNotIn("partialFingerprints", result)

    def test_empty_run_is_valid_sarif(self):
        sarif = cflite_sarif.build_sarif([])
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])
        json.dumps(sarif)

    def test_unlocated_finding_points_at_the_build_script(self):
        finding = cflite_sarif.Finding(
            target="rar_headers", sanitizer="address", testcase="crash-x",
            rule_id="deadly-signal", detail="deadly signal", location=None, dedup_token=None,
        )
        result = cflite_sarif.build_sarif([finding])["runs"][0]["results"][0]
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], ".clusterfuzzlite/build.sh"
        )


class MainTests(unittest.TestCase):
    def test_end_to_end_writes_sarif_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "artifacts" / "rar_extract" / "address"
            directory.mkdir(parents=True)
            (directory / "timeout-aaaa").write_bytes(b"\x00")
            (directory / "timeout-aaaa.summary").write_text(TIMEOUT_SUMMARY)
            out = root / "nested" / "cflite.sarif"
            step_summary = root / "summary.md"
            rc = cflite_sarif.main(
                [
                    "--artifacts", str(root / "artifacts"),
                    "--output", str(out),
                    "--source-prefix", PREFIX,
                    "--summary-path", str(step_summary),
                    "--run-url", "https://example.invalid/run/1",
                ]
            )
            self.assertEqual(rc, 0)
            sarif = json.loads(out.read_text())
            self.assertEqual(sarif["runs"][0]["properties"]["runUrl"], "https://example.invalid/run/1")
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
            self.assertIn("| `rar_extract` | timeout after 35 s |", step_summary.read_text())

    def test_no_artifacts_directory_still_writes_empty_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "cflite.sarif"
            rc = cflite_sarif.main(["--artifacts", str(Path(tmp) / "missing"), "--output", str(out)])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out.read_text())["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
