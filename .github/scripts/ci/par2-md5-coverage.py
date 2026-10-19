#!/usr/bin/env python3
"""Fail closed when a PAR2 MD5 backend or safety selector loses coverage."""

import argparse
import json
import platform
from pathlib import Path
import sys
import unittest

NATIVE = {
    "checksum::tests::paired_assembly_matches_scalar_states_and_rust_pairs",
    "checksum::tests::paired_native_streaming_uses_selected_assembly",
    "checksum::tests::paired_streams_random_chunks_match_rustcrypto",
    "checksum::tests::paired_assembly_stops_at_guard_page",
    "checksum::tests::paired_assembly_respects_exact_allocations",
    "checksum::tests::stitched_md5_matches_independent_states_at_every_offset",
    "checksum::tests::md5_native_backend_matches_independent_reference",
    "checksum::tests::md5_native_backend_matches_reference_at_every_length_and_split",
}
COMMON = {"checksum::tests::md5_default_backend_matches_reference_vector"}
RUST_ONLY = "checksum::tests::rust_only_md5_keeps_safe_streaming_pair_fallback"
BOTH = "checksum::tests::md5_native_backend_matches_rustcrypto_backend"
NATIVE_DISPATCH = "verify::tests::single_read_keeps_parallel_chains_and_stitches_serial_work"
STRICT = {
    "verify::tests::single_read_verdicts_match_the_two_pass_path_for_every_damage_position",
    "verify::tests::single_read_reads_a_damaged_file_once",
}


def required_tests(mode, strict=False):
    tests = COMMON | ({RUST_ONLY} if mode == "rust" else NATIVE)
    if mode == "both":
        tests |= {BOTH}
    if strict:
        tests |= STRICT
        if mode != "rust":
            tests |= {NATIVE_DISPATCH}
    return tests


def validate_listing(listing, mode, strict=False):
    suites = [
        suite for suite in listing["rust-suites"].values()
        if suite["package-name"] == "par2-rs" and suite["kind"] == "lib"
    ]
    if len(suites) != 1 or suites[0]["status"] != "listed":
        raise ValueError("expected one listed par2-rs lib test binary")
    cases = suites[0]["testcases"]
    required = required_tests(mode, strict)
    for name in sorted(required):
        case = cases.get(name)
        if (not case or case["kind"] != "test" or case["ignored"]
                or case["filter-match"]["status"] != "matches"):
            raise ValueError(f"required MD5 test missing, ignored or filtered: {name}")
    forbidden = NATIVE | {BOTH, NATIVE_DISPATCH} if mode == "rust" else {RUST_ONLY}
    if mode == "native":
        forbidden |= {BOTH}
    unexpected = forbidden & cases.keys()
    if unexpected:
        raise ValueError(f"wrong compiled MD5 feature mode: {sorted(unexpected)}")
    return sorted(required)


def validate_rust_ir(text):
    if "RustCrypto" not in text:
        raise ValueError("Rust-only IR has no RustCrypto backend evidence")
    if "md5_asm" in text or "md5_pair_asm" in text:
        raise ValueError("handwritten MD5 assembly module remains in Rust-only IR")


def normalized_arch(value):
    return {"x64": "x86_64", "amd64": "x86_64", "arm64": "aarch64"}.get(
        value.lower(), value.lower()
    )


class CoverageChecks(unittest.TestCase):
    @staticmethod
    def listing(mode="native", strict=False):
        return {"rust-suites": {"par2-rs": {
            "package-name": "par2-rs", "kind": "lib", "status": "listed",
            "testcases": {name: {
                "kind": "test", "ignored": False,
                "filter-match": {"status": "matches"},
            } for name in required_tests(mode, strict)},
        }}}

    def test_each_feature_mode_and_strict_selector(self):
        for mode in ["native", "both", "rust"]:
            for strict in [False, True]:
                validate_listing(self.listing(mode, strict), mode, strict)

    def test_missing_ignored_and_filtered_assembly_are_errors(self):
        name = "checksum::tests::paired_native_streaming_uses_selected_assembly"
        for failure in ["missing", "ignored", "filtered"]:
            listing = self.listing()
            cases = listing["rust-suites"]["par2-rs"]["testcases"]
            if failure == "missing":
                del cases[name]
            elif failure == "ignored":
                cases[name]["ignored"] = True
            else:
                cases[name]["filter-match"] = {"status": "mismatch"}
            with self.assertRaises(ValueError):
                validate_listing(listing, "native")

    def test_rust_only_rejects_compiled_native_tests_even_if_filtered(self):
        listing = self.listing("rust")
        listing["rust-suites"]["par2-rs"]["testcases"][next(iter(NATIVE))] = {
            "kind": "test", "ignored": False,
            "filter-match": {"status": "mismatch"},
        }
        with self.assertRaises(ValueError):
            validate_listing(listing, "rust")

    def test_skipped_binary_and_missing_strict_test_are_errors(self):
        listing = self.listing()
        listing["rust-suites"]["par2-rs"]["status"] = "skipped"
        with self.assertRaises(ValueError):
            validate_listing(listing, "native")
        with self.assertRaises(ValueError):
            validate_listing(self.listing(), "native", strict=True)

    def test_ir_requires_rust_and_rejects_both_native_modules(self):
        validate_rust_ir("RustCrypto MD5")
        for text in ["", "RustCrypto md5_asm", "RustCrypto md5_pair_asm"]:
            with self.assertRaises(ValueError):
                validate_rust_ir(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["native", "both", "rust"])
    parser.add_argument("--listing", type=Path)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--expected-arch")
    parser.add_argument("--rust-only-ir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(CoverageChecks)
        return 0 if unittest.TextTestRunner().run(suite).wasSuccessful() else 1
    if not args.mode or not args.listing:
        parser.error("--mode and --listing are required")
    arch = normalized_arch(platform.machine())
    if args.expected_arch and arch != normalized_arch(args.expected_arch):
        raise ValueError(f"native runner architecture {arch} != {args.expected_arch}")
    names = validate_listing(json.loads(args.listing.read_text()), args.mode, args.strict)
    if args.rust_only_ir:
        if args.mode != "rust":
            parser.error("IR exclusion audit requires --mode rust")
        validate_rust_ir(args.rust_only_ir.read_text())
    print(f"MD5 coverage: architecture={arch}, mode={args.mode}, required={len(names)}")
    for name in names:
        print(f"  required, non-ignored, selected: {name}")
    if args.rust_only_ir:
        print("Rust-only LLVM IR: RustCrypto present, both handwritten MD5 modules absent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
