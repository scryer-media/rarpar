#!/usr/bin/env python3
"""Confirm how the native code in a release build was built.

release.yml runs this after "Build rarpar" in every build job, through
confirm-native-code.sh or confirm-native-code.ps1, and ci.yml's
target-checks lanes run it after building the same feature list from the
workspace. It reads three records of one build and fails on the first that
disagrees with the release policy:

1. The dependency graph of the exact feature list (`cargo tree`). AWS-LC must
   be in it, and on musl targets so must mimalloc: a matrix entry that lost
   `crypto-aws-lc` or `musl-allocator` would otherwise build, test and ship
   without a word.
2. The aws-lc-sys build-script output Cargo keeps in the target directory,
   which is what `cargo build -vv` prints for that crate. The build jobs set
   CC_ENABLE_DEBUG_OUTPUT=1, so it holds every compiler command the cc crate
   ran. AWS-LC must have been built from source by its cc builder and linked
   statically, with assembly and not size-optimised; its ordinary C sources
   must have been compiled at the release optimisation level (-O3, or /O2 for
   clang-cl, whose cl dialect has no -O3); and its jitterentropy sources at
   -O0 (-Od for clang-cl). jitterentropy-base.c refuses to compile under
   __OPTIMIZE__, and the cc crate appends CFLAGS after the build script's own
   flags, so an optimisation flag in CFLAGS would override that -O0. On
   Windows the compiler must be clang-cl.
3. The stripped binary. It must carry AWS-LC's assembly, recognised by the
   CRYPTOGAMS credit string that every perlasm module AWS-LC ships embeds in
   its code section, and on musl targets mimalloc, recognised by the prefix
   of its warning messages. Both are data next to code the binary calls, so
   stripping symbols does not remove them.

Copies of the dependency graph and of the aws-lc-sys build output are written
next to the build logs (`--log-prefix`). Uses only the Python standard library
and runs on Python 3.10, the Ubuntu 22.04 runners' version.

Usage: confirm_native_code.py --manifest-path Cargo.toml --features LIST
       --target TRIPLE --target-dir DIR --log-prefix PREFIX
"""

import argparse
import glob
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

AWS_LC_MARKER = b"CRYPTOGAMS by <appro@openssl.org>"
MIMALLOC_MARKER = b"mimalloc: warning: "
WRAPPERS = {"sccache", "ccache"}
CL_DRIVERS = {"cl", "clang-cl"}
TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"')
ESCAPE = re.compile(r"\\(u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)")
SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}
# Flags that set the optimisation level. cl's /Ob, /Oi, /Os, /Ot and /Oy
# tune a level rather than set one.
LEVEL = re.compile(r"(?:-O(?:[0-3sz]|fast|g)?|[-/]O[12dx])")
NO_ASM_OR_SMALL = re.compile(r"[-/]DOPENSSL_(?:NO_ASM|SMALL)(?:=.*)?")
# AWS-LC's sources sit under aws-lc/ in the aws-lc-sys crate directory. On
# Windows aws-lc-sys names that directory by its 8.3 short name (AWS-LC~1.0,
# say) to keep cl command lines under MAX_PATH; the part below it is as written.
CRATE_DIR = r"/(?:aws-lc-sys-[^/]+|[^/]*~[0-9][^/]*)/aws-lc/"
LIBRARY_SOURCE = re.compile(CRATE_DIR + r"(?!tests/)")
JITTER_SOURCE = re.compile(CRATE_DIR + r"third_party/jitterentropy/")
MINIMUM_C_SOURCES = 100


def is_musl(target):
    return target.endswith("-musl")


def is_windows(target):
    return "-windows-" in target


def unescape(text):
    """Undo the Rust `{:?}` quoting the cc crate prints arguments with."""

    def replace(match):
        code = match.group(1)
        if code.startswith("u{"):
            return chr(int(code[2:-1], 16))
        if code.startswith("x") and len(code) == 3:
            return chr(int(code[1:], 16))
        return SIMPLE_ESCAPES.get(code, code)

    return ESCAPE.sub(replace, text)


def program_name(path):
    name = re.split(r"[\\/]", path)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def compile_commands(build_output):
    """Yield (compiler, source, arguments) for each compile the cc crate ran."""
    for line in build_output.splitlines():
        if not line.startswith("running: "):
            continue
        words = [unescape(token) for token in TOKEN.findall(line[len("running: "):])]
        if not words:
            continue
        compiler, arguments = program_name(words[0]), words[1:]
        if compiler in WRAPPERS and arguments:
            compiler, arguments = program_name(arguments[0]), arguments[1:]
        if "-c" not in arguments and "/c" not in arguments:
            continue
        yield compiler, arguments[-1].replace("\\", "/"), arguments


def optimisation_level(arguments):
    """The level the compiler applies: the last level flag on its command line."""
    levels = [argument for argument in arguments if LEVEL.fullmatch(argument)]
    return levels[-1].lstrip("-/") if levels else None


def check_dependency_graph(tree, target):
    errors = []
    if not re.search(r"\baws-lc-sys v", tree):
        errors.append("the release feature list resolved no aws-lc-sys; the crypto backend "
                      "regressed to RustCrypto")
    if is_musl(target) and not re.search(r"\bmimalloc v", tree):
        errors.append(f"the release feature list for {target} resolved no mimalloc; the musl "
                      "build lost the musl-allocator feature")
    return errors


def check_aws_lc_build(build_output, target):
    """Check one aws-lc-sys build-script output. Returns (errors, summary)."""
    errors = []
    lines = build_output.splitlines()
    if "cargo:warning=Building with: CC" not in lines:
        built_with = [line.split("Building with: ", 1)[1] for line in lines
                      if line.startswith("cargo:warning=Building with: ")]
        errors.append("AWS-LC was not built from source by the aws-lc-sys cc builder "
                      f"(builder: {', '.join(built_with) or 'not reported'})")
    if "cargo:link_kind=static" not in lines or not any(
            line.startswith("cargo:rustc-link-lib=static=aws_lc_") for line in lines):
        errors.append("aws-lc-sys did not link AWS-LC statically")
    for message in ("Size-optimized AWS-LC build enabled", "AWS_LC_SYS_NO_ASM found"):
        if any(message in line for line in lines):
            errors.append(f"aws-lc-sys reported: {message}")
    if not any(line.startswith("running: ") for line in lines):
        errors.append("the aws-lc-sys build output records no compiler commands; "
                      "the build must run with CC_ENABLE_DEBUG_OUTPUT=1")
        return errors, ""

    ordinary, jitter, compilers = {}, {}, set()
    defines, wrong_level = {}, {}
    for compiler, source, arguments in compile_commands(build_output):
        if not LIBRARY_SOURCE.search(source):
            continue
        name = source.rsplit("/", 1)[-1]
        for argument in arguments:
            if NO_ASM_OR_SMALL.fullmatch(argument):
                defines.setdefault(argument, []).append(name)
        if not source.endswith(".c"):
            continue
        compilers.add(compiler)
        cl_like = compiler in CL_DRIVERS
        level = optimisation_level(arguments)
        if JITTER_SOURCE.search(source):
            kind, expected = "jitterentropy", "Od" if cl_like else "O0"
            jitter[name] = level
        else:
            kind, expected = "ordinary", "O2" if cl_like else "O3"
            ordinary[name] = level
        if level != expected:
            wrong_level.setdefault((kind, level, expected), []).append(name)
    for define, names in sorted(defines.items()):
        errors.append(f"{len(names)} AWS-LC sources were compiled with {define} "
                      f"({', '.join(names[:3])}{', ...' if len(names) > 3 else ''})")
    for (kind, level, expected), names in sorted(wrong_level.items(), key=str):
        errors.append(f"{len(names)} {kind} AWS-LC C sources were compiled at "
                      f"{level or 'no optimisation flag'}, not {expected} "
                      f"({', '.join(names[:3])}{', ...' if len(names) > 3 else ''})")

    if len(ordinary) < MINIMUM_C_SOURCES:
        errors.append(f"found {len(ordinary)} AWS-LC C sources in the build output, "
                      f"fewer than the {MINIMUM_C_SOURCES} expected")
    if "jitterentropy-base.c" not in jitter:
        errors.append("the build output records no jitterentropy-base.c compile")
    if is_windows(target) and compilers != {"clang-cl"}:
        errors.append("AWS-LC was compiled with " + ", ".join(sorted(compilers) or ["nothing"])
                      + ", not clang-cl")
    summary = (f"AWS-LC: cc builder, static; {len(ordinary)} C sources at "
               f"{', '.join(sorted({level or '-' for level in ordinary.values()}))}; "
               f"jitterentropy at {', '.join(sorted({level or '-' for level in jitter.values()}))} "
               f"({', '.join(sorted(jitter))}); compiler {', '.join(sorted(compilers))}")
    return errors, summary


def check_binary(binary, target):
    errors = []
    if AWS_LC_MARKER not in binary:
        errors.append(f"the binary carries no AWS-LC assembly (no {AWS_LC_MARKER.decode()!r})")
    if is_musl(target) and MIMALLOC_MARKER not in binary:
        errors.append(f"the binary carries no mimalloc (no {MIMALLOC_MARKER.decode()!r})")
    return errors


def aws_lc_build_output(target_dir, target):
    pattern = os.path.join(glob.escape(str(target_dir)), target, "release", "build",
                           "aws-lc-sys-*", "output")
    outputs = sorted(glob.glob(pattern))
    if len(outputs) != 1:
        raise SystemExit(f"::error::expected one aws-lc-sys build output at {pattern}, "
                         f"found {len(outputs)}")
    return Path(outputs[0])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--features", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--log-prefix", required=True)
    args = parser.parse_args(argv)
    Path(args.log_prefix).parent.mkdir(parents=True, exist_ok=True)

    tree = subprocess.run(
        ["cargo", "tree", "--locked", "-e", "normal", "--manifest-path", args.manifest_path,
         "--no-default-features", "--features", args.features, "--target", args.target],
        check=True, capture_output=True, text=True,
    ).stdout
    Path(f"{args.log_prefix}-tree.log").write_text(tree, encoding="utf-8")
    errors = check_dependency_graph(tree, args.target)

    output = aws_lc_build_output(args.target_dir, args.target)
    shutil.copyfile(output, f"{args.log_prefix}-aws-lc-sys-build.log")
    build_errors, summary = check_aws_lc_build(
        output.read_text(encoding="utf-8", errors="replace"), args.target)
    errors += build_errors

    exe = "rarpar.exe" if is_windows(args.target) else "rarpar"
    binary = args.target_dir / args.target / "release" / exe
    errors += check_binary(binary.read_bytes(), args.target)

    if summary:
        print(summary)
    for error in errors:
        print(f"::error::{error}")
    if errors:
        return 1
    markers = [AWS_LC_MARKER] + ([MIMALLOC_MARKER] if is_musl(args.target) else [])
    print(f"{binary} carries " + " and ".join(repr(m.decode()) for m in markers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
