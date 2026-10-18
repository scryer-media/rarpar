#!/usr/bin/env bash
# release.yml, build-linux, and ci.yml, target-checks-linux: "Confirm a
# baseline x86_64 C toolchain". The shipped x86_64 binaries must start on any
# x86_64 CPU; only code behind a runtime CPU check (AWS-LC's assembly, the
# par2 and RAR kernels) may use newer instructions. rarpar 0.9.0's musl binary
# was built with Ubuntu's amd64v3 musl-tools and died with SIGILL on CPUs
# without AVX in mimalloc's startup environment scan. This fails the build
# when the C compiler the target uses defaults to anything past baseline
# x86-64, or when musl's libc.a carries such instructions.
set -euo pipefail
target="${RELEASE_TARGET:-${TARGET:?}}"
case "$target" in
  x86_64-*-linux-musl) compiler=musl-gcc ;;
  x86_64-*-linux-gnu) compiler=cc ;;
  *) echo "$target is not an x86_64 Linux target; nothing to confirm"; exit 0 ;;
esac
failed=0
# Baseline x86-64 predefines none of these.
macros="$("$compiler" -dM -E -x c /dev/null)"
for macro in __SSE3__ __SSSE3__ __SSE4_1__ __SSE4_2__ __POPCNT__ __AVX__ __AVX2__ \
             __BMI__ __BMI2__ __FMA__ __F16C__ __LZCNT__ __MOVBE__ __AVX512F__; do
  if grep -q "^#define $macro " <<< "$macros"; then
    echo "::error::$compiler predefines $macro: it compiles past baseline x86-64 by default"
    failed=1
  fi
done
if [ "$compiler" = musl-gcc ]; then
  libc="$(musl-gcc -print-file-name=libc.a)"
  [ -f "$libc" ] || { echo "::error::musl-gcc names no libc.a ($libc)"; exit 1; }
  # VEX/EVEX vector code, and the BMI, LZCNT, MOVBE, POPCNT and CRC32 scalar
  # instructions that x86-64-v2 and v3 add. objdump prints tzcnt for the
  # rep bsf baseline compilers emit, so tzcnt is not on the list.
  pattern='^[[:space:]]*[0-9a-f]+:[[:space:]]+(v[a-z0-9]+[[:space:]].*%[xyz]mm|.*%[yz]mm|(andn|bextr|blsi|blsmsk|blsr|bzhi|mulx|pdep|pext|rorx|sarx|shlx|shrx|lzcnt|movbe|popcnt|crc32)[bwlq]?[[:space:]])'
  hits="$(objdump -d --no-show-raw-insn "$libc" | grep -E "$pattern" || true)"
  if [ -n "$hits" ]; then
    echo "::error::$libc carries $(wc -l <<< "$hits") instructions past baseline x86-64"
    head -n 20 <<< "$hits"
    failed=1
  fi
fi
[ "$failed" = 0 ] || exit 1
echo "$compiler and its C runtime target baseline x86-64"
