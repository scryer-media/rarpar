#!/usr/bin/env bash
# release.yml, build-linux, and ci.yml, target-checks-linux: "Confirm a
# baseline x86_64 C toolchain". The shipped x86_64 binaries must start on any
# x86_64 CPU; only code behind a runtime CPU check (AWS-LC's assembly, the
# par2 and RAR kernels) may use newer instructions. rarpar 0.9.0's musl binary
# was built with Ubuntu's amd64v3 toolchain and died with SIGILL on CPUs
# without AVX in mimalloc's startup environment scan. This fails the build
# when the C compiler the target uses defaults to anything past baseline
# x86-64, with or without the target's CFLAGS, or when a C runtime archive it
# links statically (libgcc, musl's libc.a, glibc's start files) carries such
# instructions.
set -euo pipefail
target="${RELEASE_TARGET:-${TARGET:?}}"
case "$target" in
  x86_64-*-linux-musl) compiler=musl-gcc ;;
  x86_64-*-linux-gnu) compiler=cc ;;
  *) echo "$target is not an x86_64 Linux target; nothing to confirm"; exit 0 ;;
esac
failed=0
target_env="${target//-/_}"
cflags_var="CFLAGS_$target_env"
read -r -a cflags <<< "${!cflags_var:-}"
# Baseline x86-64 predefines none of these.
check_macros() {
  local what="$1"; shift
  local macros macro
  macros="$("$compiler" "$@" -dM -E -x c /dev/null)"
  for macro in __SSE3__ __SSSE3__ __SSE4_1__ __SSE4_2__ __POPCNT__ __AVX__ __AVX2__ \
               __BMI__ __BMI2__ __FMA__ __F16C__ __LZCNT__ __MOVBE__ __AVX512F__; do
    if grep -q "^#define $macro " <<< "$macros"; then
      echo "::error::$compiler $what predefines $macro: it compiles past baseline x86-64"
      failed=1
    fi
  done
}
check_macros "by default"
check_macros "with $cflags_var" "${cflags[@]}"
# VEX/EVEX vector code, and the BMI, LZCNT, MOVBE, POPCNT and CRC32 scalar
# instructions that x86-64-v2 and v3 add. objdump prints tzcnt for the
# rep bsf baseline compilers emit, so tzcnt is not on the list.
pattern='^[[:space:]]*[0-9a-f]+:[[:space:]]+(v[a-z0-9]+[[:space:]].*%[xyz]mm|.*%[yz]mm|(andn|bextr|blsi|blsmsk|blsr|bzhi|mulx|pdep|pext|rorx|sarx|shlx|shrx|lzcnt|movbe|popcnt|crc32)[bwlq]?[[:space:]])'
check_archive() {
  local archive="$1" hits
  if [ ! -f "$archive" ]; then
    echo "::error::$archive does not exist"
    failed=1
    return
  fi
  hits="$(objdump -d --no-show-raw-insn "$archive" | grep -E "$pattern" || true)"
  if [ -n "$hits" ]; then
    echo "::error::$archive carries $(wc -l <<< "$hits") instructions past baseline x86-64"
    head -n 10 <<< "$hits"
    failed=1
  else
    echo "$archive: baseline x86-64"
  fi
}
check_archive "$(gcc -print-libgcc-file-name)"
check_archive "$(gcc -print-file-name=libgcc_eh.a)"
if [ "$compiler" = musl-gcc ]; then
  # musl-gcc's specs file supplies musl's library directory only when it
  # links, so -print-file-name would name glibc's libc.a; ask the package.
  musl_libc="$(dpkg -L musl-dev | grep -m1 '/libc\.a$' || true)"
  check_archive "${musl_libc:-musl-dev ships no libc.a}"
else
  for object in crt1.o crti.o crtn.o libc_nonshared.a; do
    check_archive "$(gcc -print-file-name="$object")"
  done
fi
[ "$failed" = 0 ] || exit 1
echo "$compiler and the C runtime it links target baseline x86-64"
