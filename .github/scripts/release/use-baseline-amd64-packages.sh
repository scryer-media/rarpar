#!/usr/bin/env bash
# Run by the Linux build-dependency installers before they install anything.
# GitHub's ubuntu-26.04 x86_64 image enables Ubuntu's amd64v3 architecture
# variant, and its preinstalled C toolchain comes from that pool: a gcc built
# to target x86-64-v3 (AVX2, BMI2, FMA) by default, with libgcc and glibc's
# static start files built the same way. musl-tools from that pool adds a
# libc.a built for x86-64-v3 too. rarpar 0.9.0's musl binary carried that
# code and died with SIGILL on x86_64 CPUs without AVX, before main.
#
# Naming the baseline architecture on every deb822 source keeps apt on the
# amd64 index, as the runner image itself does for the git PPA; reinstalling
# the toolchain packages then swaps the preinstalled v3 builds for baseline
# ones. confirm-baseline-x86-64-c-toolchain.sh checks the result.
set -euo pipefail
[ "$(dpkg --print-architecture)" = amd64 ] || exit 0
shopt -s nullglob
for sources in /etc/apt/sources.list.d/*.sources; do
  # A stanza without an Architectures field gets "Architectures: amd64".
  restricted="$(awk '
    function flush() {
      if (n) {
        for (i = 1; i <= n; i++) print buf[i]
        if (uris && !arches) print "Architectures: amd64"
      }
      n = 0; uris = 0; arches = 0
    }
    /^[[:space:]]*$/ { flush(); print; next }
    { buf[++n] = $0 }
    /^URIs:/ { uris = 1 }
    /^Architectures:/ { arches = 1 }
    END { flush() }
  ' "$sources")"
  if [ "$restricted" != "$(cat "$sources")" ]; then
    printf '%s\n' "$restricted" | sudo tee "$sources" > /dev/null
    echo "restricted $sources to the baseline amd64 index"
  fi
done
sudo apt-get update
# The packages that decide what the C compiler emits by default and what it
# links statically: gcc, its per-triplet driver and back end, libgcc, and
# glibc's development files.
mapfile -t toolchain < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' \
  'gcc-[0-9]*' 'cpp-[0-9]*' 'g++-[0-9]*' 'libgcc-[0-9]*-dev' 'libstdc++-[0-9]*-dev' \
  'libc6' 'libc6-dev' 'libgcc-s1' 'libstdc++6' 2>/dev/null | awk '$1 == "ii" { print $2 }')
if [ "${#toolchain[@]}" -gt 0 ]; then
  echo "reinstalling the baseline amd64 builds of: ${toolchain[*]}"
  sudo apt-get install -y --no-install-recommends --reinstall "${toolchain[@]}"
fi
gcc -v 2>&1 | grep -o -e '--with-arch[^ ]*' -e '--with-tune[^ ]*' || echo "gcc configures no default --with-arch"
