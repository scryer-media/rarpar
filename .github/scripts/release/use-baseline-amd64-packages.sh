#!/usr/bin/env bash
# Run by the Linux build-dependency installers before apt-get update.
# GitHub's ubuntu-26.04 x86_64 image enables Ubuntu's amd64v3 architecture
# variant, so apt installs packages built for x86-64-v3 (AVX2, BMI2, FMA).
# musl-tools from that pool gives a musl-gcc that compiles for x86-64-v3 and a
# libc.a built the same way: rarpar 0.9.0's musl binary carried both and died
# with SIGILL on x86_64 CPUs without AVX, before main. Naming the baseline
# architecture on every deb822 source keeps apt on the amd64 index, as the
# runner image itself does for the git PPA. confirm-baseline-x86-64-c-toolchain.sh
# checks the result.
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
