#!/usr/bin/env bash
# release.yml, build-linux: "Configure build environment".
set -euo pipefail
echo "RUSTFLAGS=--remap-path-prefix=${GITHUB_WORKSPACE}=. -C link-arg=-fuse-ld=mold" >> "$GITHUB_ENV"
case "$RELEASE_TARGET" in
  *-musl)
    target_env="$RELEASE_TARGET"
    target_env="${target_env//-/_}"
    printf 'CC_%s=%s\n' "$target_env" "musl-gcc" >> "$GITHUB_ENV"
    ;;
  *)
    echo "CC=cc" >> "$GITHUB_ENV"
    echo "CXX=c++" >> "$GITHUB_ENV"
    ;;
esac
