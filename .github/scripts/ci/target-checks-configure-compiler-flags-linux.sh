#!/usr/bin/env bash
# ci.yml, target-checks-linux: "Configure compiler flags".
set -euo pipefail
{
  echo "RUSTFLAGS=--remap-path-prefix=${GITHUB_WORKSPACE}=. -C link-arg=-fuse-ld=mold"
  case "$TARGET" in
    *-musl)
      target_env="$TARGET"
      target_env="${target_env//-/_}"
      printf 'CC_%s=%s\n' "$target_env" "sccache musl-gcc"
      ;;
    *)
      echo "CC=sccache cc"
      echo "CXX=sccache c++"
      ;;
  esac
} >> "$GITHUB_ENV"
