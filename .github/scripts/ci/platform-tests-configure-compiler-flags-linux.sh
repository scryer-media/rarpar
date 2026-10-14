#!/usr/bin/env bash
# ci.yml, platform-tests-linux: "Configure compiler flags".
set -euo pipefail
{
  echo "RUSTFLAGS=--remap-path-prefix=${GITHUB_WORKSPACE}=. -C link-arg=-fuse-ld=mold"
  echo "CC=sccache cc"
  echo "CXX=sccache c++"
} >> "$GITHUB_ENV"
