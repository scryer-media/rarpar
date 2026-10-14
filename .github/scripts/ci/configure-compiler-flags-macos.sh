#!/usr/bin/env bash
# ci.yml, platform-tests-macos and target-checks-macos: "Configure compiler flags".
set -euo pipefail
{
  echo "RUSTFLAGS=--remap-path-prefix=${GITHUB_WORKSPACE}=."
  echo "CC=sccache clang"
  echo "CXX=sccache clang++"
} >> "$GITHUB_ENV"
