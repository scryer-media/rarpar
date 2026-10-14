#!/usr/bin/env bash
# release.yml, build-macos: "Configure build environment".
set -euo pipefail
echo "RUSTFLAGS=--remap-path-prefix=${GITHUB_WORKSPACE}=." >> "$GITHUB_ENV"
echo "CC=clang" >> "$GITHUB_ENV"
echo "CXX=clang++" >> "$GITHUB_ENV"
