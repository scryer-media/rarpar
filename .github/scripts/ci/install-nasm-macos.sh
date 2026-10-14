#!/usr/bin/env bash
# ci.yml, platform-tests-macos and target-checks-macos: "Install NASM". The
# matrix `nasm` field says which rows need it; the others run this step and
# install nothing.
set -euo pipefail
if [ "$NEEDS_NASM" != true ]; then
  echo "this matrix row builds without NASM"
  exit 0
fi
brew install nasm
