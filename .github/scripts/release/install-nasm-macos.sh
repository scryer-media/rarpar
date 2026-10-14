#!/usr/bin/env bash
# release.yml, build-macos: "Install NASM". The matrix `nasm` field says which
# rows need it; the others run this step and install nothing.
set -euo pipefail
if [ "$RELEASE_NASM" != true ]; then
  echo "$RELEASE_PLATFORM builds without NASM"
  exit 0
fi
brew install nasm
