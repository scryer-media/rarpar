#!/usr/bin/env bash
# release.yml, build-linux: "Install build dependencies".
set -euo pipefail
packages=(mold)
case "$RELEASE_TARGET" in
  x86_64-*) packages+=(nasm) ;;
esac
case "$RELEASE_TARGET" in
  *-musl) packages+=(musl-tools) ;;
esac
sudo apt-get update
sudo apt-get install -y --no-install-recommends "${packages[@]}"
