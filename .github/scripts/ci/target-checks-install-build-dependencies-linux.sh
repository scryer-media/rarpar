#!/usr/bin/env bash
# ci.yml, target-checks-linux: "Install build dependencies".
set -euo pipefail
packages=(mold)
case "$TARGET" in
  x86_64-*) packages+=(nasm) ;;
esac
case "$TARGET" in
  *-musl) packages+=(musl-tools) ;;
esac
sudo apt-get update
sudo apt-get install -y --no-install-recommends "${packages[@]}"
