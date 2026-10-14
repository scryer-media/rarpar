#!/usr/bin/env bash
# ci.yml, target-checks-linux and target-checks-macos: "Confirm the release
# feature list links AWS-LC". target-checks-windows runs the same body inline:
# it runs under Git Bash there, and a script from a Windows checkout has CRLF
# line endings.
# Same guard the release workflow runs after its build, at PR time: the
# dependency graph of the exact matrix feature list must contain
# `aws-lc-sys`, so an entry that lost `crypto-aws-lc` fails here rather
# than shipping the RustCrypto backend.
set -euo pipefail
cargo tree --locked -p rarpar -e normal --no-default-features \
  --features "$FEATURES" --target "$TARGET" > rarpar-tree.txt
if ! grep -q aws-lc-sys rarpar-tree.txt; then
  echo "::error::rarpar resolved no aws-lc-sys for $FEATURES; the crypto backend regressed to RustCrypto"
  exit 1
fi
