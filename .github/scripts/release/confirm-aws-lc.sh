#!/usr/bin/env bash
# release.yml, build-linux and build-macos: "Confirm the built artifact links AWS-LC".
# The feature audit reads the resolver's feature sets; this reads the
# dependency graph of the exact feature list that was just built. Both
# have to agree that `aws-lc-sys` is in it before the binary ships: a
# matrix entry that lost `crypto-aws-lc` would otherwise build, test
# and release a RustCrypto binary without a word.
set -euo pipefail
log="logs/rarpar-${RELEASE_PLATFORM}-tree.log"
cargo tree --locked -e normal \
  --manifest-path "$RARPAR_RELEASE_SOURCE/Cargo.toml" \
  --no-default-features --features "$RELEASE_FEATURES" \
  --target "$RELEASE_TARGET" > "$log"
if ! grep -q aws-lc-sys "$log"; then
  echo "::error::release build resolved no aws-lc-sys; the crypto backend regressed to RustCrypto"
  exit 1
fi
