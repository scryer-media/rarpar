#!/usr/bin/env bash
# release.yml, build-linux: "Stage package root inspection artifact".
set -euo pipefail
rm -rf package-root package-roots
mkdir -p package-roots
cargo run --locked -p xtask -- package-root \
  --binary "$RARPAR_RELEASE_TARGET_DIR/$RELEASE_TARGET/release/rarpar" \
  --docs target/dist/docs \
  --out package-root \
  --target "$RELEASE_TARGET"
tar -czf "package-roots/package-root-${RELEASE_TAG}-${RELEASE_PLATFORM}.tar.gz" \
  -C package-root .
