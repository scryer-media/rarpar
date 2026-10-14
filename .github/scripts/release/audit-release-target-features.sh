#!/usr/bin/env bash
# release.yml, build-linux and build-macos: "Audit release target features".
set -euo pipefail
cargo run --locked -p xtask -- feature-audit \
  --manifest "$RARPAR_RELEASE_SOURCE/Cargo.toml" --target "$RELEASE_TARGET" \
  --features "$RELEASE_FEATURES"
