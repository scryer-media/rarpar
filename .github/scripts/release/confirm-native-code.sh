#!/usr/bin/env bash
# release.yml, build-linux and build-macos: "Confirm AWS-LC and the allocator
# in the release binary". The feature audit reads the resolver's feature sets;
# confirm_native_code.py reads the dependency graph of the exact feature list
# that was just built, the aws-lc-sys build-script output, and the binary.
# All have to agree before the binary ships: AWS-LC built from source by the
# cc builder, statically, with assembly, at the release optimisation level,
# jitterentropy at -O0, and on musl targets mimalloc linked in.
set -euo pipefail
python3 .github/scripts/release/confirm_native_code.py \
  --manifest-path "$RARPAR_RELEASE_SOURCE/Cargo.toml" \
  --features "$RELEASE_FEATURES" \
  --target "$RELEASE_TARGET" \
  --target-dir "$RARPAR_RELEASE_TARGET_DIR" \
  --log-prefix "logs/rarpar-${RELEASE_PLATFORM}"
