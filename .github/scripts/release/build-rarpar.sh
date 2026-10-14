#!/usr/bin/env bash
# release.yml, build-linux and build-macos: "Build rarpar".
set -euo pipefail
# The packaged crate is unpacked outside the workspace, where it is its own
# workspace root and the workspace's [profile.release] does not apply. Pass
# that profile explicitly, read from the workspace manifest.
profile="$(python3 .github/scripts/release/release_profile.py Cargo.toml)"
echo "Workspace [profile.release], passed to the packaged build:"
profile_args=()
while IFS= read -r setting; do
  echo "  --config $setting"
  profile_args+=(--config "$setting")
done <<< "$profile"
mkdir -p logs
cargo build --locked --release --no-default-features \
  --manifest-path "$RARPAR_RELEASE_SOURCE/Cargo.toml" \
  "${profile_args[@]}" \
  --features "$RELEASE_FEATURES" \
  --target "$RELEASE_TARGET" \
  --target-dir "$RARPAR_RELEASE_TARGET_DIR" 2>&1 \
  | tee "logs/rarpar-${RELEASE_PLATFORM}-build.log"
