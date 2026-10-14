#!/usr/bin/env bash
# release.yml, build-linux and build-macos: "Smoke test release binary".
set -euo pipefail
exe="$RARPAR_RELEASE_TARGET_DIR/$RELEASE_TARGET/release/rarpar"
"$exe" --help > "logs/rarpar-${RELEASE_PLATFORM}-help.log"
"$exe" --version > "logs/rarpar-${RELEASE_PLATFORM}-version.log"
grep -Fxq "rarpar ${RELEASE_TAG#rarpar-v}" "logs/rarpar-${RELEASE_PLATFORM}-version.log"
"$exe" lb crates/unrar-rs/tests/fixtures/rar5/rar5_store.rar \
  > "logs/rarpar-${RELEASE_PLATFORM}-lb.log"
grep -Fxq small.txt "logs/rarpar-${RELEASE_PLATFORM}-lb.log"
