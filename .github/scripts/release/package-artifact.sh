#!/usr/bin/env bash
# release.yml, build-linux and build-macos: "Package artifact".
set -euo pipefail
archive="rarpar-${RELEASE_TAG}-${RELEASE_PLATFORM}.${RELEASE_ARCHIVE_EXT}"
rm -rf package
mkdir -p package dist
cp "$RARPAR_RELEASE_TARGET_DIR/$RELEASE_TARGET/release/rarpar" package/
cp README.md package/
cp tools/rarpar/LICENSE package/LICENSE
cp -R target/dist/docs/share package/share
tar -czf "$archive" -C package .
mv "$archive" dist/
