#!/usr/bin/env bash
# release.yml, build-linux and build-macos: "Stage rarpar release source".
set -euo pipefail
version="${RELEASE_TAG#rarpar-v}"
cargo package --locked --no-verify -p rarpar
rm -rf "$RUNNER_TEMP/rarpar-release-source"
mkdir -p "$RUNNER_TEMP/rarpar-release-source"
tar -xzf "target/package/rarpar-${version}.crate" -C "$RUNNER_TEMP/rarpar-release-source"
source_dir="$RUNNER_TEMP/rarpar-release-source/rarpar-${version}"
cargo metadata --locked --format-version 1 --no-deps \
  --manifest-path "$source_dir/Cargo.toml" \
  > "$RUNNER_TEMP/rarpar-release-source/metadata.json"
python3 - "$RUNNER_TEMP/rarpar-release-source/metadata.json" <<'PY'
import json
import sys

metadata = json.load(open(sys.argv[1], "r", encoding="utf-8"))
package = next(
    package for package in metadata["packages"] if package["name"] == "rarpar"
)
dependencies = {dep["name"]: dep for dep in package["dependencies"]}
for name in ("par2-rs", "unrar-rs"):
    dep = dependencies.get(name)
    if dep is None or dep.get("source") is None or dep.get("path") or not dep.get("req"):
        print(f"{name} must be a registry dependency in packaged rarpar", file=sys.stderr)
        sys.exit(1)
PY
echo "RARPAR_RELEASE_SOURCE=$source_dir" >> "$GITHUB_ENV"
