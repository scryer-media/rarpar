# release.yml, build-windows: "Stage rarpar release source".
$ErrorActionPreference = "Stop"
$version = $env:RELEASE_TAG -replace '^rarpar-v', ''
cargo package --locked --no-verify -p rarpar
$root = Join-Path $env:RUNNER_TEMP "rarpar-release-source"
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $root | Out-Null
tar -xzf "target/package/rarpar-$version.crate" -C $root
$sourceDir = Join-Path $root "rarpar-$version"
$manifest = Join-Path $sourceDir "Cargo.toml"
$metadata = Join-Path $root "metadata.json"
cargo metadata --locked --format-version 1 --no-deps --manifest-path $manifest `
  | Out-File -Encoding utf8 $metadata
$check = @'
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
'@
$check | python3 - $metadata
if ($LASTEXITCODE -ne 0) {
  throw "packaged rarpar manifest dependency validation failed"
}
"RARPAR_RELEASE_SOURCE=$sourceDir" | Out-File -Append -Encoding utf8 $env:GITHUB_ENV
