# release.yml, build-windows: "Audit release target features".
$ErrorActionPreference = "Stop"
$manifest = Join-Path $env:RARPAR_RELEASE_SOURCE "Cargo.toml"
cargo run --locked -p xtask -- feature-audit `
  --manifest $manifest --target $env:RELEASE_TARGET `
  --features $env:RELEASE_FEATURES
