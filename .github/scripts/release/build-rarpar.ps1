# release.yml, build-windows: "Build rarpar".
$ErrorActionPreference = "Stop"
# The packaged crate is unpacked outside the workspace, where it is its own
# workspace root and the workspace's [profile.release] does not apply. Pass
# that profile explicitly, read from the workspace manifest.
$profileSettings = @(python3 .github/scripts/release/release_profile.py Cargo.toml)
if ($LASTEXITCODE -ne 0) {
  throw "could not read the workspace [profile.release]"
}
Write-Host "Workspace [profile.release], passed to the packaged build:"
$profileArgs = foreach ($setting in $profileSettings) {
  Write-Host "  --config $setting"
  "--config"
  $setting
}
New-Item -ItemType Directory -Force logs | Out-Null
$manifest = Join-Path $env:RARPAR_RELEASE_SOURCE "Cargo.toml"
cargo build --locked --release --no-default-features `
  --manifest-path $manifest `
  @profileArgs `
  --features $env:RELEASE_FEATURES `
  --target $env:RELEASE_TARGET `
  --target-dir $env:RARPAR_RELEASE_TARGET_DIR 2>&1 `
  | Tee-Object -FilePath "logs\rarpar-${env:RELEASE_PLATFORM}-build.log"
