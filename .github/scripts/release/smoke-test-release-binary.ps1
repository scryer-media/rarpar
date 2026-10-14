# release.yml, build-windows: "Smoke test release binary".
$ErrorActionPreference = "Stop"
$exe = Join-Path $env:RARPAR_RELEASE_TARGET_DIR "${env:RELEASE_TARGET}\release\rarpar.exe"
& $exe --help | Tee-Object -FilePath "logs\rarpar-${env:RELEASE_PLATFORM}-help.log"
& $exe --version | Tee-Object -FilePath "logs\rarpar-${env:RELEASE_PLATFORM}-version.log"
$version = Get-Content "logs\rarpar-${env:RELEASE_PLATFORM}-version.log" -Raw
if ($version.Trim() -ne "rarpar $($env:RELEASE_TAG -replace '^rarpar-v', '')") {
  throw "rarpar --version output did not match release tag"
}
& $exe lb crates\unrar-rs\tests\fixtures\rar5\rar5_store.rar `
  | Tee-Object -FilePath "logs\rarpar-${env:RELEASE_PLATFORM}-lb.log"
if (-not (Select-String -Path "logs\rarpar-${env:RELEASE_PLATFORM}-lb.log" -Pattern '^small\.txt$' -Quiet)) {
  throw "rarpar lb smoke test did not list small.txt"
}
