# release.yml, build-windows: "Confirm the built artifact links AWS-LC".
# The feature audit reads the resolver's feature sets; this reads the
# dependency graph of the exact feature list that was just built. Both
# have to agree that `aws-lc-sys` is in it before the binary ships: a
# matrix entry that lost `crypto-aws-lc` would otherwise build, test
# and release a RustCrypto binary without a word.
$ErrorActionPreference = "Stop"
$manifest = Join-Path $env:RARPAR_RELEASE_SOURCE "Cargo.toml"
$log = "logs\rarpar-${env:RELEASE_PLATFORM}-tree.log"
cargo tree --locked -e normal `
  --manifest-path $manifest `
  --no-default-features --features $env:RELEASE_FEATURES `
  --target $env:RELEASE_TARGET | Out-File -Encoding utf8 $log
if (-not (Select-String -Path $log -Pattern "aws-lc-sys" -Quiet)) {
  throw "release build resolved no aws-lc-sys; the crypto backend regressed to RustCrypto"
}
