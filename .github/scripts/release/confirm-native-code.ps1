# release.yml, build-windows: "Confirm AWS-LC and the allocator in the release
# binary". The feature audit reads the resolver's feature sets;
# confirm_native_code.py reads the dependency graph of the exact feature list
# that was just built, the aws-lc-sys build-script output, and the binary.
# All have to agree before the binary ships: AWS-LC built from source by the
# cc builder with clang-cl, statically, with assembly, at the release
# optimisation level, and jitterentropy at -Od.
$ErrorActionPreference = "Stop"
python3 .github/scripts/release/confirm_native_code.py `
  --manifest-path (Join-Path $env:RARPAR_RELEASE_SOURCE "Cargo.toml") `
  --features $env:RELEASE_FEATURES `
  --target $env:RELEASE_TARGET `
  --target-dir $env:RARPAR_RELEASE_TARGET_DIR `
  --log-prefix "logs/rarpar-${env:RELEASE_PLATFORM}"
if ($LASTEXITCODE -ne 0) {
  throw "the release binary's native code does not match the release policy"
}
