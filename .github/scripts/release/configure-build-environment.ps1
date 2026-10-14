# release.yml, build-windows: "Configure build environment".
# RUSTFLAGS replaces the [target.'cfg(all(windows, target_env = "msvc"))']
# rustflags in .cargo/config.toml rather than adding to them, so the 8 MiB
# main-thread stack reserve set there is repeated here. confirm-stack-reserve.ps1
# checks that it reached the binary.
$ErrorActionPreference = "Stop"
"RUSTFLAGS=--remap-path-prefix=$env:GITHUB_WORKSPACE=. -Clinker=lld-link -C link-arg=/STACK:8388608" | Out-File -Append -Encoding utf8 $env:GITHUB_ENV
