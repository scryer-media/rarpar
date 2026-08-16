#!/bin/bash
set -euo pipefail

# The clusterfuzzlite builder image's bundled nightly lags the workspace MSRV
# (rust-version 1.97.1 vs the image's 1.91.0-nightly when this last failed),
# and the sanitizer build must stay on a nightly for -Zsanitizer. Install a
# current nightly at build time rather than trusting the image's. The image
# pins RUSTUP_TOOLCHAIN in the environment, which outranks `rustup default`, so
# the selection has to be made through that variable to take effect.
rustup toolchain install nightly --profile minimal
export RUSTUP_TOOLCHAIN=nightly

cd "$SRC/rarpar/crates/unrar-rs"
cargo fuzz build -O rar_headers
cp fuzz/target/x86_64-unknown-linux-gnu/release/rar_headers "$OUT/"

cd "$SRC/rarpar/crates/par2-rs"
cargo fuzz build -O par2_packets
cp fuzz/target/x86_64-unknown-linux-gnu/release/par2_packets "$OUT/"
