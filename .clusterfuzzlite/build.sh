#!/bin/bash
set -euo pipefail

# The clusterfuzzlite builder image's bundled nightly lags the workspace MSRV
# (rust-version 1.97.1 vs the image's 1.91.0-nightly when this last failed),
# and the sanitizer build must stay on a nightly for -Zsanitizer. Install a
# current nightly at build time rather than trusting the image's.
rustup toolchain install nightly --profile minimal
rustup default nightly

cd "$SRC/rarpar/crates/unrar-rs"
cargo fuzz build -O rar_headers
cp fuzz/target/x86_64-unknown-linux-gnu/release/rar_headers "$OUT/"

cd "$SRC/rarpar/crates/par2-rs"
cargo fuzz build -O par2_packets
cp fuzz/target/x86_64-unknown-linux-gnu/release/par2_packets "$OUT/"
