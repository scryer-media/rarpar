#!/bin/bash
set -euo pipefail

cd "$SRC/rarpar/crates/unrar-rs"
cargo fuzz build -O rar_headers
cp fuzz/target/x86_64-unknown-linux-gnu/release/rar_headers "$OUT/"

cd "$SRC/rarpar/crates/par2-rs"
cargo fuzz build -O par2_packets
cp fuzz/target/x86_64-unknown-linux-gnu/release/par2_packets "$OUT/"
