#!/bin/bash
# Generate encrypted RAR test fixtures using Docker RAR images.
#
# These fixtures use -p (data-only encryption), NOT -hp (header encryption).
# This means headers are readable without a password, but file data requires
# the password to decrypt. The test password is "testpass123".
#
# Writers come from the shared pinned toolchain
# (bench/rarpar-bench/config/toolchains.json): RAR5 sets from the rarlab-7.20
# image, RAR4 sets from the rarlab-6.24 image.
#
# Requirements: docker on PATH, with the toolchain images built:
#     cargo run --locked -p xtask -- bench toolchains build
#
# Usage: cd crates/unrar-rs/tests/fixtures && bash generate_encrypted.sh
#
# Regenerating is a corpus revision (docs/test-corpus.md): every run draws fresh
# KDF salts and IVs, so the output is shape-identical, never byte-identical.
# Refresh test-corpus/sources.json afterwards.
set -euo pipefail

FIXTURE_DIR="$(cd "$(dirname "$0")" && pwd)"
RAR5_DIR="$FIXTURE_DIR/rar5"
RAR4_DIR="$FIXTURE_DIR/rar4"
PASSWORD="testpass123"

# Image tags as pinned in bench/rarpar-bench/config/toolchains.json.
RAR5_IMAGE="rarpar-bench-rarlab:7.20"
RAR4_IMAGE="rarpar-bench-rarlab:6.24"

mkdir -p "$RAR5_DIR" "$RAR4_DIR"

# Helper: run RAR5 (7.20) inside Docker
rar5() {
    docker run --rm --platform linux/amd64 -v "$FIXTURE_DIR:/work" -w /work "$RAR5_IMAGE" "$@"
}

# Helper: run RAR4 (6.24, forced RAR4 format) inside Docker
rar4() {
    docker run --rm --platform linux/amd64 -v "$FIXTURE_DIR:/work" -w /work "$RAR4_IMAGE" "$@"
}

# Use existing originals as source files
SRCDIR="$FIXTURE_DIR/originals"

echo "=== Generating RAR5 encrypted fixtures (password: $PASSWORD) ==="

# Clean the four sets this script owns. (Not `rar5_enc_*`: that glob would
# also take generate_stored_layout.sh's rar5_enc_mv_store_pair and
# rar5_enc_store_pair sets.)
rm -f "$RAR5_DIR"/rar5_enc_store.rar "$RAR5_DIR"/rar5_enc_lz.rar \
      "$RAR5_DIR"/rar5_enc_mv_store.part*.rar "$RAR5_DIR"/rar5_enc_mv_video.part*.rar

echo "  [1/4] encrypted stored (small.txt)"
rar5 a -m0 -ep1 -p"$PASSWORD" rar5/rar5_enc_store.rar originals/small.txt

echo "  [2/4] encrypted LZ compressed (compressible.txt)"
rar5 a -m3 -ep1 -p"$PASSWORD" rar5/rar5_enc_lz.rar originals/compressible.txt

echo "  [3/4] encrypted multi-volume stored (binary.bin → 5 volumes)"
rar5 a -m0 -v55k -ep1 -p"$PASSWORD" rar5/rar5_enc_mv_store.rar originals/binary.bin

echo "  [4/4] encrypted multi-volume video (test_clip.mkv → 5 volumes)"
rar5 a -m0 -v240k -ep1 -p"$PASSWORD" rar5/rar5_enc_mv_video.rar originals/test_clip.mkv

echo ""
echo "=== Generating RAR4 encrypted fixtures (password: $PASSWORD) ==="

# Clean the four sets this script owns.
rm -f "$RAR4_DIR"/rar4_enc_store.rar "$RAR4_DIR"/rar4_enc_lz.rar \
      "$RAR4_DIR"/rar4_enc_mv_store.part*.rar "$RAR4_DIR"/rar4_enc_mv_video.part*.rar

echo "  [1/4] encrypted stored (small.txt)"
rar4 a -ma4 -m0 -ep1 -p"$PASSWORD" rar4/rar4_enc_store.rar originals/small.txt

echo "  [2/4] encrypted LZ compressed (compressible.txt)"
rar4 a -ma4 -m3 -ep1 -p"$PASSWORD" rar4/rar4_enc_lz.rar originals/compressible.txt

echo "  [3/4] encrypted multi-volume stored (binary.bin → 5 volumes)"
rar4 a -ma4 -m0 -v55k -ep1 -p"$PASSWORD" rar4/rar4_enc_mv_store.rar originals/binary.bin

echo "  [4/4] encrypted multi-volume video (test_clip.mkv → 5 volumes)"
rar4 a -ma4 -m0 -v240k -ep1 -p"$PASSWORD" rar4/rar4_enc_mv_video.rar originals/test_clip.mkv

echo ""
echo "=== Verifying fixture counts ==="
echo "RAR5 encrypted: $(ls "$RAR5_DIR"/rar5_enc_* 2>/dev/null | wc -l | tr -d ' ') files"
echo "RAR4 encrypted: $(ls "$RAR4_DIR"/rar4_enc_* 2>/dev/null | wc -l | tr -d ' ') files"
echo ""
echo "=== Done! ==="
