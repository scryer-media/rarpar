#!/bin/bash
# Generate the rar5_heavy_damage fixture: an ~80 MB RAR5 archive with a
# 64 KiB-slice PAR2 set carrying 500 recovery blocks. Designed to push PAR2
# repair to its limits.
#
# Everything comes from the shared pinned toolchain
# (bench/rarpar-bench/config/toolchains.json):
# - the heavy MKV input from the benchmark's pinned FFmpeg encoder, through
#   `rarpar-bench payload video` (no ffmpeg command line lives here);
# - the RAR5 archive from the rarlab-7.20 image;
# - the PAR2 set from the par2cmdline-turbo 1.4.0 image.
#
# Requirements:
# - docker on PATH, with the toolchain images built:
#     cargo run --locked -p xtask -- bench toolchains build
# - cargo + go (for `xtask bench payload video`)
#
# Regenerating is a corpus revision (docs/test-corpus.md): the checked-in set is
# also imported by bench/rarpar-bench/config/corpus.json under a pinned digest
# (par2-heavy-damage-28 / -250), so a regeneration changes the benchmark corpus
# configuration as well and needs that pin refreshed deliberately.
set -euo pipefail

FIXTURE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$FIXTURE_DIR/../../../.." && pwd)"
OUTDIR="$FIXTURE_DIR/rar5_heavy_damage"
WORK="$(mktemp -d)"
cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

# Image tags as pinned in bench/rarpar-bench/config/toolchains.json.
RAR5_IMAGE="rarpar-bench-rarlab:7.20"
PAR2_IMAGE="rarpar-bench-par2:1.4.0"

# The heavy clip: aim at 80 MiB so the archive holds ~1,200 slices at 64 KiB.
CLIP_TARGET_BYTES=$((80 * 1024 * 1024))

mkdir -p "$OUTDIR"

echo "==> Generating the ~80 MB source video through the pinned encoder..."
(cd "$REPO_ROOT" && cargo run --locked -q -p xtask -- bench payload video \
    --profile ffmpeg-video --target-bytes "$CLIP_TARGET_BYTES" \
    --out "$WORK/heavy_damage_clip.mkv")

SRC_SIZE=$(stat -f%z "$WORK/heavy_damage_clip.mkv" 2>/dev/null || stat -c%s "$WORK/heavy_damage_clip.mkv")
echo "    source: $(( SRC_SIZE / 1024 / 1024 ))MB"

echo "==> Creating RAR5 archive (single volume, LZ compression)..."
docker run --rm --platform linux/amd64 \
  -v "$WORK:/work" -w /work \
  "$RAR5_IMAGE" \
  a -idq -m5 -ep1 fixture_rar5_heavy_damage.rar heavy_damage_clip.mkv

RAR_SIZE=$(stat -f%z "$WORK/fixture_rar5_heavy_damage.rar" 2>/dev/null || stat -c%s "$WORK/fixture_rar5_heavy_damage.rar")
echo "    archive: $(( RAR_SIZE / 1024 / 1024 ))MB"

# 64KB slices, 500 recovery blocks: ~1,200 slices at ~76 MB, so up to 500
# damaged slices are recoverable.
echo "==> Creating PAR2 recovery set (64KB slices, 500 recovery blocks)..."
docker run --rm --platform linux/amd64 \
  -v "$WORK:/work" -w /work \
  "$PAR2_IMAGE" \
  create -q -s65536 -c500 -n10 \
  fixture_rar5_heavy_damage_repair.par2 \
  fixture_rar5_heavy_damage.rar

cd "$WORK"
PAR2_TOTAL=0
for f in fixture_rar5_heavy_damage_repair*.par2; do
    sz=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f")
    PAR2_TOTAL=$(( PAR2_TOTAL + sz ))
done
echo "    recovery: $(( PAR2_TOTAL / 1024 / 1024 ))MB across $(ls fixture_rar5_heavy_damage_repair*.par2 | wc -l | tr -d ' ') files"

TOTAL_SLICES=$(( (RAR_SIZE + 65535) / 65536 ))
echo "    slices: $TOTAL_SLICES (500 recoverable)"

echo "==> Copying to fixture directory..."
rm -f "$OUTDIR"/*
cp fixture_rar5_heavy_damage.rar "$OUTDIR/"
cp fixture_rar5_heavy_damage_repair*.par2 "$OUTDIR/"

echo "==> Done."
echo ""
ls -lh "$OUTDIR/"
echo ""
echo "This is a corpus revision: refresh test-corpus/sources.json and the"
echo "par2-heavy-damage fixture_sha256 pins in bench/rarpar-bench/config/corpus.json"
echo "(see docs/test-corpus.md)."
