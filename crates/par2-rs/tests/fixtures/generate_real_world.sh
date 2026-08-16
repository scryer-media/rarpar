#!/bin/bash
# Regenerate the checked-in PAR2 repair fixtures used by
# tests/real_world_generated.rs.
#
# Everything comes from the shared pinned toolchain
# (bench/rarpar-bench/config/toolchains.json):
# - the MKV input from the benchmark's pinned FFmpeg encoder, through
#   `rarpar-bench payload video` (no ffmpeg command line lives here);
# - the RAR5 set from the rarlab-7.20 image, the RAR4 set from rarlab-6.24;
# - the PAR2 sets from the par2cmdline-turbo 1.4.0 image.
#
# Requirements:
# - docker on PATH, with the toolchain images built:
#     cargo run --locked -p xtask -- bench toolchains build
# - cargo + go (for `xtask bench payload video`)
#
# Regenerating is a corpus revision: RAR stamps times into headers and -p sets
# draw fresh salts, so the output is shape-identical, never byte-identical.
# Update test-corpus/sources.json afterwards (docs/test-corpus.md).
set -euo pipefail

FIXTURE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$FIXTURE_DIR/../../../.." && pwd)"
WORK="$(mktemp -d)"
cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

# Image tags as pinned in bench/rarpar-bench/config/toolchains.json.
RAR5_IMAGE="rarpar-bench-rarlab:7.20"
RAR4_IMAGE="rarpar-bench-rarlab:6.24"
PAR2_IMAGE="rarpar-bench-par2:1.4.0"

# The ordinary clip: about 1.1 MB, the size the checked-in sets were made from.
CLIP_TARGET_BYTES=1100000

mkdir -p "$FIXTURE_DIR/source" "$FIXTURE_DIR/rar5_lz_plain" "$FIXTURE_DIR/rar4_store_enc"

(cd "$REPO_ROOT" && cargo run --locked -q -p xtask -- bench payload video \
    --profile ffmpeg-video --target-bytes "$CLIP_TARGET_BYTES" \
    --out "$WORK/generated_sample_clip.mkv")

cp "$WORK/generated_sample_clip.mkv" "$FIXTURE_DIR/source/generated_sample_clip.mkv"

make_set() {
    local image="$1"
    local maflag="$2"
    local mode_flag="$3"
    local encflag="$4"
    local stem="$5"
    local outdir="$6"

    rm -f "$outdir"/*
    cp "$WORK/generated_sample_clip.mkv" "$WORK/input_clip.mkv"

    local -a rar_args=(a -idq)
    if [ -n "$maflag" ]; then
        rar_args+=("$maflag")
    fi
    rar_args+=("$mode_flag" -ep1 -v192k)
    if [ -n "$encflag" ]; then
        rar_args+=("$encflag")
    fi
    docker run --rm --platform linux/amd64 -v "$WORK:/work" -w /work "$image" \
        "${rar_args[@]}" "$stem.rar" input_clip.mkv >/dev/null

    docker run --rm --platform linux/amd64 -v "$WORK:/work" -w /work "$PAR2_IMAGE" \
        create -q -s65536 -c12 -n6 "${stem}_repair.par2" "${stem}"*.rar >/dev/null

    find "$WORK" -maxdepth 1 -type f \( -name "${stem}*.rar" -o -name "${stem}_repair*.par2" \) \
        -exec cp {} "$outdir/" \;
    find "$WORK" -maxdepth 1 -type f \( -name "${stem}*.rar" -o -name "${stem}_repair*.par2" \) \
        -delete
    rm -f "$WORK/input_clip.mkv"
}

make_set "$RAR5_IMAGE" "" "-m5" "" "fixture_rar5_lz_plain" "$FIXTURE_DIR/rar5_lz_plain"
make_set "$RAR4_IMAGE" "-ma4" "-m0" "-ptestpass123" "fixture_rar4_store_enc" "$FIXTURE_DIR/rar4_store_enc"

echo "Generated PAR2 real-world fixtures."
echo ""
echo "NOTE: rar5_heavy_damage is generated separately via generate_heavy_damage.sh"
echo "NOTE: this is a corpus revision; refresh test-corpus/sources.json (see docs/test-corpus.md)"
