#!/bin/bash
# Regenerate the checked-in generated matrix fixtures used by
# tests/generated_multivolume_matrix.rs.
#
# Everything comes from the shared pinned toolchain
# (bench/rarpar-bench/config/toolchains.json): the MKV input from the
# benchmark's pinned FFmpeg encoder through `rarpar-bench payload video` (no
# ffmpeg command line lives here), RAR5 sets from the rarlab-7.20 image, RAR4
# sets from the rarlab-6.24 image.
#
# Requirements:
# - docker on PATH, with the toolchain images built:
#     cargo run --locked -p xtask -- bench toolchains build
# - cargo + go (for `xtask bench payload video`)
#
# Regenerating is a corpus revision (docs/test-corpus.md): rar stamps times into
# the headers and -p sets draw fresh salts, so the output is shape-identical,
# never byte-identical. Refresh test-corpus/sources.json afterwards.
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

# The matrix clip: about 1.1 MB, the size the checked-in sets were made from
# (seven 160k volumes).
CLIP_TARGET_BYTES=1100000

(cd "$REPO_ROOT" && cargo run --locked -q -p xtask -- bench payload video \
    --profile ffmpeg-video --target-bytes "$CLIP_TARGET_BYTES" \
    --out "$WORK/generated_matrix_clip.mkv")

cp "$WORK/generated_matrix_clip.mkv" "$FIXTURE_DIR/originals/generated_matrix_clip.mkv"

for flavor in rar5 rar4; do
    if [ "$flavor" = "rar5" ]; then
        image="$RAR5_IMAGE"
        maflag=""
    else
        image="$RAR4_IMAGE"
        maflag="-ma4"
    fi

    for mode in store lz; do
        if [ "$mode" = "store" ]; then
            mode_flag="-m0"
        else
            mode_flag="-m5"
        fi

        for enc in plain enc; do
            base="generated_matrix_${flavor}_${mode}_${enc}"
            rm -f "$FIXTURE_DIR/$flavor/${base}"*.rar
            if [ -n "$maflag" ]; then
                if [ "$enc" = "enc" ]; then
                    docker run --rm --platform linux/amd64 -v "$WORK:/work" -w /work "$image" \
                        a -idq "$maflag" "$mode_flag" -ep1 -v160k -ptestpass123 \
                        "$base.rar" generated_matrix_clip.mkv >/dev/null
                else
                    docker run --rm --platform linux/amd64 -v "$WORK:/work" -w /work "$image" \
                        a -idq "$maflag" "$mode_flag" -ep1 -v160k \
                        "$base.rar" generated_matrix_clip.mkv >/dev/null
                fi
            else
                if [ "$enc" = "enc" ]; then
                    docker run --rm --platform linux/amd64 -v "$WORK:/work" -w /work "$image" \
                        a -idq "$mode_flag" -ep1 -v160k -ptestpass123 \
                        "$base.rar" generated_matrix_clip.mkv >/dev/null
                else
                    docker run --rm --platform linux/amd64 -v "$WORK:/work" -w /work "$image" \
                        a -idq "$mode_flag" -ep1 -v160k \
                        "$base.rar" generated_matrix_clip.mkv >/dev/null
                fi
            fi

            find "$WORK" -maxdepth 1 -type f -name "${base}*.rar" -exec cp {} "$FIXTURE_DIR/$flavor/" \;
            find "$WORK" -maxdepth 1 -type f -name "${base}*.rar" -delete
        done
    done
done

echo "Generated multivolume matrix fixtures."
