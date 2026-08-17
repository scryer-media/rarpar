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

# Every target ships three things: the binary, the seeds it starts from, and
# the dictionary of format tokens.
#
# The seeds matter more than they look. These formats are almost all structure
# — an eight-byte signature, then typed headers whose lengths have to agree —
# and a mutator starting from nothing spends its whole budget failing the first
# check. Seeded with real archives it starts inside the format and mutates
# toward the parts that are actually hard: length arithmetic, back-references,
# filter programs, recovery-slice exponents.
#
# The seeds are committed under each crate's fuzz/corpus/<target>/, which is
# also where `cargo fuzz run <target>` picks them up locally, so a developer
# reproducing a finding starts from the same place CI does.
build_target() {
  local crate="$1" target="$2" dictionary="$3"

  cd "$SRC/rarpar/crates/$crate"
  cargo fuzz build -O "$target"
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"

  if [ -d "fuzz/corpus/$target" ]; then
    # Zipped flat: ClusterFuzzLite unpacks <target>_seed_corpus.zip into the
    # starting corpus for that target and nothing else.
    (cd "fuzz/corpus/$target" && zip -q -r -j "$OUT/${target}_seed_corpus.zip" .)
    echo "seeded $target with $(ls "fuzz/corpus/$target" | wc -l) input(s)"
  else
    echo "note: $target has no seed corpus; it starts from nothing"
  fi

  if [ -f "fuzz/$dictionary" ]; then
    cp "fuzz/$dictionary" "$OUT/${target}.dict"
  fi
}

build_target unrar-rs rar_headers rar.dict
build_target unrar-rs rar_extract rar.dict
build_target unrar-rs rar_recovery_restore rar.dict

build_target par2-rs par2_packets par2.dict
build_target par2-rs par2_verify_repair par2.dict
