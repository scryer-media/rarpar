//! Crypto backend selection.
//!
//! Every aws-lc-touching or RustCrypto-touching primitive lives in one of the
//! submodules below, each exposing the same minimal seam consumed by the
//! shared code in [`crate::crypto`]. The shared code never references a
//! concrete crypto library directly.
//!
//! Both backend modules *compile* whenever their feature is enabled — this is
//! what lets the differential tests compare them side by side — but only one
//! is re-exported as the active backend. AWS-LC wins on native targets; on
//! `wasm` its dependencies are absent (target-gated in `Cargo.toml`), so the
//! portable RustCrypto backend is selected instead.

#[cfg(all(feature = "crypto-aws-lc", not(target_family = "wasm")))]
pub(crate) mod aws_lc;
// When `crypto-rust` is enabled but AWS-LC is the *active* backend (native,
// both features on), this module is compiled only for differential tests, so
// its seam is dead code in a non-test build — allow that specific case. When
// it is the active backend (or wasm), the normal dead-code lint applies.
#[cfg(feature = "crypto-rust")]
#[cfg_attr(
    all(feature = "crypto-aws-lc", not(target_family = "wasm")),
    allow(dead_code)
)]
pub(crate) mod rust;

#[cfg(all(feature = "crypto-aws-lc", not(target_family = "wasm")))]
pub(crate) use aws_lc::*;
#[cfg(all(
    feature = "crypto-rust",
    any(not(feature = "crypto-aws-lc"), target_family = "wasm")
))]
pub(crate) use rust::*;

#[cfg(not(any(
    all(feature = "crypto-aws-lc", not(target_family = "wasm")),
    feature = "crypto-rust"
)))]
compile_error!(
    "weaver-unrar needs a crypto backend: enable feature `crypto-aws-lc` (native, default) or `crypto-rust` (portable/wasm)."
);
