//! Crypto backend selection.
//!
//! Every aws-lc-touching or RustCrypto-touching primitive lives in one of the
//! submodules below, each exposing the same minimal seam consumed by the
//! shared code in [`crate::crypto`]. The shared code never references a
//! concrete crypto library directly.
//!
//! Backend precedence: **AWS-LC (native) > crypto-host (wasm+feature) >
//! crypto-rust**. AWS-LC wins on native targets whenever `crypto-aws-lc` is
//! enabled. On `wasm` its dependencies are absent (target-gated in
//! `Cargo.toml`), so AWS-LC is never active there; if `crypto-host` is on, the
//! host-delegated backend wins, otherwise the portable RustCrypto backend does.
//!
//! Backend modules *compile* whenever their inputs are available — the AWS-LC
//! and RustCrypto modules both build on native (both features on) so the
//! differential tests can compare them side by side, and the host module also
//! builds in a native `#[cfg(test)]` config so its guest CBC IV-chaining logic
//! can be proven against a reference decrypt without a wasm host. Only one
//! module is re-exported as the active backend.

#[cfg(all(feature = "crypto-aws-lc", not(target_family = "wasm")))]
pub(crate) mod aws_lc;
// This module is compiled whenever `crypto-rust` is on, but it is not always
// the *active* backend, and in those cases parts of its seam are dead code:
//   * AWS-LC active (native, both features on): it exists only for the
//     differential tests, so its whole seam is dead in a non-test build.
//   * Host backend active (wasm + `crypto-host`): the host backend re-exports
//     only this module's KDF primitives, so its AES-CBC decryptors are unused.
// Allow dead code in exactly those two configurations. When `rust` really is
// the active backend (plain `crypto-rust`), the normal dead-code lint applies.
#[cfg(feature = "crypto-rust")]
#[cfg_attr(
    any(
        all(feature = "crypto-aws-lc", not(target_family = "wasm")),
        all(target_arch = "wasm32", feature = "crypto-host")
    ),
    allow(dead_code)
)]
pub(crate) mod rust;
// Host-delegated backend (wasm guest side). Active only on `wasm32` with
// `crypto-host`. It is ALSO compiled in a native `#[cfg(test)]` build (whenever
// the RustCrypto deps it borrows are available) purely so its CBC IV-chaining
// differential test can run natively; in that configuration it is not the
// active backend, so its re-exported seam is dead code — allow that.
#[cfg(any(
    all(target_arch = "wasm32", feature = "crypto-host"),
    all(test, feature = "crypto-rust")
))]
#[cfg_attr(
    not(all(target_arch = "wasm32", feature = "crypto-host")),
    allow(dead_code, unused_imports)
)]
pub(crate) mod host;

// --- Active backend selection (exactly one `pub(crate) use *`). ---

// 1. AWS-LC on native whenever it is enabled — highest precedence.
#[cfg(all(feature = "crypto-aws-lc", not(target_family = "wasm")))]
pub(crate) use aws_lc::*;
// 2. Host-delegated backend on wasm when `crypto-host` is on — beats crypto-rust.
#[cfg(all(target_arch = "wasm32", feature = "crypto-host"))]
pub(crate) use host::*;
// 3. Portable RustCrypto backend: enabled, and neither AWS-LC (native) nor the
//    host backend (wasm+crypto-host) is active.
#[cfg(all(
    feature = "crypto-rust",
    not(all(feature = "crypto-aws-lc", not(target_family = "wasm"))),
    not(all(target_arch = "wasm32", feature = "crypto-host"))
))]
pub(crate) use rust::*;

#[cfg(not(any(
    all(feature = "crypto-aws-lc", not(target_family = "wasm")),
    all(target_arch = "wasm32", feature = "crypto-host"),
    feature = "crypto-rust"
)))]
compile_error!(
    "weaver-unrar needs a crypto backend: enable feature `crypto-aws-lc` (native, default), \
     `crypto-host` (wasm; delegates AES to the host), or `crypto-rust` (portable/wasm)."
);
