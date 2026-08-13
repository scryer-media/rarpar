//! Whether the current build can actually run rayon work on worker threads.
//!
//! # Why this is not a plain `cfg!`
//!
//! Every parallel guard in this workspace used to spell its platform test as
//! `!cfg!(target_family = "wasm")`, on the assumption that "wasm" and "no
//! worker pool" are the same thing. That is true for `wasm32-wasip1`, but not
//! for `wasm32-wasip1-threads`, where `std::thread::spawn` works and rayon
//! runs with real parallelism.
//!
//! The obvious gate — `cfg!(target_feature = "atomics")` — **does not work on
//! stable rustc**. The `wasm32-wasip1-threads` target spec really does enable
//! the feature (`features: +atomics,+bulk-memory,+mutable-globals`), but
//! `atomics` is an *unstable* wasm target feature, and stable rustc does not
//! surface unstable target features to `cfg!(target_feature = ...)`. Measured
//! on 1.97.1: `rustc --target wasm32-wasip1-threads --print cfg` emits an
//! identical feature list to plain `wasm32-wasip1`, and
//! `cfg!(target_feature = "atomics")` evaluates to `false` on both — even when
//! `-C target-feature=+atomics` is passed explicitly (it warns
//! "unstable feature specified for `-Ctarget-feature`" and still reports
//! `false`). There is therefore **no stable compile-time cfg** that separates
//! the two wasm targets.
//!
//! So the wasm arm probes the capability at runtime, once, by spawning and
//! joining a trivial thread: on `wasm32-wasip1` that returns
//! `Err(Unsupported)` immediately (errno 58), and on `wasm32-wasip1-threads`
//! under a threads-enabled runtime it succeeds. The answer is cached in a
//! `OnceLock`, which keeps it **process-stable** — a hard requirement, because
//! `configured_create_threads` feeds PAR2 memory planning and `Par2CreatePlan`
//! equality depends on that value never changing within a process.
//!
//! # Native codegen is unchanged
//!
//! [`parallel_enabled`] tests `cfg!(target_family = "wasm")` *first* and
//! returns the literal `true` on native. That arm const-folds exactly like the
//! `!cfg!(target_family = "wasm")` expression it replaces, so native builds
//! keep byte-identical codegen and never reach — or link — the probe.

/// True when parallel (rayon) execution can actually make progress here.
///
/// * Native targets: a compile-time `true`; const-folds at every call site.
/// * `wasm32-wasip1`: `false` (thread spawn is unsupported).
/// * `wasm32-wasip1-threads` under a threads-enabled runtime: `true`.
///
/// Callers use this in place of the older `!cfg!(target_family = "wasm")`
/// spelling. It is cheap after the first call (a cached load on wasm, nothing
/// at all on native).
#[inline(always)]
pub fn parallel_enabled() -> bool {
    // Const-folds to `true` on native, leaving the guard expressions at call
    // sites identical to their pre-wasm-threads form. The probe below is only
    // ever compiled and reached on wasm.
    if !cfg!(target_family = "wasm") {
        return true;
    }
    wasm_threads_available()
}

/// Give rayon a correctly sized global pool on wasm. **No-op on native.**
///
/// Native builds deliberately do nothing here: rayon's own default sizing
/// (`available_parallelism`) is already correct, and touching the global pool
/// would be a behavior change. The whole body const-folds away.
///
/// wasm needs the help because `available_parallelism()` returns `Ok(1)` under
/// wasi — the guest cannot see the host's core count — so rayon's default
/// global pool would be a *single* worker even on `wasm32-wasip1-threads`.
/// Every `par_iter` would then run serially and every
/// `rayon::current_num_threads() > 1` guard would stay false, which would make
/// the threads target indistinguishable from plain wasip1. `threads` is
/// therefore supplied by the caller (from the embedder-provided width, e.g.
/// `WEAVER_PAR2_CREATE_THREADS`).
///
/// Safe to call repeatedly and from anywhere: it runs at most once, and a
/// failure — which is what `build_global` returns when a pool already exists,
/// including one the *embedder* installed deliberately — is ignored, so a
/// caller-installed pool always wins.
///
/// `threads` is a closure rather than a value so that native builds do not even
/// *compute* the width: the early return fires first and the closure is never
/// called, so adding this call to a native code path costs literally nothing
/// and observes nothing.
pub fn ensure_pool(threads: impl FnOnce() -> usize) {
    // Const-folds to an early return on native, leaving rayon's global pool
    // exactly as the crate has always left it: untouched.
    if !cfg!(target_family = "wasm") {
        return;
    }
    if !parallel_enabled() {
        return;
    }
    let threads = threads();
    if threads <= 1 {
        return;
    }
    static POOL_INIT: std::sync::Once = std::sync::Once::new();
    POOL_INIT.call_once(|| {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global();
    });
}

/// Runtime probe for wasm targets: can we spawn a thread at all?
///
/// Cached, so the spawn happens at most once per process and the answer is
/// stable for the lifetime of the module (required by PAR2 plan equality).
#[cfg(target_family = "wasm")]
fn wasm_threads_available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        // `Builder::spawn` returns `io::Result` rather than panicking, which is
        // what makes this probe safe on `wasm32-wasip1`, where the spawn fails
        // with `Unsupported`. A small stack keeps the probe cheap on the
        // targets where it does succeed.
        std::thread::Builder::new()
            .stack_size(16 * 1024)
            .spawn(|| ())
            .map(|handle| handle.join().is_ok())
            .unwrap_or(false)
    })
}

/// Never compiled on native — [`parallel_enabled`] returns before reaching it.
#[cfg(not(target_family = "wasm"))]
#[inline(always)]
fn wasm_threads_available() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On every target this workspace tests natively, parallelism is available.
    #[test]
    fn native_reports_parallel_enabled() {
        assert!(parallel_enabled());
    }

    /// The answer must not change within a process: PAR2 memory planning and
    /// `Par2CreatePlan` equality both depend on it being stable.
    #[test]
    fn answer_is_stable_across_calls() {
        let first = parallel_enabled();
        for _ in 0..16 {
            assert_eq!(parallel_enabled(), first);
        }
    }
}
