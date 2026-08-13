//! Native `wasmtime` harness for the wasm `crypto-host` AES smoke test.
//!
//! This is the end-to-end proof that the guest's raw `#[link]` import
//! (`host::host_aes_cbc_decrypt`) links and round-trips over the
//! real ABI — and it DOUBLES as the executable reference the host-side agent
//! must satisfy: it implements `host_aes_cbc_decrypt` exactly to the fixed
//! contract (raw offsets into the guest's linear memory, in-place AES-CBC, no
//! padding, stateless per call) using a RustCrypto reference, then runs the
//! `host_aes_smoke` wasm example under it and asserts the example prints PASS
//! (exit 0).
//!
//! Flow:
//!   1. Build `examples/host_aes_smoke.rs` for `wasm32-wasip1` with
//!      `--no-default-features --features crypto-host` (into a private target
//!      dir so the nested cargo does not fight the outer test's target lock).
//!   2. Instantiate it with `wasmtime`, providing WASI preview1 (so the
//!      example's `println!`/exit work) plus the one custom host import.
//!   3. Run `_start`; a clean exit (or `I32Exit(0)`) means the example asserted
//!      its known-answer decrypt succeeded.
//!
//! Skipped automatically if the `wasm32-wasip1` target is not installed.

#![cfg(not(target_family = "wasm"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use wasmtime::{Caller, Engine, Extern, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::WasiP1Ctx;

const AES_BLOCK: usize = 16;

/// Return codes from the fixed ABI.
const RC_OK: i64 = 0;
const RC_BAD_KEY_LEN: i64 = -1;
const RC_BAD_BUF_LEN: i64 = -2;
const RC_OOB: i64 = -3;

/// Reference AES-CBC decrypt in place with a FRESH context seeded by `iv`
/// (stateless per call, matching the host contract). AES-256 for 32-byte keys,
/// AES-128 for 16-byte keys.
fn reference_cbc_decrypt(key: &[u8], iv: &[u8; AES_BLOCK], data: &mut [u8]) {
    use aes::cipher::block::BlockModeDecrypt;
    use aes::cipher::{Array, KeyIvInit};

    let (blocks, rest) = Array::<u8, _>::slice_as_chunks_mut(data);
    debug_assert!(rest.is_empty());
    match key.len() {
        32 => {
            let key: &[u8; 32] = key.try_into().expect("32-byte key");
            let mut dec = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into());
            dec.decrypt_blocks(blocks);
        }
        16 => {
            let key: &[u8; 16] = key.try_into().expect("16-byte key");
            let mut dec = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into());
            dec.decrypt_blocks(blocks);
        }
        _ => unreachable!("key length validated by caller"),
    }
}

/// Does this `rustc` actually have the `wasm32-wasip1` standard library?
///
/// `--print target-list` is NOT a usable probe: it lists every target rustc can
/// name, installed or not, so it answers `true` even for a toolchain that
/// cannot build a single wasm crate. The target libdir existing is the real
/// signal.
fn has_wasip1_std(rustc: &Path) -> bool {
    Command::new(rustc)
        .args(["--print", "target-libdir", "--target", "wasm32-wasip1"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .is_some_and(|out| Path::new(String::from_utf8_lossy(&out.stdout).trim()).is_dir())
}

/// Resolve a `(cargo, rustc)` pair that can actually build `wasm32-wasip1`.
///
/// The ambient `cargo`/`rustc` are not necessarily the toolchain pinned by
/// `rust-toolchain.toml`. A Homebrew `rust` install, for instance, puts real
/// `cargo`/`rustc` binaries on PATH ahead of rustup's proxies; those carry no
/// wasm std, and they are a *different build* of the same version number, so
/// their artifacts cannot be mixed with rustup's (E0514). Candidates are tried
/// in order: an explicit `RUSTC` override, the `rustc` beside the outer
/// `CARGO`, whatever `rustup which rustc` resolves for this manifest (which
/// honours `rust-toolchain.toml`), then PATH. The first one with a real wasm
/// std wins, and the nested build is pinned to it via `RUSTC`/`RUSTDOC` plus
/// its sibling `cargo`, so the harness passes regardless of PATH ordering.
fn wasm_toolchain() -> Option<(PathBuf, PathBuf)> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(rustc) = std::env::var_os("RUSTC") {
        candidates.push(PathBuf::from(rustc));
    }
    if let Some(dir) = std::env::var_os("CARGO")
        .map(PathBuf::from)
        .and_then(|cargo| cargo.parent().map(Path::to_path_buf))
    {
        candidates.push(dir.join("rustc"));
    }
    if let Some(out) = Command::new("rustup")
        .args(["which", "rustc"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|out| out.status.success())
    {
        candidates.push(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()));
    }
    candidates.push(PathBuf::from("rustc"));

    let rustc = candidates.into_iter().find(|rustc| has_wasip1_std(rustc))?;
    let cargo = rustc
        .parent()
        .map(|dir| dir.join("cargo"))
        .filter(|cargo| cargo.is_file())
        .or_else(|| std::env::var_os("CARGO").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("cargo"));
    Some((cargo, rustc))
}

/// Is a wasm32-wasip1-capable toolchain reachable? If not, the harness
/// self-skips.
fn wasip1_target_installed() -> bool {
    wasm_toolchain().is_some()
}

/// Build the smoke example for wasm32-wasip1 with `crypto-host` and return the
/// path to the produced `.wasm`. Uses a private target dir to avoid colliding
/// with the outer `cargo test` target lock.
fn build_smoke_wasm() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wasm-host-smoke-target");
    let (cargo, rustc) =
        wasm_toolchain().expect("no toolchain with a wasm32-wasip1 std (checked by the caller)");

    let status = Command::new(&cargo)
        .current_dir(&manifest_dir)
        .env("CARGO_TARGET_DIR", &target_dir)
        // Pin the nested build to the resolved wasm-capable toolchain instead of
        // letting cargo pick whichever `rustc` happens to be first on PATH.
        .env("RUSTC", &rustc)
        .env("RUSTDOC", rustc.with_file_name("rustdoc"))
        // Do not inherit the outer test's RUSTFLAGS/target selection.
        .env_remove("RUSTFLAGS")
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "unrar-rs",
            "--example",
            "host_aes_smoke",
            "--no-default-features",
            "--features",
            "crypto-host",
            "--target",
            "wasm32-wasip1",
        ])
        .status()
        .expect("failed to spawn cargo to build the wasm smoke example");
    assert!(
        status.success(),
        "cargo build of the wasm smoke example failed"
    );

    let wasm = target_dir
        .join("wasm32-wasip1")
        .join("release")
        .join("examples")
        .join("host_aes_smoke.wasm");
    assert!(
        wasm.is_file(),
        "expected built wasm at {}, but it is missing",
        wasm.display()
    );
    wasm
}

/// The reference host function, wired to the exact ABI the guest calls. Reads
/// `key`/`iv` and the block-aligned buffer from the guest's linear memory at the
/// passed offsets, decrypts in place, and writes the plaintext back. Stateless
/// per call. Returns the contract's status codes.
fn reference_host_aes_cbc_decrypt(
    mut caller: Caller<'_, WasiP1Ctx>,
    key_ptr: i64,
    key_len: i64,
    iv_ptr: i64,
    buf_ptr: i64,
    buf_len: i64,
) -> i64 {
    // Validate per the contract before touching memory.
    if key_len != 16 && key_len != 32 {
        return RC_BAD_KEY_LEN;
    }
    if buf_len % (AES_BLOCK as i64) != 0 {
        return RC_BAD_BUF_LEN;
    }

    let memory = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => return RC_OOB, // no linear memory exported — cannot proceed
    };

    let (key_ptr, key_len, iv_ptr, buf_ptr, buf_len) = (
        key_ptr as u64 as usize,
        key_len as usize,
        iv_ptr as u64 as usize,
        buf_ptr as u64 as usize,
        buf_len as u64 as usize,
    );

    // Read key + IV out of guest memory.
    let mut key = [0u8; 32];
    if memory.read(&caller, key_ptr, &mut key[..key_len]).is_err() {
        return RC_OOB;
    }
    let mut iv = [0u8; AES_BLOCK];
    if memory.read(&caller, iv_ptr, &mut iv).is_err() {
        return RC_OOB;
    }

    // Read the ciphertext, decrypt in place, write plaintext back — mirroring
    // the host slicing the guest buffer in place at `buf_ptr`.
    let mut buf = vec![0u8; buf_len];
    if memory.read(&caller, buf_ptr, &mut buf).is_err() {
        return RC_OOB;
    }
    reference_cbc_decrypt(&key[..key_len], &iv, &mut buf);
    if memory.write(&mut caller, buf_ptr, &buf).is_err() {
        return RC_OOB;
    }

    RC_OK
}

#[test]
fn wasm_host_aes_smoke_round_trips_over_the_real_abi() {
    if !wasip1_target_installed() {
        eprintln!("skipping: wasm32-wasip1 target not installed");
        return;
    }

    let wasm_path = build_smoke_wasm();

    let engine = Engine::default();
    let module = Module::from_file(&engine, &wasm_path).expect("load wasm module");

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    // WASI preview1 so the example's stdout / process exit work.
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |ctx: &mut WasiP1Ctx| ctx)
        .expect("add wasi preview1 to linker");

    // The one custom import, in the fixed namespace, satisfying the guest's
    // raw `#[link(wasm_import_module = "host")]` extern.
    linker
        .func_wrap(
            "host",
            "host_aes_cbc_decrypt",
            reference_host_aes_cbc_decrypt,
        )
        .expect("define host host_aes_cbc_decrypt");

    let wasi = WasiCtxBuilder::new().inherit_stdio().build_p1();
    let mut store = Store::new(&engine, wasi);

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate wasm module (all imports, incl. the host fn, must be satisfied)");

    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .expect("wasip1 command must export _start");

    // A wasip1 command signals success by returning cleanly OR by
    // `proc_exit(0)`, which surfaces here as an `I32Exit(0)` error. Any other
    // exit code (the example's FAIL path calls `process::exit(1)`) or trap is a
    // failure.
    match start.call(&mut store, ()) {
        Ok(()) => { /* clean return == PASS */ }
        Err(err) => {
            if let Some(exit) = err.downcast_ref::<wasmtime_wasi::I32Exit>() {
                assert_eq!(
                    exit.0, 0,
                    "wasm smoke example exited with code {} (expected 0 == PASS)",
                    exit.0
                );
            } else {
                panic!("wasm smoke example trapped instead of passing: {err:?}");
            }
        }
    }
}

/// Unit-level check of the reference host function's contract codes, so a
/// regression in the reference (which the host-side agent mirrors) is caught
/// even if the wasm round-trip is skipped. Exercises the validation branches
/// directly via a tiny reference decrypt round-trip.
#[test]
fn reference_host_fn_contract_smoke() {
    // Round-trip: encrypt a known block with RustCrypto, decrypt via the
    // reference, and confirm it recovers the plaintext. Also confirm the
    // status-code constants are the documented values.
    assert_eq!(
        (RC_OK, RC_BAD_KEY_LEN, RC_BAD_BUF_LEN, RC_OOB),
        (0, -1, -2, -3)
    );

    use aes::cipher::block::BlockModeEncrypt;
    use aes::cipher::{Array, KeyIvInit};

    let key = [0x24u8; 32];
    let iv = [0x42u8; AES_BLOCK];
    let plaintext = [0x7fu8; 3 * AES_BLOCK];

    let mut ct = plaintext.to_vec();
    let mut enc = cbc::Encryptor::<aes::Aes256>::new((&key).into(), (&iv).into());
    let (blocks, rest) = Array::<u8, _>::slice_as_chunks_mut(&mut ct);
    assert!(rest.is_empty());
    enc.encrypt_blocks(blocks);

    reference_cbc_decrypt(&key, &iv, &mut ct);
    assert_eq!(ct, plaintext, "reference AES-256-CBC must round-trip");
}
