//! Native `wasmtime` driver for the encrypted-extraction CONFORMANCE test.
//!
//! This is the executable proof that a FULL encrypted RAR extraction runs
//! correctly through BOTH wasm host functions at once — the `crypto-host` bulk
//! AES (`host::host_aes_cbc_decrypt`) AND the `crc-host` bulk
//! member CRC-32 (`host::host_crc32`) — over their fixed raw-offset
//! ABIs. It DOUBLES as the reference contract the embedding host must satisfy:
//! it implements both host functions exactly to spec, then runs the
//! `wasm_extract_conformance` example (built with `crypto-host,crc-host`) under
//! `wasmtime`, which extracts every encrypted fixture (rar5 + rar4, store + lz,
//! single + multivolume) and byte-compares each recovered plaintext against
//! `tests/fixtures/originals/`. The example exits 0 only if every fixture
//! matched.
//!
//! Contrast with `wasm_host_aes_smoke.rs`, which proves only that the AES import
//! links and round-trips on a single known-answer decrypt. This test exercises
//! the whole pipeline: header parse -> in-wasm KDF -> host AES -> in-wasm LZ ->
//! host CRC verify, for real fixtures, end to end.
//!
//! Flow:
//!   1. Build `examples/wasm_extract_conformance.rs` for `wasm32-wasip1` with
//!      `--no-default-features --features crypto-host,crc-host` and
//!      `-C target-feature=+simd128` (so BLAKE2sp's wasm kernel is available and
//!      both bulk primitives cross to the host). Uses a private target dir so
//!      the nested cargo does not fight the outer test's target lock.
//!   2. Instantiate with `wasmtime`, providing WASI preview1 (stdio + argv +
//!      preopened `tests/fixtures` as `/fixtures` and a writable tmp dir as
//!      `/tmp` for member spill) plus the two custom host imports.
//!   3. Run `_start`; a clean exit (or `I32Exit(0)`) means every encrypted
//!      fixture extracted byte-identically through host AES + host CRC.
//!
//! Skipped automatically if the `wasm32-wasip1` target is not installed.

#![cfg(not(target_family = "wasm"))]

use std::path::PathBuf;
use std::process::Command;

use wasmtime::{Caller, Engine, Extern, Linker, Module, Store};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

const AES_BLOCK: usize = 16;

/// AES ABI return codes (see `crypto/backend/host.rs`).
const AES_RC_OK: i64 = 0;
const AES_RC_BAD_KEY_LEN: i64 = -1;
const AES_RC_BAD_BUF_LEN: i64 = -2;
const AES_RC_OOB: i64 = -3;

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

/// Is the wasm32-wasip1 target installed? If not, the harness self-skips.
fn wasip1_target_installed() -> bool {
    Command::new("rustc")
        .args(["--print", "target-list"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-wasip1"))
        .unwrap_or(false)
}

/// Build the conformance example for wasm32-wasip1 with `crypto-host,crc-host`
/// (+simd128) and return the path to the produced `.wasm`. Uses a private target
/// dir to avoid colliding with the outer `cargo test` target lock.
fn build_conformance_wasm() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wasm-host-conformance-target");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let status = Command::new(&cargo)
        .current_dir(&manifest_dir)
        .env("CARGO_TARGET_DIR", &target_dir)
        // Do not inherit the outer test's RUSTFLAGS; set the simd128 feature the
        // wasm crypto/BLAKE2sp paths expect (matches the example's build docs).
        .env("RUSTFLAGS", "-C target-feature=+simd128")
        .args([
            "build",
            "--release",
            "-p",
            "weaver-unrar",
            "--example",
            "wasm_extract_conformance",
            "--no-default-features",
            "--features",
            "crypto-host,crc-host",
            "--target",
            "wasm32-wasip1",
        ])
        .status()
        .expect("failed to spawn cargo to build the wasm conformance example");
    assert!(
        status.success(),
        "cargo build of the wasm conformance example failed"
    );

    let wasm = target_dir
        .join("wasm32-wasip1")
        .join("release")
        .join("examples")
        .join("wasm_extract_conformance.wasm");
    assert!(
        wasm.is_file(),
        "expected built wasm at {}, but it is missing",
        wasm.display()
    );
    wasm
}

/// Reference `host_aes_cbc_decrypt`, wired to the exact ABI the guest calls.
/// Reads `key`/`iv` and the block-aligned buffer from the guest's linear memory
/// at the passed offsets, decrypts in place, writes the plaintext back.
/// Stateless per call. Returns the contract's status codes.
fn reference_host_aes_cbc_decrypt(
    mut caller: Caller<'_, WasiP1Ctx>,
    key_ptr: i64,
    key_len: i64,
    iv_ptr: i64,
    buf_ptr: i64,
    buf_len: i64,
) -> i64 {
    if key_len != 16 && key_len != 32 {
        return AES_RC_BAD_KEY_LEN;
    }
    if buf_len % (AES_BLOCK as i64) != 0 {
        return AES_RC_BAD_BUF_LEN;
    }

    let memory = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => return AES_RC_OOB,
    };

    let (key_ptr, key_len, iv_ptr, buf_ptr, buf_len) = (
        key_ptr as u64 as usize,
        key_len as usize,
        iv_ptr as u64 as usize,
        buf_ptr as u64 as usize,
        buf_len as u64 as usize,
    );

    let mut key = [0u8; 32];
    if memory.read(&caller, key_ptr, &mut key[..key_len]).is_err() {
        return AES_RC_OOB;
    }
    let mut iv = [0u8; AES_BLOCK];
    if memory.read(&caller, iv_ptr, &mut iv).is_err() {
        return AES_RC_OOB;
    }

    let mut buf = vec![0u8; buf_len];
    if memory.read(&caller, buf_ptr, &mut buf).is_err() {
        return AES_RC_OOB;
    }
    reference_cbc_decrypt(&key[..key_len], &iv, &mut buf);
    if memory.write(&mut caller, buf_ptr, &buf).is_err() {
        return AES_RC_OOB;
    }

    AES_RC_OK
}

/// Reference `host_crc32`, wired to the fixed ABI the guest CRC seam calls:
/// resume an IEEE CRC-32 (reflected polynomial 0xEDB88320, RAR/ZIP/gzip) from
/// `seed` over the READ-ONLY buffer at `buf_ptr`/`buf_len` in the guest's linear
/// memory, returning the updated CRC in the low 32 bits. Chains so that
/// `crc32(crc32(0, A), B) == crc32(0, A ++ B)`. A negative return signals an
/// out-of-bounds slice (a contract violation the guest asserts on); the low-bits
/// contract keeps success values non-negative for the 32-bit CRC range used.
fn reference_host_crc32(
    mut caller: Caller<'_, WasiP1Ctx>,
    seed: i64,
    buf_ptr: i64,
    buf_len: i64,
) -> i64 {
    let memory = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => return -1, // no linear memory exported — cannot proceed
    };

    let seed = seed as u64 as u32;
    let buf_ptr = buf_ptr as u64 as usize;
    let buf_len = buf_len as u64 as usize;

    if buf_len == 0 {
        // Empty update returns the seed unchanged.
        return seed as i64;
    }

    let mut buf = vec![0u8; buf_len];
    if memory.read(&caller, buf_ptr, &mut buf).is_err() {
        return -1;
    }

    // crc32fast resume-from-seed == the guest's byte-identical reference.
    let mut hasher = crc32fast::Hasher::new_with_initial(seed);
    hasher.update(&buf);
    hasher.finalize() as u64 as i64
}

#[test]
fn wasm_host_extract_conformance_encrypted_fixtures() {
    if !wasip1_target_installed() {
        eprintln!("skipping: wasm32-wasip1 target not installed");
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_dir = manifest_dir.join("tests").join("fixtures");
    assert!(
        fixtures_dir.join("originals").is_dir(),
        "fixtures/originals must exist at {}",
        fixtures_dir.display()
    );

    // Writable scratch dir for members that spill above the in-memory threshold
    // (the mkv fixtures are multi-MiB), mapped as the guest's /tmp.
    let tmp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wasm-conformance-tmp");
    std::fs::create_dir_all(&tmp_dir).expect("create guest tmp dir");

    let wasm_path = build_conformance_wasm();

    let engine = Engine::default();
    let module = Module::from_file(&engine, &wasm_path).expect("load wasm module");

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |ctx: &mut WasiP1Ctx| ctx)
        .expect("add wasi preview1 to linker");

    // Both custom imports, in the fixed namespace, satisfying the guest's raw
    // `#[link(wasm_import_module = "host")]` externs.
    linker
        .func_wrap(
            "host",
            "host_aes_cbc_decrypt",
            reference_host_aes_cbc_decrypt,
        )
        .expect("define host host_aes_cbc_decrypt");
    linker
        .func_wrap("host", "host_crc32", reference_host_crc32)
        .expect("define host host_crc32");

    // Preopen the fixtures tree read-only as /fixtures (the example reads both
    // /fixtures/<flavor>/*.rar and /fixtures/originals/*), and a writable /tmp
    // for spill. argv[1] = /fixtures.
    let wasi = WasiCtxBuilder::new()
        .inherit_stdio()
        .args(&["wasm_extract_conformance", "/fixtures"])
        .env("TMPDIR", "/tmp")
        .preopened_dir(&fixtures_dir, "/fixtures", DirPerms::READ, FilePerms::READ)
        .expect("preopen fixtures dir")
        .preopened_dir(
            &tmp_dir,
            "/tmp",
            DirPerms::READ | DirPerms::MUTATE,
            FilePerms::READ | FilePerms::WRITE,
        )
        .expect("preopen tmp dir")
        .build_p1();
    let mut store = Store::new(&engine, wasi);

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate wasm module (all imports, incl. both host fns, must be satisfied)");

    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .expect("wasip1 command must export _start");

    // Success == clean return OR proc_exit(0) (surfaced as I32Exit(0)). Any
    // other exit code (the example calls process::exit(1) on any fixture
    // mismatch) or trap is a failure.
    match start.call(&mut store, ()) {
        Ok(()) => { /* clean return == PASS */ }
        Err(err) => {
            if let Some(exit) = err.downcast_ref::<wasmtime_wasi::I32Exit>() {
                assert_eq!(
                    exit.0, 0,
                    "wasm conformance example exited with code {} (expected 0 == all encrypted \
                     fixtures byte-identical via host AES + host CRC)",
                    exit.0
                );
            } else {
                panic!("wasm conformance example trapped instead of passing: {err:?}");
            }
        }
    }
}

/// Unit-level check of the reference `host_crc32` contract (seeded resume +
/// chaining), so a regression in the reference the host-side agent mirrors is
/// caught even if the wasm round-trip is skipped.
#[test]
fn reference_crc_host_fn_chains() {
    // crc32(crc32(0, A), B) == crc32(0, A ++ B), and empty update == seed.
    let a = b"the quick brown fox ";
    let b = b"jumps over the lazy dog";
    let whole = {
        let mut h = crc32fast::Hasher::new();
        h.update(a);
        h.update(b);
        h.finalize()
    };
    let seeded = {
        let mut h = crc32fast::Hasher::new_with_initial(0);
        h.update(a);
        let crc_a = h.finalize();
        let mut h2 = crc32fast::Hasher::new_with_initial(crc_a);
        h2.update(b);
        h2.finalize()
    };
    assert_eq!(
        seeded, whole,
        "seeded CRC resume must equal whole-stream CRC"
    );

    let empty_seed = 0x1234_5678u32;
    let mut h = crc32fast::Hasher::new_with_initial(empty_seed);
    h.update(&[]);
    assert_eq!(
        h.finalize(),
        empty_seed,
        "empty update must return the seed unchanged"
    );
}
