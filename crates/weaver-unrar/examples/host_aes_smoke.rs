//! WASM smoke test for the host-delegated AES backend (`crypto-host`).
//!
//! Built for `wasm32-wasip1` with `--features crypto-host`, this decrypts a
//! KNOWN AES-256-CBC (no-padding) vector through the public
//! [`weaver_unrar::crypto::CbcDecryptor`], which on this build routes into the
//! `backend::host` `Aes256CbcDec` and therefore calls the real host import
//! `extism:host/user::scryer_aes_cbc_decrypt` over the fixed raw-offset ABI.
//!
//! The ciphertext is decrypted in SEVERAL block-sized chunks so the guest CBC
//! IV chaining is exercised end-to-end across host calls, not just a single
//! shot. It prints a one-line `PASS`/`FAIL` and exits non-zero on any mismatch,
//! so the native `wasmtime` harness (tests/wasm_host_aes_smoke.rs) can assert on
//! it. That harness supplies a reference `scryer_aes_cbc_decrypt`, making this
//! example the executable reference the host-side agent must satisfy.
//!
//! Build & run (from the workspace root):
//!   cargo build --release --example host_aes_smoke \
//!     -p weaver-unrar --no-default-features --features crypto-host \
//!     --target wasm32-wasip1
//!   # then run under the harness, which provides the host function:
//!   cargo test -p weaver-unrar --test wasm_host_aes_smoke
//!
//! Running the raw module under a plain `wasmtime` CLI will trap at
//! instantiation because the `scryer_aes_cbc_decrypt` import is unsatisfied —
//! that is expected; the module is only meaningful with a host that provides it.

use weaver_unrar::crypto::CbcDecryptor;

// Known AES-256-CBC (no padding) vector, generated with RustCrypto AES-256-CBC.
// 5 blocks (80 bytes) so a chunked decrypt threads the IV across boundaries.
// `EXPECTED_PLAINTEXT[i] == (i * 37) ^ 0xA5`.
const KEY: [u8; 32] = [
    0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e, 0x65, 0x6c,
    0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc,
];
const IV: [u8; 16] = [
    0x05, 0x12, 0x1f, 0x2c, 0x39, 0x46, 0x53, 0x60, 0x6d, 0x7a, 0x87, 0x94, 0xa1, 0xae, 0xbb, 0xc8,
];
const CIPHERTEXT: [u8; 80] = [
    0x18, 0xe1, 0x2c, 0xd6, 0x87, 0x87, 0x68, 0x68, 0xc1, 0x38, 0x9f, 0x28, 0x91, 0x0f, 0x0c, 0xcd,
    0xdc, 0xb1, 0x02, 0xfe, 0x8d, 0xe9, 0x87, 0x7f, 0x10, 0xbd, 0xf3, 0x11, 0xa9, 0x3c, 0x82, 0xec,
    0xed, 0x36, 0x47, 0x93, 0x00, 0x8c, 0xc1, 0x63, 0x78, 0x29, 0xff, 0x06, 0x2b, 0x8c, 0x9d, 0xa4,
    0xbd, 0x55, 0x46, 0x05, 0x28, 0xc9, 0x82, 0x90, 0x63, 0xf3, 0x84, 0x33, 0xbc, 0xa1, 0xbc, 0x08,
    0x51, 0x45, 0xbd, 0x7b, 0x1a, 0x14, 0x62, 0xa8, 0x20, 0xf6, 0x68, 0xc6, 0x5b, 0xd9, 0x4e, 0x30,
];
const EXPECTED_PLAINTEXT: [u8; 80] = [
    0xa5, 0x80, 0xef, 0xca, 0x31, 0x1c, 0x7b, 0xa6, 0x8d, 0xe8, 0xd7, 0x32, 0x19, 0x44, 0xa3, 0x8e,
    0xf5, 0xd0, 0x3f, 0x1a, 0x41, 0xac, 0x8b, 0xf6, 0xdd, 0x38, 0x67, 0x42, 0xa9, 0x94, 0xf3, 0xde,
    0x05, 0x60, 0x4f, 0xaa, 0x91, 0xfc, 0xdb, 0x06, 0x6d, 0x48, 0xb7, 0x92, 0xf9, 0x24, 0x03, 0x6e,
    0x55, 0xb0, 0x9f, 0xfa, 0x21, 0x0c, 0x6b, 0x56, 0xbd, 0x98, 0xc7, 0x22, 0x09, 0x74, 0x53, 0xbe,
    0xe5, 0xc0, 0x2f, 0x0a, 0x71, 0x5c, 0xbb, 0xe6, 0xcd, 0x28, 0x17, 0x72, 0x59, 0x84, 0xe3, 0xce,
];

/// Chunk boundaries (block multiples) that sum to 80 bytes: 1 + 2 + 1 + 1 block
/// splits, forcing the IV to be threaded across four separate host calls.
const CHUNK_BLOCKS: [usize; 4] = [1, 2, 1, 1];

fn main() {
    let mut buf = CIPHERTEXT.to_vec();
    let mut dec = CbcDecryptor::new(&KEY, &IV);

    let mut offset = 0usize;
    for &blocks in &CHUNK_BLOCKS {
        let len = blocks * 16;
        dec.decrypt_blocks(&mut buf[offset..offset + len]);
        offset += len;
    }
    assert_eq!(offset, buf.len(), "chunk sizes must cover the whole buffer");

    if buf == EXPECTED_PLAINTEXT {
        println!(
            "PASS host_aes_smoke: AES-256-CBC via host import, {} bytes, IV chained across {} chunks",
            buf.len(),
            CHUNK_BLOCKS.len()
        );
    } else {
        let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        eprintln!(
            "FAIL host_aes_smoke: decrypt mismatch\n  got     = {}\n  expected= {}",
            hex(&buf),
            hex(&EXPECTED_PLAINTEXT)
        );
        std::process::exit(1);
    }
}
