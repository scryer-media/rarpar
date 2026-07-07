//! Throughput baseline for the crypto primitives, using only public APIs.
//!
//! Prints one tab-separated line per measurement:
//!   `<name>\t<MB/s>`      for byte-throughput measurements
//!   `rar5_kdf\t<derivations/s>` for the key-derivation measurement
//!
//! Which crypto backend runs depends on the build features (default is
//! AWS-LC; build with `--no-default-features --features crypto-rust` for the
//! portable path). The numbers are a rough single-thread baseline, not a
//! statistical benchmark: 1 warmup + 3 timed reps, best rep reported.
//!
//! Run:  cargo run --release --example crypto_baseline -p weaver-unrar

use std::time::Instant;

use weaver_unrar::crypto::{Blake2spHasher, CbcDecryptor, derive_rar5_material};

// Buffer sizes — kept as consts so they are easy to tweak.
const KDF_LG2_COUNT: u8 = 15; // 2^15 PBKDF2 iterations.
const CBC_TOTAL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB decrypted per rep.
const CBC_CHUNK_BYTES: usize = 64 * 1024; // 64 KiB decrypt chunks.
const HASH_TOTAL_BYTES: usize = 32 * 1024 * 1024; // 32 MiB hashed per rep.
const HASH_CHUNK_BYTES: usize = 64 * 1024; // 64 KiB hash updates.

const WARMUP_REPS: usize = 1;
const TIMED_REPS: usize = 3;

/// Run `f` once to warm up, then `TIMED_REPS` times; return the shortest
/// elapsed duration in seconds (best throughput).
fn best_secs(mut f: impl FnMut()) -> f64 {
    for _ in 0..WARMUP_REPS {
        f();
    }
    let mut best = f64::INFINITY;
    for _ in 0..TIMED_REPS {
        let start = Instant::now();
        f();
        best = best.min(start.elapsed().as_secs_f64());
    }
    best
}

fn mb_per_s(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

fn main() {
    // --- rar5_kdf: derivations per second ---
    {
        let salt = [0x5Au8; 16];
        // Prevent the optimizer from eliding the derivation.
        let mut sink = 0u8;
        let secs = best_secs(|| {
            let material =
                derive_rar5_material("correct horse battery staple", &salt, KDF_LG2_COUNT)
                    .expect("kdf");
            sink ^= material.key[0];
        });
        std::hint::black_box(sink);
        println!("rar5_kdf\t{:.2}", 1.0 / secs);
    }

    // --- aes256_cbc_decrypt: MB/s over 64 MiB in 64 KiB chunks ---
    {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        // Random-ish ciphertext; content is irrelevant to decrypt throughput.
        let mut buf = vec![0u8; CBC_TOTAL_BYTES];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        let secs = best_secs(|| {
            let mut dec = CbcDecryptor::new(&key, &iv);
            for chunk in buf.chunks_mut(CBC_CHUNK_BYTES) {
                dec.decrypt_blocks(chunk);
            }
        });
        std::hint::black_box(buf[0]);
        println!("aes256_cbc_decrypt\t{:.2}", mb_per_s(CBC_TOTAL_BYTES, secs));
    }

    // --- blake2sp: MB/s over 32 MiB in 64 KiB updates ---
    {
        let data = vec![0x5Cu8; HASH_TOTAL_BYTES];
        let mut sink = 0u8;
        let secs = best_secs(|| {
            let mut hasher = Blake2spHasher::new();
            for chunk in data.chunks(HASH_CHUNK_BYTES) {
                hasher.update(chunk);
            }
            sink ^= hasher.finalize()[0];
        });
        std::hint::black_box(sink);
        println!("blake2sp\t{:.2}", mb_per_s(HASH_TOTAL_BYTES, secs));
    }

    // --- crc32: MB/s over 32 MiB in 64 KiB updates ---
    {
        let data = vec![0x3Cu8; HASH_TOTAL_BYTES];
        let mut sink = 0u32;
        let secs = best_secs(|| {
            let mut hasher = crc32fast::Hasher::new();
            for chunk in data.chunks(HASH_CHUNK_BYTES) {
                hasher.update(chunk);
            }
            sink ^= hasher.finalize();
        });
        std::hint::black_box(sink);
        println!("crc32\t{:.2}", mb_per_s(HASH_TOTAL_BYTES, secs));
    }
}
