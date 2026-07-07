//! Encrypted-extraction conformance harness for the wasm host backends.
//!
//! This is the guest half of the `crypto-host` + `crc-host` CONFORMANCE test.
//! Built for `wasm32-wasip1` with `--no-default-features --features
//! crypto-host,crc-host`, it drives a FULL encrypted RAR extraction so that:
//!
//!   * every bulk AES-CBC decrypt crosses the wasm boundary to the host import
//!     `extism:host/user::scryer_aes_cbc_decrypt` (the `crypto-host` backend),
//!     and
//!   * every bulk member-data CRC-32 crosses to `extism:host/user::scryer_crc32`
//!     (the `crc-host` seam) — because `verify: true` makes the extractor check
//!     each member's stored CRC, and on wasm that CRC runs through the host.
//!
//! The KDF (PBKDF2 / RAR29 SHA-1) and the LZ decode stay in-wasm; only the two
//! bulk primitives are delegated. For each encrypted fixture it extracts the
//! member payload and BYTE-COMPARES it against the matching plaintext in
//! `originals/` (matched by basename, since the fixtures were created with RAR's
//! `-ep1`, which stores bare file names). A byte match through this path proves
//! the whole encrypted pipeline — host AES + in-wasm KDF/LZ + host CRC — is
//! correct end to end, not just a single AES call.
//!
//! The required matrix (all encrypted): rar5 AND rar4, x {store, lz}, x {single,
//! multivolume}.
//!
//! Build (wasm):
//!   RUSTFLAGS="-C target-feature=+simd128" cargo build --release \
//!     -p weaver-unrar --no-default-features --features crypto-host,crc-host \
//!     --target wasm32-wasip1 --example wasm_extract_conformance
//!
//! It is not meaningful under a bare `wasmtime` CLI: the `scryer_aes_cbc_decrypt`
//! and `scryer_crc32` imports are unsatisfied there and instantiation traps. Run
//! it through the native driver, which provides both reference host functions:
//!   cargo test -p weaver-unrar --test wasm_host_extract_conformance
//!
//! Also runnable natively for parity debugging (uses the portable backends):
//!   cargo run --release -p weaver-unrar --example wasm_extract_conformance -- <tests/fixtures>

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use weaver_unrar::{ExtractOptions, MemberInfo, RarArchive};

/// The encrypted fixture password (see tests/fixtures/generate_encrypted.sh and
/// generate_generated_matrix.sh — all encrypted fixtures share it).
const PW: &str = "testpass123";

/// One encrypted fixture in the conformance matrix. `original` is the basename
/// of the single expected member, resolved against `<root>/originals/`.
struct Case {
    label: &'static str,
    first: &'static str,
    rest: &'static [&'static str],
    original: &'static str,
}

/// Encrypted matrix: rar5 & rar4 x {store, lz} x {single, multivolume}. Every
/// case is password-encrypted, so every case exercises the host AES; `verify`
/// makes every case exercise the host CRC.
const CASES: &[Case] = &[
    // ---------- rar5 ----------
    Case {
        label: "rar5 store enc single",
        first: "rar5/rar5_enc_store.rar",
        rest: &[],
        original: "small.txt",
    },
    Case {
        label: "rar5 lz    enc single",
        first: "rar5/rar5_enc_lz.rar",
        rest: &[],
        original: "compressible.txt",
    },
    Case {
        label: "rar5 store enc mv    ",
        first: "rar5/rar5_enc_mv_store.part1.rar",
        rest: &[
            "rar5/rar5_enc_mv_store.part2.rar",
            "rar5/rar5_enc_mv_store.part3.rar",
            "rar5/rar5_enc_mv_store.part4.rar",
            "rar5/rar5_enc_mv_store.part5.rar",
        ],
        original: "binary.bin",
    },
    Case {
        label: "rar5 lz    enc mv    ",
        first: "rar5/generated_matrix_rar5_lz_enc.part1.rar",
        rest: &[
            "rar5/generated_matrix_rar5_lz_enc.part2.rar",
            "rar5/generated_matrix_rar5_lz_enc.part3.rar",
            "rar5/generated_matrix_rar5_lz_enc.part4.rar",
            "rar5/generated_matrix_rar5_lz_enc.part5.rar",
            "rar5/generated_matrix_rar5_lz_enc.part6.rar",
            "rar5/generated_matrix_rar5_lz_enc.part7.rar",
        ],
        original: "generated_matrix_clip.mkv",
    },
    // ---------- rar4 ----------
    Case {
        label: "rar4 store enc single",
        first: "rar4/rar4_enc_store.rar",
        rest: &[],
        original: "small.txt",
    },
    Case {
        label: "rar4 lz    enc single",
        first: "rar4/rar4_enc_lz.rar",
        rest: &[],
        original: "compressible.txt",
    },
    Case {
        label: "rar4 store enc mv    ",
        first: "rar4/rar4_enc_mv_store.part1.rar",
        rest: &[
            "rar4/rar4_enc_mv_store.part2.rar",
            "rar4/rar4_enc_mv_store.part3.rar",
            "rar4/rar4_enc_mv_store.part4.rar",
            "rar4/rar4_enc_mv_store.part5.rar",
        ],
        original: "binary.bin",
    },
    Case {
        label: "rar4 lz    enc mv    ",
        first: "rar4/generated_matrix_rar4_lz_enc.part1.rar",
        rest: &[
            "rar4/generated_matrix_rar4_lz_enc.part2.rar",
            "rar4/generated_matrix_rar4_lz_enc.part3.rar",
            "rar4/generated_matrix_rar4_lz_enc.part4.rar",
            "rar4/generated_matrix_rar4_lz_enc.part5.rar",
            "rar4/generated_matrix_rar4_lz_enc.part6.rar",
            "rar4/generated_matrix_rar4_lz_enc.part7.rar",
        ],
        original: "generated_matrix_clip.mkv",
    },
];

fn open_archive(root: &Path, case: &Case) -> Result<RarArchive, String> {
    let first_path = root.join(case.first);
    let first =
        File::open(&first_path).map_err(|e| format!("open {}: {e}", first_path.display()))?;

    let mut archive = RarArchive::open_with_password(first, PW)
        .map_err(|e| format!("open_with_password {}: {e:?}", first_path.display()))?;
    archive.set_password(PW);

    for (i, rel) in case.rest.iter().enumerate() {
        let p = root.join(rel);
        let f = File::open(&p).map_err(|e| format!("open volume {}: {e}", p.display()))?;
        archive
            .add_volume(i + 1, Box::new(f))
            .map_err(|e| format!("add_volume {}: {e:?}", p.display()))?;
    }
    Ok(archive)
}

/// Members with an extractable data payload (skip dirs / links).
fn is_data_member(m: &MemberInfo) -> bool {
    !m.is_directory && !m.is_symlink && !m.is_hardlink && !m.is_file_copy
}

/// Extract the single data member of an encrypted fixture (through host AES +
/// host CRC) and byte-compare it against its plaintext original. Returns the
/// number of bytes verified.
fn verify_case(root: &Path, case: &Case) -> Result<u64, String> {
    let mut archive = open_archive(root, case)?;
    // `verify: true` makes the extractor recompute and check each member's CRC
    // — on wasm that CRC crosses to the host `scryer_crc32`, so a clean extract
    // already proves the host CRC path; the explicit byte-compare below is the
    // stronger, independent check that the recovered plaintext is exactly right.
    let options = ExtractOptions {
        verify: true,
        password: Some(PW.to_string()),
        restore_owners: false,
    };

    let expected = {
        let p = root.join("originals").join(case.original);
        std::fs::read(&p).map_err(|e| format!("read original {}: {e}", p.display()))?
    };

    let members = archive.metadata().members;
    let member_count = members.len();

    let mut verified_any = false;
    let mut verified_bytes = 0u64;
    for (idx, member) in members.iter().enumerate() {
        if !is_data_member(member) {
            continue;
        }
        let extracted = archive.extract_member(idx, &options, None).map_err(|e| {
            format!(
                "[{}] extract_member {idx} ({}): {e:?}",
                case.label, member.name
            )
        })?;
        let bytes = extracted
            .into_bytes()
            .map_err(|e| format!("[{}] into_bytes {idx}: {e:?}", case.label))?;

        if bytes != expected {
            return Err(format!(
                "[{}] BYTE MISMATCH for member '{}' vs original '{}': got {} bytes, expected {} bytes",
                case.label,
                member.name,
                case.original,
                bytes.len(),
                expected.len()
            ));
        }
        verified_any = true;
        verified_bytes += bytes.len() as u64;
    }

    if !verified_any {
        return Err(format!(
            "[{}] no data members extracted (count={member_count})",
            case.label
        ));
    }
    Ok(verified_bytes)
}

fn main() {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/fixtures"));

    eprintln!(
        "wasm_extract_conformance: fixtures root = {} (host AES + host CRC)",
        root.display()
    );

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut rows: Vec<String> = Vec::new();

    for case in CASES {
        match verify_case(&root, case) {
            Ok(bytes) => {
                passed += 1;
                rows.push(format!(
                    "PASS | {:<22} | {:>11} bytes byte-identical to original",
                    case.label, bytes
                ));
            }
            Err(e) => {
                failed += 1;
                rows.push(format!("FAIL | {:<22} | {e}", case.label));
            }
        }
    }

    let mut stdout = io::stdout();
    let _ = writeln!(
        stdout,
        "==== encrypted extraction conformance (host AES + host CRC) ===="
    );
    for r in &rows {
        let _ = writeln!(stdout, "{r}");
    }
    let _ = writeln!(
        stdout,
        "================================================================"
    );
    let _ = writeln!(stdout, "passed={passed} failed={failed}");
    // WASI aborts do not flush libc stdout buffers; flush explicitly so the
    // report is never lost even if a later change reintroduces a panic.
    let _ = stdout.flush();

    if failed != 0 {
        std::process::exit(1);
    }
}
