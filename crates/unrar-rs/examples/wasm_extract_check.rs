//! End-to-end wasm extraction harness (Phase 1 runtime de-risk).
//!
//! Given a preopened fixtures directory, this opens each RAR fixture as a real
//! `std::fs::File` (real WASI I/O), extracts every regular-file member, and
//! reports PASS/FAIL per fixture. The extractor verifies each member's CRC32 /
//! BLAKE2sp internally when `verify: true`, so a clean completion means the
//! decrypted / decompressed output is correct.
//!
//!   * Non-solid members go through the in-memory `extract_member` API, which
//!     drives the streaming LZ/PPMd decode + the `ExtractedMemberSink` spool
//!     (memory below 1 MiB, `NamedTempFile` above it). The harness reports how
//!     many members spilled to a temp file so the spill path is observably
//!     exercised, not just compiled.
//!   * Solid members go through `extract_member_solid_chunked` (the chunked
//!     decode path that Gate 2 forces onto the single-thread route on wasm),
//!     capturing bytes into an in-memory buffer.
//!
//! Build (wasm):
//!   RUSTFLAGS="-C target-feature=+simd128" cargo build --release \
//!     -p unrar-rs --no-default-features --features crypto-rust \
//!     --target wasm32-wasip1 --example wasm_extract_check
//!
//! Run (wasmtime 47; host::guest preopens):
//!   wasmtime run --dir <fixtures>::/fixtures --dir <tmp>::/tmp --env TMPDIR=/tmp \
//!     target/wasm32-wasip1/release/examples/wasm_extract_check.wasm /fixtures
//!
//! Also runnable natively for parity debugging:
//!   cargo run --release -p unrar-rs --example wasm_extract_check -- <fixtures>

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use unrar_rs::{ExtractOptions, ExtractedMember, MemberInfo, RarArchive};

/// One fixture in the matrix.
struct Case {
    label: &'static str,
    first: &'static str,
    rest: &'static [&'static str],
    password: Option<&'static str>,
}

const PW: Option<&'static str> = Some("testpass123");

/// The required matrix: rar5 & rar4 x {store/plain, lz, enc} x {single, mv},
/// plus solid + PPMd rows for broader runtime coverage.
const CASES: &[Case] = &[
    // ---------- rar5 ----------
    Case {
        label: "rar5 store plain single",
        first: "rar5/rar5_store.rar",
        rest: &[],
        password: None,
    },
    Case {
        label: "rar5 lz    plain single",
        first: "rar5/rar5_lz.rar",
        rest: &[],
        password: None,
    },
    Case {
        label: "rar5 lz    enc   single",
        first: "rar5/rar5_enc_lz.rar",
        rest: &[],
        password: PW,
    },
    Case {
        label: "rar5 store enc   single",
        first: "rar5/rar5_enc_store.rar",
        rest: &[],
        password: PW,
    },
    Case {
        label: "rar5 lz    plain SOLID ",
        first: "rar5/rar5_solid.rar",
        rest: &[],
        password: None,
    },
    Case {
        label: "rar5 store plain mv    ",
        first: "rar5/rar5_mv_store.part1.rar",
        rest: &[
            "rar5/rar5_mv_store.part2.rar",
            "rar5/rar5_mv_store.part3.rar",
            "rar5/rar5_mv_store.part4.rar",
            "rar5/rar5_mv_store.part5.rar",
        ],
        password: None,
    },
    Case {
        label: "rar5 lz    plain mv    ",
        first: "rar5/generated_matrix_rar5_lz_plain.part1.rar",
        rest: &[
            "rar5/generated_matrix_rar5_lz_plain.part2.rar",
            "rar5/generated_matrix_rar5_lz_plain.part3.rar",
            "rar5/generated_matrix_rar5_lz_plain.part4.rar",
            "rar5/generated_matrix_rar5_lz_plain.part5.rar",
            "rar5/generated_matrix_rar5_lz_plain.part6.rar",
            "rar5/generated_matrix_rar5_lz_plain.part7.rar",
        ],
        password: None,
    },
    Case {
        label: "rar5 lz    enc   mv    ",
        first: "rar5/generated_matrix_rar5_lz_enc.part1.rar",
        rest: &[
            "rar5/generated_matrix_rar5_lz_enc.part2.rar",
            "rar5/generated_matrix_rar5_lz_enc.part3.rar",
            "rar5/generated_matrix_rar5_lz_enc.part4.rar",
            "rar5/generated_matrix_rar5_lz_enc.part5.rar",
            "rar5/generated_matrix_rar5_lz_enc.part6.rar",
            "rar5/generated_matrix_rar5_lz_enc.part7.rar",
        ],
        password: PW,
    },
    Case {
        label: "rar5 store enc   mv    ",
        first: "rar5/rar5_enc_mv_store.part1.rar",
        rest: &[
            "rar5/rar5_enc_mv_store.part2.rar",
            "rar5/rar5_enc_mv_store.part3.rar",
            "rar5/rar5_enc_mv_store.part4.rar",
            "rar5/rar5_enc_mv_store.part5.rar",
        ],
        password: PW,
    },
    // ---------- rar4 ----------
    Case {
        label: "rar4 store plain single",
        first: "rar4/rar4_store.rar",
        rest: &[],
        password: None,
    },
    Case {
        label: "rar4 lz    plain single",
        first: "rar4/rar4_lz.rar",
        rest: &[],
        password: None,
    },
    Case {
        label: "rar4 lz    enc   single",
        first: "rar4/rar4_enc_lz.rar",
        rest: &[],
        password: PW,
    },
    Case {
        label: "rar4 store enc   single",
        first: "rar4/rar4_enc_store.rar",
        rest: &[],
        password: PW,
    },
    Case {
        label: "rar4 lz    plain SOLID ",
        first: "rar4/rar4_solid.rar",
        rest: &[],
        password: None,
    },
    Case {
        label: "rar4 ppmd  plain SOLID ",
        first: "rar4/rar4_ppm_solid_restart.rar",
        rest: &[],
        password: None,
    },
    Case {
        label: "rar4 store plain mv    ",
        first: "rar4/rar4_mv_store.part1.rar",
        rest: &[
            "rar4/rar4_mv_store.part2.rar",
            "rar4/rar4_mv_store.part3.rar",
            "rar4/rar4_mv_store.part4.rar",
            "rar4/rar4_mv_store.part5.rar",
        ],
        password: None,
    },
    Case {
        label: "rar4 lz    plain mv    ",
        first: "rar4/generated_matrix_rar4_lz_plain.part1.rar",
        rest: &[
            "rar4/generated_matrix_rar4_lz_plain.part2.rar",
            "rar4/generated_matrix_rar4_lz_plain.part3.rar",
            "rar4/generated_matrix_rar4_lz_plain.part4.rar",
            "rar4/generated_matrix_rar4_lz_plain.part5.rar",
            "rar4/generated_matrix_rar4_lz_plain.part6.rar",
            "rar4/generated_matrix_rar4_lz_plain.part7.rar",
        ],
        password: None,
    },
    Case {
        label: "rar4 lz    enc   mv    ",
        first: "rar4/generated_matrix_rar4_lz_enc.part1.rar",
        rest: &[
            "rar4/generated_matrix_rar4_lz_enc.part2.rar",
            "rar4/generated_matrix_rar4_lz_enc.part3.rar",
            "rar4/generated_matrix_rar4_lz_enc.part4.rar",
            "rar4/generated_matrix_rar4_lz_enc.part5.rar",
            "rar4/generated_matrix_rar4_lz_enc.part6.rar",
            "rar4/generated_matrix_rar4_lz_enc.part7.rar",
        ],
        password: PW,
    },
    Case {
        label: "rar4 store enc   mv    ",
        first: "rar4/rar4_enc_mv_store.part1.rar",
        rest: &[
            "rar4/rar4_enc_mv_store.part2.rar",
            "rar4/rar4_enc_mv_store.part3.rar",
            "rar4/rar4_enc_mv_store.part4.rar",
            "rar4/rar4_enc_mv_store.part5.rar",
        ],
        password: PW,
    },
    Case {
        label: "rar4 lz    plain SOLIDmv",
        first: "rar4/rar4_lz_solid_mv.rar",
        rest: &[],
        password: None,
    },
    Case {
        label: "rar4 ppmd  plain SOLIDmv",
        first: "rar4/rar4_ppm_solid_mv.rar",
        rest: &[],
        password: None,
    },
];

/// Per-fixture extraction outcome.
struct Outcome {
    members_extracted: usize,
    total_bytes: u64,
    spilled_members: usize,
    /// Rolling digest over every extracted member's name and bytes, in member
    /// order. The extractor already verifies each member's CRC32/BLAKE2sp
    /// internally, so this is not a second correctness check — it is the
    /// cross-lane identity gate: native and every wasm lane must agree on the
    /// exact decoded bytes, which a per-member CRC verified independently on
    /// each side cannot demonstrate on its own.
    digest: u64,
}

/// FNV-1a-64 with a final avalanche, length-folded so truncation cannot alias.
fn digest64(state: u64, bytes: &[u8]) -> u64 {
    let mut hash = state;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= bytes.len() as u64;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^ (hash >> 33)
}

/// Which arithmetic build this binary is, for the report header.
fn lane_label() -> &'static str {
    if cfg!(all(target_arch = "wasm32", target_feature = "relaxed-simd")) {
        "wasm32 +simd128 +relaxed-simd"
    } else if cfg!(all(target_arch = "wasm32", target_feature = "simd128")) {
        "wasm32 +simd128"
    } else if cfg!(target_arch = "wasm32") {
        "wasm32 portable (no simd128)"
    } else {
        "native"
    }
}

/// Timing-mode iteration count; `0` (the default) means PASS/FAIL mode.
fn bench_iters() -> usize {
    std::env::var("WEAVER_WASM_BENCH")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

/// A `Write` that appends into a shared in-memory buffer. Single-threaded only,
/// which is exactly the wasm extraction model (Gate 2 forces single-thread).
#[derive(Clone)]
struct SharedVecWriter(Rc<RefCell<Vec<u8>>>);

impl Write for SharedVecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn open_archive(root: &Path, case: &Case) -> Result<RarArchive, String> {
    let first_path = root.join(case.first);
    let first =
        File::open(&first_path).map_err(|e| format!("open {}: {e}", first_path.display()))?;

    let mut archive = match case.password {
        Some(pw) => RarArchive::open_with_password(first, pw)
            .map_err(|e| format!("open_with_password {}: {e:?}", first_path.display()))?,
        None => {
            RarArchive::open(first).map_err(|e| format!("open {}: {e:?}", first_path.display()))?
        }
    };
    if let Some(pw) = case.password {
        archive.set_password(pw);
    }

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

fn extract_case(root: &Path, case: &Case) -> Result<Outcome, String> {
    let mut archive = open_archive(root, case)?;
    // The archive already carries the password and verifies by default. These
    // options exist for `extract_member` alone, which the non-solid arm below
    // still needs: whether a member spooled to a temporary file is only
    // observable through the `ExtractedMember` it returns, and that is what
    // this check is here to report on wasm.
    let options = ExtractOptions {
        verify: true,
        password: case.password.map(String::from),
        restore_owners: false,
    };

    let members = archive.metadata().members;
    let member_count = members.len();
    let solid = archive.is_solid();

    let mut out = Outcome {
        members_extracted: 0,
        total_bytes: 0,
        spilled_members: 0,
        digest: 0xcbf2_9ce4_8422_2325,
    };

    for (idx, member) in members.iter().enumerate().take(member_count) {
        if !is_data_member(member) {
            continue;
        }

        if solid {
            // Chunked solid decode into an in-memory buffer. The factory may be
            // called once per volume-transition; all calls share one buffer so
            // we measure the full member payload.
            let buf = Rc::new(RefCell::new(Vec::<u8>::new()));
            let writer_buf = Rc::clone(&buf);
            archive
                .by_index(idx)
                .and_then(|entry| {
                    entry.copy_to_volumes(move |_transition| {
                        Ok(SharedVecWriter(Rc::clone(&writer_buf)))
                    })
                })
                .map_err(|e| {
                    format!(
                        "[{}] solid member {idx} ({}): {e:?}",
                        case.label, member.name
                    )
                })?;
            out.members_extracted += 1;
            out.total_bytes += buf.borrow().len() as u64;
            out.digest = digest64(out.digest, member.name.as_bytes());
            out.digest = digest64(out.digest, &buf.borrow());
        } else {
            // Deliberately the buffered entry point: the spool decision this
            // check reports is carried by `ExtractedMember` and nothing else.
            #[allow(deprecated)]
            let extracted = archive.extract_member(idx, &options, None).map_err(|e| {
                format!(
                    "[{}] extract_member {idx} ({}): {e:?}",
                    case.label, member.name
                )
            })?;
            out.members_extracted += 1;
            out.total_bytes += extracted.len() as u64;
            if matches!(extracted, ExtractedMember::TempFile { .. }) {
                out.spilled_members += 1;
            }
            let bytes = extracted.to_bytes().map_err(|e| {
                format!(
                    "[{}] materialize member {idx} ({}): {e:?}",
                    case.label, member.name
                )
            })?;
            out.digest = digest64(out.digest, member.name.as_bytes());
            out.digest = digest64(out.digest, &bytes);
        }
    }

    if out.members_extracted == 0 {
        return Err(format!(
            "[{}] no data members extracted (count={member_count})",
            case.label
        ));
    }
    Ok(out)
}

fn main() {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/fixtures"));

    eprintln!("wasm_extract_check: fixtures root = {}", root.display());

    if bench_iters() > 0 {
        run_bench(&root);
        return;
    }

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut total_spilled = 0usize;
    let mut rows: Vec<String> = Vec::new();

    for case in CASES {
        match extract_case(&root, case) {
            Ok(o) => {
                passed += 1;
                total_spilled += o.spilled_members;
                rows.push(format!(
                    "PASS | {:<24} | {:>3} members | {:>11} bytes | spill={} | digest={:016x}",
                    case.label, o.members_extracted, o.total_bytes, o.spilled_members, o.digest
                ));
            }
            Err(e) => {
                failed += 1;
                rows.push(format!("FAIL | {:<24} | {e}", case.label));
            }
        }
    }

    let mut stdout = io::stdout();
    let _ = writeln!(stdout, "lane={}", lane_label());
    let _ = writeln!(stdout, "==== wasm extraction PASS/FAIL ====");
    for r in &rows {
        let _ = writeln!(stdout, "{r}");
    }
    let _ = writeln!(stdout, "===================================");
    let _ = writeln!(
        stdout,
        "passed={passed} failed={failed} tempfile_spilled_members={total_spilled}"
    );
    // WASI aborts do not flush libc stdout buffers; flush explicitly so the
    // report is never lost even if a later change reintroduces a panic.
    let _ = stdout.flush();

    if failed != 0 {
        std::process::exit(1);
    }
}

/// Timing mode: min-of-N decode wall time per fixture for this lane.
///
/// Min-of-N rather than mean, because this machine may be running other work:
/// the minimum is the least contaminated estimate. Absolute values are only
/// meaningful relative to the other lanes measured in the same session.
fn run_bench(root: &Path) {
    let iters = bench_iters();
    let mut stdout = io::stdout();
    let _ = writeln!(stdout, "lane={}", lane_label());
    let _ = writeln!(
        stdout,
        "==== RAR extraction timing, min of {iters} (seconds; lower is better) ===="
    );
    let _ = writeln!(
        stdout,
        "{:<26} | {:>10} | {:>12} | {:>10}",
        "fixture", "best_s", "bytes", "MiB/s"
    );

    for case in CASES {
        let mut best = f64::MAX;
        let mut bytes = 0u64;
        let mut error: Option<String> = None;
        for _ in 0..iters {
            let start = std::time::Instant::now();
            match extract_case(root, case) {
                Ok(o) => {
                    let elapsed = start.elapsed().as_secs_f64();
                    bytes = o.total_bytes;
                    if elapsed < best {
                        best = elapsed;
                    }
                }
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        match error {
            Some(e) => {
                let _ = writeln!(stdout, "{:<26} | ERR {e}", case.label);
            }
            None => {
                let throughput = (bytes as f64) / best / (1024.0 * 1024.0);
                let _ = writeln!(
                    stdout,
                    "{:<26} | {:>10.4} | {:>12} | {:>10.1}",
                    case.label, best, bytes, throughput
                );
            }
        }
        let _ = stdout.flush();
    }
    let _ = writeln!(stdout, "===================================");
    let _ = stdout.flush();
}
