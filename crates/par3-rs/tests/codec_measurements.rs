//! What the FFT decoder actually computes, measured on this host.
//!
//! `#[ignore]`d: this is a measurement probe, not a regression. It prints one
//! row per cohort geometry — the domain the transform runs over, the stripe the
//! ledger admitted, the symbols in a row, the transform calls, the butterflies
//! run and skipped, and the multiply-accumulates — so the report can say what
//! the pruning removes instead of promising it.
//!
//! Run it with:
//!
//! ```sh
//! cargo test --locked -p par3-rs --release --test codec_measurements -- --ignored --nocapture
//! ```
//!
//! The corpus rows use the real geometries of the sets `par3cmdline` wrote, read
//! out of their FFT Matrix packets; the payload is this crate's own deterministic
//! stream, because the counters depend on the shape of the work and not on the
//! bytes. No PAR3 packet is assembled here.
mod common;

use std::path::Path;
use std::time::Instant;

use par3_rs::fft::{FftCodec, FftGeometry, FftInput};
use par3_rs::packet::PacketBody;
use par3_rs::runtime::{ExecutionOptions, MemoryBudget};
use par3_rs::{Par3Set, scan_packets_from_path};

/// One measured geometry: a single cohort of an FFT set.
struct Cohort {
    label: String,
    inputs: u64,
    capacity_log2: i8,
    block_size: u64,
    /// Input rows to reconstruct, as a fraction of the cohort.
    lost: usize,
}

struct Row {
    label: String,
    field_bits: u32,
    inputs: usize,
    capacity: usize,
    domain: usize,
    stripe: u64,
    symbols: usize,
    lost: usize,
    calls: u64,
    butterflies: u64,
    skipped: u64,
    macs: u64,
    millis: f64,
}

fn measure(cohort: &Cohort) -> Row {
    let geometry = FftGeometry::new(cohort.inputs, cohort.capacity_log2).unwrap();
    let inputs = geometry.inputs();
    let capacity = geometry.capacity();
    let size = cohort.block_size as usize;

    // A deterministic payload: the counters measure the shape of the work.
    let mut all = vec![0u8; inputs * size];
    let mut hash = blake3::Hasher::new();
    hash.update(b"PAR3 codec measurement");
    hash.update(&cohort.inputs.to_le_bytes());
    hash.update(&cohort.block_size.to_le_bytes());
    hash.finalize_xof().fill(&mut all);
    let data: Vec<&[u8]> = all.chunks_exact(size).collect();

    let mut options = ExecutionOptions::default();
    options.memory = MemoryBudget::new(2 << 30);
    let codec = FftCodec::new(geometry, options.clone()).unwrap();
    let mut parity = vec![vec![0u8; size]; capacity];
    codec
        .encode(
            cohort.block_size,
            0,
            capacity,
            |index, offset, out| {
                out.copy_from_slice(&data[index][offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |index, offset, bytes| {
                parity[index][offset as usize..offset as usize + bytes.len()]
                    .copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    drop(codec);

    // Losses spread evenly through the cohort, which is what damage to a run of
    // consecutive blocks looks like once the interleave has spread it.
    let stride = (inputs / cohort.lost.max(1)).max(1);
    let lost: Vec<usize> = (0..cohort.lost).map(|slot| slot * stride).collect();
    let recovery: Vec<usize> = (0..lost.len()).collect();

    let mut options = ExecutionOptions::default();
    options.memory = MemoryBudget::new(2 << 30);
    let codec = FftCodec::new(geometry, options.clone()).unwrap();
    let mut sink = vec![0u8; size];
    let started = Instant::now();
    codec
        .decode(
            cohort.block_size,
            &lost,
            &recovery,
            |row, offset, out| {
                let from = match row {
                    FftInput::Original(index) => data[index],
                    FftInput::Recovery(index) => &parity[index],
                };
                out.copy_from_slice(&from[offset as usize..offset as usize + out.len()]);
                Ok(())
            },
            |_, offset, bytes| {
                sink[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    let millis = started.elapsed().as_secs_f64() * 1000.0;
    let codec_counters = options.diagnostics.codec();
    let stripe = options.diagnostics.admission().stripe_bytes;
    Row {
        label: cohort.label.clone(),
        field_bits: if geometry.field_bytes() == 1 { 8 } else { 16 },
        inputs,
        capacity,
        domain: geometry.domain(),
        stripe,
        symbols: stripe as usize / geometry.field_bytes(),
        lost: lost.len(),
        calls: codec_counters.transform_calls,
        butterflies: codec_counters.butterflies,
        skipped: codec_counters.butterflies_skipped,
        macs: codec_counters.multiply_accumulates,
        millis,
    }
}

/// Every fixture set that carries an FFT Matrix packet, as one cohort each.
///
/// The eight sets of the repository test corpus are all Cauchy — that is what
/// `par3cmdline` writes for them — so the FFT geometries here come from the
/// pinned reference FFT sets under `tests/fixtures/advanced`, which the
/// reference produced with its FFT encoder.
fn fixture_cohorts() -> Vec<Cohort> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut indexes: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&root) {
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            indexes.push(root.join(name).join("set.par3"));
        }
    }
    indexes.push(root.join("advanced/fft.par3"));
    indexes.push(root.join("advanced/fft16.par3"));

    let mut out = Vec::new();
    for index in indexes {
        let Ok(packets) = scan_packets_from_path(&index) else {
            continue;
        };
        let packets: Vec<_> = packets.into_iter().map(|(_, packet)| packet).collect();
        let Ok(Some(set)) = Par3Set::from_packets(packets).map(|sets| sets.into_iter().next())
        else {
            continue;
        };
        let name = index
            .strip_prefix(&root)
            .unwrap_or(&index)
            .to_string_lossy()
            .into_owned();
        for packet in set.matrix_packets() {
            let PacketBody::FftMatrix(matrix) = packet.body() else {
                continue;
            };
            let cohorts = matrix.interleave + 1;
            let covered = set.block_count();
            let inputs = covered.div_ceil(cohorts);
            let lost = 1.max(inputs as usize / 20);
            out.push(Cohort {
                label: format!("fixture {name} ({cohorts}x{inputs})"),
                inputs,
                capacity_log2: matrix.max_recovery_blocks_log2,
                block_size: set.block_size(),
                lost,
            });
        }
    }
    out
}

#[test]
#[ignore = "measurement probe: prints the FFT work table for this host"]
fn fft_transform_work_on_this_host() {
    let mut cohorts = fixture_cohorts();
    if cohorts.is_empty() {
        println!("no FFT fixture found: synthetic geometries only");
    }
    // A GF8 domain, and a synthetic three-cohort set: 999 blocks of 16 KiB
    // interleaved three ways, which is the shape a large set takes when the
    // writer spreads damage across cohorts.
    cohorts.push(Cohort {
        label: "synthetic gf8 (1 cohort, 200 blocks)".into(),
        inputs: 200,
        capacity_log2: 5,
        block_size: 4096,
        lost: 4,
    });
    for cohort in 0..3u64 {
        cohorts.push(Cohort {
            label: format!("synthetic 3-cohort #{cohort} (999 blocks of 16 KiB)"),
            inputs: 333,
            capacity_log2: 6,
            block_size: 16384,
            lost: 8,
        });
    }

    let rows: Vec<Row> = cohorts.iter().map(measure).collect();
    println!();
    println!(
        "{:<44} {:>3} {:>6} {:>5} {:>6} {:>7} {:>7} {:>5} {:>6} {:>12} {:>12} {:>15} {:>9}",
        "cohort",
        "gf",
        "inputs",
        "cap",
        "domain",
        "stripe",
        "symbols",
        "lost",
        "calls",
        "butterflies",
        "skipped",
        "mul-acc",
        "ms"
    );
    for row in &rows {
        println!(
            "{:<44} {:>3} {:>6} {:>5} {:>6} {:>7} {:>7} {:>5} {:>6} {:>12} {:>12} {:>15} {:>9.1}",
            row.label,
            row.field_bits,
            row.inputs,
            row.capacity,
            row.domain,
            row.stripe,
            row.symbols,
            row.lost,
            row.calls,
            row.butterflies,
            row.skipped,
            row.macs,
            row.millis
        );
    }
    println!();
    for row in &rows {
        let full = row.butterflies + row.skipped;
        let share = if full == 0 {
            0.0
        } else {
            row.skipped as f64 * 100.0 / full as f64
        };
        println!(
            "{:<44} {share:>5.1}% of the decode's butterflies skipped",
            row.label
        );
    }
}

/// What the Cauchy repair path spends on code-matrix elements, measured on the
/// repository corpus — every one of whose eight sets the reference wrote with a
/// Cauchy matrix.
///
/// The question this answers is whether a source block's recovery-row factors
/// are worth computing once per source instead of once per stripe pass. It
/// reports the recomputations a real repair performs, the pool entries each
/// stripe dispatches, and — beside them — what those recomputations cost
/// against the multiply-accumulate they precede.
#[test]
#[ignore = "measurement probe: prints the Cauchy factor table for this host"]
fn cauchy_factor_work_on_this_host() {
    use par3_rs::runtime::ExecutionOptions;
    use par3_rs::session::Par3RepairSession;
    use par3_rs::source::{MemorySourceAccess, SourceId};
    use std::sync::Arc;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut names: Vec<String> = match std::fs::read_dir(&root) {
        Ok(entries) => entries
            .flatten()
            .filter(|entry| entry.path().join("in").is_dir())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    if names.is_empty() {
        println!("corpus not hydrated: nothing to measure");
        return;
    }

    // What one code-matrix element costs against the multiply-accumulate it
    // precedes: an exclusive-or and a table lookup, against a stripe of SIMD.
    use par3_rs::{Field, Gf16};
    let field = Gf16::new(0x1100B).unwrap();
    let mut sum = 0u64;
    let rounds = 1u64 << 20;
    let started = Instant::now();
    for round in 0..rounds {
        let factor = par3_rs::cauchy::element(&field, round % 4096, round % 64).unwrap();
        sum = sum.wrapping_add(u64::from(factor));
    }
    let factor_nanos = started.elapsed().as_secs_f64() * 1e9 / rounds as f64;
    let mut dst = vec![0u8; 64 << 10];
    let src = vec![0x5au8; 64 << 10];
    let started = Instant::now();
    for round in 0..256u64 {
        field.mul_acc(&mut dst, &src, (round as u16).wrapping_add(3));
    }
    let acc_nanos = started.elapsed().as_secs_f64() * 1e9 / 256.0;
    println!();
    println!("one cauchy::element: {factor_nanos:.1} ns (checksum {sum})");
    println!("one 64 KiB mul_acc:  {acc_nanos:.1} ns");
    println!(
        "factor share of a 64 KiB stripe pass: {:.4}%",
        factor_nanos * 100.0 / (factor_nanos + acc_nanos)
    );

    println!();
    println!(
        "{:<18} {:>4} {:>7} {:>7} {:>5} {:>8} {:>7} {:>6} {:>5} {:>10} {:>9} {:>9} {:>7}",
        "set",
        "gf",
        "block",
        "blocks",
        "lost",
        "stripe",
        "passes",
        "bufs",
        "thr",
        "factors",
        "ms",
        "factor ms",
        "share"
    );
    println!("(`factor ms` is `factors` times the measured cost of one element above)");
    // Each set twice: once as the default stripe admits it, and once with the
    // stripe forced to 4 KiB, which is what a repair under memory pressure
    // does and what multiplies the per-stripe factor recomputation.
    for name in names {
        for stripe_bytes in [ExecutionOptions::default().stripe_bytes, 4096] {
            let dir = root.join(&name);
            let mut packets = Vec::new();
            let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "par3")
                })
                .collect();
            files.sort();
            for file in &files {
                let Ok(scanned) = scan_packets_from_path(file) else {
                    continue;
                };
                packets.extend(scanned.into_iter().map(|(_, packet)| packet));
            }
            let Ok(mut sets) = Par3Set::from_packets(packets) else {
                continue;
            };
            let Some(set) = sets.pop() else { continue };
            if set.recovery_blocks().is_empty() {
                continue;
            }

            // Damage the largest input, in as many blocks as there is recovery
            // for, on our own copy. Nothing here edits a PAR3 packet.
            let mut access = MemorySourceAccess::default();
            let mut damaged_blocks = 0usize;
            let largest = set
                .files()
                .iter()
                .enumerate()
                .max_by_key(|(_, file)| file.size())
                .map(|(index, _)| index)
                .unwrap();
            let mut bindings = Vec::new();
            for (index, file) in set.files().iter().enumerate() {
                let mut bytes = std::fs::read(dir.join("in").join(file.path())).unwrap();
                if index == largest {
                    let block = set.block_size() as usize;
                    let want = set.recovery_blocks().len().min(8);
                    while damaged_blocks < want && (damaged_blocks + 1) * block <= bytes.len() {
                        bytes[damaged_blocks * block] ^= 0xff;
                        damaged_blocks += 1;
                    }
                }
                let id = SourceId(index as u64 + 1);
                access.insert(id, 1, bytes.into());
                bindings.push((file.path().to_owned(), id));
            }
            if damaged_blocks == 0 {
                continue;
            }

            let mut options = ExecutionOptions::default();
            options.stripe_bytes = stripe_bytes;
            let mut session =
                Par3RepairSession::new(set.input_set_id(), Arc::new(access), options.clone())
                    .unwrap();
            for file in &files {
                let bytes = std::fs::read(file).unwrap();
                for packet in common::scanned_packets(bytes, &options) {
                    session.merge(packet).unwrap();
                }
            }
            for (path, id) in &bindings {
                session.bind_file(path, *id).unwrap();
            }
            let assessment = session.assess().unwrap();
            let lost = assessment.lost_blocks.len();
            let output = common::TempTree::new(&format!("cauchy-measure-{name}-{stripe_bytes}"));
            let started = Instant::now();
            let report = session.repair(output.path(), false).unwrap();
            let millis = started.elapsed().as_secs_f64() * 1000.0;
            assert!(report.reconstructed_blocks > 0, "{name} repaired nothing");
            let codec = options.diagnostics.codec();
            let admission = options.diagnostics.admission();
            let passes = if admission.stripe_bytes == 0 {
                0
            } else {
                set.block_size().div_ceil(admission.stripe_bytes)
            };
            println!(
                "{:<18} {:>4} {:>7} {:>7} {:>5} {:>8} {:>7} {:>6} {:>5} {:>10} {:>9.1} {:>9.3} {:>6.2}%",
                name,
                u32::from(set.galois_field().size) * 8,
                set.block_size(),
                set.block_count(),
                lost,
                admission.stripe_bytes,
                passes,
                admission.stripe_buffers,
                admission.workers,
                codec.factors_computed,
                millis,
                codec.factors_computed as f64 * factor_nanos / 1e6,
                codec.factors_computed as f64 * factor_nanos / 1e4 / millis
            );
        }
    }
}
