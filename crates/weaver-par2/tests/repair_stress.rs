//! Stress tests for PAR2 repair with moderate-size data.
//!
//! These tests generate synthetic PAR2 sets entirely in-memory and exercise
//! the full verify → plan → repair → re-verify pipeline with enough data to
//! make the hot paths (GF region multiply, matrix inversion, verification
//! hashing) measurable.

#![cfg(feature = "slow-tests")]

use std::time::Instant;

use weaver_par2::{
    FileAccess, MemoryFileAccess, Repairability, execute_repair, plan_repair, verify_all,
};

#[path = "support/synthetic_par2.rs"]
mod synthetic_par2;
use synthetic_par2::{Rng, SyntheticFile, SyntheticPar2, build_synthetic_par2};

fn run_repair_scenario(
    synthetic: &SyntheticPar2,
    damage: impl FnOnce(&[&SyntheticFile], &mut MemoryFileAccess),
    label: &str,
) {
    let mut access = MemoryFileAccess::new();
    for f in &synthetic.files {
        access.add_file(f.file_id, f.data.clone());
    }

    // Apply damage.
    damage(&synthetic.files.iter().collect::<Vec<_>>(), &mut access);

    // Verify — should detect damage.
    let t0 = Instant::now();
    let result = verify_all(&synthetic.par2_set, &access);
    let verify_ms = t0.elapsed().as_millis();
    eprintln!(
        "  verify (damaged): {verify_ms}ms — {} missing blocks",
        result.total_missing_blocks
    );
    assert!(
        matches!(result.repairable, Repairability::Repairable { .. }),
        "{label}: expected repairable, got {:?}",
        result.repairable
    );

    // Plan.
    let plan = plan_repair(&synthetic.par2_set, &result).unwrap();
    eprintln!(
        "  plan: {} missing slices, {} recovery exponents",
        plan.missing_slices.len(),
        plan.recovery_exponents.len()
    );

    // Repair.
    let t0 = Instant::now();
    execute_repair(&plan, &synthetic.par2_set, &mut access).unwrap();
    let repair_ms = t0.elapsed().as_millis();
    eprintln!("  repair: {repair_ms}ms");

    // Verify repaired data matches original byte-for-byte.
    for f in &synthetic.files {
        let repaired = access.read_file(&f.file_id).unwrap();
        assert_eq!(
            repaired.len(),
            f.data.len(),
            "{label}: file {} length mismatch",
            f.filename
        );
        assert_eq!(
            repaired, f.data,
            "{label}: file {} data mismatch after repair",
            f.filename
        );
    }

    // Re-verify — should be clean.
    let t0 = Instant::now();
    let result = verify_all(&synthetic.par2_set, &access);
    let reverify_ms = t0.elapsed().as_millis();
    eprintln!("  verify (repaired): {reverify_ms}ms");
    assert!(
        matches!(result.repairable, Repairability::NotNeeded),
        "{label}: expected NotNeeded after repair, got {:?}",
        result.repairable
    );
    assert_eq!(
        result.total_missing_blocks, 0,
        "{label}: blocks still missing"
    );

    eprintln!("  PASS: {label}");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn repair_single_file_4mb_8_missing() {
    eprintln!("\n=== repair_single_file_4mb_8_missing ===");
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_0001);
    let synthetic = build_synthetic_par2(&[4 * 1024 * 1024], 65536, 16, &mut rng);

    run_repair_scenario(
        &synthetic,
        |files, access| {
            // Damage 8 evenly-spaced slices out of 64.
            let f = &files[0];
            let ss = 65536usize;
            for i in (0..64).step_by(8) {
                let offset = i * ss;
                let end = offset + ss;
                let zeroed = vec![0xAA; ss];
                access.add_file(f.file_id, {
                    let mut data = access.read_file(&f.file_id).unwrap();
                    data[offset..end].copy_from_slice(&zeroed);
                    data
                });
            }
        },
        "4MB single file, 8/64 slices damaged",
    );
}

#[test]
fn repair_multi_file_set() {
    eprintln!("\n=== repair_multi_file_set ===");
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_0002);
    let synthetic =
        build_synthetic_par2(&[1024 * 1024, 1200 * 1024, 900 * 1024], 65536, 12, &mut rng);

    run_repair_scenario(
        &synthetic,
        |files, access| {
            let ss = 65536usize;
            // Damage 2 slices in file 0.
            {
                let f = &files[0];
                let mut data = access.read_file(&f.file_id).unwrap();
                for i in [1, 3] {
                    let offset = i * ss;
                    data[offset..offset + ss].fill(0xBB);
                }
                access.add_file(f.file_id, data);
            }
            // Damage 2 slices in file 1.
            {
                let f = &files[1];
                let mut data = access.read_file(&f.file_id).unwrap();
                for i in [0, 5] {
                    let offset = i * ss;
                    let end = (offset + ss).min(data.len());
                    data[offset..end].fill(0xCC);
                }
                access.add_file(f.file_id, data);
            }
            // Damage 2 slices in file 2.
            {
                let f = &files[2];
                let mut data = access.read_file(&f.file_id).unwrap();
                for i in [2, 4] {
                    let offset = i * ss;
                    let end = (offset + ss).min(data.len());
                    data[offset..end].fill(0xDD);
                }
                access.add_file(f.file_id, data);
            }
        },
        "3-file set, 6 slices damaged across files",
    );
}

#[test]
fn repair_many_recovery_blocks() {
    eprintln!("\n=== repair_many_recovery_blocks ===");
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_0003);
    let synthetic = build_synthetic_par2(&[2 * 1024 * 1024], 65536, 20, &mut rng);

    run_repair_scenario(
        &synthetic,
        |files, access| {
            // Damage 16 of 32 slices — uses all 20 recovery blocks (well, 16).
            let f = &files[0];
            let ss = 65536usize;
            let mut data = access.read_file(&f.file_id).unwrap();
            for i in 0..16 {
                let offset = (i * 2) * ss; // every other slice
                data[offset..offset + ss].fill(0xEE);
            }
            access.add_file(f.file_id, data);
        },
        "2MB, 16/32 slices damaged, 20 recovery blocks",
    );
}

#[test]
fn repair_large_slices() {
    eprintln!("\n=== repair_large_slices ===");
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_0004);
    let slice_size = 256 * 1024u64; // 256KB slices
    let synthetic = build_synthetic_par2(&[2 * 1024 * 1024], slice_size, 4, &mut rng);

    run_repair_scenario(
        &synthetic,
        |files, access| {
            let f = &files[0];
            let ss = slice_size as usize;
            let mut data = access.read_file(&f.file_id).unwrap();
            // Damage slices 1 and 5 (out of 8).
            for i in [1, 5] {
                let offset = i * ss;
                data[offset..offset + ss].fill(0xFF);
            }
            access.add_file(f.file_id, data);
        },
        "2MB, 256KB slices, 2/8 damaged",
    );
}

#[test]
fn repair_fully_missing_file() {
    eprintln!("\n=== repair_fully_missing_file ===");
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_0005);
    let synthetic = build_synthetic_par2(&[512 * 1024], 65536, 8, &mut rng);

    run_repair_scenario(
        &synthetic,
        |files, access| {
            // Zero the entire file — all 8 slices missing.
            let f = &files[0];
            let zeroed = vec![0u8; f.data.len()];
            access.add_file(f.file_id, zeroed);
        },
        "512KB fully missing, 8/8 slices from 8 recovery blocks",
    );
}
