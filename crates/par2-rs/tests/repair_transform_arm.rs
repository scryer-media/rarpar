//! The repair transform arm must be bit-identical to the dense executor.
//!
//! Every case here repairs the same damage twice — once with the arm forced
//! off, once with it forced on — and compares both restorations against the
//! untouched originals. The arm is switched in-process through
//! [`par2_rs::set_transform_arm_override`], which is thread-local, so these
//! tests do not race each other through the environment.

use par2_rs::{
    FileAccess, MemoryFileAccess, RepairOptions, TransformArm, execute_repair_with_options,
    plan_repair, set_transform_arm_override, transform_arm_stats, verify_all,
};

#[path = "support/synthetic_par2.rs"]
mod synthetic_par2;
use synthetic_par2::{Rng, SyntheticPar2, build_synthetic_par2};

/// Repair `synthetic` after `damage`, with the arm in the given state.
///
/// Returns the restored files in set order and whether the arm actually ran.
fn repair_with(
    synthetic: &SyntheticPar2,
    arm: TransformArm,
    memory_limit: Option<usize>,
    damage: &dyn Fn(&mut MemoryFileAccess, &SyntheticPar2),
) -> (Vec<Vec<u8>>, bool) {
    let mut access = MemoryFileAccess::new();
    for file in &synthetic.files {
        access.add_file(file.file_id, file.data.clone());
    }
    damage(&mut access, synthetic);

    let verification = verify_all(&synthetic.par2_set, &access);
    let plan = plan_repair(&synthetic.par2_set, &verification).expect("the set must be repairable");

    set_transform_arm_override(Some(arm));
    let before = transform_arm_stats();
    let outcome = execute_repair_with_options(
        &plan,
        &synthetic.par2_set,
        &mut access,
        &RepairOptions {
            cancel: None,
            progress: None,
            memory_limit,
        },
    );
    let after = transform_arm_stats();
    set_transform_arm_override(None);
    outcome.expect("repair must succeed");

    let restored = synthetic
        .files
        .iter()
        .map(|file| access.read_file(&file.file_id).expect("read back"))
        .collect();
    (restored, after.executed > before.executed)
}

/// Run one shape both ways and assert the two restorations equal the originals.
fn both_ways(
    label: &str,
    synthetic: &SyntheticPar2,
    memory_limit: Option<usize>,
    expect_arm: bool,
    damage: &dyn Fn(&mut MemoryFileAccess, &SyntheticPar2),
) {
    let (dense, dense_ran) = repair_with(synthetic, TransformArm::Off, memory_limit, damage);
    let (transform, transform_ran) = repair_with(synthetic, TransformArm::On, memory_limit, damage);

    assert!(
        !dense_ran,
        "{label}: the forced-off run must take the dense path"
    );
    assert_eq!(
        transform_ran, expect_arm,
        "{label}: transform arm engagement"
    );
    for (index, file) in synthetic.files.iter().enumerate() {
        assert_eq!(dense[index], file.data, "{label}: dense file {index}");
        assert_eq!(
            transform[index], file.data,
            "{label}: transform file {index}"
        );
    }
}

fn fixture(sizes: &[usize], slice_size: u64, recovery: usize, seed: u64) -> SyntheticPar2 {
    let mut rng = Rng::new(seed);
    build_synthetic_par2(sizes, slice_size, recovery, &mut rng)
}

#[test]
fn multi_file_damage_repairs_identically() {
    // Four files, a short last slice in each, damage spread over all of them.
    let synthetic = fixture(&[4000, 7000, 1500, 9000], 512, 24, 0xA11CE);
    both_ways("multi-file", &synthetic, None, true, &|access, set| {
        for (index, file) in set.files.iter().enumerate() {
            let mut data = file.data.clone();
            let start = (index + 1) * 512;
            let end = (start + 512).min(data.len());
            if start < end {
                data[start..end].fill(0xC3);
            }
            access.add_file(file.file_id, data);
        }
    });
}

#[test]
fn a_slice_size_that_is_not_a_multiple_of_64_repairs_identically() {
    // 516 = 4 * 129: a legal PAR2 slice size that no stripe alignment divides.
    let synthetic = fixture(&[5000, 3000], 516, 16, 0xB0B);
    both_ways("odd slice size", &synthetic, None, true, &|access, set| {
        for file in &set.files {
            let mut data = file.data.clone();
            data[..516].fill(0);
            access.add_file(file.file_id, data);
        }
    });
}

#[test]
fn a_damaged_file_keeps_contributing_its_surviving_slices() {
    // One file damaged in place: its intact slices are present sources the
    // transform must fold, while its broken ones are outputs.
    let synthetic = fixture(&[16384, 8192], 1024, 20, 0xDEC0DE);
    both_ways(
        "damaged in place",
        &synthetic,
        None,
        true,
        &|access, set| {
            let file = &set.files[0];
            let mut data = file.data.clone();
            for slice in [0usize, 3, 7, 12] {
                data[slice * 1024..slice * 1024 + 1024].fill(0x7E);
            }
            access.add_file(file.file_id, data);
        },
    );
}

#[test]
fn a_whole_missing_file_repairs_identically() {
    let synthetic = fixture(&[4096, 4096, 2048], 512, 20, 0xFEED);
    both_ways("missing file", &synthetic, None, true, &|access, set| {
        // An empty file is a file whose every slice is missing.
        access.add_file(set.files[1].file_id, Vec::new());
    });
}

#[test]
fn a_tiny_memory_limit_forces_many_bands_and_still_matches() {
    // 64 KiB slices against a 1 MiB limit: the band cannot hold a whole slice,
    // so the arm walks each one in pieces.
    let synthetic = fixture(&[65536 * 6, 65536 * 3], 65536, 12, 0x5EED);
    both_ways(
        "many bands",
        &synthetic,
        Some(1024 * 1024),
        true,
        &|access, set| {
            let file = &set.files[0];
            let mut data = file.data.clone();
            data[65536..65536 * 3].fill(0x44);
            access.add_file(file.file_id, data);
        },
    );
}

#[test]
fn a_limit_that_cannot_buy_a_band_takes_the_dense_path() {
    let synthetic = fixture(&[65536 * 4], 65536, 8, 0x1DEA);
    both_ways(
        "no admissible band",
        &synthetic,
        Some(8 * 1024),
        false,
        &|access, set| {
            let file = &set.files[0];
            let mut data = file.data.clone();
            data[..65536].fill(0x33);
            access.add_file(file.file_id, data);
        },
    );
}

#[test]
fn small_everyday_repairs_never_reach_the_arm() {
    // The automatic gate, not a forced arm: a handful of missing blocks must
    // take today's path untouched.
    let synthetic = fixture(&[8192, 8192], 1024, 8, 0x0DD);
    let mut access = MemoryFileAccess::new();
    for file in &synthetic.files {
        access.add_file(file.file_id, file.data.clone());
    }
    let mut damaged = synthetic.files[0].data.clone();
    damaged[..1024].fill(0);
    access.add_file(synthetic.files[0].file_id, damaged);

    let verification = verify_all(&synthetic.par2_set, &access);
    let plan = plan_repair(&synthetic.par2_set, &verification).unwrap();

    set_transform_arm_override(None);
    let before = transform_arm_stats();
    execute_repair_with_options(
        &plan,
        &synthetic.par2_set,
        &mut access,
        &RepairOptions::default(),
    )
    .unwrap();
    let after = transform_arm_stats();
    assert_eq!(after, before, "the automatic gate must not engage the arm");
    assert_eq!(
        access.read_file(&synthetic.files[0].file_id).unwrap(),
        synthetic.files[0].data
    );
}

/// Repair `synthetic` after `damage` and report the arm counters it moved.
///
/// Unlike [`repair_with`] this keeps the whole `TransformArmStats` delta, so a
/// caller can tell which solver ran behind the seam.
fn repair_counting(
    synthetic: &SyntheticPar2,
    arm: TransformArm,
    damage: &dyn Fn(&mut MemoryFileAccess, &SyntheticPar2),
) -> (Vec<Vec<u8>>, u64, u64) {
    let mut access = MemoryFileAccess::new();
    for file in &synthetic.files {
        access.add_file(file.file_id, file.data.clone());
    }
    damage(&mut access, synthetic);

    let verification = verify_all(&synthetic.par2_set, &access);
    let plan = plan_repair(&synthetic.par2_set, &verification).expect("the set must be repairable");

    set_transform_arm_override(Some(arm));
    let before = transform_arm_stats();
    let outcome = execute_repair_with_options(
        &plan,
        &synthetic.par2_set,
        &mut access,
        &RepairOptions::default(),
    );
    let after = transform_arm_stats();
    set_transform_arm_override(None);
    outcome.expect("repair must succeed");

    let restored = synthetic
        .files
        .iter()
        .map(|file| access.read_file(&file.file_id).expect("read back"))
        .collect();
    (
        restored,
        after.executed - before.executed,
        after.consecutive_solves - before.consecutive_solves,
    )
}

/// A shape big enough to cross `CONSECUTIVE_SOLVE_MIN_ROWS`: 600 slices in one
/// file, 520 of them destroyed.
fn large_m_fixture() -> SyntheticPar2 {
    fixture(&[600 * 64], 64, 560, 0x5017E)
}

fn damage_first_520(access: &mut MemoryFileAccess, set: &SyntheticPar2) {
    let file = &set.files[0];
    let mut data = file.data.clone();
    data[..520 * 64].fill(0x9B);
    access.add_file(file.file_id, data);
}

#[test]
fn the_closed_form_solver_matches_the_dense_path_at_five_hundred_rows() {
    let synthetic = large_m_fixture();
    let (dense, dense_ran, _) = repair_counting(&synthetic, TransformArm::Off, &damage_first_520);
    let (transform, transform_ran, consecutive) =
        repair_counting(&synthetic, TransformArm::On, &damage_first_520);

    assert_eq!(dense_ran, 0, "the forced-off run must take the dense path");
    assert_eq!(transform_ran, 1, "the arm must run");
    assert_eq!(
        consecutive, 1,
        "520 consecutive exponents must pick the closed-form solve"
    );
    assert_eq!(dense[0], synthetic.files[0].data);
    assert_eq!(transform[0], synthetic.files[0].data);
}

#[test]
fn the_explicit_inverse_still_serves_a_wide_selection_at_five_hundred_rows() {
    // Same damage, but a hole punched in the recovery set makes the selected
    // exponents non-consecutive, so the seam must fall back to the inverse.
    let mut synthetic = large_m_fixture();
    synthetic.par2_set.recovery_slices.remove(&7);

    let (dense, dense_ran, _) = repair_counting(&synthetic, TransformArm::Off, &damage_first_520);
    let (transform, transform_ran, consecutive) =
        repair_counting(&synthetic, TransformArm::On, &damage_first_520);

    assert_eq!(dense_ran, 0, "the forced-off run must take the dense path");
    assert_eq!(transform_ran, 1, "the arm must run");
    assert_eq!(
        consecutive, 0,
        "a gapped selection must not reach the closed-form solve"
    );
    assert_eq!(dense[0], synthetic.files[0].data);
    assert_eq!(transform[0], synthetic.files[0].data);
}
