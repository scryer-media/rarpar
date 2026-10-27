#![cfg(feature = "slow-tests")]

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use par2_rs::{
    DiskFileAccess, FileStatus, Par2FileSet, PlacementFileAccess, Repairability,
    apply_placement_plan, execute_repair, plan_repair, scan_placement, verify_all,
};
use tempfile::TempDir;

const HEAVY_DAMAGE_SLICE_SIZE: u64 = 65536;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn copy_fixture_dir(name: &str) -> TempDir {
    let temp = TempDir::new().unwrap();
    let src = fixture_root().join(name);
    copy_dir_contents(&src, temp.path());
    temp
}

fn copy_dir_contents(src: &Path, dst: &Path) {
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&dst_path).unwrap();
            copy_dir_contents(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).unwrap();
        }
    }
}

fn collect_paths(dir: &Path, prefix: &str, extension: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.extension() == Some(OsStr::new(extension))
                && path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(prefix))
        })
        .collect();
    paths.sort();
    paths
}

fn load_par2_set(paths: &[PathBuf]) -> Par2FileSet {
    let raw: Vec<Vec<u8>> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
    let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
    Par2FileSet::from_files(&refs).unwrap()
}

fn assert_volumes_match_fixture(dir: &Path, fixture: &str, prefix: &str) {
    // PAR2 verification already proved every protected file by MD5; this also
    // checks the repaired volumes against the untouched fixture copies.
    let pristine_paths = collect_paths(&fixture_root().join(fixture), prefix, "rar");
    let repaired_paths = collect_paths(dir, prefix, "rar");
    assert_eq!(repaired_paths.len(), pristine_paths.len());
    for (pristine, repaired) in pristine_paths.iter().zip(&repaired_paths) {
        assert_eq!(pristine.file_name(), repaired.file_name());
        assert!(
            fs::read(pristine).unwrap() == fs::read(repaired).unwrap(),
            "{} differs from the fixture after repair",
            repaired.display()
        );
    }
}

fn assert_repairable(result: &par2_rs::VerificationResult, context: &str) {
    assert!(
        matches!(result.repairable, Repairability::Repairable { .. }),
        "{context}: expected repairable result, got {:?}",
        result.repairable
    );
    assert!(
        result.total_missing_blocks > 0,
        "{context}: expected missing blocks"
    );
}

fn assert_not_needed(result: &par2_rs::VerificationResult, context: &str) {
    assert!(
        matches!(result.repairable, Repairability::NotNeeded),
        "{context}: expected repaired result, got {:?}",
        result.repairable
    );
    assert_eq!(
        result.total_missing_blocks, 0,
        "{context}: missing blocks remained"
    );
}

fn corrupt_file(path: &Path, offset: u64, len: usize) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&vec![0xA5; len]).unwrap();
    file.sync_data().unwrap();
}

fn swap_files(left: &Path, right: &Path) {
    let temp = left.with_extension("swap-tmp");
    fs::rename(left, &temp).unwrap();
    fs::rename(right, left).unwrap();
    fs::rename(temp, right).unwrap();
}

#[test]
fn repairs_missing_middle_volume_rar5_lz() {
    let temp = copy_fixture_dir("rar5_lz_plain");
    let prefix = "fixture_rar5_lz_plain";
    let volume_paths = collect_paths(temp.path(), prefix, "rar");
    let par2_paths = collect_paths(temp.path(), "fixture_rar5_lz_plain_repair", "par2");
    let victim = volume_paths[volume_paths.len() / 2].clone();
    let victim_name = victim
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap()
        .to_owned();
    fs::remove_file(&victim).unwrap();

    let par2_set = load_par2_set(&par2_paths);
    let mut access = DiskFileAccess::new(temp.path().to_path_buf(), &par2_set);
    let verification = verify_all(&par2_set, &access);
    assert_repairable(&verification, "missing middle volume");
    let victim_status = verification
        .files
        .iter()
        .find(|file| file.filename == victim_name)
        .map(|file| &file.status)
        .unwrap();
    assert!(matches!(victim_status, FileStatus::Missing));

    let plan = plan_repair(&par2_set, &verification).unwrap();
    execute_repair(&plan, &par2_set, &mut access).unwrap();

    let repaired = verify_all(&par2_set, &access);
    assert_not_needed(&repaired, "missing middle volume repaired");
    assert_volumes_match_fixture(temp.path(), "rar5_lz_plain", prefix);
}

#[test]
fn repairs_corrupted_encrypted_rar4_store_volume() {
    let temp = copy_fixture_dir("rar4_store_enc");
    let prefix = "fixture_rar4_store_enc";
    let volume_paths = collect_paths(temp.path(), prefix, "rar");
    let par2_paths = collect_paths(temp.path(), "fixture_rar4_store_enc_repair", "par2");
    let victim = volume_paths[volume_paths.len() / 2].clone();
    let victim_name = victim
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap()
        .to_owned();
    let file_len = fs::metadata(&victim).unwrap().len();
    let offset = (file_len / 3).max(8192);
    corrupt_file(&victim, offset, 32 * 1024);

    let par2_set = load_par2_set(&par2_paths);
    let mut access = DiskFileAccess::new(temp.path().to_path_buf(), &par2_set);
    let verification = verify_all(&par2_set, &access);
    assert_repairable(&verification, "corrupted encrypted volume");
    let victim_status = verification
        .files
        .iter()
        .find(|file| file.filename == victim_name)
        .map(|file| &file.status)
        .unwrap();
    assert!(matches!(victim_status, FileStatus::Damaged(n) if *n > 0));

    let plan = plan_repair(&par2_set, &verification).unwrap();
    execute_repair(&plan, &par2_set, &mut access).unwrap();

    let repaired = verify_all(&par2_set, &access);
    assert_not_needed(&repaired, "corrupted encrypted volume repaired");
    assert_volumes_match_fixture(temp.path(), "rar4_store_enc", prefix);
}

#[test]
fn repairs_missing_volume_with_swapped_valid_names() {
    let temp = copy_fixture_dir("rar5_lz_plain");
    let prefix = "fixture_rar5_lz_plain";
    let volume_paths = collect_paths(temp.path(), prefix, "rar");
    let par2_paths = collect_paths(temp.path(), "fixture_rar5_lz_plain_repair", "par2");
    swap_files(&volume_paths[1], &volume_paths[2]);
    fs::remove_file(&volume_paths[4]).unwrap();

    let par2_set = load_par2_set(&par2_paths);
    let placement = scan_placement(temp.path(), &par2_set).unwrap();
    assert_eq!(placement.swaps.len(), 1, "expected one swapped pair");
    assert_eq!(placement.unresolved.len(), 1, "expected one missing volume");

    let mut access =
        PlacementFileAccess::from_plan(temp.path().to_path_buf(), &par2_set, &placement);
    let verification = verify_all(&par2_set, &access);
    assert_repairable(&verification, "swapped-plus-missing set");

    let plan = plan_repair(&par2_set, &verification).unwrap();
    execute_repair(&plan, &par2_set, &mut access).unwrap();
    apply_placement_plan(temp.path(), &placement).unwrap();

    let access = DiskFileAccess::new(temp.path().to_path_buf(), &par2_set);
    let repaired = verify_all(&par2_set, &access);
    assert_not_needed(&repaired, "swapped-plus-missing set repaired");
    assert_volumes_match_fixture(temp.path(), "rar5_lz_plain", prefix);
}

/// Heavy damage: 28 corrupted regions spread across a ~73MB RAR archive.
/// With 30 recovery blocks at 64KB slices, this is 2 blocks from the repair
/// ceiling. Tests multi-slice repair at scale with varied corruption patterns.
#[test]
fn repairs_heavy_damage_28_regions_rar5() {
    let temp = copy_fixture_dir("rar5_heavy_damage");
    let prefix = "fixture_rar5_heavy_damage";
    let rar_path = temp.path().join("fixture_rar5_heavy_damage.rar");
    let rar_size = fs::metadata(&rar_path).unwrap().len();
    let total_slices = rar_size.div_ceil(HEAVY_DAMAGE_SLICE_SIZE) as usize;
    let par2_paths = collect_paths(temp.path(), "fixture_rar5_heavy_damage_repair", "par2");
    let par2_set = load_par2_set(&par2_paths);

    // Spread 28 corruption sites across the file. Use a deterministic stride
    // so each hit lands in a different 64KB slice. Vary corruption sizes from
    // 1 byte up to 4KB to exercise different damage patterns.
    let stride = total_slices / 29; // 28 sites, skip first and last slice
    let corruption_sizes: &[usize] = &[
        1, 16, 64, 256, 512, 1024, 2048, 4096, // 8 sizes
        1, 16, 64, 256, 512, 1024, 2048, 4096, // repeat
        1, 16, 64, 256, 512, 1024, 2048, 4096, // repeat
        1, 16, 64, 256, // remaining 4
    ];

    for (i, &corrupt_len) in corruption_sizes.iter().enumerate() {
        let slice_idx = stride * (i + 1); // skip slice 0 (RAR header)
        let offset = (slice_idx as u64) * HEAVY_DAMAGE_SLICE_SIZE + 100; // +100 to avoid slice boundary
        corrupt_file(&rar_path, offset, corrupt_len);
    }

    // Verify — should detect exactly 28 damaged slices.
    let mut access = DiskFileAccess::new(temp.path().to_path_buf(), &par2_set);
    let verification = verify_all(&par2_set, &access);
    assert_repairable(&verification, "heavy damage 28 regions");
    eprintln!(
        "heavy damage: {} missing blocks (30 available)",
        verification.total_missing_blocks
    );
    assert!(
        verification.total_missing_blocks <= 30,
        "expected at most 30 missing blocks, got {}",
        verification.total_missing_blocks
    );

    // Repair.
    let plan = plan_repair(&par2_set, &verification).unwrap();
    eprintln!(
        "repair plan: {} missing slices, {} recovery exponents",
        plan.missing_slices.len(),
        plan.recovery_exponents.len()
    );
    execute_repair(&plan, &par2_set, &mut access).unwrap();

    // Verify repaired — should be clean.
    let repaired = verify_all(&par2_set, &access);
    assert_not_needed(&repaired, "heavy damage 28 regions repaired");

    assert_volumes_match_fixture(temp.path(), "rar5_heavy_damage", prefix);
}
