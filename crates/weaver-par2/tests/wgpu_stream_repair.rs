//! End-to-end streaming repair through the wgpu GPU arm.
//!
//! Deliberately the ONLY test in this binary: it must set `WEAVER_GF16_WGPU=1`
//! to force the arm past the size gate, and `std::env::set_var` is only sound
//! while no other thread can call `getenv` concurrently. A lone test in its
//! own binary sets the variable on the main thread before any GPU/driver or
//! rayon threads exist, and the process exits when the test ends, so the
//! forced mode cannot leak into other tests' tier coverage either.

#![cfg(feature = "wgpu")]

use weaver_par2::{
    FileAccess, MemoryFileAccess, RepairOptions, Repairability, execute_repair_with_options,
    plan_repair, verify_all,
};

#[path = "support/synthetic_par2.rs"]
mod synthetic_par2;
use synthetic_par2::{Rng, build_synthetic_par2};

/// A tiny `memory_limit` forces the streamed chunk path, and the forced gate
/// makes the GPU arm engage regardless of repair size (with the universal CPU
/// tier as its in-band fallback). When no adapter exists the repair still runs
/// on the CPU and the byte-for-byte assertions still hold, so the test is
/// meaningful either way.
#[test]
fn repair_streaming_through_wgpu_arm() {
    eprintln!("\n=== repair_streaming_through_wgpu_arm ===");
    // SAFETY: single-test binary; set on the main thread before any code that
    // could spawn env-reading threads (GPU stack, rayon) runs. See module doc.
    unsafe { std::env::set_var("WEAVER_GF16_WGPU", "1") };

    let mut rng = Rng::new(0x57EA_11ED_6F00_0001);
    let synthetic = build_synthetic_par2(&[4 * 1024 * 1024], 65536, 16, &mut rng);

    let mut access = MemoryFileAccess::new();
    for f in &synthetic.files {
        access.add_file(f.file_id, f.data.clone());
    }
    // Damage 8 slices spread across the file.
    {
        let f = &synthetic.files[0];
        let mut data = f.data.to_vec();
        for k in 0..8usize {
            let off = k * 8 * 65536 + 17;
            data[off] ^= 0xA5;
        }
        access.add_file(f.file_id, data);
    }

    let result = verify_all(&synthetic.par2_set, &access);
    assert!(matches!(
        result.repairable,
        Repairability::Repairable { .. }
    ));
    let plan = plan_repair(&synthetic.par2_set, &result).unwrap();

    // 1 MiB budget: far below the 4 MiB set, so the repair must stream.
    let options = RepairOptions {
        memory_limit: Some(1024 * 1024),
        ..Default::default()
    };
    execute_repair_with_options(&plan, &synthetic.par2_set, &mut access, &options).unwrap();

    for f in &synthetic.files {
        let repaired = access.read_file(&f.file_id).unwrap();
        assert_eq!(repaired, f.data, "data mismatch after wgpu-arm repair");
    }
    let result = verify_all(&synthetic.par2_set, &access);
    assert!(matches!(result.repairable, Repairability::NotNeeded));
    eprintln!("  PASS: repair_streaming_through_wgpu_arm");
}
