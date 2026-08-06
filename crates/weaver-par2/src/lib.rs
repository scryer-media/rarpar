//! General-purpose PAR2 verification and repair engine.
//!
//! A pure-Rust implementation of PAR2 (Parity Archive Volume Set v2.0): load a
//! set, find out what is damaged, and repair it from the recovery data.
//!
//! # Verifying a set
//!
//! A PAR2 set is usually spread across several `.par2` files. Packets from all
//! of them aggregate into one [`Par2FileSet`], and verification runs against
//! that.
//!
//! ```no_run
//! use par2_rs::{DiskFileAccess, Par2FileSet, Repairability, scan_packets_from_path, verify_all};
//!
//! # fn main() -> par2_rs::Result<()> {
//! let packets = scan_packets_from_path(std::path::Path::new("release.par2"))?
//!     .into_iter()
//!     .map(|(packet, _offset)| packet)
//!     .collect();
//! let set = Par2FileSet::from_packets(packets)?;
//!
//! let access = DiskFileAccess::new("/downloads/release".into(), &set);
//! let result = verify_all(&set, &access);
//!
//! println!("{} recovery blocks available", result.recovery_blocks_available);
//! match result.repairable {
//!     Repairability::NotNeeded => println!("everything verified clean"),
//!     Repairability::Repairable { blocks_needed, .. } => {
//!         println!("repairable: {blocks_needed} blocks to rebuild")
//!     }
//!     Repairability::Insufficient { blocks_needed, .. } => {
//!         println!("not enough recovery data: {blocks_needed} blocks short")
//!     }
//!     other => println!("{other:?}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Verification is **slice-level**, using the CRC32 + MD5 pairs in IFSC packets,
//! so damage is localised to the slices that are actually wrong rather than
//! condemning the whole file. Sets carrying no IFSC data fall back to full-file
//! MD5, and [`quick_check_16k`] identifies a candidate file cheaply before
//! either.
//!
//! # Verifying bytes that are not files
//!
//! [`verify_all`] reads through the [`FileAccess`] trait, not the filesystem.
//! [`DiskFileAccess`] is the ordinary implementation; supply your own and a set
//! can be verified against bytes still arriving over a network, or assembled
//! from somewhere that has no paths at all. [`MemoryFileAccess`] is useful in
//! tests.
//!
//! # Repair
//!
//! [`Par2Repairer`] drives the whole sequence — scan, verify, solve, repair,
//! then verify again. Repair is placement-aware: files that were renamed or
//! moved are matched by content rather than by name, so a set still repairs
//! after its files have been reorganised.
//!
//! # Repairing across a whole download
//!
//! [`Par2RepairSession`] is the retained form: one session accumulates
//! evidence — per-slice verdicts, whole-file proofs — while the data is still
//! arriving, so assessment is incremental and repair runs from what is already
//! known instead of a fresh walk. Its sources may be files under a base
//! directory, or bytes served through a [`FileAccess`] handle
//! ([`Par2RepairSessionOptions::with_source_access`]) for sets that never
//! became files — and where the `.par2` volumes themselves never became files
//! either, [`Par2RepairSessionOptions::from_set`] takes the parsed set
//! directly. Repair *output* is always real files either way.
//!
//! # Damaged PAR2 files
//!
//! A malformed or truncated packet does not fail the set. The scanner skips
//! forward to the next valid packet, because the recovery data that survived is
//! usually still enough — which is the entire point of parity.
//!
//! # Feature flags
//!
//! - `native-crypto` *(default)*: AWS-LC-backed MD5.
//! - `metal` / `wgpu`: GPU-accelerated repair through [`reedsolomon_rs`], each
//!   falling back to CPU when no suitable device or driver is present.
//!
//! The format is specified in the [Parity Volume Set Specification 2.0](https://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html).

#[cfg(all(
    feature = "native-crypto",
    not(any(
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "musl"),
        all(target_arch = "aarch64", target_os = "linux", target_env = "musl"),
        all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"),
        all(target_arch = "aarch64", target_os = "windows", target_env = "msvc")
    ))
))]
compile_error!(
    "par2-rs native-crypto only supports x86_64/aarch64 on macOS, Linux GNU/musl, and Windows MSVC"
);

pub mod checksum;
mod cpu_repair_controller;
pub mod disk;
pub mod error;
pub mod evidence;
mod file_cache;
pub mod matrix;
pub mod md5_simd;
pub mod packet;
pub mod par2_set;
pub mod path;
pub mod placement;
pub mod rename;
pub mod repair;
pub mod repair_session;
pub mod repairer;
pub mod session;
pub mod types;
pub mod verify;

// Re-export key types for convenience.
pub use checksum::{FileHashState, SliceChecksumState};
pub use disk::{DiskFileAccess, MultiDirectoryFileAccess, PlacementFileAccess};
pub use error::{Par2Error, Result};
pub use evidence::{CommittedFileEvidence, ContiguousAssemblyProof, FileStatFingerprint};
pub use gf::{add as gf_add, input_slice_constants, inv as gf_inv, mul as gf_mul, pow as gf_pow};
pub use gf_simd::{FactorDst, mul_acc_multi_region, mul_acc_region};
pub use matrix::{Matrix, build_decode_matrix};
pub use packet::{
    CreatorPacket, FileDescriptionPacket, IfscPacket, MainPacket, Packet, PacketHeader, PacketType,
    RecoverySliceData, RecoverySlicePacket, ScannedPacket, parse_packet, scan_packets,
    scan_packets_from_path, scan_packets_from_path_with_set_ids,
};
pub use par2_set::{
    FileDescription, MergeResult, Par2Diagnostic, Par2FileSet, Par2ParseResult, RecoverySlice,
};
pub use path::{translate_par2_name_to_local_path, translate_par2_name_to_relative};
pub use placement::{PlacementEntry, PlacementPlan, apply_placement_plan, scan_placement};
pub use reedsolomon_rs::{gf, gf_pmul, gf_simd, matrix_tiled};
pub use rename::{
    MatchType, RenameSuggestion, SplitFileGroup, detect_split_files, identify_par2_files,
    scan_for_renames,
};
pub use repair::{
    NativeRepairSolver, RepairOptions, RepairPlan, RepairProblem, RepairSolver, SolverError,
    execute_repair, execute_repair_with_options, execute_repair_with_solver, plan_repair,
    plan_repair_with_memory_limit, prepare_recovery_buffers, reconstruct_and_write, xor_out_slice,
};
pub use repair_session::{
    DEFAULT_RETAINED_STATE_LIMIT, Par2RepairSession, Par2RepairSessionDiagnostics,
    Par2RepairSessionOptions, Par2SessionError,
};
pub use repairer::{
    BlockLocation, BlockLocationKind, PacketDiagnostics, PacketInventory, Par2RepairOutcome,
    Par2RepairStatus, Par2Repairer, Par2RepairerOptions, ScanCarry, ScanDiagnostics, SourceBlock,
    SourceFileEntry, SourceLocation,
};
pub use session::{
    FeedDisposition, FeedOutcome, SettleRead, SliceEvidence, SliceEvidenceStrength,
    VerificationMemoryBudget, VerificationSession, VerificationSessionOptions,
};
pub use types::{CancellationToken, ProgressCallback, ProgressStage, ProgressUpdate};
pub use types::{FileId, RecoveryExponent, RecoverySetId, SliceChecksum, SliceIndex};
pub use verify::{
    FileAccess, FileStatus, FileVerification, MemoryFileAccess, Repairability, VerificationResult,
    VerifyOptions, quick_check_16k, verify_all, verify_all_with_options, verify_full_hash,
    verify_selected_file_ids, verify_selected_file_ids_with_options, verify_slices,
    verify_slices_from_crcs,
};
