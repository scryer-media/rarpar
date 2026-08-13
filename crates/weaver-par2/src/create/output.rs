#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(windows)]
use std::mem::MaybeUninit;
use std::mem::size_of;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::checksum::Md5State;
use crate::error::{Par2Error, Result};
use crate::packet::encode::{encode_header, encode_packet, start_streamed_hash};
use crate::packet::header::{HEADER_SIZE, PacketHeader, TYPE_CREATOR};
use crate::packet::{Packet, scan_packets_from_path_with_set_ids_cancellable};
use crate::types::{CancellationToken, FileId, RecoveryExponent, RecoverySetId};

use super::encode::{ForwardEncoder, ForwardEncoderOptions, ForwardRecoverySink};
use super::metal::{SelectedBackend, selected_policy};
use super::options::{CreationBackend, Par2CreatorOptions};
use super::plan::Par2CreatePlan;
use super::source::{CreationSource, DiskSourceProvider};
use super::volume::RecoveryVolumePlan;

const CREATOR_ID: &[u8] = b"par2-rs";
static ZERO_WRITE_BUFFER: [u8; 64 * 1024] = [0; 64 * 1024];

#[cfg(test)]
static CANCEL_AFTER_VALIDATION_SCAN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn validation_checkpoint(cancellation: &CancellationToken) {
    use std::sync::atomic::Ordering;

    if CANCEL_AFTER_VALIDATION_SCAN.swap(false, Ordering::Relaxed) {
        cancellation.cancel();
    }
}

#[cfg(not(test))]
fn validation_checkpoint(_: &CancellationToken) {}

pub(crate) fn estimate_critical_packet_bytes(sources: &[CreationSource]) -> Result<usize> {
    let main_body = 12usize
        .checked_add(sources.len().checked_mul(16).ok_or_else(|| {
            Par2Error::ResourceLimitExceeded {
                reason: "Main packet memory estimate overflows".to_string(),
            }
        })?)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: "Main packet memory estimate overflows".to_string(),
        })?;
    let mut total = encoded_packet_len(main_body)?;
    for source in sources {
        let description_body = 56usize.checked_add(source.par2_name.len()).ok_or_else(|| {
            Par2Error::ResourceLimitExceeded {
                reason: "FileDesc memory estimate overflows".to_string(),
            }
        })?;
        let checksum_body = 16usize
            .checked_add(
                source
                    .slice_checksums
                    .len()
                    .checked_mul(20)
                    .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                        reason: "IFSC memory estimate overflows".to_string(),
                    })?,
            )
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "IFSC memory estimate overflows".to_string(),
            })?;
        total = checked_memory_add(
            total,
            encoded_packet_len(description_body)?,
            "critical packet memory estimate overflows",
        )?;
        total = checked_memory_add(
            total,
            encoded_packet_len(checksum_body)?,
            "critical packet memory estimate overflows",
        )?;
    }
    Ok(total)
}

pub(crate) fn estimate_packet_build_workspace_bytes(sources: &[CreationSource]) -> Result<usize> {
    let mut largest_body = 0usize;
    for source in sources {
        let description_body = 56usize
            .checked_add(source.par2_name.len())
            .and_then(|length| length.checked_add(3))
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "FileDesc packet workspace estimate overflows".to_string(),
            })?;
        let checksum_body = 16usize
            .checked_add(
                source
                    .slice_checksums
                    .len()
                    .checked_mul(20)
                    .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                        reason: "IFSC packet workspace estimate overflows".to_string(),
                    })?,
            )
            .and_then(|length| length.checked_add(3))
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "IFSC packet workspace estimate overflows".to_string(),
            })?;
        largest_body = largest_body.max(description_body).max(checksum_body);
    }
    checked_memory_add(
        size_of::<Vec<u8>>(),
        largest_body,
        "critical packet workspace estimate overflows",
    )
}

pub(crate) fn estimate_transaction_workspace_bytes(
    base_path: &Path,
    output_stem: &Path,
    main_path: &Path,
    output_paths: &[PathBuf],
    volumes: &[RecoveryVolumePlan],
    sources: &[CreationSource],
    recovery_count: u32,
) -> Result<usize> {
    let critical_count = 1usize
        .checked_add(sources.len().checked_mul(2).ok_or_else(|| {
            Par2Error::ResourceLimitExceeded {
                reason: "critical packet controller estimate overflows".to_string(),
            }
        })?)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: "critical packet controller estimate overflows".to_string(),
        })?;
    let mut total = checked_memory_product(
        critical_count,
        size_of::<(ExpectedPacket, Vec<u8>)>(),
        "critical packet controller estimate overflows",
    )?;
    total = checked_memory_add(
        total,
        encoded_packet_len(CREATOR_ID.len())?,
        "creation transaction estimate overflows",
    )?;
    total = checked_memory_add(
        total,
        checked_memory_product(
            output_paths.len(),
            size_of::<VolumeState>(),
            "staged volume estimate overflows",
        )?,
        "creation transaction estimate overflows",
    )?;
    total = checked_memory_add(
        total,
        checked_memory_product(
            recovery_count as usize,
            size_of::<RecoveryLocation>(),
            "recovery location estimate overflows",
        )?,
        "creation transaction estimate overflows",
    )?;

    for (index, volume) in volumes.iter().enumerate() {
        let expected_count = expected_packet_count(volume.recovery_count, critical_count)?;
        let expected_capacity = allocation_capacity_upper_bound(expected_count)?;
        let slot_capacity = allocation_capacity_upper_bound(volume.recovery_count as usize)?;
        total = checked_memory_add(
            total,
            checked_memory_product(
                expected_capacity,
                size_of::<ExpectedPacket>(),
                "expected packet estimate overflows",
            )?,
            "creation transaction estimate overflows",
        )?;
        total = checked_memory_add(
            total,
            checked_memory_product(
                slot_capacity,
                size_of::<RecoverySlot>(),
                "recovery slot estimate overflows",
            )?,
            "creation transaction estimate overflows",
        )?;
        let path = output_paths
            .get(index)
            .ok_or_else(|| Par2Error::InvalidCreationOptions {
                reason: "creation plan volume paths are inconsistent".to_string(),
            })?;
        total = checked_memory_add(
            total,
            path_memory_bytes(path).checked_add(128).ok_or_else(|| {
                Par2Error::ResourceLimitExceeded {
                    reason: "staged path estimate overflows".to_string(),
                }
            })?,
            "creation transaction estimate overflows",
        )?;
        total = checked_memory_add(
            total,
            volume.filename.len().checked_add(64).ok_or_else(|| {
                Par2Error::ResourceLimitExceeded {
                    reason: "volume filename estimate overflows".to_string(),
                }
            })?,
            "creation transaction estimate overflows",
        )?;
    }

    for bytes in [
        checked_memory_product(sources.len(), 128, "source provider estimate overflows")?,
        checked_memory_product(
            recovery_count as usize,
            size_of::<RecoveryExponent>(),
            "encoder exponent estimate overflows",
        )?,
        checked_memory_product(
            volumes.len(),
            size_of::<RecoveryVolumePlan>(),
            "volume plan estimate overflows",
        )?,
        checked_memory_product(
            output_paths.len(),
            size_of::<PathBuf>(),
            "output path estimate overflows",
        )?,
    ] {
        total = checked_memory_add(total, bytes, "creation transaction estimate overflows")?;
    }
    for path in output_paths {
        total = checked_memory_add(
            total,
            path_memory_bytes(path).checked_add(128).ok_or_else(|| {
                Par2Error::ResourceLimitExceeded {
                    reason: "output path estimate overflows".to_string(),
                }
            })?,
            "output path estimate overflows",
        )?;
    }
    for path in [base_path, output_stem, main_path] {
        total = checked_memory_add(
            total,
            path_memory_bytes(path).checked_add(128).ok_or_else(|| {
                Par2Error::ResourceLimitExceeded {
                    reason: "creation path estimate overflows".to_string(),
                }
            })?,
            "creation path estimate overflows",
        )?;
    }
    let cloned_path_capacity = allocation_capacity_upper_bound(output_paths.len())?;
    for (count, element_size) in [
        (cloned_path_capacity, size_of::<PathBuf>()),
        (cloned_path_capacity, size_of::<TargetSnapshot>()),
        (cloned_path_capacity, size_of::<BackupEntry>()),
        (cloned_path_capacity, size_of::<InstalledTarget>()),
    ] {
        total = checked_memory_add(
            total,
            checked_memory_product(
                count,
                element_size,
                "transaction metadata estimate overflows",
            )?,
            "creation transaction estimate overflows",
        )?;
    }
    for path in output_paths {
        let path_copy_bytes = path_memory_bytes(path).checked_add(256).ok_or_else(|| {
            Par2Error::ResourceLimitExceeded {
                reason: "transaction path capacity estimate overflows".to_string(),
            }
        })?;
        total = checked_memory_add(
            total,
            checked_memory_product(
                6,
                path_copy_bytes,
                "transaction path capacity estimate overflows",
            )?,
            "creation transaction estimate overflows",
        )?;
    }
    total = checked_memory_add(
        total,
        size_of::<StagedOutputs>(),
        "creation transaction estimate overflows",
    )?;
    Ok(total)
}

pub(crate) fn estimate_validation_workspace_bytes(
    sources: &[CreationSource],
    output_paths: &[PathBuf],
    volumes: &[RecoveryVolumePlan],
    critical_packet_bytes: usize,
) -> Result<usize> {
    const SCANNER_BUFFER_BYTES: usize = 256 * 1024;
    const RECOVERY_HASH_BUFFER_BYTES: usize = 256 * 1024;
    const MAX_CREATOR_BODY_BYTES: usize = 100_000;

    let critical_count = 1usize
        .checked_add(sources.len().checked_mul(2).ok_or_else(|| {
            Par2Error::ResourceLimitExceeded {
                reason: "validation critical packet count overflows".to_string(),
            }
        })?)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: "validation critical packet count overflows".to_string(),
        })?;
    let max_recovery_count = volumes
        .iter()
        .map(|volume| volume.recovery_count)
        .max()
        .unwrap_or(0);
    let critical_copies = usize::try_from(bit_length(max_recovery_count).max(1)).map_err(|_| {
        Par2Error::ResourceLimitExceeded {
            reason: "validation critical copy count overflows".to_string(),
        }
    })?;
    let max_packet_count = expected_packet_count(max_recovery_count, critical_count)?;
    let parsed_critical_bytes = checked_memory_product(
        critical_packet_bytes,
        critical_copies,
        "validation parsed critical packet estimate overflows",
    )?;
    let parsed_packet_slots = checked_memory_product(
        allocation_capacity_upper_bound(max_packet_count)?,
        size_of::<crate::packet::ScannedPacket>(),
        "validation parsed packet controller estimate overflows",
    )?;
    let recovery_path_bytes = output_paths
        .iter()
        .map(|path| path_memory_bytes(path).saturating_add(128))
        .max()
        .unwrap_or(128);
    let parsed_recovery_paths = checked_memory_product(
        max_packet_count,
        recovery_path_bytes,
        "validation recovery path estimate overflows",
    )?;
    let per_volume = [
        parsed_critical_bytes,
        parsed_packet_slots,
        parsed_recovery_paths,
        size_of::<Vec<crate::packet::ScannedPacket>>(),
        MAX_CREATOR_BODY_BYTES
            .checked_add(size_of::<crate::packet::Packet>())
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "validation Creator packet estimate overflows".to_string(),
            })?,
        SCANNER_BUFFER_BYTES,
        RECOVERY_HASH_BUFFER_BYTES,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| {
        checked_memory_add(total, bytes, "validation workspace estimate overflows")
    })?;
    // Validation runs volumes concurrently (StagedOutputs::validate), each
    // holding its own full workspace, so the peak scales with the concurrent
    // volume count. StagedOutputs holds one staged volume per OUTPUT PATH
    // (the index .par2 plus the recovery volumes; `volumes` counts recovery
    // volumes only), so the gate mirrors validate()'s parallel/sequential
    // split over that collection, and the +1 covers the calling thread
    // participating in the pool. Uses the process-stable thread count, never
    // rayon's pool-relative view.
    let staged_volumes = output_paths.len();
    let threads = super::encode::configured_create_threads();
    let concurrent_volumes = if threads == 1 || staged_volumes <= 1 {
        1
    } else {
        staged_volumes.min(threads.saturating_add(1))
    };
    checked_memory_product(
        per_volume,
        concurrent_volumes,
        "concurrent validation workspace estimate overflows",
    )
}

fn expected_packet_count(recovery_count: u32, critical_count: usize) -> Result<usize> {
    let recovery_count_usize = recovery_count as usize;
    if recovery_count == 0 {
        return critical_count
            .checked_add(1)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "expected packet estimate overflows".to_string(),
            });
    }
    let copies = bit_length(recovery_count) as usize;
    let mut pending = 0u64;
    let mut total =
        recovery_count_usize
            .checked_add(1)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "expected packet estimate overflows".to_string(),
            })?;
    for _ in 0..recovery_count {
        pending = pending
            .checked_add(
                (copies as u64)
                    .checked_mul(critical_count as u64)
                    .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                        reason: "expected packet estimate overflows".to_string(),
                    })?,
            )
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "expected packet estimate overflows".to_string(),
            })?;
        while pending >= recovery_count as u64 {
            total = total
                .checked_add(1)
                .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                    reason: "expected packet estimate overflows".to_string(),
                })?;
            pending -= recovery_count as u64;
        }
    }
    Ok(total)
}

fn allocation_capacity_upper_bound(length: usize) -> Result<usize> {
    if length == 0 {
        Ok(0)
    } else {
        length
            .checked_next_power_of_two()
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "transaction allocation estimate overflows".to_string(),
            })
    }
}

fn checked_memory_product(left: usize, right: usize, reason: &'static str) -> Result<usize> {
    left.checked_mul(right)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: reason.to_string(),
        })
}

fn checked_memory_add(left: usize, right: usize, reason: &'static str) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: reason.to_string(),
        })
}

fn encoded_packet_len(body_len: usize) -> Result<usize> {
    let padded = body_len
        .checked_add(3)
        .map(|length| length / 4 * 4)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: "packet memory estimate overflows".to_string(),
        })?;
    HEADER_SIZE
        .checked_add(padded)
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: "packet memory estimate overflows".to_string(),
        })
}

fn path_memory_bytes(path: &Path) -> usize {
    path.as_os_str().len()
}

/// Files produced by a successful creation transaction.
#[derive(Debug, Clone)]
pub struct Par2CreateOutcome {
    /// Recovery-set identifier shared by all packets.
    pub recovery_set_id: RecoverySetId,
    /// Main output path.
    pub main_path: PathBuf,
    /// Recovery volume paths.
    pub volume_paths: Vec<PathBuf>,
    /// All committed output paths, with the main file first.
    pub output_paths: Vec<PathBuf>,
    /// Total number of source slices.
    pub source_slice_count: u32,
    /// Total number of recovery slices.
    pub recovery_count: u32,
    /// Total bytes committed across all output files.
    pub bytes_written: u64,
    /// True when no output files were written.
    pub dry_run: bool,
    /// Backend policy requested by the creator.
    pub requested_backend: CreationBackend,
    /// Backend selected after preflight.
    pub selected_backend: CreationBackend,
}

#[derive(Clone)]
enum ExpectedPacket {
    Main,
    FileDescription(FileId),
    InputFileSliceChecksum(FileId),
    Recovery(RecoveryExponent),
    Creator,
}

struct RecoverySlot {
    exponent: RecoveryExponent,
    header_offset: u64,
    data_offset: u64,
    bytes_written: u64,
    hasher: Md5State,
}

struct VolumeState {
    stage_path: PathBuf,
    target_path: PathBuf,
    file: File,
    expected: Vec<ExpectedPacket>,
    recovery_slots: Vec<RecoverySlot>,
}

#[derive(Clone, Copy)]
struct RecoveryLocation {
    volume_index: usize,
    slot_index: usize,
}

struct StagedOutputs {
    volumes: Vec<VolumeState>,
    locations: Vec<RecoveryLocation>,
    planned_targets: Vec<TargetSnapshot>,
    committed: bool,
}

#[derive(Clone)]
struct InstalledTarget {
    path: PathBuf,
    identity: Option<FileIdentity>,
}

struct BackupEntry {
    target: PathBuf,
    backup: PathBuf,
    namespace: PathBuf,
    identity: FileIdentity,
}

#[derive(Debug)]
enum PublishError {
    NotInstalled(std::io::Error),
    Installed {
        identity: FileIdentity,
        error: std::io::Error,
    },
}

impl PublishError {
    #[cfg(test)]
    fn into_io_error(self) -> std::io::Error {
        match self {
            Self::NotInstalled(error) | Self::Installed { error, .. } => error,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RollbackTarget {
    Missing,
    OwnedQuarantined(PathBuf),
    Unchanged,
}

impl RollbackTarget {
    fn can_restore_backup(&self) -> bool {
        matches!(self, Self::Missing | Self::OwnedQuarantined(_))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows { volume: u32, index: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetSnapshot {
    Absent,
    File(FileIdentity),
    Directory,
    Symlink,
    Special,
}

#[cfg(windows)]
#[repr(C)]
#[allow(dead_code)]
struct WindowsFileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[cfg(windows)]
#[repr(C)]
#[allow(dead_code)]
struct WindowsByHandleFileInformation {
    file_attributes: u32,
    creation_time: WindowsFileTime,
    last_access_time: WindowsFileTime,
    last_write_time: WindowsFileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[cfg(windows)]
#[allow(non_snake_case)]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        file: std::os::windows::io::RawHandle,
        information: *mut WindowsByHandleFileInformation,
    ) -> i32;
}

impl FileIdentity {
    #[cfg(unix)]
    fn from_metadata(metadata: &fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;

        Some(Self::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    fn from_file(file: &File) -> std::io::Result<Self> {
        use std::os::windows::io::AsRawHandle;

        let mut information = MaybeUninit::<WindowsByHandleFileInformation>::uninit();
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) }
                != 0;
        if !succeeded {
            return Err(std::io::Error::last_os_error());
        }
        let information = unsafe { information.assume_init() };
        Ok(Self::Windows {
            volume: information.volume_serial_number,
            index: (u64::from(information.file_index_high) << 32)
                | u64::from(information.file_index_low),
        })
    }
}

impl StagedOutputs {
    fn create(
        plan: &Par2CreatePlan,
        critical: &[(ExpectedPacket, Vec<u8>)],
        creator: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let mut volumes: Vec<VolumeState> = Vec::with_capacity(plan.output_paths.len());
        for (index, target) in plan.output_paths.iter().enumerate() {
            if cancellation.is_cancelled() {
                cleanup_stage_files(volumes);
                return Err(Par2Error::Cancelled);
            }
            let (stage_path, file) = match create_stage_file(target, index) {
                Ok(result) => result,
                Err(error) => {
                    cleanup_stage_files(volumes);
                    return Err(error);
                }
            };
            volumes.push(VolumeState {
                stage_path,
                target_path: target.clone(),
                file,
                expected: Vec::new(),
                recovery_slots: Vec::new(),
            });
        }
        let mut staged = Self {
            volumes,
            locations: Vec::with_capacity(plan.recovery_count as usize),
            planned_targets: plan.target_snapshots.clone(),
            committed: false,
        };

        for (expected, packet) in critical {
            check_cancel(cancellation)?;
            append_packet(&mut staged.volumes[0], expected.clone(), packet)?;
        }
        check_cancel(cancellation)?;
        append_packet(&mut staged.volumes[0], ExpectedPacket::Creator, creator)?;

        for (volume_offset, volume_plan) in plan.volumes.iter().enumerate() {
            check_cancel(cancellation)?;
            let volume_index = volume_offset + 1;
            if volume_plan.recovery_count == 0 {
                for (expected, packet) in critical {
                    check_cancel(cancellation)?;
                    append_packet(&mut staged.volumes[volume_index], expected.clone(), packet)?;
                }
            } else {
                let copies = bit_length(volume_plan.recovery_count) as u64;
                let critical_count = critical.len() as u64;
                let mut packet_count = 0u64;
                let mut next_critical = 0usize;
                for offset in 0..volume_plan.recovery_count {
                    check_cancel(cancellation)?;
                    let exponent = volume_plan.first_exponent + offset;
                    let global_index = staged.locations.len();
                    append_recovery_slot(
                        &mut staged,
                        volume_index,
                        global_index,
                        exponent,
                        plan,
                        cancellation,
                    )?;
                    packet_count = packet_count
                        .checked_add(copies.checked_mul(critical_count).ok_or_else(|| {
                            Par2Error::ResourceLimitExceeded {
                                reason: "critical packet interleaving count overflows".to_string(),
                            }
                        })?)
                        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                            reason: "critical packet interleaving count overflows".to_string(),
                        })?;
                    while packet_count >= volume_plan.recovery_count as u64 {
                        check_cancel(cancellation)?;
                        let (expected, packet) = &critical[next_critical];
                        append_packet(&mut staged.volumes[volume_index], expected.clone(), packet)?;
                        next_critical = (next_critical + 1) % critical.len();
                        packet_count -= volume_plan.recovery_count as u64;
                    }
                }
            }
            check_cancel(cancellation)?;
            append_packet(
                &mut staged.volumes[volume_index],
                ExpectedPacket::Creator,
                creator,
            )?;
        }
        Ok(staged)
    }

    fn finish_recovery_headers(
        &mut self,
        slice_size: usize,
        set_id: RecoverySetId,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        for volume in &mut self.volumes {
            for slot in &mut volume.recovery_slots {
                check_cancel(cancellation)?;
                if slot.bytes_written != slice_size as u64 {
                    return Err(Par2Error::CreationValidation {
                        path: volume.stage_path.display().to_string(),
                        reason: format!(
                            "recovery exponent {} received {} of {} bytes",
                            slot.exponent, slot.bytes_written, slice_size
                        ),
                    });
                }
                let packet_length = (HEADER_SIZE as u64)
                    .checked_add(4)
                    .and_then(|length| length.checked_add(slice_size as u64))
                    .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                        reason: "recovery packet length overflows".to_string(),
                    })?;
                let hash = std::mem::replace(&mut slot.hasher, Md5State::new()).finalize();
                let header = encode_header(
                    crate::packet::header::TYPE_RECOVERY,
                    set_id,
                    packet_length,
                    hash,
                )?;
                volume.file.seek(SeekFrom::Start(slot.header_offset))?;
                volume.file.write_all(&header)?;
            }
            volume.file.flush()?;
            volume.file.sync_all()?;
        }
        Ok(())
    }

    fn validate(
        &mut self,
        plan: &Par2CreatePlan,
        sources: &[CreationSource],
        cancellation: &CancellationToken,
    ) -> Result<()> {
        // Volumes validate independently; running them in parallel overlaps
        // their fsyncs and re-read hashing, which dominates on network
        // storage. The sequential arm keeps the wasm / pinned-single-thread
        // behavior, and errors surface first-by-volume-order in both arms
        // (rayon's own Result collection would report an arbitrary racer).
        let validate_parallel = !cfg!(target_family = "wasm")
            && self.volumes.len() > 1
            && super::encode::configured_create_threads() != 1;
        if !validate_parallel {
            for volume in &mut self.volumes {
                check_cancel(cancellation)?;
                volume.file.flush()?;
                volume.file.sync_all()?;
                validate_staged_volume(volume, plan, sources, cancellation)?;
            }
            return Ok(());
        }
        use rayon::prelude::*;
        self.volumes
            .par_iter_mut()
            .map(|volume| {
                check_cancel(cancellation)?;
                volume.file.flush()?;
                volume.file.sync_all()?;
                validate_staged_volume(volume, plan, sources, cancellation)
            })
            .collect::<Vec<Result<()>>>()
            .into_iter()
            .collect::<Result<Vec<()>>>()
            .map(|_| ())
    }

    fn commit(self, overwrite: bool, cancellation: &CancellationToken) -> Result<()> {
        self.commit_with_publish_hook(overwrite, cancellation, |_, _| {})
    }

    fn commit_with_publish_hook<F>(
        self,
        overwrite: bool,
        cancellation: &CancellationToken,
        before_publish: F,
    ) -> Result<()>
    where
        F: FnMut(&Path, &Path),
    {
        self.commit_with_transaction_hooks(overwrite, cancellation, |_, _| {}, before_publish)
    }

    fn commit_with_transaction_hooks<F, G>(
        mut self,
        overwrite: bool,
        cancellation: &CancellationToken,
        mut before_backup_rename: F,
        mut before_publish: G,
    ) -> Result<()>
    where
        F: FnMut(&Path, &Path),
        G: FnMut(&Path, &Path),
    {
        for volume in &mut self.volumes {
            volume.file.flush()?;
            volume.file.sync_all()?;
        }
        let volumes = std::mem::take(&mut self.volumes);
        let stage_paths = volumes
            .iter()
            .map(|volume| volume.stage_path.clone())
            .collect::<Vec<_>>();
        let targets = volumes
            .iter()
            .map(|volume| volume.target_path.clone())
            .collect::<Vec<_>>();
        drop(volumes);
        let planned_targets = std::mem::take(&mut self.planned_targets);

        let mut backups = Vec::<BackupEntry>::new();
        let mut installed = Vec::<InstalledTarget>::new();
        let result = (|| {
            if planned_targets.len() != targets.len() {
                return Err(Par2Error::InvalidCreationOptions {
                    reason: "creation target snapshot count is inconsistent".to_string(),
                });
            }
            if overwrite {
                for (index, target) in targets.iter().enumerate() {
                    if cancellation.is_cancelled() {
                        return Err(Par2Error::Cancelled);
                    }
                    let planned = planned_targets[index];
                    let current = capture_target_snapshot(target).map_err(Par2Error::Io)?;
                    if current != planned {
                        return Err(Par2Error::CreationValidation {
                            path: target.display().to_string(),
                            reason: "output target changed after planning".to_string(),
                        });
                    }
                    if matches!(planned, TargetSnapshot::Directory) {
                        return Err(Par2Error::UnsafeCreationOutput {
                            path: target.display().to_string(),
                            reason: "output path is a directory".to_string(),
                        });
                    }
                    if matches!(planned, TargetSnapshot::Absent) {
                        continue;
                    }
                    let TargetSnapshot::File(_) = planned else {
                        return Err(Par2Error::UnsafeCreationOutput {
                            path: target.display().to_string(),
                            reason: "output path is not a regular file".to_string(),
                        });
                    };
                    let (namespace, backup) = reserve_backup_namespace(target, index)?;
                    before_backup_rename(target, &backup);
                    if let Err(error) = fs::rename(target, &backup) {
                        let _ = fs::remove_dir(&namespace);
                        return Err(Par2Error::Io(error));
                    }
                    let moved = capture_target_snapshot(&backup).map_err(Par2Error::Io)?;
                    if moved != planned {
                        match restore_moved_target(&backup, target, moved) {
                            Ok(true) => {
                                fs::remove_dir(&namespace).map_err(|error| {
                                    backup_recovery_error(
                                        target,
                                        &backup,
                                        format!("output backup cleanup failed: {error}"),
                                    )
                                })?;
                            }
                            Ok(false) => {
                                return Err(backup_recovery_error(
                                    target,
                                    &backup,
                                    "output restore found an occupied target".to_string(),
                                ));
                            }
                            Err(error) => {
                                return Err(backup_recovery_error(
                                    target,
                                    &backup,
                                    format!("output restore failed: {error}"),
                                ));
                            }
                        }
                        return Err(Par2Error::CreationValidation {
                            path: target.display().to_string(),
                            reason: "output target changed while reserving backup".to_string(),
                        });
                    }
                    let TargetSnapshot::File(identity) = moved else {
                        return Err(Par2Error::CreationValidation {
                            path: target.display().to_string(),
                            reason: "output identity is unavailable".to_string(),
                        });
                    };
                    backups.push(BackupEntry {
                        target: target.clone(),
                        backup,
                        namespace,
                        identity,
                    });
                }
            }
            for (stage, target) in stage_paths.iter().zip(targets.iter()) {
                if cancellation.is_cancelled() {
                    return Err(Par2Error::Cancelled);
                }
                let identity = match publish_no_replace_with_tracking(stage, target, || {
                    before_publish(stage, target)
                }) {
                    Ok(identity) => identity,
                    Err(PublishError::Installed { identity, error }) => {
                        installed.push(InstalledTarget {
                            path: target.clone(),
                            identity: Some(identity),
                        });
                        return Err(Par2Error::Io(error));
                    }
                    Err(PublishError::NotInstalled(error)) => {
                        if error.kind() == std::io::ErrorKind::AlreadyExists {
                            return Err(Par2Error::CreationOutputExists {
                                path: target.display().to_string(),
                            });
                        }
                        return Err(Par2Error::Io(error));
                    }
                };
                installed.push(InstalledTarget {
                    path: target.clone(),
                    identity: Some(identity),
                });
            }
            sync_parent_directories(&targets)?;
            Ok(())
        })();

        if let Err(error) = result {
            let mut restorable_targets = Vec::new();
            let mut rollback_error = None;
            for installed_target in installed.iter().rev() {
                match quarantine_owned_target(installed_target) {
                    Ok(rollback) => {
                        if rollback.can_restore_backup() {
                            restorable_targets.push(installed_target.path.clone());
                        }
                    }
                    Err(error) => {
                        if rollback_error.is_none() {
                            rollback_error = Some(error);
                        }
                    }
                }
            }
            if overwrite {
                for backup_entry in backups.iter().rev() {
                    if !installed
                        .iter()
                        .any(|installed_target| installed_target.path == backup_entry.target)
                        || restorable_targets
                            .iter()
                            .any(|restorable| restorable == &backup_entry.target)
                    {
                        // Restore without replacement. Rollback keeps the
                        // private backup recoverable because stable Rust has
                        // no cross-platform handle-bound unlink primitive.
                        let identity = target_file_identity(&backup_entry.backup);
                        if !matches!(identity, Ok(Some(identity)) if identity == backup_entry.identity)
                        {
                            if rollback_error.is_none() {
                                rollback_error = Some(match identity {
                                    Err(error) => Par2Error::Io(error),
                                    Ok(_) => Par2Error::CreationValidation {
                                        path: backup_entry.target.display().to_string(),
                                        reason: "backup identity changed during restore"
                                            .to_string(),
                                    },
                                });
                            }
                            continue;
                        }
                        match restore_moved_target(
                            &backup_entry.backup,
                            &backup_entry.target,
                            TargetSnapshot::File(backup_entry.identity),
                        ) {
                            Ok(true) => {}
                            Ok(false) => {
                                if rollback_error.is_none() {
                                    rollback_error = Some(backup_recovery_error(
                                        &backup_entry.target,
                                        &backup_entry.backup,
                                        "output restore lost a replacement race".to_string(),
                                    ));
                                }
                            }
                            Err(error) => {
                                if rollback_error.is_none() {
                                    rollback_error = Some(backup_recovery_error(
                                        &backup_entry.target,
                                        &backup_entry.backup,
                                        format!("output restore failed: {error}"),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            for backup_entry in &backups {
                if !backup_entry.backup.exists() {
                    let _ = fs::remove_dir(&backup_entry.namespace);
                }
            }
            for stage in &stage_paths {
                let _ = fs::remove_file(stage);
            }
            return Err(rollback_error.unwrap_or(error));
        }
        let mut cleanup_error = None;
        for backup_entry in backups {
            match target_file_identity(&backup_entry.backup) {
                Ok(Some(identity)) if identity == backup_entry.identity => {
                    if let Err(error) = fs::remove_file(&backup_entry.backup) {
                        if cleanup_error.is_none() {
                            cleanup_error = Some(backup_recovery_error(
                                &backup_entry.target,
                                &backup_entry.backup,
                                format!("output backup cleanup failed: {error}"),
                            ));
                        }
                    } else if let Err(error) = fs::remove_dir(&backup_entry.namespace)
                        && cleanup_error.is_none()
                    {
                        cleanup_error = Some(backup_recovery_error(
                            &backup_entry.target,
                            &backup_entry.namespace,
                            format!("output backup namespace cleanup failed: {error}"),
                        ));
                    }
                }
                Ok(_) => {
                    if cleanup_error.is_none() {
                        cleanup_error = Some(backup_recovery_error(
                            &backup_entry.target,
                            &backup_entry.backup,
                            "output backup changed before cleanup".to_string(),
                        ));
                    }
                }
                Err(error) => {
                    if cleanup_error.is_none() {
                        cleanup_error = Some(backup_recovery_error(
                            &backup_entry.target,
                            &backup_entry.backup,
                            format!("output backup cleanup could not be verified: {error}"),
                        ));
                    }
                }
            }
        }
        self.committed = true;
        cleanup_error.map_or(Ok(()), Err)
    }

    fn bytes_written(&self) -> Result<u64> {
        self.volumes.iter().try_fold(0u64, |total, volume| {
            fs::metadata(&volume.stage_path)
                .map(|metadata| metadata.len())
                .or_else(|_| fs::metadata(&volume.target_path).map(|metadata| metadata.len()))
                .map_err(Par2Error::Io)
                .and_then(|length| {
                    total
                        .checked_add(length)
                        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                            reason: "output byte count overflows".to_string(),
                        })
                })
        })
    }
}

impl Drop for StagedOutputs {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        cleanup_stage_files(std::mem::take(&mut self.volumes));
    }
}

fn cleanup_stage_files(volumes: Vec<VolumeState>) {
    let stage_paths = volumes
        .iter()
        .map(|volume| volume.stage_path.clone())
        .collect::<Vec<_>>();
    drop(volumes);
    for stage_path in stage_paths {
        let _ = fs::remove_file(stage_path);
    }
}

pub(crate) fn write_outputs(
    plan: &Par2CreatePlan,
    sources: &[CreationSource],
    options: &Par2CreatorOptions,
    mut backend: SelectedBackend,
) -> Result<Par2CreateOutcome> {
    if options.cancellation.is_cancelled() {
        return Err(Par2Error::Cancelled);
    }
    let critical = build_critical_packets(plan, sources)?;
    let creator = encode_creator_packet(plan.recovery_set_id)?;
    let mut staged = StagedOutputs::create(plan, &critical, &creator, &options.cancellation)?;

    if plan.recovery_count > 0 {
        let slice_size =
            usize::try_from(plan.slice_size).map_err(|_| Par2Error::ResourceLimitExceeded {
                reason: "slice size exceeds addressable memory".to_string(),
            })?;
        let mut provider = DiskSourceProvider::open(sources, slice_size, &options.cancellation)?;
        {
            let mut sink = RecoveryWriter {
                outputs: &mut staged,
                cancellation: &options.cancellation,
                slice_size,
            };
            match &mut backend {
                SelectedBackend::Cpu => {
                    let encoder = ForwardEncoder::new(slice_size, plan.recovery_exponents.clone())?;
                    encoder.encode_to(
                        &mut provider,
                        &ForwardEncoderOptions {
                            memory_limit: options.memory_limit,
                            cancel: Some(options.cancellation.clone()),
                            progress: options.progress.clone(),
                            kernel: options.forward_kernel,
                        },
                        &mut sink,
                    )?;
                }
                #[cfg(all(feature = "metal", target_os = "macos", target_arch = "aarch64"))]
                SelectedBackend::Metal(state) => state.encode(
                    &mut provider,
                    &plan.recovery_exponents,
                    slice_size,
                    &options.cancellation,
                    options.progress.clone(),
                    &mut sink,
                )?,
            }
        }
        provider.verify_unchanged()?;
        staged.finish_recovery_headers(slice_size, plan.recovery_set_id, &options.cancellation)?;
    }

    staged.validate(plan, sources, &options.cancellation)?;
    let bytes_written = staged.bytes_written()?;
    staged.commit(options.overwrite, &options.cancellation)?;
    Ok(Par2CreateOutcome {
        recovery_set_id: plan.recovery_set_id,
        main_path: plan.main_path.clone(),
        volume_paths: plan.volume_paths.clone(),
        output_paths: plan.output_paths.clone(),
        source_slice_count: plan.source_slice_count,
        recovery_count: plan.recovery_count,
        bytes_written,
        dry_run: false,
        requested_backend: options.backend,
        selected_backend: selected_policy(&backend),
    })
}

fn build_critical_packets(
    plan: &Par2CreatePlan,
    sources: &[CreationSource],
) -> Result<Vec<(ExpectedPacket, Vec<u8>)>> {
    let mut main_body = Vec::with_capacity(12 + sources.len() * 16);
    main_body.extend_from_slice(&plan.slice_size.to_le_bytes());
    main_body.extend_from_slice(&(sources.len() as u32).to_le_bytes());
    for source in sources {
        main_body.extend_from_slice(source.file_id.as_bytes());
    }
    let mut packets = Vec::with_capacity(1 + sources.len() * 2);
    packets.push((
        ExpectedPacket::Main,
        encode_packet(
            crate::packet::header::TYPE_MAIN,
            plan.recovery_set_id,
            &main_body,
        )?,
    ));
    for source in sources {
        let mut body = Vec::with_capacity(56 + source.par2_name.len() + 3);
        body.extend_from_slice(source.file_id.as_bytes());
        body.extend_from_slice(&source.hash_full);
        body.extend_from_slice(&source.hash_16k);
        body.extend_from_slice(&source.file_length.to_le_bytes());
        body.extend_from_slice(source.par2_name.as_bytes());
        pad_body(&mut body)?;
        packets.push((
            ExpectedPacket::FileDescription(source.file_id),
            encode_packet(
                crate::packet::header::TYPE_FILE_DESC,
                plan.recovery_set_id,
                &body,
            )?,
        ));
    }
    for source in sources {
        let mut body = Vec::with_capacity(16 + source.slice_checksums.len() * 20);
        body.extend_from_slice(source.file_id.as_bytes());
        for checksum in &source.slice_checksums {
            body.extend_from_slice(&checksum.md5);
            body.extend_from_slice(&checksum.crc32.to_le_bytes());
        }
        pad_body(&mut body)?;
        packets.push((
            ExpectedPacket::InputFileSliceChecksum(source.file_id),
            encode_packet(
                crate::packet::header::TYPE_IFSC,
                plan.recovery_set_id,
                &body,
            )?,
        ));
    }
    Ok(packets)
}

fn encode_creator_packet(set_id: RecoverySetId) -> Result<Vec<u8>> {
    let mut body = CREATOR_ID.to_vec();
    pad_body(&mut body)?;
    encode_packet(TYPE_CREATOR, set_id, &body)
}

fn append_packet(volume: &mut VolumeState, expected: ExpectedPacket, packet: &[u8]) -> Result<()> {
    volume.file.write_all(packet).map_err(Par2Error::Io)?;
    volume.expected.push(expected);
    Ok(())
}

fn append_recovery_slot(
    staged: &mut StagedOutputs,
    volume_index: usize,
    global_index: usize,
    exponent: RecoveryExponent,
    plan: &Par2CreatePlan,
    cancellation: &CancellationToken,
) -> Result<()> {
    check_cancel(cancellation)?;
    let slice_size =
        usize::try_from(plan.slice_size).map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: "slice size exceeds addressable memory".to_string(),
        })?;
    let packet_length = (HEADER_SIZE as u64)
        .checked_add(4)
        .and_then(|length| length.checked_add(slice_size as u64))
        .ok_or_else(|| Par2Error::ResourceLimitExceeded {
            reason: "recovery packet length overflows".to_string(),
        })?;
    let volume =
        staged
            .volumes
            .get_mut(volume_index)
            .ok_or_else(|| Par2Error::CreationValidation {
                path: plan.output_paths.get(volume_index).map_or_else(
                    || "recovery output".to_string(),
                    |path| path.display().to_string(),
                ),
                reason: "recovery volume index is out of range".to_string(),
            })?;
    let header_offset = volume.file.stream_position().map_err(Par2Error::Io)?;
    let header = encode_header(
        crate::packet::header::TYPE_RECOVERY,
        plan.recovery_set_id,
        packet_length,
        [0; 16],
    )?;
    volume.file.write_all(&header).map_err(Par2Error::Io)?;
    volume
        .file
        .write_all(&exponent.to_le_bytes())
        .map_err(Par2Error::Io)?;
    let data_offset = volume.file.stream_position().map_err(Par2Error::Io)?;
    write_zeroes(&mut volume.file, slice_size, cancellation)?;
    check_cancel(cancellation)?;
    volume.expected.push(ExpectedPacket::Recovery(exponent));
    let slot_index = volume.recovery_slots.len();
    volume.recovery_slots.push(RecoverySlot {
        exponent,
        header_offset,
        data_offset,
        bytes_written: 0,
        hasher: {
            let mut hasher =
                start_streamed_hash(plan.recovery_set_id, crate::packet::header::TYPE_RECOVERY);
            hasher.update(&exponent.to_le_bytes());
            hasher
        },
    });
    if global_index != staged.locations.len() {
        return Err(Par2Error::CreationValidation {
            path: volume.stage_path.display().to_string(),
            reason: "recovery output order is inconsistent".to_string(),
        });
    }
    staged.locations.push(RecoveryLocation {
        volume_index,
        slot_index,
    });
    Ok(())
}

fn validate_staged_volume(
    volume: &VolumeState,
    plan: &Par2CreatePlan,
    sources: &[CreationSource],
    cancellation: &CancellationToken,
) -> Result<()> {
    check_cancel(cancellation)?;
    let file_length = fs::metadata(&volume.stage_path)
        .map_err(Par2Error::Io)?
        .len();
    let scanned =
        match scan_packets_from_path_with_set_ids_cancellable(&volume.stage_path, cancellation) {
            Ok(scanned) => scanned,
            Err(Par2Error::Cancelled) => return Err(Par2Error::Cancelled),
            Err(error) => {
                return Err(Par2Error::CreationValidation {
                    path: volume.stage_path.display().to_string(),
                    reason: error.to_string(),
                });
            }
        };
    validation_checkpoint(cancellation);
    check_cancel(cancellation)?;
    if scanned.len() != volume.expected.len() {
        return Err(validation_error(
            &volume.stage_path,
            format!(
                "parsed {} packets but staged {} packets",
                scanned.len(),
                volume.expected.len()
            ),
        ));
    }
    let mut file = File::open(&volume.stage_path).map_err(Par2Error::Io)?;
    let mut offset = 0u64;
    for (scanned, expected) in scanned.iter().zip(&volume.expected) {
        check_cancel(cancellation)?;
        if scanned.offset != offset || scanned.recovery_set_id != plan.recovery_set_id {
            return Err(validation_error(
                &volume.stage_path,
                "packet offsets or recovery-set identifiers are inconsistent".to_string(),
            ));
        }
        let mut header_bytes = [0u8; HEADER_SIZE];
        file.seek(SeekFrom::Start(offset)).map_err(Par2Error::Io)?;
        file.read_exact(&mut header_bytes).map_err(Par2Error::Io)?;
        let header = PacketHeader::parse(&header_bytes, offset)
            .map_err(|error| validation_error(&volume.stage_path, error.to_string()))?;
        offset = offset.checked_add(header.length).ok_or_else(|| {
            validation_error(&volume.stage_path, "packet offsets overflow".to_string())
        })?;
        validate_expected_packet(
            scanned,
            expected,
            plan,
            sources,
            &volume.stage_path,
            cancellation,
        )?;
    }
    check_cancel(cancellation)?;
    if offset != file_length {
        return Err(validation_error(
            &volume.stage_path,
            format!("packet stream ends at {offset}, file length is {file_length}"),
        ));
    }
    Ok(())
}

fn validate_expected_packet(
    scanned: &crate::packet::ScannedPacket,
    expected: &ExpectedPacket,
    plan: &Par2CreatePlan,
    sources: &[CreationSource],
    path: &Path,
    cancellation: &CancellationToken,
) -> Result<()> {
    check_cancel(cancellation)?;
    if scanned.recovery_set_id != plan.recovery_set_id {
        return Err(validation_error(
            path,
            "packet recovery-set identifier differs from plan".to_string(),
        ));
    }
    match (expected, &scanned.packet) {
        (ExpectedPacket::Main, Packet::Main(packet)) => {
            let ids = sources
                .iter()
                .map(|source| source.file_id)
                .collect::<Vec<_>>();
            if packet.slice_size != plan.slice_size
                || packet.recovery_file_ids != ids
                || !packet.non_recovery_file_ids.is_empty()
            {
                return Err(validation_error(
                    path,
                    "Main packet content differs from plan".to_string(),
                ));
            }
        }
        (ExpectedPacket::FileDescription(file_id), Packet::FileDescription(packet)) => {
            let source = source_by_id(sources, *file_id).ok_or_else(|| {
                validation_error(
                    path,
                    "FileDesc packet references an unknown file".to_string(),
                )
            })?;
            if packet.file_id != source.file_id
                || packet.hash_full != source.hash_full
                || packet.hash_16k != source.hash_16k
                || packet.file_length != source.file_length
                || packet.par2_name != source.par2_name
            {
                return Err(validation_error(
                    path,
                    "FileDesc packet content differs from source".to_string(),
                ));
            }
        }
        (
            ExpectedPacket::InputFileSliceChecksum(file_id),
            Packet::InputFileSliceChecksum(packet),
        ) => {
            let source = source_by_id(sources, *file_id).ok_or_else(|| {
                validation_error(path, "IFSC packet references an unknown file".to_string())
            })?;
            if packet.file_id != source.file_id || packet.checksums != source.slice_checksums {
                return Err(validation_error(
                    path,
                    "IFSC packet content differs from source".to_string(),
                ));
            }
        }
        (ExpectedPacket::Recovery(exponent), Packet::RecoverySlice(packet)) => {
            if packet.exponent != *exponent || packet.data.len() != plan.slice_size as usize {
                return Err(validation_error(
                    path,
                    "recovery packet length or exponent differs from plan".to_string(),
                ));
            }
            let valid = match packet.data.validate_packet_hash_cancellable(
                plan.recovery_set_id.as_bytes(),
                *exponent,
                cancellation,
            ) {
                Ok(valid) => valid,
                Err(Par2Error::Cancelled) => return Err(Par2Error::Cancelled),
                Err(error) => return Err(validation_error(path, error.to_string())),
            };
            if !valid {
                return Err(validation_error(
                    path,
                    "recovery packet hash is invalid".to_string(),
                ));
            }
        }
        (ExpectedPacket::Creator, Packet::Creator(packet)) => {
            if packet.creator_id.as_bytes() != CREATOR_ID {
                return Err(validation_error(
                    path,
                    "Creator packet identifier differs from plan".to_string(),
                ));
            }
        }
        _ => {
            return Err(validation_error(
                path,
                "packet type differs from expected critical order".to_string(),
            ));
        }
    }
    Ok(())
}

fn source_by_id(sources: &[CreationSource], file_id: FileId) -> Option<&CreationSource> {
    sources.iter().find(|source| source.file_id == file_id)
}

struct RecoveryWriter<'a> {
    outputs: &'a mut StagedOutputs,
    cancellation: &'a CancellationToken,
    slice_size: usize,
}

impl ForwardRecoverySink for RecoveryWriter<'_> {
    fn write_recovery_chunk(
        &mut self,
        output_index: usize,
        exponent: RecoveryExponent,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > self.slice_size
            || usize::try_from(offset)
                .ok()
                .and_then(|start| start.checked_add(data.len()))
                .is_none_or(|end| end > self.slice_size)
        {
            return Err(Par2Error::CreationValidation {
                path: "recovery output".to_string(),
                reason: "encoder supplied a chunk outside the slice".to_string(),
            });
        }
        let location = *self.outputs.locations.get(output_index).ok_or_else(|| {
            Par2Error::CreationValidation {
                path: "recovery output".to_string(),
                reason: "encoder supplied an unknown output index".to_string(),
            }
        })?;
        let volume = self
            .outputs
            .volumes
            .get_mut(location.volume_index)
            .ok_or_else(|| Par2Error::CreationValidation {
                path: "recovery output".to_string(),
                reason: "recovery volume index is out of range".to_string(),
            })?;
        let slot = volume
            .recovery_slots
            .get_mut(location.slot_index)
            .ok_or_else(|| Par2Error::CreationValidation {
                path: volume.stage_path.display().to_string(),
                reason: "recovery slot index is out of range".to_string(),
            })?;
        if slot.exponent != exponent || slot.bytes_written != offset {
            return Err(Par2Error::CreationValidation {
                path: volume.stage_path.display().to_string(),
                reason: "encoder recovery chunks are out of order".to_string(),
            });
        }
        let write_offset = slot.data_offset.checked_add(offset).ok_or_else(|| {
            Par2Error::ResourceLimitExceeded {
                reason: "recovery write offset overflows".to_string(),
            }
        })?;
        volume.file.seek(SeekFrom::Start(write_offset))?;
        volume.file.write_all(data)?;
        slot.hasher.update(data);
        slot.bytes_written = slot
            .bytes_written
            .checked_add(data.len() as u64)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "recovery byte count overflows".to_string(),
            })?;
        Ok(())
    }
}

fn sync_parent_directories(paths: &[PathBuf]) -> Result<()> {
    #[cfg(unix)]
    {
        let mut synced = Vec::<PathBuf>::new();
        for path in paths {
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            if synced.iter().any(|previous| previous == parent) {
                continue;
            }
            File::open(parent).map_err(Par2Error::Io)?.sync_all()?;
            synced.push(parent.to_path_buf());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = paths;
    }
    Ok(())
}

fn target_file_identity(path: &Path) -> std::io::Result<Option<FileIdentity>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        Ok(FileIdentity::from_metadata(&metadata))
    }
    #[cfg(windows)]
    {
        match File::open(path) {
            Ok(file) => match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    FileIdentity::from_file(&file).map(Some)
                }
                Ok(_) => Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(None)
    }
}

pub(crate) fn capture_target_snapshot(path: &Path) -> std::io::Result<TargetSnapshot> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(TargetSnapshot::Symlink),
        Ok(metadata) if metadata.is_dir() => Ok(TargetSnapshot::Directory),
        Ok(metadata) if metadata.is_file() => target_file_identity(path)?
            .map(TargetSnapshot::File)
            .ok_or_else(|| std::io::Error::other("output identity is unavailable")),
        Ok(_) => Ok(TargetSnapshot::Special),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(TargetSnapshot::Absent),
        Err(error) => Err(error),
    }
}

fn quarantine_owned_target(target: &InstalledTarget) -> Result<RollbackTarget> {
    quarantine_owned_target_with_hook(target, || {})
}

fn quarantine_owned_target_with_hook<F: FnOnce()>(
    target: &InstalledTarget,
    before_move: F,
) -> Result<RollbackTarget> {
    let Some(expected) = target.identity else {
        return Ok(RollbackTarget::Unchanged);
    };
    let (namespace, quarantine) = reserve_quarantine_namespace(&target.path, 0)?;
    match target_file_identity(&target.path).map_err(Par2Error::Io)? {
        Some(identity) if identity == expected => {}
        None => {
            let _ = fs::remove_dir(&namespace);
            return Ok(RollbackTarget::Missing);
        }
        Some(_) => {
            let _ = fs::remove_dir(&namespace);
            return Err(Par2Error::CreationValidation {
                path: target.path.display().to_string(),
                reason: "installed output identity changed before rollback".to_string(),
            });
        }
    }
    before_move();
    match fs::rename(&target.path, &quarantine) {
        Ok(()) => {
            let identity = target_file_identity(&quarantine).map_err(Par2Error::Io)?;
            if identity == Some(expected) {
                // The owned object remains recoverable in its private
                // namespace. Stable Rust has no cross-platform handle-bound
                // unlink primitive that can safely delete it after a race.
                Ok(RollbackTarget::OwnedQuarantined(namespace))
            } else {
                let moved = capture_target_snapshot(&quarantine).map_err(Par2Error::Io)?;
                match restore_moved_target(&quarantine, &target.path, moved) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(backup_recovery_error(
                            &target.path,
                            &quarantine,
                            "installed output restore found an occupied target".to_string(),
                        ));
                    }
                    Err(error) => {
                        return Err(backup_recovery_error(
                            &target.path,
                            &quarantine,
                            format!("installed output restore failed: {error}"),
                        ));
                    }
                }
                fs::remove_dir(&namespace).map_err(|error| {
                    backup_recovery_error(
                        &target.path,
                        &quarantine,
                        format!("installed output quarantine cleanup failed: {error}"),
                    )
                })?;
                Err(Par2Error::CreationValidation {
                    path: target.path.display().to_string(),
                    reason: "installed output identity changed during rollback".to_string(),
                })
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_dir(&namespace);
            Ok(RollbackTarget::Missing)
        }
        Err(error) => {
            let _ = fs::remove_dir(&namespace);
            Err(Par2Error::Io(error))
        }
    }
}

fn backup_recovery_error(target: &Path, backup: &Path, reason: String) -> Par2Error {
    Par2Error::CreationValidation {
        path: target.display().to_string(),
        reason: format!("{reason}; recovery path: {}", backup.display()),
    }
}

fn restore_moved_target(
    source: &Path,
    target: &Path,
    moved: TargetSnapshot,
) -> std::io::Result<bool> {
    if matches!(moved, TargetSnapshot::Absent) {
        return Ok(true);
    }
    match rename_no_replace(source, target) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) if no_replace_unavailable(&error) => {
            if matches!(moved, TargetSnapshot::Directory) {
                return Err(error);
            }
            match fs::hard_link(source, target) {
                Ok(()) => match fs::remove_file(source) {
                    Ok(()) => Ok(true),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
                    Err(error) => Err(error),
                },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn no_replace_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
    )
}

#[cfg(target_os = "linux")]
fn rename_no_replace(source: &Path, target: &Path) -> std::io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let target = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_no_replace(source: &Path, target: &Path) -> std::io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let target = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_no_replace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result =
        unsafe { move_file_ex_w(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "MoveFileExW"]
    fn move_file_ex_w(source: *const u16, target: *const u16, flags: u32) -> i32;
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn rename_no_replace(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(not(any(unix, windows)))]
fn rename_no_replace(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(test)]
fn publish_no_replace(stage: &Path, target: &Path) -> std::io::Result<Option<FileIdentity>> {
    publish_no_replace_with_hook(stage, target, || {})
}

#[cfg(test)]
fn publish_no_replace_with_hook<F: FnOnce()>(
    stage: &Path,
    target: &Path,
    before_publish: F,
) -> std::io::Result<Option<FileIdentity>> {
    publish_no_replace_with_tracking(stage, target, before_publish)
        .map(Some)
        .map_err(PublishError::into_io_error)
}

fn publish_no_replace_with_tracking<F: FnOnce()>(
    stage: &Path,
    target: &Path,
    before_publish: F,
) -> std::result::Result<FileIdentity, PublishError> {
    publish_no_replace_with_tracking_hooks(stage, target, before_publish, || {})
}

fn publish_no_replace_with_tracking_hooks<F: FnOnce(), G: FnOnce()>(
    stage: &Path,
    target: &Path,
    before_publish: F,
    after_link: G,
) -> std::result::Result<FileIdentity, PublishError> {
    let stage_identity = match target_file_identity(stage) {
        Ok(Some(identity)) => identity,
        Ok(None) => {
            return Err(PublishError::NotInstalled(std::io::Error::other(
                "staged output identity is unavailable",
            )));
        }
        Err(error) => return Err(PublishError::NotInstalled(error)),
    };
    before_publish();
    // The stage and target are deliberately in the same directory. A hard
    // link is an atomic create-without-replace operation on supported local
    // filesystems; unlike rename, it cannot clobber a target created after
    // planning. There is intentionally no replacing fallback.
    fs::hard_link(stage, target).map_err(PublishError::NotInstalled)?;
    after_link();
    if let Err(error) = fs::remove_file(stage) {
        return Err(PublishError::Installed {
            identity: stage_identity,
            error,
        });
    }
    Ok(stage_identity)
}

fn create_stage_file(target: &Path, index: usize) -> Result<(PathBuf, File)> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    for attempt in 0..100u32 {
        let name = format!(
            ".par2-create-{}-{stamp}-{index}-{attempt}.tmp",
            std::process::id()
        );
        let path = parent.join(name);
        // Existing stage files are never reused; create_new makes crash
        // residue inert and preserves concurrent transactions.
        match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(Par2Error::Io(error)),
        }
    }
    Err(Par2Error::ResourceLimitExceeded {
        reason: "could not allocate a unique staged output path".to_string(),
    })
}

fn reserve_backup_namespace(target: &Path, index: usize) -> Result<(PathBuf, PathBuf)> {
    reserve_private_namespace(target, index, "backup")
}

fn reserve_quarantine_namespace(target: &Path, index: usize) -> Result<(PathBuf, PathBuf)> {
    reserve_private_namespace(target, index, "quarantine")
}

fn reserve_private_namespace(
    target: &Path,
    index: usize,
    kind: &str,
) -> Result<(PathBuf, PathBuf)> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let target_name = target
        .file_name()
        .ok_or_else(|| Par2Error::UnsafeCreationOutput {
            path: target.display().to_string(),
            reason: "output path has no filename".to_string(),
        })?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    for attempt in 0..100u32 {
        let namespace = parent.join(format!(
            ".par2-create-{kind}-{}-{stamp}-{index}-{attempt}.tmp",
            std::process::id()
        ));
        match create_private_directory(&namespace) {
            Ok(()) => return Ok((namespace.clone(), namespace.join(target_name))),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(Par2Error::Io(error)),
        }
    }
    Err(Par2Error::ResourceLimitExceeded {
        reason: "could not allocate a unique transaction path".to_string(),
    })
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    fs::create_dir(path)
}

fn write_zeroes(
    file: &mut File,
    mut length: usize,
    cancellation: &CancellationToken,
) -> Result<()> {
    while length > 0 {
        check_cancel(cancellation)?;
        let take = length.min(ZERO_WRITE_BUFFER.len());
        file.write_all(&ZERO_WRITE_BUFFER[..take])
            .map_err(Par2Error::Io)?;
        length -= take;
    }
    Ok(())
}

fn check_cancel(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(Par2Error::Cancelled)
    } else {
        Ok(())
    }
}

fn pad_body(body: &mut Vec<u8>) -> Result<()> {
    let padding = (4 - body.len() % 4) % 4;
    body.try_reserve(padding)
        .map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: "packet body allocation failed".to_string(),
        })?;
    body.resize(body.len() + padding, 0);
    Ok(())
}

fn bit_length(value: u32) -> u32 {
    u32::BITS - value.leading_zeros()
}

fn validation_error(path: &Path, reason: String) -> Par2Error {
    Par2Error::CreationValidation {
        path: path.display().to_string(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_fill_honors_cancellation_before_writing() {
        let staged = tempfile::NamedTempFile::new().unwrap();
        let mut file = OpenOptions::new().write(true).open(staged.path()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error =
            write_zeroes(&mut file, ZERO_WRITE_BUFFER.len() * 2, &cancellation).unwrap_err();
        assert!(matches!(error, Par2Error::Cancelled));
        assert_eq!(file.metadata().unwrap().len(), 0);
    }

    #[test]
    fn cleanup_stage_files_drops_handles_before_removal() {
        let directory = tempfile::tempdir().unwrap();
        let stage_path = directory.path().join("stage.tmp");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&stage_path)
            .unwrap();
        cleanup_stage_files(vec![VolumeState {
            stage_path: stage_path.clone(),
            target_path: directory.path().join("target.par2"),
            file,
            expected: Vec::new(),
            recovery_slots: Vec::new(),
        }]);
        assert!(!stage_path.exists());
    }

    #[test]
    fn no_replace_publication_rejects_a_deterministic_target_race() {
        let directory = tempfile::tempdir().unwrap();
        let stage = directory.path().join("stage.tmp");
        let target = directory.path().join("set.par2");
        fs::write(&stage, b"staged").unwrap();

        let error = publish_no_replace_with_hook(&stage, &target, || {
            fs::write(&target, b"foreign").unwrap();
        })
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&stage).unwrap(), b"staged");
        assert_eq!(fs::read(&target).unwrap(), b"foreign");
    }

    #[test]
    fn published_target_is_tracked_when_stage_unlink_fails() {
        let directory = tempfile::tempdir().unwrap();
        let stage = directory.path().join("stage.tmp");
        let target = directory.path().join("set.par2");
        fs::write(&stage, b"staged").unwrap();

        let error = publish_no_replace_with_tracking_hooks(
            &stage,
            &target,
            || {},
            || {
                fs::remove_file(&stage).unwrap();
                fs::create_dir(&stage).unwrap();
            },
        )
        .unwrap_err();

        assert!(matches!(error, PublishError::Installed { .. }));
        assert_eq!(fs::read(&target).unwrap(), b"staged");
        assert!(stage.is_dir());
    }

    #[test]
    fn rollback_boundary_swap_preserves_a_foreign_target() {
        let directory = tempfile::tempdir().unwrap();
        let stage = directory.path().join("stage.tmp");
        let target = directory.path().join("set.par2");
        fs::write(&stage, b"staged").unwrap();
        let identity = publish_no_replace(&stage, &target)
            .unwrap()
            .expect("local test files have a strong identity");

        let installed = InstalledTarget {
            path: target.clone(),
            identity: Some(identity),
        };

        let error = quarantine_owned_target_with_hook(&installed, || {
            fs::remove_file(&target).unwrap();
            fs::write(&target, b"foreign").unwrap();
        })
        .unwrap_err();
        assert!(matches!(error, Par2Error::CreationValidation { .. }));
        assert_eq!(fs::read(&target).unwrap(), b"foreign");
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".par2-create-quarantine-")
        }));
    }

    #[test]
    fn overwrite_backup_boundary_restores_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("set.par2");
        fs::write(&target, b"planned").unwrap();
        let staged = test_staged_outputs(&directory, &["set"]);

        let error = staged
            .commit_with_transaction_hooks(
                true,
                &CancellationToken::new(),
                |target, _| {
                    fs::remove_file(target).unwrap();
                    fs::create_dir(target).unwrap();
                    fs::write(target.join("foreign"), b"foreign directory material").unwrap();
                },
                |_, _| {},
            )
            .unwrap_err();

        assert!(matches!(error, Par2Error::CreationValidation { .. }));
        assert!(target.is_dir());
        assert_eq!(
            fs::read(target.join("foreign")).unwrap(),
            b"foreign directory material"
        );
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".par2-create-backup-")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn overwrite_backup_boundary_restores_a_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("set.par2");
        let referent = directory.path().join("foreign.bin");
        fs::write(&target, b"planned").unwrap();
        fs::write(&referent, b"foreign symlink material").unwrap();
        let staged = test_staged_outputs(&directory, &["set"]);

        let error = staged
            .commit_with_transaction_hooks(
                true,
                &CancellationToken::new(),
                |target, _| {
                    fs::remove_file(target).unwrap();
                    symlink(&referent, target).unwrap();
                },
                |_, _| {},
            )
            .unwrap_err();

        assert!(matches!(error, Par2Error::CreationValidation { .. }));
        assert!(
            fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&target).unwrap(), referent);
        assert_eq!(fs::read(&target).unwrap(), b"foreign symlink material");
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".par2-create-backup-")
        }));
    }

    fn test_staged_outputs(directory: &tempfile::TempDir, names: &[&str]) -> StagedOutputs {
        let volumes: Vec<VolumeState> = names
            .iter()
            .map(|name| {
                let stage_path = directory.path().join(format!(".{name}.stage"));
                let target_path = directory.path().join(format!("{name}.par2"));
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&stage_path)
                    .unwrap();
                file.write_all(format!("staged-{name}").as_bytes()).unwrap();
                VolumeState {
                    stage_path,
                    target_path,
                    file,
                    expected: Vec::new(),
                    recovery_slots: Vec::new(),
                }
            })
            .collect();
        let planned_targets = volumes
            .iter()
            .map(|volume| capture_target_snapshot(&volume.target_path).unwrap())
            .collect();
        StagedOutputs {
            volumes,
            locations: Vec::new(),
            planned_targets,
            committed: false,
        }
    }

    #[test]
    fn overwrite_rejects_a_file_that_appears_after_absent_planning() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("set.par2");
        let staged = test_staged_outputs(&directory, &["set"]);
        fs::write(&target, b"foreign").unwrap();

        let error = staged.commit(true, &CancellationToken::new()).unwrap_err();

        assert!(matches!(error, Par2Error::CreationValidation { .. }));
        assert_eq!(fs::read(&target).unwrap(), b"foreign");
    }

    #[test]
    fn overwrite_rejects_a_replacement_of_the_planned_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("set.par2");
        fs::write(&target, b"planned").unwrap();
        let staged = test_staged_outputs(&directory, &["set"]);
        fs::remove_file(&target).unwrap();
        fs::write(&target, b"foreign replacement").unwrap();

        let error = staged.commit(true, &CancellationToken::new()).unwrap_err();

        assert!(matches!(error, Par2Error::CreationValidation { .. }));
        assert_eq!(fs::read(&target).unwrap(), b"foreign replacement");
    }

    #[test]
    fn overwrite_rejects_a_directory_that_appears_after_absent_planning() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("set.par2");
        let staged = test_staged_outputs(&directory, &["set"]);
        fs::create_dir(&target).unwrap();
        fs::write(target.join("foreign"), b"foreign directory material").unwrap();

        let error = staged.commit(true, &CancellationToken::new()).unwrap_err();

        assert!(matches!(error, Par2Error::CreationValidation { .. }));
        assert_eq!(
            fs::read(target.join("foreign")).unwrap(),
            b"foreign directory material"
        );
    }

    #[test]
    fn no_overwrite_failure_after_an_earlier_output_keeps_foreign_output_and_quarantines_owned() {
        let directory = tempfile::tempdir().unwrap();
        let second = directory.path().join("second.par2");
        fs::write(&second, b"foreign").unwrap();

        let staged = test_staged_outputs(&directory, &["first", "second"]);
        let error = staged.commit(false, &CancellationToken::new()).unwrap_err();

        assert!(matches!(error, Par2Error::CreationOutputExists { .. }));
        assert!(!directory.path().join("first.par2").exists());
        assert_eq!(fs::read(&second).unwrap(), b"foreign");
        assert!(fs::read_dir(directory.path()).unwrap().any(|entry| {
            let path = entry.unwrap().path();
            path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with(".par2-create-quarantine-")
            }) && path.join("first.par2").is_file()
        }));
    }

    #[test]
    fn overwrite_failure_after_an_earlier_output_restores_owned_and_preserves_foreign() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.par2");
        let second = directory.path().join("second.par2");
        fs::write(&first, b"old-first").unwrap();
        fs::write(&second, b"old-second").unwrap();

        let staged = test_staged_outputs(&directory, &["first", "second"]);
        let error = staged
            .commit_with_publish_hook(true, &CancellationToken::new(), |_, target| {
                if target == second.as_path() {
                    fs::write(target, b"foreign").unwrap();
                }
            })
            .unwrap_err();

        assert!(matches!(error, Par2Error::CreationValidation { .. }));
        assert_eq!(fs::read(&first).unwrap(), b"old-first");
        assert_eq!(fs::read(&second).unwrap(), b"foreign");
        assert!(fs::read_dir(directory.path()).unwrap().any(|entry| {
            let path = entry.unwrap().path();
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".par2-create-backup-"))
                && path.join("second.par2").is_file()
        }));
    }

    #[test]
    fn cancellation_during_staged_validation_cleans_every_stage() {
        use std::sync::atomic::Ordering;

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let output = directory.path().join("cancelled");
        fs::write(&source, b"staged validation cancellation").unwrap();

        let cancellation = CancellationToken::new();
        let mut options = Par2CreatorOptions::with_output(
            output.clone(),
            Some(directory.path().to_path_buf()),
            vec![source],
        );
        options.recovery_amount = super::super::options::RecoveryAmount::Count(0);
        options.cancellation = cancellation;
        let creator = crate::create::Par2Creator::new(options);
        let plan = creator.plan().unwrap();

        CANCEL_AFTER_VALIDATION_SCAN.store(true, Ordering::Relaxed);
        let error = creator.create(&plan).unwrap_err();

        assert!(matches!(error, Par2Error::Cancelled));
        assert!(!output.with_extension("par2").exists());
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".par2-create-")
        }));
    }

    #[test]
    fn backup_namespace_is_atomically_reserved_and_cleanable() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("set.par2");
        fs::write(&target, b"old").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (first, second) = std::thread::scope(|scope| {
            let first_barrier = std::sync::Arc::clone(&barrier);
            let first_target = target.clone();
            let first = scope.spawn(move || {
                first_barrier.wait();
                reserve_backup_namespace(&first_target, 0).unwrap()
            });
            let second_barrier = std::sync::Arc::clone(&barrier);
            let second_target = target.clone();
            let second = scope.spawn(move || {
                second_barrier.wait();
                reserve_backup_namespace(&second_target, 0).unwrap()
            });
            (first.join().unwrap(), second.join().unwrap())
        });
        let (namespace, backup) = first;
        let (second_namespace, second_backup) = second;
        assert!(namespace.is_dir());
        assert!(second_namespace.is_dir());
        assert_ne!(namespace, second_namespace);
        assert!(!backup.exists());
        assert!(!second_backup.exists());
        fs::rename(&target, &backup).unwrap();
        assert!(!target.exists());
        fs::rename(&backup, &target).unwrap();
        fs::remove_dir(&namespace).unwrap();
        fs::remove_dir(&second_namespace).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"old");
    }
}
