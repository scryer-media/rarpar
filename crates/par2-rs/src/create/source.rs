use std::collections::HashSet;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::checksum::{self, FileHashState, Md5State, SliceChecksumState};
use crate::error::{Par2Error, Result};
use crate::md5_simd;
use crate::path::translate_par2_name_to_relative;
use crate::types::{
    CancellationToken, FileId, MAX_FILES_PER_SET, MAX_SLICES_PER_FILE, MAX_TOTAL_INPUT_SLICES,
    ProgressCallback, ProgressStage, SliceChecksum,
};

use super::encode::{ForwardSourceObserver, ForwardSourceProvider};

const FIRST_HASH_BYTES: u64 = 16 * 1024;
const READ_BUFFER_BYTES: usize = 256 * 1024;
const MAX_PAR2_NAME_BYTES: usize = 100_000;
/// Staging budget for one file's multi-buffer slice-hash batch.
///
/// Matches the verifier's and the repair scanner's equivalent budgets so the
/// three hashing paths admit the same per-task working set. `plan.rs` accounts
/// this exact number, so the two must move together.
pub(crate) const CREATE_MD5_BATCH_MEMORY_BYTES: usize = 4 * 1024 * 1024;

/// How many consecutive slices of one file to hash per multi-buffer MD5 call.
///
/// Consecutive slices are independent messages, so they lane directly. The
/// width is the narrower of what the kernel offers ([`md5_simd::max_lanes`]:
/// 8 on AVX2, 4 on NEON/SSE2/simd128, 1 scalar) and what the staging budget
/// affords. A block size large enough to leave only one lane falls back to the
/// streaming scan, which needs just one `READ_BUFFER_BYTES` chunk.
pub(crate) fn create_md5_batch_lanes(block_size: usize) -> usize {
    if block_size == 0 {
        return 1;
    }
    (CREATE_MD5_BATCH_MEMORY_BYTES / block_size).clamp(1, md5_simd::max_lanes())
}

/// A validated explicit source file and the metadata needed by critical PAR2
/// packets.
///
/// # What a planned source has, and what only a created one has
///
/// Planning needs a file's identity — path, PAR2 name, length, the 16 KiB
/// digest, the [`FileId`] derived from them, and how many slices the file
/// occupies. It does not need the file's *contents*: `hash_full` and the
/// per-slice checksums are read by exactly one place, the FileDesc and IFSC
/// bodies in `output.rs`, and those are only written when outputs are.
///
/// So [`collect_sources`] fills only the identity, leaving `hash_full` zero
/// and one zeroed [`SliceChecksum`] per slice — correctly *sized*, so every
/// quantity derived from a source (packet lengths, the memory plan, the
/// staged packet layout) is already final at planning time — and creation
/// fills the contents in, either from the encoder's own feed
/// ([`FusedSourceHasher`], the fast path: the bytes are hashed as the
/// arithmetic reads them, so there is no separate hashing pass at all) or
/// from [`hydrate_source_hashes`] where the feed cannot serve them.
///
/// A source held by a [`Par2CreatePlan`](super::plan::Par2CreatePlan)
/// therefore carries placeholder content hashes; the sources handed to
/// packet building never do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationSource {
    /// Canonical path read during creation.
    pub path: PathBuf,
    /// Safe path recorded in PAR2 packets, using `/` separators.
    pub par2_name: String,
    /// PAR2 file identifier.
    pub file_id: FileId,
    /// Source length in bytes.
    pub file_length: u64,
    /// MD5 of the complete source file. Zero until creation fills it; see the
    /// type's note on planned versus created sources.
    pub hash_full: [u8; 16],
    /// MD5 of the first 16KiB, or the complete file when shorter.
    pub hash_16k: [u8; 16],
    /// Zero-padded per-slice CRC32 and MD5 pairs. One entry per slice from
    /// planning onward; the entries are zero until creation fills them.
    pub slice_checksums: Vec<SliceChecksum>,
}

/// The placeholder a planned source carries until creation hashes the bytes.
const DEFERRED_SLICE_CHECKSUM: SliceChecksum = SliceChecksum {
    crc32: 0,
    md5: [0; 16],
};

impl CreationSource {
    /// Number of source slices represented by this source.
    pub fn slice_count(&self) -> u32 {
        self.slice_checksums.len() as u32
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InputLength {
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceFingerprint {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

/// Per-creator memo of the source scan, so one `Par2Creator` reads and hashes
/// its inputs once instead of once per `build_plan` call.
///
/// `Par2Creator::create` rebuilds the plan from the current inputs and compares
/// it with the caller's, which means the whole input set is otherwise scanned
/// twice for one creation: once in `plan()` and once in `create()`. An entry is
/// only reused when a fresh `stat` of the same canonical path still yields the
/// identical [`SourceFingerprint`] (length, mtime, and on unix device+inode)
/// *and* the same block size, so what changes is which read the hashes come
/// from, not whether the inputs are re-validated. A file that moved, was
/// replaced, was rewritten in place, or whose length changed misses the memo
/// and is rehashed exactly as before.
///
/// Entries are removed as they are used: the memory plan admits two live copies
/// of the source metadata (`source_metadata_bytes * 2`) for the create phase,
/// and draining is what keeps that true while the rebuilt plan is assembled.
pub(crate) struct SourceScanCache {
    entries: std::sync::Mutex<Vec<CachedScan>>,
}

struct CachedScan {
    fingerprint: SourceFingerprint,
    block_size: u64,
    source: CreationSource,
}

impl SourceScanCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn take(
        &self,
        path: &Path,
        fingerprint: &SourceFingerprint,
        block_size: u64,
    ) -> Option<CreationSource> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = entries.iter().position(|entry| {
            entry.block_size == block_size
                && entry.fingerprint == *fingerprint
                && entry.source.path == path
        })?;
        Some(entries.swap_remove(index).source)
    }

    fn store(&self, fingerprint: SourceFingerprint, block_size: u64, source: &CreationSource) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|entry| entry.source.path != source.path);
        entries.push(CachedScan {
            fingerprint,
            block_size,
            source: source.clone(),
        });
    }
}

impl SourceFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }
}

/// Sources that will be protected, and the inputs that will not be.
///
/// A PAR2 set cannot describe a zero-length file: the format protects slices,
/// an empty file has none, and its FileDescription packet would claim a slice
/// range no recovery packet covers. The reference encoder resolves this by
/// dropping such inputs from the set (`commandline.cpp`, "Ignore all 0 byte
/// files") and telling the operator it did, on every noise level. Dropping them
/// silently is the one part of that this crate used to leave out, which meant a
/// set could protect fewer files than the caller listed with nothing to say so.
pub(crate) struct CollectedSources {
    pub(crate) sources: Vec<CreationSource>,
    /// Inputs excluded because they are zero-length, in the order given, spelled
    /// the way the caller spelled them rather than canonicalized — this is
    /// destined for a human who is looking for the name they typed.
    pub(crate) skipped_empty: Vec<PathBuf>,
}

/// Resolve and validate explicit source files in input order, reading each
/// file's identity (length, 16 KiB digest, [`FileId`], slice count).
///
/// The whole-file digest and the per-slice checksums are deliberately NOT read
/// here — see [`CreationSource`] for what a planned source carries and who
/// fills the rest in.
pub(crate) fn collect_sources(
    base_path: &Path,
    inputs: &[PathBuf],
    block_size: u64,
    cancellation: &CancellationToken,
    progress: Option<&ProgressCallback>,
    total_bytes: u64,
    cache: Option<&SourceScanCache>,
) -> Result<CollectedSources> {
    if inputs.is_empty() {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "at least one source file is required".to_string(),
        });
    }
    let base = fs::canonicalize(base_path).map_err(Par2Error::Io)?;
    let metadata = fs::metadata(&base).map_err(Par2Error::Io)?;
    if !metadata.is_dir() {
        return Err(Par2Error::UnsafeCreationSource {
            path: base.display().to_string(),
            reason: "base path is not a directory".to_string(),
        });
    }

    let mut active_inputs = Vec::with_capacity(inputs.len());
    let mut skipped_empty = Vec::new();
    for input in inputs {
        if cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        let path = resolve_input_path(&base, input)?;
        let metadata = fs::metadata(&path).map_err(Par2Error::Io)?;
        if !metadata.is_file() {
            return Err(Par2Error::UnsafeCreationSource {
                path: input.display().to_string(),
                reason: "source is not a regular file".to_string(),
            });
        }
        let relative = path
            .strip_prefix(&base)
            .map_err(|_| Par2Error::UnsafeCreationSource {
                path: input.display().to_string(),
                reason: "source is outside the base directory".to_string(),
            })?;
        validate_relative_path(relative, input)?;
        if relative.to_str().is_none() {
            return Err(Par2Error::UnsafeCreationSource {
                path: input.display().to_string(),
                reason: "source filename is not valid UTF-8".to_string(),
            });
        }
        if metadata.len() > 0 {
            active_inputs.push(input);
        } else {
            // Validated exactly like a protected input above — a zero-length
            // file that is outside the base path or is not a regular file is
            // still an error, not a skip — and only then set aside.
            skipped_empty.push(input.clone());
        }
    }
    if active_inputs.is_empty() {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "at least one non-empty source file is required".to_string(),
        });
    }
    validate_main_file_count(active_inputs.len())?;

    let mut names = HashSet::with_capacity(active_inputs.len());
    let mut ids = HashSet::with_capacity(active_inputs.len());
    let bytes_processed = AtomicU64::new(0);
    let file_total =
        u32::try_from(active_inputs.len()).map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: "source file count exceeds the supported progress range".to_string(),
        })?;
    let mut total_slices = 0usize;

    let hash_one = |(index, input): (usize, &&PathBuf)| -> Result<CreationSource> {
        if cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        resolve_source_identity(
            &base,
            input,
            block_size,
            cancellation,
            progress,
            index as u32,
            file_total,
            &bytes_processed,
            total_bytes,
            cache,
        )
    };
    // Hash one file per rayon task; each file's scan is independent. The
    // shared byte counter is monotonic, but callbacks fire concurrently, so
    // DELIVERY to the progress callback is not ordered. The sequential arm
    // is the single-threaded-wasm path (no worker pool, matching the crate's
    // other guards; `wasm32-wasip1-threads` probes `true` and hashes in
    // parallel like native)
    // and the WEAVER_PAR2_CREATE_THREADS=1 pre-banding escape hatch.
    let scan_parallel = reedsolomon_rs::threading::parallel_enabled()
        && active_inputs.len() > 1
        && super::encode::configured_create_threads() != 1;
    let scanned: Vec<CreationSource> = if scan_parallel {
        // Collect every per-file Result, then surface the FIRST error by
        // input order: rayon's Result collection reports an arbitrary
        // racer's error, which would let a concurrent I/O error mask
        // `Cancelled` (or make the reported path vary run to run). The
        // deliberate cost is losing error short-circuiting — in-flight
        // files hash to completion before the error surfaces.
        active_inputs
            .par_iter()
            .enumerate()
            .map(hash_one)
            .collect::<Vec<Result<_>>>()
            .into_iter()
            .collect::<Result<Vec<_>>>()?
    } else {
        active_inputs
            .iter()
            .enumerate()
            .map(hash_one)
            .collect::<Result<Vec<_>>>()?
    };
    // The creation memory plan accounts this vector by LENGTH (plan.rs passes
    // `sources.len()` into `estimate_source_metadata_bytes`), so a collect
    // through a Result adapter cannot skew the estimate. The exact-capacity
    // rebuild stays so the allocation itself matches what the plan admits.
    let mut sources = Vec::with_capacity(active_inputs.len());
    sources.extend(scanned);

    for (source, input) in sources.iter().zip(active_inputs.iter()) {
        if !names.insert(source.par2_name.clone()) {
            return Err(Par2Error::UnsafeCreationSource {
                path: input.display().to_string(),
                reason: "duplicate relative PAR2 name".to_string(),
            });
        }
        if !ids.insert(source.file_id) {
            return Err(Par2Error::UnsafeCreationSource {
                path: input.display().to_string(),
                reason: "duplicate PAR2 file identifier".to_string(),
            });
        }
        total_slices = total_slices
            .checked_add(source.slice_checksums.len())
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "total source slice count overflows".to_string(),
            })?;
        if total_slices > MAX_TOTAL_INPUT_SLICES {
            return Err(Par2Error::ResourceLimitExceeded {
                reason: format!(
                    "total source slice count {total_slices} exceeds {MAX_TOTAL_INPUT_SLICES}"
                ),
            });
        }
    }
    Ok(CollectedSources {
        sources,
        skipped_empty,
    })
}

/// Resolve explicit inputs and collect their lengths before selecting a slice size.
pub(crate) fn collect_input_lengths(
    base_path: &Path,
    inputs: &[PathBuf],
    cancellation: &CancellationToken,
) -> Result<Vec<InputLength>> {
    if inputs.is_empty() {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "at least one source file is required".to_string(),
        });
    }
    let base = fs::canonicalize(base_path).map_err(Par2Error::Io)?;
    let base_metadata = fs::metadata(&base).map_err(Par2Error::Io)?;
    if !base_metadata.is_dir() {
        return Err(Par2Error::UnsafeCreationSource {
            path: base.display().to_string(),
            reason: "base path is not a directory".to_string(),
        });
    }

    let mut lengths = Vec::with_capacity(inputs.len());
    for input in inputs {
        if cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        let path = resolve_input_path(&base, input)?;
        let metadata = fs::metadata(&path).map_err(Par2Error::Io)?;
        if !metadata.is_file() {
            return Err(Par2Error::UnsafeCreationSource {
                path: input.display().to_string(),
                reason: "source is not a regular file".to_string(),
            });
        }
        let relative = path
            .strip_prefix(&base)
            .map_err(|_| Par2Error::UnsafeCreationSource {
                path: input.display().to_string(),
                reason: "source is outside the base directory".to_string(),
            })?;
        validate_relative_path(relative, input)?;
        if relative.to_str().is_none() {
            return Err(Par2Error::UnsafeCreationSource {
                path: input.display().to_string(),
                reason: "source filename is not valid UTF-8".to_string(),
            });
        }
        if metadata.len() > 0 {
            lengths.push(InputLength {
                length: metadata.len(),
            });
        }
    }
    validate_main_file_count(lengths.len())?;
    Ok(lengths)
}

fn validate_main_file_count(file_count: usize) -> Result<()> {
    if file_count > MAX_FILES_PER_SET {
        return Err(Par2Error::ResourceLimitExceeded {
            reason: format!(
                "source file count {file_count} exceeds the Main packet limit of {MAX_FILES_PER_SET}"
            ),
        });
    }
    Ok(())
}

/// Seek/read source slices for one forward-encoding pass.
pub(crate) struct DiskSourceProvider<'a> {
    sources: &'a [CreationSource],
    files: Vec<File>,
    fingerprints: Vec<SourceFingerprint>,
    slice_starts: Vec<usize>,
    slice_size: usize,
    cancellation: &'a CancellationToken,
}

impl<'a> DiskSourceProvider<'a> {
    pub(crate) fn open(
        sources: &'a [CreationSource],
        slice_size: usize,
        cancellation: &'a CancellationToken,
    ) -> Result<Self> {
        if slice_size == 0 {
            return Err(Par2Error::ResourceLimitExceeded {
                reason: "source provider slice size is zero".to_string(),
            });
        }
        let mut files = Vec::with_capacity(sources.len());
        let mut fingerprints = Vec::with_capacity(sources.len());
        let mut slice_starts = Vec::with_capacity(sources.len());
        let mut next_start = 0usize;
        for source in sources {
            if cancellation.is_cancelled() {
                return Err(Par2Error::Cancelled);
            }
            let metadata = fs::metadata(&source.path).map_err(Par2Error::Io)?;
            if !metadata.is_file() || metadata.len() != source.file_length {
                return Err(Par2Error::CreationSourceChanged {
                    path: source.path.display().to_string(),
                });
            }
            let slice_count = source.slice_checksums.len();
            slice_starts.push(next_start);
            next_start = next_start.checked_add(slice_count).ok_or_else(|| {
                Par2Error::ResourceLimitExceeded {
                    reason: "source slice provider index overflows".to_string(),
                }
            })?;
            fingerprints.push(SourceFingerprint::from_metadata(&metadata));
            files.push(File::open(&source.path).map_err(Par2Error::Io)?);
        }
        Ok(Self {
            sources,
            files,
            fingerprints,
            slice_starts,
            slice_size,
            cancellation,
        })
    }

    pub(crate) fn verify_unchanged(&self) -> Result<()> {
        for (source, fingerprint) in self.sources.iter().zip(&self.fingerprints) {
            let metadata = fs::metadata(&source.path).map_err(Par2Error::Io)?;
            if SourceFingerprint::from_metadata(&metadata) != *fingerprint {
                return Err(Par2Error::CreationSourceChanged {
                    path: source.path.display().to_string(),
                });
            }
        }
        Ok(())
    }

    fn source_location(&self, source_index: usize) -> Result<(usize, usize)> {
        let file_index = self
            .slice_starts
            .partition_point(|&start| start <= source_index)
            .checked_sub(1)
            .ok_or_else(|| Par2Error::CreationSourceChanged {
                path: "source slice index is out of range".to_string(),
            })?;
        let local_index = source_index
            .checked_sub(self.slice_starts[file_index])
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source slice index underflows".to_string(),
            })?;
        if local_index >= self.sources[file_index].slice_checksums.len() {
            return Err(Par2Error::CreationSourceChanged {
                path: self.sources[file_index].path.display().to_string(),
            });
        }
        Ok((file_index, local_index))
    }
}

impl ForwardSourceProvider for DiskSourceProvider<'_> {
    fn source_count(&self) -> usize {
        self.sources
            .iter()
            .map(|source| source.slice_checksums.len())
            .sum()
    }

    fn source_slice_len(&self, source_index: usize) -> Result<usize> {
        let (file_index, local_index) = self.source_location(source_index)?;
        let offset = (local_index as u64)
            .checked_mul(self.slice_size as u64)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source slice offset overflows".to_string(),
            })?;
        usize::try_from(
            self.sources[file_index]
                .file_length
                .saturating_sub(offset)
                .min(self.slice_size as u64),
        )
        .map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: "source slice length exceeds addressable memory".to_string(),
        })
    }

    fn read_source_chunk(
        &mut self,
        source_index: usize,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        let (file_index, local_index) = self.source_location(source_index)?;
        let slice_len = self.source_slice_len(source_index)?;
        let start = offset.min(slice_len);
        let take = destination.len().min(slice_len.saturating_sub(start));
        if take == 0 {
            return Ok(0);
        }
        let slice_offset = (local_index as u64)
            .checked_mul(self.slice_size as u64)
            .and_then(|value| value.checked_add(start as u64))
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source read offset overflows".to_string(),
            })?;
        self.files[file_index]
            .seek(SeekFrom::Start(slice_offset))
            .map_err(Par2Error::Io)?;
        self.files[file_index]
            .read_exact(&mut destination[..take])
            .map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    Par2Error::CreationSourceChanged {
                        path: self.sources[file_index].path.display().to_string(),
                    }
                } else {
                    Par2Error::Io(error)
                }
            })?;
        Ok(take)
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_source_identity(
    base: &Path,
    input: &Path,
    block_size: u64,
    cancellation: &CancellationToken,
    progress: Option<&ProgressCallback>,
    file_index: u32,
    file_total: u32,
    bytes_processed: &AtomicU64,
    total_bytes: u64,
    cache: Option<&SourceScanCache>,
) -> Result<CreationSource> {
    if block_size == 0 || !block_size.is_multiple_of(4) {
        return Err(Par2Error::InvalidCreationOptions {
            reason: format!("source block size {block_size} is not a positive multiple of four"),
        });
    }
    let path = resolve_input_path(base, input)?;
    let metadata = fs::metadata(&path).map_err(Par2Error::Io)?;
    if !metadata.is_file() {
        return Err(Par2Error::UnsafeCreationSource {
            path: input.display().to_string(),
            reason: "source is not a regular file".to_string(),
        });
    }
    let fingerprint = SourceFingerprint::from_metadata(&metadata);
    let relative = path
        .strip_prefix(base)
        .map_err(|_| Par2Error::UnsafeCreationSource {
            path: input.display().to_string(),
            reason: "source is outside the base directory".to_string(),
        })?;
    validate_relative_path(relative, input)?;
    let relative_name = relative
        .to_str()
        .ok_or_else(|| Par2Error::UnsafeCreationSource {
            path: input.display().to_string(),
            reason: "source filename is not valid UTF-8".to_string(),
        })?;
    let par2_name = relative_name.replace('\\', "/");
    let par2_name = translate_par2_name_to_relative(&par2_name).map_err(|error| {
        Par2Error::UnsafeCreationSource {
            path: input.display().to_string(),
            reason: error.to_string(),
        }
    })?;
    if par2_name.is_empty()
        || par2_name.len() > MAX_PAR2_NAME_BYTES
        || par2_name.as_bytes().contains(&0)
    {
        return Err(Par2Error::UnsafeCreationSource {
            path: input.display().to_string(),
            reason: "PAR2 name is empty, contains NUL, or exceeds 100000 bytes".to_string(),
        });
    }

    // Memo hit: this exact path, at this exact fingerprint and block size, was
    // already read and hashed by this creator, and the `stat` above is the
    // guard that says so. The bytes are not read again; progress is still
    // reported one slice at a time, with the same byte steps a real scan of
    // this file would produce, so the callback stream a caller sees does not
    // depend on which read the hashes came from.
    if let Some(source) = cache.and_then(|cache| cache.take(&path, &fingerprint, block_size)) {
        debug_assert_eq!(source.par2_name, par2_name);
        report_scan_progress(
            ScanProgress {
                progress,
                file_index,
                file_total,
                bytes_processed,
                total_bytes,
            },
            fingerprint.length,
            block_size,
            source.slice_checksums.len(),
            cancellation,
        )?;
        return Ok(source);
    }

    let mut file = File::open(&path).map_err(Par2Error::Io)?;
    let slice_count = if fingerprint.length == 0 {
        0
    } else {
        fingerprint
            .length
            .checked_add(block_size - 1)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source slice count overflows".to_string(),
            })?
            / block_size
    };
    if slice_count > MAX_SLICES_PER_FILE as u64 {
        return Err(Par2Error::ResourceLimitExceeded {
            reason: format!("source slice count {slice_count} exceeds {MAX_SLICES_PER_FILE}"),
        });
    }
    let slice_count_usize =
        usize::try_from(slice_count).map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: "source slice count exceeds addressable memory".to_string(),
        })?;

    // Identity only: the first 16 KiB (or the whole file when shorter) is
    // what the FileId is derived from, and the FileId is what planning needs.
    // The rest of the file is read exactly once, by the encoder, and hashed
    // there — see `CreationSource`.
    let head_len = usize::try_from(FIRST_HASH_BYTES.min(fingerprint.length)).map_err(|_| {
        Par2Error::ResourceLimitExceeded {
            reason: "source head length exceeds addressable memory".to_string(),
        }
    })?;
    let mut head = vec![0u8; head_len];
    read_exact_or_changed(&mut file, &mut head, input)?;
    let mut first_hash = Md5State::new();
    first_hash.update(&head);
    drop(head);

    let after = fs::metadata(&path).map_err(Par2Error::Io)?;
    if SourceFingerprint::from_metadata(&after) != fingerprint {
        return Err(Par2Error::CreationSourceChanged {
            path: input.display().to_string(),
        });
    }

    let hash_16k = first_hash.finalize();
    let mut file_id_hash = Md5State::new();
    file_id_hash.update(&hash_16k);
    file_id_hash.update(&fingerprint.length.to_le_bytes());
    file_id_hash.update(par2_name.as_bytes());
    let file_id = FileId::from_bytes(file_id_hash.finalize());
    // The same per-slice byte steps a content scan of this file would emit, so
    // the callback stream a caller sees does not depend on which pass the
    // hashes come from (the memo-hit arm above reports identically).
    report_scan_progress(
        ScanProgress {
            progress,
            file_index,
            file_total,
            bytes_processed,
            total_bytes,
        },
        fingerprint.length,
        block_size,
        slice_count_usize,
        cancellation,
    )?;

    let source = CreationSource {
        path,
        par2_name,
        file_id,
        file_length: fingerprint.length,
        hash_full: [0; 16],
        hash_16k,
        slice_checksums: vec![DEFERRED_SLICE_CHECKSUM; slice_count_usize],
    };
    if let Some(cache) = cache {
        cache.store(fingerprint, block_size, &source);
    }
    Ok(source)
}

fn resolve_input_path(base: &Path, input: &Path) -> Result<PathBuf> {
    if input.is_absolute() {
        return fs::canonicalize(input).map_err(Par2Error::Io);
    }

    fs::canonicalize(base.join(input)).map_err(Par2Error::Io)
}

fn validate_relative_path(relative: &Path, input: &Path) -> Result<()> {
    if relative.as_os_str().is_empty()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Par2Error::UnsafeCreationSource {
            path: input.display().to_string(),
            reason: "source does not have a safe relative path".to_string(),
        });
    }
    Ok(())
}

/// The progress-reporting context of one source-scan task.
struct ScanProgress<'a> {
    progress: Option<&'a ProgressCallback>,
    file_index: u32,
    file_total: u32,
    bytes_processed: &'a AtomicU64,
    total_bytes: u64,
}

/// Emit one source-scan progress step per slice of one file.
fn report_scan_progress(
    context: ScanProgress<'_>,
    file_length: u64,
    block_size: u64,
    slice_count: usize,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut remaining = file_length;
    for _ in 0..slice_count {
        if cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        let step = remaining.min(block_size);
        remaining -= step;
        let processed_total = context
            .bytes_processed
            .fetch_add(step, Ordering::Relaxed)
            .saturating_add(step);
        report_progress(
            context.progress,
            context.file_index,
            context.file_total,
            processed_total,
            context.total_bytes,
        );
    }
    Ok(())
}

/// The content hashes of one source file: what [`CreationSource`] leaves
/// deferred until creation.
pub(crate) struct SourceContentHashes {
    pub(crate) hash_full: [u8; 16],
    pub(crate) hash_16k: [u8; 16],
    pub(crate) slice_checksums: Vec<SliceChecksum>,
}

/// Read one source file end to end and produce its content hashes.
///
/// This is the fallback: it runs only when the encoder's feed cannot serve the
/// hashes (a non-CPU backend, a pass with no recovery blocks, or a stripe
/// schedule that visits a file's bytes out of file order). The fast path is
/// [`FusedSourceHasher`], which sees the same bytes for free.
fn hash_source_contents(
    path: &Path,
    input: &Path,
    file_length: u64,
    block_size: u64,
    slice_count: usize,
    cancellation: &CancellationToken,
) -> Result<SourceContentHashes> {
    let block_size_usize =
        usize::try_from(block_size).map_err(|_| Par2Error::ResourceLimitExceeded {
            reason: format!("source block size {block_size} exceeds addressable memory"),
        })?;
    let mut file = File::open(path).map_err(Par2Error::Io)?;
    let mut full_hash = FileHashState::new();
    let mut first_hash = Md5State::new();
    let mut first_bytes = 0u64;
    let mut checksums = Vec::with_capacity(slice_count);

    // Per-slice length: every slice is a full block except the file's last,
    // which is short and zero-padded to the block size for checksum purposes.
    let slice_len = |slice_index: usize| -> Result<usize> {
        let offset = (slice_index as u64)
            .checked_mul(block_size)
            .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                reason: "source slice offset overflows".to_string(),
            })?;
        usize::try_from(file_length.saturating_sub(offset).min(block_size)).map_err(|_| {
            Par2Error::ResourceLimitExceeded {
                reason: "source slice length exceeds addressable memory".to_string(),
            }
        })
    };

    let lanes = create_md5_batch_lanes(block_size_usize);
    if lanes >= 2 {
        // Batched scan. Consecutive slices are independent MD5 messages, so a
        // batch of them goes through the multi-buffer kernel in one pass. The
        // whole-file MD5 stays a single serial stream over the same bytes: it
        // is a different message and cannot be laned within one file (see the
        // module note on why it is also not laned *across* files).
        let mut batch = vec![0u8; lanes * block_size_usize];
        let mut digests = vec![[0u8; 16]; lanes];
        let mut lens = vec![0usize; lanes];
        let mut crcs = vec![0u32; lanes];
        let mut slice_index = 0usize;

        while slice_index < slice_count {
            let batch_slices = lanes.min(slice_count - slice_index);

            for lane in 0..batch_slices {
                if cancellation.is_cancelled() {
                    return Err(Par2Error::Cancelled);
                }
                let actual_len = slice_len(slice_index + lane)?;
                let start = lane * block_size_usize;
                let slice = &mut batch[start..start + actual_len];
                read_exact_or_changed(&mut file, slice, input)?;
                lens[lane] = actual_len;

                // Both single-stream digests run here, while this slice is
                // still in the cache the read just filled, instead of after a
                // second whole-batch walk. Only the file's final slice can be
                // short, so lane order within a batch is file order and the
                // serial stream sees exactly the bytes -- and the byte order --
                // that one `batch[..batch_bytes]` absorb produced.
                let slice = &batch[start..start + actual_len];
                absorb_file_stream(&mut full_hash, &mut first_hash, &mut first_bytes, slice);
                crcs[lane] = checksum::crc32_padded(slice, block_size);
            }

            let inputs = (0..batch_slices)
                .map(|lane| {
                    let start = lane * block_size_usize;
                    &batch[start..start + lens[lane]]
                })
                .collect::<Vec<_>>();
            md5_simd::md5_multi_into(&inputs, Some(block_size), &mut digests[..batch_slices]);

            for lane in 0..batch_slices {
                checksums.push(SliceChecksum {
                    crc32: crcs[lane],
                    md5: digests[lane],
                });
            }

            slice_index += batch_slices;
        }
    } else {
        // Streaming scan: one slice at a time through a single read buffer.
        // Selected when one block already fills the staging budget, so there
        // is no second lane to fill anyway.
        let mut buffer = vec![0u8; READ_BUFFER_BYTES.min(block_size_usize.max(1))];
        for slice_index in 0..slice_count {
            if cancellation.is_cancelled() {
                return Err(Par2Error::Cancelled);
            }
            let actual_len = slice_len(slice_index)?;
            let mut remaining = actual_len;
            let mut slice_hash = SliceChecksumState::new();
            while remaining > 0 {
                if cancellation.is_cancelled() {
                    return Err(Par2Error::Cancelled);
                }
                let take = remaining.min(buffer.len());
                read_exact_or_changed(&mut file, &mut buffer[..take], input)?;
                let chunk = &buffer[..take];
                slice_hash.update(chunk);
                absorb_file_stream(&mut full_hash, &mut first_hash, &mut first_bytes, chunk);
                remaining -= take;
            }
            let pad_to = ((actual_len as u64) < block_size).then_some(block_size);
            let (crc32, md5) = slice_hash.finalize(pad_to);
            checksums.push(SliceChecksum { crc32, md5 });
        }
    }

    if full_hash.bytes_fed() != file_length {
        return Err(Par2Error::CreationSourceChanged {
            path: input.display().to_string(),
        });
    }
    Ok(SourceContentHashes {
        hash_full: full_hash.finalize(),
        hash_16k: first_hash.finalize(),
        slice_checksums: checksums,
    })
}

/// Fill in the deferred content hashes of already-identified sources by
/// reading them.
///
/// Creation's fallback when the encoder feed cannot serve them; see
/// [`CreationSource`]. Every file is re-validated against the identity the
/// plan was built on, so a file that changed between planning and creation is
/// rejected here rather than silently written into a packet.
pub(crate) fn hydrate_source_hashes(
    sources: &mut [CreationSource],
    block_size: u64,
    cancellation: &CancellationToken,
) -> Result<()> {
    let hash_one = |source: &mut CreationSource| -> Result<()> {
        if cancellation.is_cancelled() {
            return Err(Par2Error::Cancelled);
        }
        let metadata = fs::metadata(&source.path).map_err(Par2Error::Io)?;
        if !metadata.is_file() || metadata.len() != source.file_length {
            return Err(Par2Error::CreationSourceChanged {
                path: source.path.display().to_string(),
            });
        }
        let hashes = hash_source_contents(
            &source.path,
            &source.path,
            source.file_length,
            block_size,
            source.slice_checksums.len(),
            cancellation,
        )?;
        if hashes.hash_16k != source.hash_16k {
            return Err(Par2Error::CreationSourceChanged {
                path: source.path.display().to_string(),
            });
        }
        source.hash_full = hashes.hash_full;
        source.slice_checksums = hashes.slice_checksums;
        Ok(())
    };
    // Same split, and the same first-error-by-input-order rule, as the
    // identity scan above.
    let scan_parallel = reedsolomon_rs::threading::parallel_enabled()
        && sources.len() > 1
        && super::encode::configured_create_threads() != 1;
    if scan_parallel {
        sources
            .par_iter_mut()
            .map(hash_one)
            .collect::<Vec<Result<()>>>()
            .into_iter()
            .collect::<Result<Vec<()>>>()?;
    } else {
        for source in sources.iter_mut() {
            hash_one(source)?;
        }
    }
    Ok(())
}

/// The deferred content hashes of a whole recovery set, ready to be applied.
pub(crate) struct FusedSourceHashes {
    hash_full: Vec<[u8; 16]>,
    slice_checksums: Vec<Vec<SliceChecksum>>,
}

impl FusedSourceHashes {
    /// Move the hashes onto the sources they were computed from.
    pub(crate) fn apply(self, sources: &mut [CreationSource]) -> Result<()> {
        if self.hash_full.len() != sources.len() || self.slice_checksums.len() != sources.len() {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "fused source hashes do not cover the recovery set".to_string(),
            });
        }
        for ((source, hash_full), checksums) in sources
            .iter_mut()
            .zip(self.hash_full)
            .zip(self.slice_checksums)
        {
            if checksums.len() != source.slice_checksums.len() {
                return Err(Par2Error::CreationSourceChanged {
                    path: source.path.display().to_string(),
                });
            }
            source.hash_full = hash_full;
            source.slice_checksums = checksums;
        }
        Ok(())
    }
}

/// Drives a recovery set's deferred content hashes from the encoder's own
/// source feed, so the bytes are hashed while they are still in the cache the
/// arithmetic just pulled them into and are never read a second time.
///
/// Correct only while the feed is single-stripe: the whole-file MD5 is one
/// serial message over a file's bytes in file order, and a stripe-major feed
/// does not deliver them that way. The caller decides; this type refuses an
/// out-of-order feed rather than producing a wrong digest, and cross-checks
/// each file's length and 16 KiB digest against the identity the plan was
/// built on, so a source that changed between planning and creation is
/// rejected instead of silently written into a packet.
pub(crate) struct FusedSourceHasher<'a> {
    sources: &'a [CreationSource],
    /// Exclusive end of each file's slice range in encoder source order.
    slice_ends: Vec<usize>,
    block_size: u64,
    next_source_index: usize,
    file_index: usize,
    full_hash: FileHashState,
    first_hash: Md5State,
    first_bytes: u64,
    hash_full: Vec<[u8; 16]>,
    slice_checksums: Vec<Vec<SliceChecksum>>,
    digests: Vec<[u8; 16]>,
}

impl<'a> FusedSourceHasher<'a> {
    pub(crate) fn new(sources: &'a [CreationSource], block_size: u64) -> Result<Self> {
        if block_size == 0 {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "fused source hashing needs a positive block size".to_string(),
            });
        }
        let mut slice_ends = Vec::with_capacity(sources.len());
        let mut end = 0usize;
        for source in sources {
            end = end
                .checked_add(source.slice_checksums.len())
                .ok_or_else(|| Par2Error::ResourceLimitExceeded {
                    reason: "source slice index overflows".to_string(),
                })?;
            slice_ends.push(end);
        }
        Ok(Self {
            sources,
            slice_ends,
            block_size,
            next_source_index: 0,
            file_index: 0,
            full_hash: FileHashState::new(),
            first_hash: Md5State::new(),
            first_bytes: 0,
            hash_full: Vec::with_capacity(sources.len()),
            slice_checksums: sources
                .iter()
                .map(|source| Vec::with_capacity(source.slice_checksums.len()))
                .collect(),
            digests: Vec::new(),
        })
    }

    fn finish_file(&mut self) -> Result<()> {
        let source =
            self.sources
                .get(self.file_index)
                .ok_or_else(|| Par2Error::InvalidCreationOptions {
                    reason: "fused source hashing ran past the recovery set".to_string(),
                })?;
        if self.full_hash.bytes_fed() != source.file_length {
            return Err(Par2Error::CreationSourceChanged {
                path: source.path.display().to_string(),
            });
        }
        let hash_16k = std::mem::replace(&mut self.first_hash, Md5State::new()).finalize();
        if hash_16k != source.hash_16k {
            return Err(Par2Error::CreationSourceChanged {
                path: source.path.display().to_string(),
            });
        }
        self.hash_full
            .push(std::mem::take(&mut self.full_hash).finalize());
        self.first_bytes = 0;
        self.file_index += 1;
        Ok(())
    }

    /// Finalize every file and hand back the hashes.
    pub(crate) fn finish(mut self) -> Result<FusedSourceHashes> {
        while self.file_index < self.sources.len() {
            self.finish_file()?;
        }
        if self.next_source_index != self.slice_ends.last().copied().unwrap_or(0) {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "fused source hashing did not see every source slice".to_string(),
            });
        }
        Ok(FusedSourceHashes {
            hash_full: self.hash_full,
            slice_checksums: self.slice_checksums,
        })
    }
}

impl ForwardSourceObserver for FusedSourceHasher<'_> {
    fn observe_slices(&mut self, first_source_index: usize, slices: &[&[u8]]) -> Result<()> {
        if first_source_index != self.next_source_index {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "fused source hashing needs the feed in source order".to_string(),
            });
        }
        if slices.len() > self.digests.len() {
            self.digests.resize(slices.len(), [0u8; 16]);
        }
        // The whole run is one multi-buffer pass: consecutive slices are
        // independent, zero-padded messages, which is exactly what the kernel
        // lanes. The whole-file stream below cannot be laned and stays serial.
        md5_simd::md5_multi_into(
            slices,
            Some(self.block_size),
            &mut self.digests[..slices.len()],
        );
        for (offset, bytes) in slices.iter().enumerate() {
            let index = first_source_index + offset;
            while self
                .slice_ends
                .get(self.file_index)
                .is_some_and(|&end| index >= end)
            {
                self.finish_file()?;
            }
            if self.file_index >= self.sources.len() {
                return Err(Par2Error::InvalidCreationOptions {
                    reason: "fused source hashing ran past the recovery set".to_string(),
                });
            }
            absorb_file_stream(
                &mut self.full_hash,
                &mut self.first_hash,
                &mut self.first_bytes,
                bytes,
            );
            let crc32 = checksum::crc32_padded(bytes, self.block_size);
            self.slice_checksums[self.file_index].push(SliceChecksum {
                crc32,
                md5: self.digests[offset],
            });
        }
        self.next_source_index = first_source_index + slices.len();
        Ok(())
    }
}

/// Feed one contiguous, in-file-order run of source bytes to the two
/// whole-file digests.
///
/// Both are single serial MD5 streams over the entire file, so neither can be
/// laned: multi-buffer widens a batch of independent messages, not one message.
/// They stay scalar (the aws-lc backend when built with `native-crypto`) while
/// the per-slice digests beside them go through the SIMD kernel.
fn absorb_file_stream(
    full_hash: &mut FileHashState,
    first_hash: &mut Md5State,
    first_bytes: &mut u64,
    chunk: &[u8],
) {
    full_hash.update(chunk);
    if *first_bytes < FIRST_HASH_BYTES {
        let take = (FIRST_HASH_BYTES - *first_bytes).min(chunk.len() as u64) as usize;
        first_hash.update(&chunk[..take]);
        *first_bytes += take as u64;
    }
}

fn read_exact_or_changed(file: &mut File, buffer: &mut [u8], input: &Path) -> Result<()> {
    file.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Par2Error::CreationSourceChanged {
                path: input.display().to_string(),
            }
        } else {
            Par2Error::Io(error)
        }
    })
}

fn report_progress(
    progress: Option<&ProgressCallback>,
    current: u32,
    total: u32,
    bytes_processed: u64,
    total_bytes: u64,
) {
    if let Some(progress) = progress {
        progress(crate::types::ProgressUpdate {
            stage: ProgressStage::Creating,
            current,
            total,
            bytes_processed,
            total_bytes: Some(total_bytes),
            phase: crate::types::ProgressPhase::SourceScan,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planned_source(
        par2_name: &str,
        file_length: u64,
        block_size: u64,
        head: &[u8],
    ) -> CreationSource {
        let mut first = Md5State::new();
        first.update(head);
        let hash_16k = first.finalize();
        let mut file_id_hash = Md5State::new();
        file_id_hash.update(&hash_16k);
        file_id_hash.update(&file_length.to_le_bytes());
        file_id_hash.update(par2_name.as_bytes());
        let slice_count = usize::try_from(file_length.div_ceil(block_size)).unwrap();
        CreationSource {
            path: PathBuf::from(par2_name),
            par2_name: par2_name.to_string(),
            file_id: FileId::from_bytes(file_id_hash.finalize()),
            file_length,
            hash_full: [0; 16],
            hash_16k,
            slice_checksums: vec![DEFERRED_SLICE_CHECKSUM; slice_count],
        }
    }

    /// The whole-file digest is a serial message over a file's bytes in file
    /// order, so a feed that skips or reorders sources must be refused rather
    /// than producing a digest of the wrong byte sequence.
    #[test]
    fn the_fused_hasher_refuses_a_feed_that_is_not_in_source_order() {
        let payload = [7u8; 16];
        let sources = [planned_source("a.bin", 16, 8, &payload)];
        let mut hasher = FusedSourceHasher::new(&sources, 8).unwrap();
        assert!(matches!(
            hasher.observe_slices(1, &[&payload[8..]]),
            Err(Par2Error::InvalidCreationOptions { .. })
        ));
    }

    /// The feed's bytes are cross-checked against the identity the plan was
    /// built on, so a source that changed between planning and creation is
    /// rejected instead of being written into a packet.
    #[test]
    fn the_fused_hasher_rejects_bytes_that_differ_from_the_planned_identity() {
        let payload = [7u8; 16];
        let sources = [planned_source("a.bin", 16, 8, &payload)];
        let mut hasher = FusedSourceHasher::new(&sources, 8).unwrap();
        let changed = [9u8; 16];
        hasher
            .observe_slices(0, &[&changed[..8], &changed[8..]])
            .unwrap();
        assert!(matches!(
            hasher.finish(),
            Err(Par2Error::CreationSourceChanged { .. })
        ));
    }

    /// An unchanged feed produces exactly the digests a separate read does.
    #[test]
    fn the_fused_hasher_matches_a_direct_read_of_the_same_bytes() {
        let payload: Vec<u8> = (0..20u8).collect();
        let sources = [planned_source("a.bin", payload.len() as u64, 8, &payload)];
        let mut hasher = FusedSourceHasher::new(&sources, 8).unwrap();
        hasher
            .observe_slices(0, &[&payload[0..8], &payload[8..16], &payload[16..20]])
            .unwrap();
        let mut hydrated = sources.to_vec();
        hasher.finish().unwrap().apply(&mut hydrated).unwrap();
        assert_eq!(hydrated[0].hash_full, checksum::md5(&payload));
        assert_eq!(hydrated[0].slice_checksums.len(), 3);
        assert_eq!(
            hydrated[0].slice_checksums[2].md5,
            md5_simd::md5_multi(&[&payload[16..20]], Some(8))[0]
        );
        assert_eq!(
            hydrated[0].slice_checksums[2].crc32,
            checksum::crc32_padded(&payload[16..20], 8)
        );
    }

    #[test]
    fn main_file_count_boundary_matches_parser_limit() {
        assert!(validate_main_file_count(MAX_FILES_PER_SET).is_ok());
        assert!(matches!(
            validate_main_file_count(MAX_FILES_PER_SET + 1),
            Err(Par2Error::ResourceLimitExceeded { .. })
        ));
    }
}
