use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use thiserror::Error;

use crate::types::FileId;

/// A snapshot of the filesystem identity and size of a committed file.
///
/// This is captured while constructing [`CommittedFileEvidence`] and can be
/// compared by callers before trusting that the committed path still names the
/// file whose checksums were recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStatFingerprint {
    length: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileStatFingerprint {
    fn capture(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        Ok(Self::from_metadata(&metadata))
    }

    /// Fingerprint `path` exactly as this crate's stat gates compare it.
    ///
    /// Symlinks are not followed and only regular files fingerprint, so a path
    /// that is (or became) a directory, a symlink or a device reads as `None`
    /// rather than as a file — the same rule the carry gate applies, because
    /// this *is* the function that gate calls.
    ///
    /// Callers building a [`crate::ScanCarry`] from their own verification pass
    /// must capture the fingerprint at the moment they read the file's bytes,
    /// not afterwards: the gate's whole guarantee is that the file the repair
    /// reads is the file the fingerprint describes, and a fingerprint taken
    /// late silently covers whatever changed in between.
    ///
    /// What this can prove is what `stat` can prove — length, mtime, and on
    /// Unix device and inode. A same-length rewrite that also restores the
    /// original mtime in place is invisible to it, which is why a repair that
    /// consumes a carry re-checks the bytes themselves against their slice
    /// checksums as it reads them.
    pub fn capture_path(path: impl AsRef<Path>) -> Option<Self> {
        fs::symlink_metadata(path.as_ref())
            .ok()
            .filter(|meta| meta.file_type().is_file())
            .map(|meta| Self::from_metadata(&meta))
    }

    /// Build a fingerprint from metadata the caller already has. Callers that
    /// need to distinguish "not a regular file" from "changed" must apply that
    /// filter themselves; this records what the stat said, nothing more.
    pub(crate) fn from_metadata(metadata: &fs::Metadata) -> Self {
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

    /// File length recorded by the stat call.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Last-modified timestamp recorded by the stat call, when available.
    pub fn modified(&self) -> Option<SystemTime> {
        self.modified
    }

    /// Unix device number recorded by the stat call.
    #[cfg(unix)]
    pub fn device(&self) -> u64 {
        self.device
    }

    /// Unix inode number recorded by the stat call.
    #[cfg(unix)]
    pub fn inode(&self) -> u64 {
        self.inode
    }
}

/// Why an aggregate contiguous-assembly claim cannot be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ContiguousAssemblyProofError {
    #[error("committed length {committed_length} does not match expected length {expected_length}")]
    ExpectedCommittedLengthMismatch {
        expected_length: u64,
        committed_length: u64,
    },
    #[error("covered length {covered_length} does not match expected length {expected_length}")]
    ExpectedCoveredLengthMismatch {
        expected_length: u64,
        covered_length: u64,
    },
    #[error("contiguous assembly has coverage gaps")]
    CoverageGaps,
    #[error("contiguous assembly has overlapping parts")]
    Overlaps,
    #[error("contiguous assembly has mismatched duplicate parts")]
    MismatchedDuplicates,
    #[error("not all article CRCs were verified")]
    UnverifiedArticleCrcs,
}

/// Validated aggregate evidence that a committed file was assembled
/// contiguously from CRC-verified articles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContiguousAssemblyProof {
    expected_length: u64,
    committed_length: u64,
    covered_length: u64,
}

impl ContiguousAssemblyProof {
    /// Validate and record an aggregate contiguous-assembly claim.
    ///
    /// All supplied lengths must agree, coverage must be gap-free and
    /// non-overlapping, duplicate articles must agree, and every article CRC
    /// must already have been verified.
    pub fn try_new(
        expected_length: u64,
        committed_length: u64,
        covered_length: u64,
        has_gaps: bool,
        has_overlaps: bool,
        has_mismatched_duplicates: bool,
        all_parts_crc_verified: bool,
    ) -> Result<Self, ContiguousAssemblyProofError> {
        if committed_length != expected_length {
            return Err(
                ContiguousAssemblyProofError::ExpectedCommittedLengthMismatch {
                    expected_length,
                    committed_length,
                },
            );
        }
        if covered_length != expected_length {
            return Err(
                ContiguousAssemblyProofError::ExpectedCoveredLengthMismatch {
                    expected_length,
                    covered_length,
                },
            );
        }
        if has_gaps {
            return Err(ContiguousAssemblyProofError::CoverageGaps);
        }
        if has_overlaps {
            return Err(ContiguousAssemblyProofError::Overlaps);
        }
        if has_mismatched_duplicates {
            return Err(ContiguousAssemblyProofError::MismatchedDuplicates);
        }
        if !all_parts_crc_verified {
            return Err(ContiguousAssemblyProofError::UnverifiedArticleCrcs);
        }

        Ok(Self {
            expected_length,
            committed_length,
            covered_length,
        })
    }

    /// The length expected from PAR2/file metadata.
    pub fn expected_length(&self) -> u64 {
        self.expected_length
    }

    /// The byte count committed to the assembled output.
    pub fn committed_length(&self) -> u64 {
        self.committed_length
    }

    /// The byte count covered by the verified input articles.
    pub fn covered_length(&self) -> u64 {
        self.covered_length
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EvidenceKind {
    FullMd5([u8; 16]),
    ContiguousAssembly {
        crc32: u32,
        hash_16k: [u8; 16],
        proof: ContiguousAssemblyProof,
    },
}

/// Errors while capturing evidence for a committed file.
#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("failed to stat committed file {path}: {source}")]
    Stat {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "committed file length {actual_length} does not match expected length {expected_length}"
    )]
    LengthMismatch {
        expected_length: u64,
        actual_length: u64,
    },
    #[error(
        "assembly proof expects length {proof_expected_length}, not evidence length {expected_length}"
    )]
    ProofExpectedLengthMismatch {
        expected_length: u64,
        proof_expected_length: u64,
    },
}

/// Immutable evidence captured when an assembled file is committed.
///
/// The fields are intentionally private: every instance is created only after
/// statting its path and checking its recorded size against the expected file
/// length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedFileEvidence {
    path: PathBuf,
    logical_name: String,
    expected_length: u64,
    stat_fingerprint: FileStatFingerprint,
    bound_file_id: Option<FileId>,
    kind: EvidenceKind,
}

impl CommittedFileEvidence {
    /// Capture evidence based on a complete file MD5.
    pub fn from_full_md5_path(
        path: impl AsRef<Path>,
        logical_name: impl Into<String>,
        expected_length: u64,
        md5: [u8; 16],
        bound_file_id: Option<FileId>,
    ) -> Result<Self, EvidenceError> {
        Self::from_path(
            path.as_ref(),
            logical_name.into(),
            expected_length,
            bound_file_id,
            EvidenceKind::FullMd5(md5),
        )
    }

    /// Capture evidence based on a contiguous CRC-verified assembly.
    pub fn from_contiguous_assembly_path(
        path: impl AsRef<Path>,
        logical_name: impl Into<String>,
        expected_length: u64,
        crc32: u32,
        hash_16k: [u8; 16],
        proof: ContiguousAssemblyProof,
        bound_file_id: Option<FileId>,
    ) -> Result<Self, EvidenceError> {
        if proof.expected_length() != expected_length {
            return Err(EvidenceError::ProofExpectedLengthMismatch {
                expected_length,
                proof_expected_length: proof.expected_length(),
            });
        }

        Self::from_path(
            path.as_ref(),
            logical_name.into(),
            expected_length,
            bound_file_id,
            EvidenceKind::ContiguousAssembly {
                crc32,
                hash_16k,
                proof,
            },
        )
    }

    fn from_path(
        path: &Path,
        logical_name: String,
        expected_length: u64,
        bound_file_id: Option<FileId>,
        kind: EvidenceKind,
    ) -> Result<Self, EvidenceError> {
        let path = path.to_path_buf();
        let stat_fingerprint =
            FileStatFingerprint::capture(&path).map_err(|source| EvidenceError::Stat {
                path: path.clone(),
                source,
            })?;
        if stat_fingerprint.length() != expected_length {
            return Err(EvidenceError::LengthMismatch {
                expected_length,
                actual_length: stat_fingerprint.length(),
            });
        }

        Ok(Self {
            path,
            logical_name,
            expected_length,
            stat_fingerprint,
            bound_file_id,
            kind,
        })
    }

    /// Path statted while this evidence was captured.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The logical output name associated with the path.
    pub fn logical_name(&self) -> &str {
        &self.logical_name
    }

    /// The expected unpadded file length.
    pub fn expected_length(&self) -> u64 {
        self.expected_length
    }

    /// Immutable stat fingerprint captured from [`Self::path`].
    pub fn stat_fingerprint(&self) -> &FileStatFingerprint {
        &self.stat_fingerprint
    }

    /// Optional PAR2 file ID explicitly bound by the caller.
    pub fn bound_file_id(&self) -> Option<FileId> {
        self.bound_file_id
    }

    /// Alias for [`Self::bound_file_id`].
    pub fn file_id(&self) -> Option<FileId> {
        self.bound_file_id()
    }

    /// Complete-file MD5 evidence, when that form was captured.
    pub fn full_md5(&self) -> Option<[u8; 16]> {
        match &self.kind {
            EvidenceKind::FullMd5(md5) => Some(*md5),
            EvidenceKind::ContiguousAssembly { .. } => None,
        }
    }

    /// Complete-file CRC32 from contiguous-assembly evidence, if present.
    pub fn assembly_crc32(&self) -> Option<u32> {
        match &self.kind {
            EvidenceKind::FullMd5(_) => None,
            EvidenceKind::ContiguousAssembly { crc32, .. } => Some(*crc32),
        }
    }

    /// MD5 of the first 16 KiB from contiguous-assembly evidence, if present.
    pub fn hash_16k(&self) -> Option<[u8; 16]> {
        match &self.kind {
            EvidenceKind::FullMd5(_) => None,
            EvidenceKind::ContiguousAssembly { hash_16k, .. } => Some(*hash_16k),
        }
    }

    /// Alias for [`Self::hash_16k`].
    pub fn first_16k_md5(&self) -> Option<[u8; 16]> {
        self.hash_16k()
    }

    /// Contiguous-assembly proof, when this evidence was captured that way.
    pub fn assembly_proof(&self) -> Option<&ContiguousAssemblyProof> {
        match &self.kind {
            EvidenceKind::FullMd5(_) => None,
            EvidenceKind::ContiguousAssembly { proof, .. } => Some(proof),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn proof_accepts_only_complete_crc_verified_contiguous_coverage() {
        let proof = ContiguousAssemblyProof::try_new(12, 12, 12, false, false, false, true)
            .expect("complete CRC-verified coverage should prove contiguity");

        assert_eq!(proof.expected_length(), 12);
        assert_eq!(proof.committed_length(), 12);
        assert_eq!(proof.covered_length(), 12);
    }

    #[test]
    fn proof_refuses_invalid_aggregate_evidence() {
        assert!(matches!(
            ContiguousAssemblyProof::try_new(12, 11, 12, false, false, false, true),
            Err(ContiguousAssemblyProofError::ExpectedCommittedLengthMismatch { .. })
        ));
        assert!(matches!(
            ContiguousAssemblyProof::try_new(12, 12, 11, false, false, false, true),
            Err(ContiguousAssemblyProofError::ExpectedCoveredLengthMismatch { .. })
        ));
        assert!(matches!(
            ContiguousAssemblyProof::try_new(12, 12, 12, true, false, false, true),
            Err(ContiguousAssemblyProofError::CoverageGaps)
        ));
        assert!(matches!(
            ContiguousAssemblyProof::try_new(12, 12, 12, false, true, false, true),
            Err(ContiguousAssemblyProofError::Overlaps)
        ));
        assert!(matches!(
            ContiguousAssemblyProof::try_new(12, 12, 12, false, false, true, true),
            Err(ContiguousAssemblyProofError::MismatchedDuplicates)
        ));
        assert!(matches!(
            ContiguousAssemblyProof::try_new(12, 12, 12, false, false, false, false),
            Err(ContiguousAssemblyProofError::UnverifiedArticleCrcs)
        ));
    }

    #[test]
    fn full_md5_evidence_owns_path_and_stat_fingerprint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("complete.bin");
        std::fs::write(&path, b"complete").unwrap();
        let file_id = FileId::from_bytes([0x13; 16]);

        let evidence = CommittedFileEvidence::from_full_md5_path(
            &path,
            "release/complete.bin",
            8,
            [0xA5; 16],
            Some(file_id),
        )
        .unwrap();

        assert_eq!(evidence.path(), path.as_path());
        assert_eq!(evidence.logical_name(), "release/complete.bin");
        assert_eq!(evidence.expected_length(), 8);
        assert_eq!(evidence.stat_fingerprint().length(), 8);
        assert_eq!(evidence.bound_file_id(), Some(file_id));
        assert_eq!(evidence.file_id(), Some(file_id));
        assert_eq!(evidence.full_md5(), Some([0xA5; 16]));
        assert_eq!(evidence.assembly_crc32(), None);
        assert_eq!(evidence.assembly_proof(), None);
    }

    #[test]
    fn contiguous_assembly_evidence_requires_matching_proof_and_file_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("assembled.bin");
        std::fs::write(&path, b"assembled").unwrap();
        let proof = ContiguousAssemblyProof::try_new(9, 9, 9, false, false, false, true).unwrap();

        let evidence = CommittedFileEvidence::from_contiguous_assembly_path(
            &path,
            "assembled.bin",
            9,
            0xCAFE_BABE,
            [0x5A; 16],
            proof.clone(),
            None,
        )
        .unwrap();
        assert_eq!(evidence.full_md5(), None);
        assert_eq!(evidence.assembly_crc32(), Some(0xCAFE_BABE));
        assert_eq!(evidence.hash_16k(), Some([0x5A; 16]));
        assert_eq!(evidence.first_16k_md5(), Some([0x5A; 16]));
        assert_eq!(evidence.assembly_proof(), Some(&proof));

        assert!(matches!(
            CommittedFileEvidence::from_contiguous_assembly_path(
                &path,
                "assembled.bin",
                8,
                0,
                [0; 16],
                proof,
                None,
            ),
            Err(EvidenceError::ProofExpectedLengthMismatch { .. })
        ));
        assert!(matches!(
            CommittedFileEvidence::from_full_md5_path(&path, "assembled.bin", 8, [0; 16], None),
            Err(EvidenceError::LengthMismatch { .. })
        ));
    }
}
