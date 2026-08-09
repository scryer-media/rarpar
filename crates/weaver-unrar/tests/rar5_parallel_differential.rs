#![cfg(not(target_family = "wasm"))]

//! End-to-end parity between normal native extraction and the scalar fallback.
//!
//! Private decoder tests prove controller dispatch. This suite verifies only
//! public archive behavior and does not assume every fixture enters that path.

use std::env;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};
use unrar_rs::{ExtractOptions, RarArchive, RarError, ReadSeek, StaticVolumeProvider};

const DISABLE_PARALLEL: &str = "WEAVER_RAR_DISABLE_PARALLEL";
const FIXTURE_PASSWORD: &str = "testpass123";
const RAR5_SIGNATURE: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];

const NORMAL: &[&str] = &["rar5/rar5_lz.rar"];
const MULTIFILE: &[&str] = &["rar5/rar5_multifile_lz.rar"];
const SOLID: &[&str] = &[
    "rar5/test_read_format_rar5_multiarchive_solid.part01.rar",
    "rar5/test_read_format_rar5_multiarchive_solid.part02.rar",
    "rar5/test_read_format_rar5_multiarchive_solid.part03.rar",
    "rar5/test_read_format_rar5_multiarchive_solid.part04.rar",
];
const MULTI_VOLUME: &[&str] = &[
    "rar5/rar5_mv_video.part1.rar",
    "rar5/rar5_mv_video.part2.rar",
    "rar5/rar5_mv_video.part3.rar",
    "rar5/rar5_mv_video.part4.rar",
    "rar5/rar5_mv_video.part5.rar",
];
const ENCRYPTED_LZ: &[&str] = &["rar5/rar5_enc_lz.rar"];
const ARM_FILTER: &[&str] = &["rar5/test_read_format_rar5_arm.rar"];
const FILTER_FAILURE: &[&str] = &["rar5/test_read_format_rar5_arm_filter_on_window_boundary.rar"];
const DISTANCE_FAILURE: &[&str] = &["rar5/test_read_format_rar5_distance_overflow.rar"];
const HUFFMAN_FAILURE: &[&str] = &["rar5/test_read_format_rar5_truncated_huff.rar"];

#[derive(Debug, PartialEq, Eq)]
struct MemberSummary {
    path: String,
    content: MemberContent,
}

#[derive(Debug, PartialEq, Eq)]
enum MemberContent {
    Directory,
    File { len: u64, sha256: [u8; 32] },
}

#[derive(Debug, PartialEq, Eq)]
enum StableError {
    Io(io::ErrorKind),
    InvalidSignature,
    UnsupportedFormat {
        version: u8,
    },
    CorruptArchive,
    HeaderCrcMismatch {
        expected: u32,
        actual: u32,
    },
    DataCrcMismatch {
        member: String,
        expected: u32,
        actual: u32,
    },
    PackedDataCrcMismatch {
        member: String,
        volume: usize,
        expected: u32,
        actual: u32,
    },
    Blake2Mismatch {
        member: String,
    },
    PackedDataBlake2Mismatch {
        member: String,
        volume: usize,
    },
    MissingVolume {
        volume: usize,
        member: String,
    },
    EncryptedArchive,
    EncryptedMember {
        member: String,
    },
    InvalidPassword,
    WrongPassword {
        member: String,
    },
    UnsupportedCompression {
        method: u8,
        version: u8,
    },
    UnsupportedEncryption {
        version: u64,
    },
    UnsupportedEncryptionKdf {
        count: u8,
        max: u8,
    },
    UnsupportedFilter {
        filter_type: u8,
    },
    DictionaryTooLarge {
        size: u64,
        max: u64,
    },
    TruncatedHeader {
        offset: u64,
    },
    TruncatedData {
        offset: u64,
    },
    InvalidVint {
        offset: u64,
    },
    InvalidHuffmanTable,
    ResourceLimit,
    MemberNotFound {
        name: String,
    },
    SolidOrderViolation {
        required: String,
        requested: String,
    },
    UnsafeLinkTarget {
        member: String,
        target: String,
    },
    UnsupportedLinkType {
        member: String,
        link_type: String,
    },
}

fn stable_error(error: &RarError) -> StableError {
    match error {
        RarError::Io(error) => StableError::Io(error.kind()),
        RarError::InvalidSignature => StableError::InvalidSignature,
        RarError::UnsupportedFormat { version } => {
            StableError::UnsupportedFormat { version: *version }
        }
        RarError::CorruptArchive { .. } => StableError::CorruptArchive,
        RarError::HeaderCrcMismatch { expected, actual } => StableError::HeaderCrcMismatch {
            expected: *expected,
            actual: *actual,
        },
        RarError::DataCrcMismatch {
            member,
            expected,
            actual,
        } => StableError::DataCrcMismatch {
            member: member.clone(),
            expected: *expected,
            actual: *actual,
        },
        RarError::PackedDataCrcMismatch {
            member,
            volume,
            expected,
            actual,
        } => StableError::PackedDataCrcMismatch {
            member: member.clone(),
            volume: *volume,
            expected: *expected,
            actual: *actual,
        },
        RarError::Blake2Mismatch { member } => StableError::Blake2Mismatch {
            member: member.clone(),
        },
        RarError::PackedDataBlake2Mismatch { member, volume } => {
            StableError::PackedDataBlake2Mismatch {
                member: member.clone(),
                volume: *volume,
            }
        }
        RarError::MissingVolume { volume, member } => StableError::MissingVolume {
            volume: *volume,
            member: member.clone(),
        },
        RarError::EncryptedArchive => StableError::EncryptedArchive,
        RarError::EncryptedMember { member } => StableError::EncryptedMember {
            member: member.clone(),
        },
        RarError::InvalidPassword => StableError::InvalidPassword,
        RarError::WrongPassword { member } => StableError::WrongPassword {
            member: member.clone(),
        },
        RarError::UnsupportedCompression { method, version } => {
            StableError::UnsupportedCompression {
                method: *method,
                version: *version,
            }
        }
        RarError::UnsupportedEncryption { version } => {
            StableError::UnsupportedEncryption { version: *version }
        }
        RarError::UnsupportedEncryptionKdf { count, max } => {
            StableError::UnsupportedEncryptionKdf {
                count: *count,
                max: *max,
            }
        }
        RarError::UnsupportedFilter { filter_type } => StableError::UnsupportedFilter {
            filter_type: *filter_type,
        },
        RarError::DictionaryTooLarge { size, max } => StableError::DictionaryTooLarge {
            size: *size,
            max: *max,
        },
        RarError::TruncatedHeader { offset } => StableError::TruncatedHeader { offset: *offset },
        RarError::TruncatedData { offset } => StableError::TruncatedData { offset: *offset },
        RarError::InvalidVint { offset } => StableError::InvalidVint { offset: *offset },
        RarError::InvalidHuffmanTable => StableError::InvalidHuffmanTable,
        RarError::ResourceLimit { .. } => StableError::ResourceLimit,
        RarError::MemberNotFound { name } => StableError::MemberNotFound { name: name.clone() },
        RarError::SolidOrderViolation {
            required,
            requested,
        } => StableError::SolidOrderViolation {
            required: required.clone(),
            requested: requested.clone(),
        },
        RarError::UnsafeLinkTarget { member, target } => StableError::UnsafeLinkTarget {
            member: member.clone(),
            target: target.clone(),
        },
        RarError::UnsupportedLinkType { member, link_type } => StableError::UnsupportedLinkType {
            member: member.clone(),
            link_type: link_type.clone(),
        },
    }
}

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

fn require_hydrated(label: &str, paths: &[&str]) {
    for relative in paths {
        let path = fixture(relative);
        let mut file = File::open(&path)
            .unwrap_or_else(|error| panic!("{label}: missing fixture {relative}: {error}"));
        let mut signature = [0u8; RAR5_SIGNATURE.len()];
        file.read_exact(&mut signature)
            .unwrap_or_else(|error| panic!("{label}: unreadable fixture {relative}: {error}"));
        assert_eq!(
            signature, RAR5_SIGNATURE,
            "{label}: fixture {relative} is not hydrated RAR5 data"
        );
    }
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn with_parallel_mode<T>(disabled: bool, operation: impl FnOnce() -> T) -> T {
    let _guard = env_lock()
        .lock()
        .expect("parallel environment lock poisoned");
    let previous = env::var_os(DISABLE_PARALLEL);
    unsafe {
        if disabled {
            env::set_var(DISABLE_PARALLEL, "1");
        } else {
            env::remove_var(DISABLE_PARALLEL);
        }
    }

    let result = catch_unwind(AssertUnwindSafe(operation));
    unsafe {
        match previous {
            Some(value) => env::set_var(DISABLE_PARALLEL, value),
            None => env::remove_var(DISABLE_PARALLEL),
        }
    }
    match result {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    }
}

fn options(password: Option<&str>) -> ExtractOptions {
    ExtractOptions {
        verify: true,
        password: password.map(str::to_owned),
        restore_owners: false,
    }
}

fn open_volumes(paths: &[PathBuf], password: Option<&str>) -> Result<RarArchive, RarError> {
    let readers: Result<Vec<Box<dyn ReadSeek>>, io::Error> = paths
        .iter()
        .map(|path| File::open(path).map(|file| Box::new(file) as Box<dyn ReadSeek>))
        .collect();
    let mut archive = RarArchive::open_volumes(readers?)?;
    if let Some(password) = password {
        archive.set_password(password);
    }
    Ok(archive)
}

fn hash_file(path: &Path) -> io::Result<(u64, [u8; 32])> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        len += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((len, hasher.finalize().into()))
}

fn extract_summaries(
    relative_paths: &[&str],
    password: Option<&str>,
) -> Result<Vec<MemberSummary>, RarError> {
    let paths: Vec<_> = relative_paths.iter().map(|path| fixture(path)).collect();
    let mut archive = open_volumes(&paths, password)?;
    let members: Vec<_> = archive
        .metadata()
        .members
        .iter()
        .map(|member| (member.name.clone(), member.is_directory))
        .collect();
    let output = tempfile::tempdir().map_err(RarError::Io)?;
    let opts = options(password);
    let mut summaries = Vec::with_capacity(members.len());

    for (index, (path, is_directory)) in members.into_iter().enumerate() {
        if is_directory {
            summaries.push(MemberSummary {
                path,
                content: MemberContent::Directory,
            });
            continue;
        }
        let output_path = output.path().join(format!("member-{index}"));
        let written = archive.extract_member_to_file(index, &opts, None, &output_path)?;
        let (len, sha256) = hash_file(&output_path).map_err(RarError::Io)?;
        assert_eq!(
            written, len,
            "member {path}: reported and durable sizes differ"
        );
        summaries.push(MemberSummary {
            path,
            content: MemberContent::File { len, sha256 },
        });
    }
    Ok(summaries)
}

fn assert_success(label: &str, paths: &[&str], password: Option<&str>) {
    let parallel = with_parallel_mode(false, || extract_summaries(paths, password))
        .unwrap_or_else(|error| panic!("{label}: normal extraction failed: {error:?}"));
    let scalar = with_parallel_mode(true, || extract_summaries(paths, password))
        .unwrap_or_else(|error| panic!("{label}: scalar extraction failed: {error:?}"));
    assert_eq!(parallel, scalar, "{label}: member paths or bytes differ");
}

fn assert_failure(label: &str, paths: &[&str], password: Option<&str>) {
    let parallel = with_parallel_mode(false, || extract_summaries(paths, password))
        .expect_err("failure fixture unexpectedly succeeded in normal mode");
    let scalar = with_parallel_mode(true, || extract_summaries(paths, password))
        .expect_err("failure fixture unexpectedly succeeded in scalar mode");
    assert_eq!(
        stable_error(&parallel),
        stable_error(&scalar),
        "{label}: error outcomes differ: {parallel:?} vs {scalar:?}"
    );
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("intentional test writer failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn streaming_writer_failure(path: &Path) -> Result<(), RarError> {
    let mut archive = RarArchive::open(File::open(path)?)?;
    let provider = StaticVolumeProvider::from_ordered(vec![path.to_path_buf()]);
    let mut writer = FailingWriter;
    archive
        .extract_member_streaming(0, &options(None), &provider, &mut writer)
        .map(|_| ())
}

fn assert_writer_failure_recovers() {
    let path = fixture(NORMAL[0]);
    let parallel = with_parallel_mode(false, || streaming_writer_failure(&path))
        .expect_err("normal-mode failing writer unexpectedly succeeded");
    let scalar = with_parallel_mode(true, || streaming_writer_failure(&path))
        .expect_err("scalar-mode failing writer unexpectedly succeeded");
    assert_eq!(stable_error(&parallel), stable_error(&scalar));
    assert_eq!(
        stable_error(&parallel),
        StableError::Io(io::ErrorKind::Other)
    );

    assert_success("post-writer recovery", NORMAL, None);
}

fn truncated_payload(bytes: &[u8]) -> Vec<u8> {
    let max_removed = bytes.len().saturating_sub(RAR5_SIGNATURE.len()).min(4096);
    for removed in 1..=max_removed {
        let candidate = bytes[..bytes.len() - removed].to_vec();
        let Ok(mut archive) = RarArchive::open(Cursor::new(candidate.clone())) else {
            continue;
        };
        if !archive.metadata().members.is_empty()
            && archive.extract_member(0, &options(None), None).is_err()
        {
            return candidate;
        }
    }
    panic!("could not truncate RAR5 member data while retaining readable headers");
}

fn assert_truncation_parity() {
    let bytes = fs::read(fixture(NORMAL[0])).expect("truncation source readable");
    let truncated = truncated_payload(&bytes);
    let run = |disabled| {
        with_parallel_mode(disabled, || {
            let mut archive = RarArchive::open(Cursor::new(truncated.clone()))?;
            archive.extract_member(0, &options(None), None).map(|_| ())
        })
    };
    let parallel = run(false).expect_err("truncated input succeeded in normal mode");
    let scalar = run(true).expect_err("truncated input succeeded in scalar mode");
    assert_eq!(stable_error(&parallel), stable_error(&scalar));
}

// This file intentionally contains one test. Environment selection is set on
// the main test thread and restored after each extraction; other integration
// test targets run in separate processes.
#[test]
fn rar5_public_extraction_matches_scalar_and_recovers_after_failures() {
    for (label, paths) in [
        ("normal", NORMAL),
        ("multifile", MULTIFILE),
        ("solid", SOLID),
        ("multi-volume", MULTI_VOLUME),
        ("encrypted LZ", ENCRYPTED_LZ),
        ("ARM filter", ARM_FILTER),
        ("filter failure", FILTER_FAILURE),
        ("distance failure", DISTANCE_FAILURE),
        ("Huffman failure", HUFFMAN_FAILURE),
    ] {
        require_hydrated(label, paths);
    }

    assert_success("normal", NORMAL, None);
    assert_success("multifile", MULTIFILE, None);
    assert_success("solid", SOLID, None);
    assert_success("multi-volume", MULTI_VOLUME, None);
    assert_success("encrypted LZ", ENCRYPTED_LZ, Some(FIXTURE_PASSWORD));
    assert_success("ARM filter", ARM_FILTER, None);

    assert_failure("password rejection", ENCRYPTED_LZ, None);
    assert_failure("filter failure", FILTER_FAILURE, None);
    assert_failure("distance failure", DISTANCE_FAILURE, None);
    assert_failure("Huffman failure", HUFFMAN_FAILURE, None);
    assert_truncation_parity();
    assert_writer_failure_recovers();
}
