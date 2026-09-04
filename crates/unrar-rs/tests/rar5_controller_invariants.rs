#![cfg(not(target_family = "wasm"))]

use std::env;
use std::fs;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;
use std::sync::Arc;

use unrar_rs::volume::{VolumeProvider, VolumeProviderError};
use unrar_rs::{ExtractOptions, RarArchive, ReadSeek};

const RAR5_DIR: &str = "rar5";
const LARGE_PASSWORD: &str = "e2e-test-password";
const DISABLE_PARALLEL: &str = "UNRAR_RS_DISABLE_PARALLEL";

fn fixture(name: &str) -> Option<Arc<Vec<u8>>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(RAR5_DIR)
        .join(name);
    if !path.exists() {
        eprintln!("skipping test: {name} fixtures not present");
        return None;
    }
    Some(Arc::new(fs::read(path).expect("fixture readable")))
}

struct ShortReadCursor {
    bytes: Arc<Vec<u8>>,
    position: u64,
    max_read: usize,
}

impl ShortReadCursor {
    fn new(bytes: Arc<Vec<u8>>, max_read: usize) -> Self {
        assert!(max_read > 0);
        Self {
            bytes,
            position: 0,
            max_read,
        }
    }
}

impl Read for ShortReadCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.position as usize;
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let amount = self.max_read.min(buf.len()).min(self.bytes.len() - start);
        buf[..amount].copy_from_slice(&self.bytes[start..start + amount]);
        self.position += amount as u64;
        Ok(amount)
    }
}

impl Seek for ShortReadCursor {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let current = self.position as i128;
        let end = self.bytes.len() as i128;
        let next = match position {
            SeekFrom::Start(offset) => offset as i128,
            SeekFrom::Current(offset) => current + offset as i128,
            SeekFrom::End(offset) => end + offset as i128,
        };
        if !(0..=u64::MAX as i128).contains(&next) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside fixture",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

struct ShortReadProvider {
    bytes: Arc<Vec<u8>>,
    max_read: usize,
}

impl VolumeProvider for ShortReadProvider {
    fn get_volume(&self, index: usize) -> Result<Box<dyn ReadSeek>, VolumeProviderError> {
        if index != 0 {
            return Err(VolumeProviderError::Unavailable {
                volume: index,
                reason: "single-volume fixture".to_string(),
            });
        }
        Ok(Box::new(ShortReadCursor::new(
            self.bytes.clone(),
            self.max_read,
        )))
    }
}

fn options() -> ExtractOptions {
    ExtractOptions {
        verify: true,
        password: None,
        restore_owners: false,
    }
}

/// Run `operation` with the block-parallel controller turned off.
///
/// The switch is a process-wide environment variable, so it is restored before
/// returning (and on unwind). Flipping it can only send a concurrently running
/// test down the single-threaded engine, which is a correct decode of the same
/// bytes, so this cannot make another test in this binary fail.
fn with_parallel_disabled<T>(operation: impl FnOnce() -> T) -> T {
    let previous = env::var_os(DISABLE_PARALLEL);
    unsafe {
        env::set_var(DISABLE_PARALLEL, "1");
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

/// The controller dispatches batch K+1 while batch K is being applied, so the
/// one thing that must not move is the output. Compare the pipelined engine
/// against the single-threaded one over the same member.
#[test]
fn rar5_pipelined_controller_matches_the_single_threaded_engine() {
    let Some(bytes) = fixture("rar5_lz.rar") else {
        return;
    };

    let extract = || {
        let mut archive = RarArchive::open(Cursor::new(bytes.as_ref().clone())).unwrap();
        archive
            .extract_member(0, &options(), None)
            .unwrap()
            .to_bytes()
            .unwrap()
    };

    let pipelined = extract();
    let single_threaded = with_parallel_disabled(extract);

    assert!(!pipelined.is_empty(), "fixture member decoded to nothing");
    assert_eq!(pipelined.len(), single_threaded.len());
    assert!(
        pipelined == single_threaded,
        "pipelined controller output differs from the single-threaded engine"
    );
}

#[test]
fn rar5_streaming_extraction_handles_short_input_reads() {
    let Some(bytes) = fixture("rar5_lz.rar") else {
        return;
    };

    let mut expected_archive = RarArchive::open(Cursor::new(bytes.as_ref().clone())).unwrap();
    let expected = expected_archive
        .extract_member(0, &options(), None)
        .unwrap()
        .to_bytes()
        .unwrap();

    let mut archive = RarArchive::open(ShortReadCursor::new(bytes.clone(), 7)).unwrap();
    let provider = ShortReadProvider { bytes, max_read: 7 };
    let mut actual = Vec::new();
    let written = archive
        .extract_member_streaming(0, &options(), &provider, &mut actual)
        .unwrap();

    assert_eq!(written, expected.len() as u64);
    assert_eq!(actual, expected);
}

#[test]
fn rar5_multifile_extraction_preserves_archive_order() {
    let Some(bytes) = fixture("rar5_multifile_lz.rar") else {
        return;
    };

    let mut expected_archive = RarArchive::open(Cursor::new(bytes.as_ref().clone())).unwrap();
    let names = expected_archive.member_names();
    assert_eq!(names, ["hello.txt", "second.txt", "zeros_64k.bin"]);

    let expected: Vec<Vec<u8>> = (0..names.len())
        .map(|index| {
            expected_archive
                .extract_member(index, &options(), None)
                .unwrap()
                .to_bytes()
                .unwrap()
        })
        .collect();

    let mut archive = RarArchive::open(ShortReadCursor::new(bytes.clone(), 23)).unwrap();
    let provider = ShortReadProvider {
        bytes,
        max_read: 23,
    };
    for (index, expected) in expected.iter().enumerate() {
        let mut actual = Vec::new();
        let written = archive
            .extract_member_streaming(index, &options(), &provider, &mut actual)
            .unwrap();
        assert_eq!(written, expected.len() as u64, "member {index}");
        assert_eq!(actual, *expected, "member {index}");
    }
}

/// One decoder serves the whole archive, so every non-solid member has to
/// start from state the previous member cannot influence.
#[test]
fn rar5_reused_decoder_matches_fresh_decoders_across_non_solid_members() {
    let Some(bytes) = fixture("test_read_format_rar5_win32.rar") else {
        return;
    };

    let file_indices: Vec<usize> = {
        let archive = RarArchive::open(Cursor::new(bytes.as_ref().clone())).unwrap();
        let metadata = archive.metadata();
        assert!(
            !metadata.is_solid,
            "fixture must be non-solid for out-of-order extraction"
        );
        metadata
            .members
            .iter()
            .enumerate()
            .filter(|(_, member)| !member.is_directory)
            .map(|(index, _)| index)
            .collect()
    };
    assert!(
        file_indices.len() > 2,
        "fixture must hold several compressed members"
    );

    // Reference: one archive — and therefore one decoder — per member.
    let expected: Vec<Vec<u8>> = file_indices
        .iter()
        .map(|&index| {
            let mut archive = RarArchive::open(Cursor::new(bytes.as_ref().clone())).unwrap();
            archive
                .extract_member(index, &options(), None)
                .unwrap()
                .to_bytes()
                .unwrap()
        })
        .collect();
    assert!(expected.iter().all(|member| !member.is_empty()));

    // One decoder reused across every member, in archive order.
    let mut archive = RarArchive::open(Cursor::new(bytes.as_ref().clone())).unwrap();
    for (position, &index) in file_indices.iter().enumerate() {
        let actual = archive
            .extract_member(index, &options(), None)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(actual, expected[position], "member {index}");
    }

    // ...and in reverse, so a member cannot be quietly inheriting the window
    // its predecessor happened to leave behind.
    let mut archive = RarArchive::open(Cursor::new(bytes.as_ref().clone())).unwrap();
    for (position, &index) in file_indices.iter().enumerate().rev() {
        let actual = archive
            .extract_member(index, &options(), None)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(
            actual, expected[position],
            "member {index} in reverse order"
        );
    }
}

#[test]
fn rar5_large_member_extraction_exceeds_dictionary() {
    let Some(bytes) = fixture("rar5_hp_large.rar") else {
        return;
    };

    let mut archive =
        RarArchive::open_with_password(ShortReadCursor::new(bytes, 4096), LARGE_PASSWORD).unwrap();
    let member = &archive.metadata().members[0];
    let unpacked_size = member.unpacked_size.expect("large member size");
    assert!(
        unpacked_size > member.compression.dict_size,
        "fixture output must exceed its dictionary"
    );

    let output_dir = tempfile::tempdir().unwrap();
    let output = output_dir.path().join("large-member");
    let options = ExtractOptions {
        verify: true,
        password: Some(LARGE_PASSWORD.to_string()),
        restore_owners: false,
    };
    let written = archive
        .extract_member_to_file(0, &options, None, &output)
        .unwrap();

    assert_eq!(written, unpacked_size);
    assert_eq!(fs::metadata(output).unwrap().len(), unpacked_size);
}

/// This member's compressed data is far larger than the input stage, so blocks
/// repeatedly straddle the staging edge. Deferring those blocks to the next
/// staged round must not move a single output byte.
#[test]
fn rar5_large_block_extraction_completes_with_verification() {
    let Some(bytes) = fixture("rar5_hp_large.rar") else {
        return;
    };

    let options = ExtractOptions {
        verify: true,
        password: Some(LARGE_PASSWORD.to_string()),
        restore_owners: false,
    };

    // One-shot input: every refill fills the stage in a single read.
    let mut oneshot = RarArchive::open_with_password(
        ShortReadCursor::new(bytes.clone(), usize::MAX),
        LARGE_PASSWORD,
    )
    .unwrap();
    let unpacked_size = oneshot.metadata().members[0]
        .unpacked_size
        .expect("large member size");
    let expected = oneshot
        .extract_member(0, &options, None)
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(expected.len() as u64, unpacked_size);

    // Dribbled input: the same member restaged over many short reads.
    let mut archive =
        RarArchive::open_with_password(ShortReadCursor::new(bytes, 64 * 1024), LARGE_PASSWORD)
            .unwrap();
    let extracted = archive.extract_member(0, &options, None).unwrap();
    let output = extracted.to_bytes().unwrap();

    assert_eq!(output.len(), expected.len());
    // Compared without `assert_eq!` so a mismatch does not try to print two
    // 80 MB buffers.
    assert!(
        output == expected,
        "dribbled decode differs from the one-shot decode"
    );
}
