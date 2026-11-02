//! Hard-link targets that pass through a symlink are refused, as UnRAR 7.30
//! beta 2 refuses them.
//!
//! The archive is libarchive's `test_read_format_rar5_hardlink.rar`: member
//! 0 is `file.txt`, member 1 is `hardlink.txt`, a hard link whose target is
//! `file.txt`. The hostile condition is the extraction directory itself — a
//! symlink already sitting where the target name resolves — which each test
//! builds at run time before extracting the unmodified archive. The fixture's
//! target has no directory component, so these tests cover a symlink as the
//! final target component; symlinked directories in the middle of a target
//! are covered by the crate's unit tests (`archive::link_anchor`,
//! `archive::member`), which drive the same code with a parsed header.
#![cfg(unix)]

use std::io::Cursor;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use unrar_rs::{RarArchive, RarError};

const HARDLINK_INDEX: usize = 1;

fn fixture() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar5/test_read_format_rar5_hardlink.rar");
    if path.is_file() {
        Some(path)
    } else {
        eprintln!("skipping test: rar57 fixtures not present");
        None
    }
}

fn open(path: &Path) -> RarArchive {
    RarArchive::open(Cursor::new(std::fs::read(path).unwrap())).unwrap()
}

struct Outside {
    dir: PathBuf,
    file: PathBuf,
}

impl Outside {
    fn new(base: &Path) -> Self {
        let dir = base.join("outside");
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("secret.txt");
        std::fs::write(&file, b"outside bytes").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self { dir, file }
    }

    fn assert_untouched(&self) {
        let metadata = std::fs::metadata(&self.file).unwrap();
        assert_eq!(std::fs::read(&self.file).unwrap(), b"outside bytes");
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(std::fs::read_dir(&self.dir).unwrap().count(), 1);
    }
}

fn assert_refused(result: unrar_rs::RarResult<u64>) {
    match result {
        Err(RarError::UnsafeLinkTarget { member, target }) => {
            assert_eq!(member, "hardlink.txt");
            assert_eq!(target, "file.txt");
        }
        // Neither arm prints the error itself: some variants carry
        // password-derived context that must not reach a log.
        Ok(written) => panic!("expected UnsafeLinkTarget, got Ok({written})"),
        Err(_) => panic!("expected UnsafeLinkTarget, got a different error"),
    }
}

#[test]
fn hardlink_target_that_is_a_symlink_to_an_outside_file_is_refused() {
    let Some(fixture) = fixture() else { return };
    let temp = tempfile::tempdir().unwrap();
    let outside = Outside::new(temp.path());
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink(&outside.file, root.join("file.txt")).unwrap();

    let mut archive = open(&fixture);
    assert_refused(
        archive
            .by_index(HARDLINK_INDEX)
            .unwrap()
            .unpack_to(root.join("hardlink.txt")),
    );
    assert!(std::fs::symlink_metadata(root.join("hardlink.txt")).is_err());
    outside.assert_untouched();
}

#[test]
fn hardlink_target_that_is_a_symlink_chain_is_refused() {
    let Some(fixture) = fixture() else { return };
    let temp = tempfile::tempdir().unwrap();
    let outside = Outside::new(temp.path());
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink(&outside.file, root.join("hop")).unwrap();
    std::os::unix::fs::symlink("hop", root.join("file.txt")).unwrap();

    let mut archive = open(&fixture);
    assert_refused(
        archive
            .by_index(HARDLINK_INDEX)
            .unwrap()
            .unpack_to(root.join("hardlink.txt")),
    );
    assert!(std::fs::symlink_metadata(root.join("hardlink.txt")).is_err());
    outside.assert_untouched();
}

/// A symlink that stays inside the root is refused too: UnRAR refuses any
/// symlink in a hard-link target, and so does unrar-rs.
#[test]
fn hardlink_target_that_is_an_in_root_symlink_is_refused() {
    let Some(fixture) = fixture() else { return };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", root.join("file.txt")).unwrap();

    let mut archive = open(&fixture);
    assert_refused(
        archive
            .by_index(HARDLINK_INDEX)
            .unwrap()
            .unpack_to(root.join("hardlink.txt")),
    );
    assert!(std::fs::symlink_metadata(root.join("hardlink.txt")).is_err());
    assert_eq!(std::fs::metadata(root.join("real.txt")).unwrap().nlink(), 1);
}

#[test]
fn whole_archive_hardlink_still_shares_the_extracted_inode() {
    let Some(fixture) = fixture() else { return };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let mut archive = open(&fixture);
    for index in 0..archive.len() {
        archive.by_index(index).unwrap().unpack_in(&root).unwrap();
    }
    let file = std::fs::metadata(root.join("file.txt")).unwrap();
    let link = std::fs::metadata(root.join("hardlink.txt")).unwrap();
    assert_eq!(file.ino(), link.ino());
    assert_eq!(file.nlink(), 2);
}

/// Extraction that keeps an existing `file.txt` (as `unrar x -o-` does)
/// still links `hardlink.txt` to it when it is a real file.
#[test]
fn hardlink_to_a_kept_existing_regular_file_still_links() {
    let Some(fixture) = fixture() else { return };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("file.txt"), b"kept").unwrap();

    let mut archive = open(&fixture);
    archive
        .by_index(HARDLINK_INDEX)
        .unwrap()
        .unpack_to(root.join("hardlink.txt"))
        .unwrap();
    assert_eq!(std::fs::read(root.join("hardlink.txt")).unwrap(), b"kept");
    assert_eq!(
        std::fs::metadata(root.join("hardlink.txt")).unwrap().ino(),
        std::fs::metadata(root.join("file.txt")).unwrap().ino()
    );
}
