#![cfg(feature = "slow-tests")]

//! Encrypted RAR4/RAR5 extraction, split out of `integration.rs`.
//!
//! Every test here runs the archive KDF, which is deliberately expensive — that
//! is what put them behind `slow-tests` in the first place. They live in their
//! own target so the KDF-heavy set can be selected on its own with
//! `--test slow_encrypted --features slow-tests`, and so `integration.rs`
//! stays a plain, always-on target. CI's `unrar-tests` lane runs the whole
//! crate once with the feature on, so this target runs there alongside it.
//!
//! The four helpers below are deliberate small copies of `integration.rs`'s, so
//! that this target stays independent of that 6.6k-line file.

use std::io::Cursor;

const TEST_PASSWORD: &str = "testpass123";

fn fixture(dir: &str, name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
        .join(name)
}

fn original(name: &str) -> Vec<u8> {
    std::fs::read(fixture("originals", name)).unwrap()
}

fn open_single(dir: &str, filename: &str) -> unrar_rs::RarArchive {
    let data = std::fs::read(fixture(dir, filename)).unwrap();
    unrar_rs::RarArchive::open(Cursor::new(data)).unwrap()
}

fn open_multi(dir: &str, filenames: &[&str]) -> unrar_rs::RarArchive {
    let readers: Vec<Box<dyn unrar_rs::ReadSeek>> = filenames
        .iter()
        .map(|f| {
            let data = std::fs::read(fixture(dir, f)).unwrap();
            Box::new(Cursor::new(data)) as Box<dyn unrar_rs::ReadSeek>
        })
        .collect();
    unrar_rs::RarArchive::open_volumes(readers).unwrap()
}

#[test]
fn test_rar5_encrypted_multivolume_video_batch() {
    let vol_names = [
        "rar5_enc_mv_video.part1.rar",
        "rar5_enc_mv_video.part2.rar",
        "rar5_enc_mv_video.part3.rar",
        "rar5_enc_mv_video.part4.rar",
        "rar5_enc_mv_video.part5.rar",
    ];
    let mut archive = open_multi("rar5", &vol_names);
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None).unwrap();
    assert_eq!(result, original("test_clip.mkv"));
}

#[test]
fn test_rar5_encrypted_multivolume_video_streaming() {
    let vol_names = [
        "rar5_enc_mv_video.part1.rar",
        "rar5_enc_mv_video.part2.rar",
        "rar5_enc_mv_video.part3.rar",
        "rar5_enc_mv_video.part4.rar",
        "rar5_enc_mv_video.part5.rar",
    ];
    let mut archive = open_multi("rar5", &vol_names);
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let paths: Vec<_> = vol_names.iter().map(|n| fixture("rar5", n)).collect();
    let provider = unrar_rs::StaticVolumeProvider::from_ordered(paths);
    let mut out = Vec::new();
    archive
        .extract_member_streaming(0, &opts, &provider, &mut out)
        .unwrap();
    assert_eq!(out, original("test_clip.mkv"));
}

#[test]
fn test_rar4_encrypted_multivolume_video_batch() {
    let vol_names = [
        "rar4_enc_mv_video.part1.rar",
        "rar4_enc_mv_video.part2.rar",
        "rar4_enc_mv_video.part3.rar",
        "rar4_enc_mv_video.part4.rar",
        "rar4_enc_mv_video.part5.rar",
    ];
    let mut archive = open_multi("rar4", &vol_names);
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None).unwrap();
    assert_eq!(result, original("test_clip.mkv"));
}

#[test]
fn test_rar5_encrypted_store_batch() {
    let mut archive = open_single("rar5", "rar5_enc_store.rar");
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None).unwrap();
    assert_eq!(result, original("small.txt"));
}

#[test]
fn test_rar5_encrypted_store_streaming() {
    let mut archive = open_single("rar5", "rar5_enc_store.rar");
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let provider =
        unrar_rs::StaticVolumeProvider::from_ordered(vec![fixture("rar5", "rar5_enc_store.rar")]);
    let mut out = Vec::new();
    archive
        .extract_member_streaming(0, &opts, &provider, &mut out)
        .unwrap();
    assert_eq!(out, original("small.txt"));
}

#[test]
fn test_rar5_encrypted_lz_batch() {
    let mut archive = open_single("rar5", "rar5_enc_lz.rar");
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None).unwrap();
    assert_eq!(result, original("compressible.txt"));
}

#[test]
fn test_rar5_encrypted_lz_streaming() {
    let mut archive = open_single("rar5", "rar5_enc_lz.rar");
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let provider =
        unrar_rs::StaticVolumeProvider::from_ordered(vec![fixture("rar5", "rar5_enc_lz.rar")]);
    let mut out = Vec::new();
    archive
        .extract_member_streaming(0, &opts, &provider, &mut out)
        .unwrap();
    assert_eq!(out, original("compressible.txt"));
}

#[test]
fn test_rar5_encrypted_multivolume_store_batch() {
    let vol_names = [
        "rar5_enc_mv_store.part1.rar",
        "rar5_enc_mv_store.part2.rar",
        "rar5_enc_mv_store.part3.rar",
        "rar5_enc_mv_store.part4.rar",
        "rar5_enc_mv_store.part5.rar",
    ];
    let mut archive = open_multi("rar5", &vol_names);
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None).unwrap();
    assert_eq!(result, original("binary.bin"));
}

#[test]
fn test_rar5_encrypted_multivolume_store_streaming() {
    let vol_names = [
        "rar5_enc_mv_store.part1.rar",
        "rar5_enc_mv_store.part2.rar",
        "rar5_enc_mv_store.part3.rar",
        "rar5_enc_mv_store.part4.rar",
        "rar5_enc_mv_store.part5.rar",
    ];
    let mut archive = open_multi("rar5", &vol_names);
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let paths: Vec<_> = vol_names.iter().map(|n| fixture("rar5", n)).collect();
    let provider = unrar_rs::StaticVolumeProvider::from_ordered(paths);
    let mut out = Vec::new();
    archive
        .extract_member_streaming(0, &opts, &provider, &mut out)
        .unwrap();
    assert_eq!(out, original("binary.bin"));
}

#[test]
fn test_rar5_encrypted_wrong_password_fails() {
    let mut archive = open_single("rar5", "rar5_enc_store.rar");
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some("wrongpassword".into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None);
    assert!(result.is_err(), "wrong password should fail");
}

#[test]
fn test_rar4_encrypted_store_batch() {
    let mut archive = open_single("rar4", "rar4_enc_store.rar");
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None).unwrap();
    assert_eq!(result, original("small.txt"));
}

#[test]
fn test_rar4_encrypted_lz_batch() {
    let mut archive = open_single("rar4", "rar4_enc_lz.rar");
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None).unwrap();
    assert_eq!(result, original("compressible.txt"));
}

#[test]
fn test_rar4_encrypted_multivolume_store_batch() {
    let vol_names = [
        "rar4_enc_mv_store.part1.rar",
        "rar4_enc_mv_store.part2.rar",
        "rar4_enc_mv_store.part3.rar",
        "rar4_enc_mv_store.part4.rar",
        "rar4_enc_mv_store.part5.rar",
    ];
    let mut archive = open_multi("rar4", &vol_names);
    archive.set_password(TEST_PASSWORD);
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some(TEST_PASSWORD.into()),
        restore_owners: false,
    };
    let result = archive.extract_member(0, &opts, None).unwrap();
    assert_eq!(result, original("binary.bin"));
}
