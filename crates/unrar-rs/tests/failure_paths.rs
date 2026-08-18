#![cfg(feature = "slow-tests")]

//! Adversarial extraction failure paths.
//!
//! Damaged input must fail cleanly: an `Err` from open or extract, never a
//! panic, hang, or silently wrong output (`verify: true` turns wrong bytes
//! into CRC errors). The sweeps intentionally allow `Ok` — truncation or a
//! flipped byte can land in dead space — the invariant under test is "clean
//! result", not "always an error".

use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::PathBuf;

const PASSWORD: &str = "testpass123";
const HP_PASSWORD: &str = "secretpass";
#[cfg(feature = "slow-tests")]
const E2E_PASSWORD: &str = "e2e-test-password";

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture_bytes(dir: &str, name: &str) -> Vec<u8> {
    fs::read(fixture_root().join(dir).join(name)).unwrap()
}

/// Open + fully extract every member; the only acceptable outcomes are a
/// clean error anywhere along the way or verified-correct output.
fn extract_all_clean(bytes: Vec<u8>, password: Option<&str>) {
    let Ok(mut archive) = unrar_rs::RarArchive::open(Cursor::new(bytes)) else {
        return;
    };
    if let Some(password) = password {
        archive.set_password(password);
    }
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: password.map(str::to_owned),
        restore_owners: false,
    };
    let count = archive.metadata().members.len();
    for index in 0..count {
        let _ = archive.extract_member(index, &opts, None);
    }
}

/// Where the corruption sweep puts its bit flips: the signature and header
/// region, then spread across the data area.
fn damage_positions(len: usize) -> [usize; 6] {
    [16, 40, len / 4, len / 2, len * 3 / 4, len - 8]
}

/// Half of one target's corruption sweep. The split is by position, not by
/// fixture: on a solid or PPMd archive a flip early in the data area costs
/// far more to re-extract than one near the end, so halving the *positions*
/// splits the cost roughly evenly, where halving the fixture list would not.
fn corrupted_target_half_fails_cleanly(dir: &str, name: &str, password: Option<&str>, half: usize) {
    let full = fixture_bytes(dir, name);
    let len = full.len();
    let positions = damage_positions(len);
    for &pos in positions.iter().skip(half).step_by(2) {
        let pos = pos.min(len - 1);
        for flip in [0xFFu8, 0x01] {
            let mut damaged = full.clone();
            damaged[pos] ^= flip;
            extract_all_clean(damaged, password);
        }
    }
}

/// The truncation sweep for one target: the signature and first block
/// boundaries, then quarter, half and one byte short.
fn truncated_target_fails_cleanly(dir: &str, name: &str, password: Option<&str>) {
    let full = fixture_bytes(dir, name);
    let len = full.len();
    let mut cuts = vec![len / 4, len / 2, len - 1];
    cuts.extend((0..24).step_by(4));
    for cut in cuts {
        extract_all_clean(full[..cut.min(len)].to_vec(), password);
    }
}

/// One test per damage target, rather than one test that walks them all.
///
/// These sweeps are the slowest thing the crate runs — fifteen targets, each
/// re-extracted twelve times for corruption and twelve more for truncation —
/// and as two `#[test]` functions they were also strictly *serial*. nextest
/// schedules tests, not loop iterations, so a whole CI shard's wall time was
/// one of these functions running alone (590 s of a 720 s shard, measured)
/// while its sibling shards sat idle. Splitting the loop is what lets the work
/// spread across a runner's cores, and it gives the shard partitioner
/// something to balance: forty-five medium tests instead of two enormous
/// ones. The corruption sweep splits again by position half, because on the
/// solid and PPMd fixtures one target alone still ran 93 s.
///
/// Coverage is unchanged — same targets, same positions, same flips, same
/// cuts. Only the scheduling boundary moved.
macro_rules! damage_target_tests {
    ($($name:ident => ($dir:expr, $file:expr, $password:expr)),* $(,)?) => {
        $(
            mod $name {
                use super::*;

                #[test]
                fn corrupted_bit_flips_fail_cleanly_a() {
                    corrupted_target_half_fails_cleanly($dir, $file, $password, 0);
                }

                #[test]
                fn corrupted_bit_flips_fail_cleanly_b() {
                    corrupted_target_half_fails_cleanly($dir, $file, $password, 1);
                }

                #[test]
                fn truncations_fail_cleanly() {
                    truncated_target_fails_cleanly($dir, $file, $password);
                }
            }
        )*
    };
}

// The full matrix, including the slow PPMd and multi-member solid fixtures.
// This file is `slow-tests`-only in its entirety (see the inner attribute at
// the top), so there is no reduced set to select between.
damage_target_tests! {
    rar4_lz => ("rar4", "rar4_lz.rar", None),
    rar4_store => ("rar4", "rar4_store.rar", None),
    rar4_solid => ("rar4", "rar4_solid.rar", None),
    rar4_lz_solid_mv => ("rar4", "rar4_lz_solid_mv.rar", None),
    rar4_ppm_solid_restart => ("rar4", "rar4_ppm_solid_restart.rar", None),
    rar4_ppm_solid_mv => ("rar4", "rar4_ppm_solid_mv.rar", None),
    rar4_enc_lz => ("rar4", "rar4_enc_lz.rar", Some(PASSWORD)),
    rar4_hp_lz => ("rar4", "rar4_hp_lz.rar", Some(HP_PASSWORD)),
    rar5_lz => ("rar5", "rar5_lz.rar", None),
    rar5_store => ("rar5", "rar5_store.rar", None),
    rar5_solid => ("rar5", "rar5_solid.rar", None),
    rar5_multifile_lz => ("rar5", "rar5_multifile_lz.rar", None),
    rar5_enc_lz => ("rar5", "rar5_enc_lz.rar", Some(PASSWORD)),
    rar5_hp_lz => ("rar5", "rar5_hp_lz.rar", Some(HP_PASSWORD)),
    rar5_solid_encrypted => ("rar5", "rar5_solid_encrypted.rar", Some(E2E_PASSWORD)),
}

#[test]
fn multivolume_truncated_last_volume_fails_cleanly() {
    for (dir, prefix, parts, password) in [
        ("rar4", "rar4_mv_video", 5, None),
        ("rar5", "rar5_mv_video", 5, None),
        ("rar5", "rar5_enc_mv_video", 5, Some(PASSWORD)),
    ] {
        let mut volumes: Vec<Vec<u8>> = (1..=parts)
            .map(|part| fixture_bytes(dir, &format!("{prefix}.part{part}.rar")))
            .collect();
        let last = volumes.last_mut().unwrap();
        last.truncate(last.len() / 2);

        let readers: Vec<Box<dyn unrar_rs::ReadSeek>> = volumes
            .into_iter()
            .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn unrar_rs::ReadSeek>)
            .collect();
        let Ok(mut archive) = unrar_rs::RarArchive::open_volumes(readers) else {
            continue;
        };
        if let Some(password) = password {
            archive.set_password(password);
        }
        let opts = unrar_rs::ExtractOptions {
            verify: true,
            password: password.map(str::to_owned),
            restore_owners: false,
        };
        let count = archive.metadata().members.len();
        for index in 0..count {
            let _ = archive.extract_member(index, &opts, None);
        }
    }
}

#[test]
fn multivolume_extraction_without_later_volumes_errors() {
    for (dir, first, password) in [
        ("rar4", "rar4_mv_video.part1.rar", None),
        ("rar5", "rar5_mv_video.part1.rar", None),
        ("rar5", "rar5_enc_mv_video.part1.rar", Some(PASSWORD)),
    ] {
        let bytes = fixture_bytes(dir, first);
        let mut archive = unrar_rs::RarArchive::open(Cursor::new(bytes)).unwrap();
        if let Some(password) = password {
            archive.set_password(password);
        }
        let opts = unrar_rs::ExtractOptions {
            verify: true,
            password: password.map(str::to_owned),
            restore_owners: false,
        };

        let result = archive.extract_member(0, &opts, None);
        assert!(
            result.is_err(),
            "{dir}/{first}: extracting a member spanning absent volumes must error"
        );

        // Streaming with a provider that only knows the first volume.
        let provider = unrar_rs::StaticVolumeProvider::from_ordered(vec![
            fixture_root().join(dir).join(first),
        ]);
        let mut sink = Vec::new();
        let result = archive.extract_member_streaming(0, &opts, &provider, &mut sink);
        assert!(
            result.is_err(),
            "{dir}/{first}: streaming without later volumes must error"
        );
    }
}

#[test]
fn wrong_password_fails_across_encryption_modes() {
    // Data-encrypted RAR4: headers list fine, extraction must fail.
    let bytes = fixture_bytes("rar4", "rar4_enc_lz.rar");
    let mut archive = unrar_rs::RarArchive::open(Cursor::new(bytes)).unwrap();
    archive.set_password("not-the-password");
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: Some("not-the-password".into()),
        restore_owners: false,
    };
    assert!(
        archive.extract_member(0, &opts, None).is_err(),
        "rar4_enc_lz: wrong password must fail extraction"
    );

    // Missing password on encrypted data must also fail, not return garbage.
    let bytes = fixture_bytes("rar4", "rar4_enc_lz.rar");
    let mut archive = unrar_rs::RarArchive::open(Cursor::new(bytes)).unwrap();
    let no_pw = unrar_rs::ExtractOptions {
        verify: true,
        password: None,
        restore_owners: false,
    };
    assert!(
        archive.extract_member(0, &no_pw, None).is_err(),
        "rar4_enc_lz: extraction without a password must fail"
    );

    // Header-encrypted archives: the wrong password must surface an error at
    // open or at extraction, never a panic or silent success.
    for (dir, name) in [("rar4", "rar4_hp_lz.rar"), ("rar5", "rar5_hp_lz.rar")] {
        let path = fixture_root().join(dir).join(name);
        let file = File::open(&path).unwrap();
        match unrar_rs::RarArchive::open_with_password(file, "not-the-password") {
            Err(err) => {
                assert!(
                    !matches!(err, unrar_rs::RarError::Io(_)),
                    "{dir}/{name}: wrong password must not surface as a bare IO error: {err}"
                );
            }
            Ok(mut archive) => {
                let opts = unrar_rs::ExtractOptions {
                    verify: true,
                    password: Some("not-the-password".into()),
                    restore_owners: false,
                };
                let count = archive.metadata().members.len();
                let mut any_err = count == 0;
                for index in 0..count {
                    if archive.extract_member(index, &opts, None).is_err() {
                        any_err = true;
                    }
                }
                assert!(
                    any_err,
                    "{dir}/{name}: wrong password produced successful extraction"
                );
            }
        }
    }
}

/// Byte-identical output through a writer that fails must surface the IO
/// error instead of being swallowed.
#[test]
fn writer_errors_propagate_from_streaming_extraction() {
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink exploded"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let path = fixture_root().join("rar5").join("rar5_lz.rar");
    let mut archive = unrar_rs::RarArchive::open(File::open(&path).unwrap()).unwrap();
    let opts = unrar_rs::ExtractOptions {
        verify: true,
        password: None,
        restore_owners: false,
    };
    let provider = unrar_rs::StaticVolumeProvider::from_ordered(vec![path]);
    let result = archive.extract_member_streaming(0, &opts, &provider, &mut FailingWriter);
    assert!(
        result.is_err(),
        "failing writer must propagate an error from streaming extraction"
    );
}
