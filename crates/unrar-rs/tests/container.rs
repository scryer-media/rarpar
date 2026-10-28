//! Service record append and removal on RARLAB fixtures: the archive still
//! opens and extracts the same members after each, and removal restores the
//! original bytes exactly.

use std::io::Cursor;
use std::path::PathBuf;

use unrar_rs::container::{BlockKind, Rar5Container, headers_sealed, service_record_header_len};
use unrar_rs::crypto::KdfCache;
use unrar_rs::error::RarError;
use unrar_rs::{RarArchive, ReadSeek};

const PASSWORD: &str = "secretpass";

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar5")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn volume_set(stem: &str, parts: usize, width: usize) -> Vec<Vec<u8>> {
    (1..=parts)
        .map(|part| fixture(&format!("{stem}.part{part:0width$}.rar")))
        .collect()
}

/// Every member's bytes, CRC-verified, or a link's target, from one archive or
/// volume set.
fn members(volumes: &[Vec<u8>], password: Option<&str>) -> Vec<(String, Vec<u8>)> {
    let mut archive = match password {
        // Encrypted headers need the password before the first volume opens.
        Some(password) => {
            let mut archive =
                RarArchive::open_with_password(Cursor::new(volumes[0].clone()), password).unwrap();
            for (index, bytes) in volumes.iter().enumerate().skip(1) {
                archive
                    .add_volume(index, Box::new(Cursor::new(bytes.clone())))
                    .unwrap();
            }
            archive
        }
        None => {
            let readers: Vec<Box<dyn ReadSeek>> = volumes
                .iter()
                .map(|bytes| Box::new(Cursor::new(bytes.clone())) as Box<dyn ReadSeek>)
                .collect();
            RarArchive::open_volumes(readers).unwrap()
        }
    };
    let listed: Vec<_> = archive
        .metadata()
        .members
        .iter()
        .map(|member| {
            let link = (member.is_symlink || member.is_hardlink || member.is_file_copy)
                .then(|| member.link_target_bytes.clone().unwrap_or_default());
            (member.name.clone(), member.is_directory, link)
        })
        .collect();
    let mut out = Vec::new();
    for (index, (name, directory, link)) in listed.into_iter().enumerate() {
        if directory {
            continue;
        }
        // A link stores its target, not data, and copy_to refuses it.
        if let Some(target) = link {
            out.push((name, target));
            continue;
        }
        let mut bytes = Vec::new();
        archive
            .by_index(index)
            .unwrap()
            .copy_to(&mut bytes)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        out.push((name, bytes));
    }
    out
}

/// Append a record to `original`, check it walks and reads back, then remove
/// it and check the original returns.
fn round_trip(original: &[u8], password: Option<&str>, record: &[u8]) -> Vec<u8> {
    let kdf = KdfCache::new();
    let map = Rar5Container::read(&mut Cursor::new(original), password, &kdf).unwrap();
    assert_eq!(map.len, original.len() as u64);
    assert!(matches!(map.blocks.last().unwrap().kind, BlockKind::End));
    let append = map
        .append_service_record("PAR3", record.len() as u64)
        .unwrap();
    assert_eq!(
        append.header().len() as u64,
        service_record_header_len(4, record.len() as u64, map.headers_sealed())
    );
    let mut with = Vec::new();
    let written = append
        .write(
            &mut Cursor::new(original),
            &mut Cursor::new(record),
            &mut with,
        )
        .unwrap();
    assert_eq!(written, with.len() as u64);
    assert_eq!(with.len() as u64, append.output_len());

    let walked = Rar5Container::read(&mut Cursor::new(&with), password, &kdf).unwrap();
    let found: Vec<_> = walked.service_records("PAR3").collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].range(), append.record());
    let data = found[0].data.clone();
    assert_eq!(&with[data.start as usize..data.end as usize], record);
    assert_eq!(walked.volume, map.volume);
    assert_eq!(walked.more_volumes, map.more_volumes);

    assert!(matches!(
        walked.append_service_record("PAR3", 1),
        Err(RarError::ModificationRefused { .. })
    ));

    let removal = walked.remove_service_record("PAR3").unwrap();
    assert_eq!(removal.record(), append.record());
    let mut without = Vec::new();
    removal
        .write(&mut Cursor::new(&with), &mut without)
        .unwrap();
    assert_eq!(without, original, "removal restores the original bytes");
    with
}

#[test]
fn a_record_round_trips_on_plain_archives_and_they_still_extract() {
    for name in ["rar5_lz.rar", "rar5_store.rar", "rar5_recovery.rar"] {
        let original = fixture(name);
        let expected = members(std::slice::from_ref(&original), None);
        let with = round_trip(&original, None, &payload(5000, 1));
        assert_eq!(members(&[with], None), expected, "{name}");
    }
}

#[test]
fn an_empty_and_a_large_payload_round_trip() {
    let original = fixture("rar5_store.rar");
    let expected = members(std::slice::from_ref(&original), None);
    for len in [0, 1, 200_000] {
        let with = round_trip(&original, None, &payload(len, 9));
        assert_eq!(members(&[with], None), expected, "{len}");
    }
}

#[test]
fn a_sealed_record_round_trips_on_encrypted_header_archives() {
    for name in ["rar5_hp_lz.rar", "rar5_hp_store.rar"] {
        let original = fixture(name);
        assert!(headers_sealed(&mut Cursor::new(&original)).unwrap());
        let expected = members(std::slice::from_ref(&original), Some(PASSWORD));
        let record = payload(3000, 2);
        let with = round_trip(&original, Some(PASSWORD), &record);
        assert_eq!(
            members(std::slice::from_ref(&with), Some(PASSWORD)),
            expected,
            "{name}"
        );
        // The record header is sealed: neither its name nor its fields appear
        // in the clear, and the walk needs the password.
        let kdf = KdfCache::new();
        let map = Rar5Container::read(&mut Cursor::new(&with), Some(PASSWORD), &kdf).unwrap();
        let block = map.service_records("PAR3").next().unwrap();
        let header = &with[block.header.start as usize..block.header.end as usize];
        assert!(!header.windows(4).any(|window| window == b"PAR3"));
        assert!(matches!(
            Rar5Container::read(&mut Cursor::new(&with), None, &kdf),
            Err(RarError::EncryptedArchive)
        ));
        assert!(Rar5Container::read(&mut Cursor::new(&with), Some("wrong"), &kdf).is_err());
    }
}

#[test]
fn every_volume_of_a_set_takes_a_record_and_the_set_still_extracts() {
    let volumes: Vec<Vec<u8>> = (1..=7)
        .map(|part| fixture(&format!("generated_matrix_rar5_store_plain.part{part}.rar")))
        .collect();
    let expected = members(&volumes, None);
    let kdf = KdfCache::new();
    let mut changed = Vec::new();
    for (index, volume) in volumes.iter().enumerate() {
        let map = Rar5Container::read(&mut Cursor::new(volume), None, &kdf).unwrap();
        assert_eq!(map.volume, Some(index as u64));
        assert_eq!(map.more_volumes, index + 1 != volumes.len());
        changed.push(round_trip(volume, None, &payload(700 + index, index as u8)));
    }
    assert_eq!(members(&changed, None), expected);
}

#[test]
fn a_locked_archive_is_refused() {
    let original = fixture("ssokolow_rar5_locked.rar");
    let kdf = KdfCache::new();
    let map = Rar5Container::read(&mut Cursor::new(&original), None, &kdf).unwrap();
    assert!(map.locked);
    assert!(matches!(
        map.append_service_record("PAR3", 10),
        Err(RarError::ModificationRefused { .. })
    ));
}

#[test]
fn a_damaged_header_stops_the_walk() {
    let mut damaged = fixture("rar5_store.rar");
    damaged[12] ^= 0x40;
    let kdf = KdfCache::new();
    assert!(Rar5Container::read(&mut Cursor::new(&damaged), None, &kdf).is_err());
}

#[test]
fn a_rar4_archive_is_not_walked() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar4/generated_matrix_rar4_lz_plain.part1.rar");
    let original = std::fs::read(path).unwrap();
    let kdf = KdfCache::new();
    assert!(matches!(
        Rar5Container::read(&mut Cursor::new(&original), None, &kdf),
        Err(RarError::InvalidSignature)
    ));
}

/// Every kind of RAR5 archive the corpus holds takes a record and gives it
/// back: compressed, stored, solid, `-p` file encryption, `-hp` header
/// encryption, volume sets of each, recovery records, quick-open data,
/// comments, BLAKE2 checksums, links, directories and empty members. Each
/// archive with its record extracts the same members byte for byte, and
/// removal restores every original byte.
#[test]
fn every_rar5_archive_kind_extracts_unchanged_with_a_record() {
    const ENC: Option<&str> = Some("testpass123");
    let singles: &[(&str, Option<&str>)] = &[
        ("rar5_lz.rar", None),
        ("rar5_store.rar", None),
        ("rar5_best.rar", None),
        ("rar5_multifile_lz.rar", None),
        ("rar5_comment.rar", None),
        ("rar5_dirs.rar", None),
        ("rar5_empty_member.rar", None),
        ("rar5_symlink.rar", None),
        ("rar5_unicode.rar", None),
        ("rar5_longname.rar", None),
        ("rar5_store_blake2.rar", None),
        ("rar5_recovery.rar", None),
        ("rar5_enc_lz.rar", ENC),
        ("rar5_enc_store_pair.rar", ENC),
        ("rar5_hp_lz.rar", Some(PASSWORD)),
        ("rar5_hp_store.rar", Some(PASSWORD)),
    ];
    /// A label, its volumes (one for a single archive), and its password.
    type Case<'a> = (String, Vec<Vec<u8>>, Option<&'a str>);
    let mut cases: Vec<Case> = singles
        .iter()
        .map(|(name, password)| (name.to_string(), vec![fixture(name)], *password))
        .collect();
    for (stem, parts, width, password) in [
        ("rar5_mv_solid_pair", 9, 2, None),
        ("test_read_format_rar5_multiarchive_solid", 4, 2, None),
        ("rar5_mv_store_rr", 6, 1, None),
        ("rar5_mv_store_blake2", 6, 1, None),
        ("rar5_tiny_volumes", 5, 1, None),
        ("generated_matrix_rar5_lz_plain", 7, 1, None),
        ("generated_matrix_rar5_lz_enc", 7, 1, ENC),
        ("rar5_enc_mv_store", 5, 1, ENC),
        ("rar5_hp_recovery_volumes", 5, 1, Some(PASSWORD)),
    ] {
        cases.push((stem.to_owned(), volume_set(stem, parts, width), password));
    }
    for (label, volumes, password) in cases {
        let expected = members(&volumes, password);
        assert!(!expected.is_empty(), "{label}");
        let changed: Vec<Vec<u8>> = volumes
            .iter()
            .enumerate()
            .map(|(index, volume)| round_trip(volume, password, &payload(900 + index, 3)))
            .collect();
        assert_eq!(members(&changed, password), expected, "{label}");
    }
}

/// The record goes after the archive's recovery record, whose locator in
/// the main header still names it and whose protected bytes (everything
/// before its `RR` header) are untouched.
#[test]
fn the_recovery_record_stays_located_and_its_protected_bytes_unchanged() {
    let mut volumes = vec![fixture("rar5_recovery.rar")];
    volumes.extend(volume_set("rar5_mv_store_rr", 6, 1));
    let kdf = KdfCache::new();
    for original in volumes {
        let with = round_trip(&original, None, &payload(4000, 5));
        let walked = Rar5Container::read(&mut Cursor::new(&with), None, &kdf).unwrap();
        assert!(walked.recovery_record);
        let rr = walked.service_records("RR").next().expect("RR record");
        assert_eq!(walked.recovery_record_at, Some(rr.header.start));
        let record = walked.service_records("PAR3").next().unwrap();
        assert!(rr.range().end <= record.header.start);
        let protected = rr.header.start as usize;
        assert_eq!(with[..protected], original[..protected]);
    }
}

/// A truncated archive is refused at every length, never walked past its
/// end and never a panic.
#[test]
fn every_truncation_is_refused() {
    let kdf = KdfCache::new();
    for (name, password) in [
        ("rar5_store.rar", None),
        ("rar5_hp_store.rar", Some(PASSWORD)),
    ] {
        let original = fixture(name);
        for len in 0..original.len() {
            let result = Rar5Container::read(&mut Cursor::new(&original[..len]), password, &kdf);
            assert!(result.is_err(), "{name} cut at {len}");
        }
    }
}

/// A chain of more headers than one volume may declare is refused rather
/// than mapped: the block map is bounded by the crate's header limit, not by
/// the file's length.
#[test]
fn a_header_chain_past_the_volume_limit_is_refused() {
    let original = fixture("rar5_store.rar");
    let kdf = KdfCache::new();
    let map = Rar5Container::read(&mut Cursor::new(&original), None, &kdf).unwrap();
    let end = map.end_header().start as usize;
    let header = unrar_rs::container::service_record_header("x", 0, None).unwrap();
    let mut flooded = original[..end].to_vec();
    for _ in 0..=unrar_rs::limits::MAX_HEADERS_PER_VOLUME {
        flooded.extend_from_slice(&header);
    }
    flooded.extend_from_slice(&original[end..]);
    assert!(matches!(
        Rar5Container::read(&mut Cursor::new(&flooded), None, &kdf),
        Err(RarError::ResourceLimit {
            kind: unrar_rs::LimitKind::HeadersPerVolume,
            ..
        })
    ));
}

/// A plan writes only over the archive it was made from: a source whose
/// length changed, or a payload longer or shorter than planned, is refused,
/// and a changed source is refused before anything is written.
#[test]
fn a_changed_source_or_a_wrong_payload_is_refused() {
    let original = fixture("rar5_store.rar");
    let kdf = KdfCache::new();
    let map = Rar5Container::read(&mut Cursor::new(&original), None, &kdf).unwrap();
    let append = map.append_service_record("PAR3", 64).unwrap();
    let mut grown = original.clone();
    grown.push(0);
    let mut out = Vec::new();
    assert!(matches!(
        append.write(
            &mut Cursor::new(&grown),
            &mut Cursor::new(payload(64, 1)),
            &mut out
        ),
        Err(RarError::ModificationRefused { .. })
    ));
    assert!(out.is_empty(), "nothing is written over a changed source");
    for len in [63, 65] {
        assert!(matches!(
            append.write(
                &mut Cursor::new(&original),
                &mut Cursor::new(payload(len, 1)),
                &mut Vec::new()
            ),
            Err(RarError::ModificationRefused { .. })
        ));
    }

    let mut with = Vec::new();
    append
        .write(
            &mut Cursor::new(&original),
            &mut Cursor::new(payload(64, 1)),
            &mut with,
        )
        .unwrap();
    let walked = Rar5Container::read(&mut Cursor::new(&with), None, &kdf).unwrap();
    let removal = walked.remove_service_record("PAR3").unwrap();
    let mut shortened = with.clone();
    shortened.pop();
    let mut out = Vec::new();
    assert!(matches!(
        removal.write(&mut Cursor::new(&shortened), &mut out),
        Err(RarError::ModificationRefused { .. })
    ));
    assert!(out.is_empty());
}

/// A payload whose record would not fit a 64-bit file length is refused at
/// planning, not wrapped.
#[test]
fn a_payload_past_the_file_length_range_is_refused() {
    let original = fixture("rar5_store.rar");
    let map = Rar5Container::read(&mut Cursor::new(&original), None, &KdfCache::new()).unwrap();
    for payload_len in [u64::MAX, u64::MAX - original.len() as u64] {
        assert!(matches!(
            map.append_service_record("PAR3", payload_len),
            Err(RarError::ModificationRefused { .. })
        ));
    }
}

/// A self-extracting archive (the signature after a module) is refused: the
/// record layout is defined for archives that start at offset 0.
#[test]
fn a_self_extracting_archive_is_refused() {
    let kdf = KdfCache::new();
    for name in [
        "ssokolow_rar5_linux_sfx.bin",
        "ssokolow_rar5_wincon_sfx.exe",
        "test_read_format_rar5_sfx.exe",
    ] {
        let original = fixture(name);
        assert!(matches!(
            Rar5Container::read(&mut Cursor::new(&original), None, &kdf),
            Err(RarError::InvalidSignature)
        ));
        assert!(!headers_sealed(&mut Cursor::new(&original)).unwrap_or(false));
    }
}

/// A record name of the longest length accepted round trips.
#[test]
fn a_record_name_of_the_longest_length_round_trips() {
    let original = fixture("rar5_store.rar");
    let name = "n".repeat(unrar_rs::container::MAX_RECORD_NAME);
    let kdf = KdfCache::new();
    let map = Rar5Container::read(&mut Cursor::new(&original), None, &kdf).unwrap();
    let append = map.append_service_record(&name, 10).unwrap();
    let mut with = Vec::new();
    append
        .write(
            &mut Cursor::new(&original),
            &mut Cursor::new(payload(10, 0)),
            &mut with,
        )
        .unwrap();
    let walked = Rar5Container::read(&mut Cursor::new(&with), None, &kdf).unwrap();
    assert_eq!(walked.service_records(&name).count(), 1);
    assert_eq!(
        members(&[with], None),
        members(std::slice::from_ref(&original), None)
    );
}
