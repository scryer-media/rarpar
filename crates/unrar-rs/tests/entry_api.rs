//! The entry handle: parity with the older entry points, and the contracts
//! only the handle carries.
//!
//! Two things are pinned here. First, every way of consuming an [`Entry`] —
//! `copy_to`, `copy_to_volumes`, `unpack_to`, and reading it as a `Read` —
//! produces the same bytes as the CRC-verified buffered extraction, on one
//! fixture per format family. Second, the solid contracts: ascending order,
//! free skipping, and the poison an interrupted solid member leaves behind.
//!
//! The pre-0.9.0 entry points are called throughout on purpose: proving the
//! handle agrees with them is the point of the file, so the deprecation
//! warnings they raise are allowed here and nowhere else.
#![allow(deprecated)]

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::{Read, Write};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::rc::Rc;

use unrar_rs::{ExtractOptions, RarArchive, RarError, StaticVolumeProvider};

const PASSWORD: &str = "testpass123";

/// One fixture per format family the handle has to serve.
struct Family {
    dir: &'static str,
    volumes: &'static [&'static str],
    password: Option<&'static str>,
}

const FAMILIES: &[Family] = &[
    // rar5 LZ, single volume.
    Family {
        dir: "rar5",
        volumes: &["rar5_lz.rar"],
        password: None,
    },
    // rar5 stored (no compression).
    Family {
        dir: "rar5",
        volumes: &["rar5_store.rar"],
        password: None,
    },
    // rar5 several members in one archive.
    Family {
        dir: "rar5",
        volumes: &["rar5_multifile_lz.rar"],
        password: None,
    },
    // rar5 multi-volume: members cross volume boundaries.
    Family {
        dir: "rar5",
        volumes: &[
            "rar5_mv_video.part1.rar",
            "rar5_mv_video.part2.rar",
            "rar5_mv_video.part3.rar",
            "rar5_mv_video.part4.rar",
            "rar5_mv_video.part5.rar",
        ],
        password: None,
    },
    // rar5 encrypted members.
    Family {
        dir: "rar5",
        volumes: &["rar5_enc_lz.rar"],
        password: Some(PASSWORD),
    },
    // rar5 ARM executable filter.
    Family {
        dir: "rar5",
        volumes: &["test_read_format_rar5_arm.rar"],
        password: None,
    },
    // rar5 solid across several volumes.
    Family {
        dir: "rar5",
        volumes: &[
            "test_read_format_rar5_multiarchive_solid.part01.rar",
            "test_read_format_rar5_multiarchive_solid.part02.rar",
            "test_read_format_rar5_multiarchive_solid.part03.rar",
            "test_read_format_rar5_multiarchive_solid.part04.rar",
        ],
        password: None,
    },
    // rar4 solid.
    Family {
        dir: "rar4",
        volumes: &["rar4_lz_solid_mv.rar"],
        password: None,
    },
];

/// The solid fixture the ordering, skipping and poison tests drive. Several
/// members, several volumes, small enough to extract many times over.
const SOLID: &Family = &FAMILIES[6];
/// A non-solid fixture with more than one member.
const NON_SOLID: &Family = &FAMILIES[2];

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn volume_paths(family: &Family) -> Vec<PathBuf> {
    family
        .volumes
        .iter()
        .map(|name| fixture_root().join(family.dir).join(name))
        .collect()
}

fn label(family: &Family) -> &'static str {
    family.volumes[0]
}

fn open(family: &Family) -> RarArchive {
    let name = label(family);
    let paths = volume_paths(family);
    let mut archive = if paths.len() == 1 {
        let file = File::open(&paths[0]).unwrap_or_else(|err| panic!("{name}: open file: {err}"));
        match family.password {
            Some(password) => RarArchive::open_with_password(file, password)
                .unwrap_or_else(|err| panic!("{name}: open_with_password: {err}")),
            None => RarArchive::open(file).unwrap_or_else(|err| panic!("{name}: open: {err}")),
        }
    } else {
        let readers: Vec<Box<dyn unrar_rs::ReadSeek>> = paths
            .iter()
            .map(|path| {
                Box::new(File::open(path).unwrap_or_else(|err| panic!("{name}: open file: {err}")))
                    as Box<dyn unrar_rs::ReadSeek>
            })
            .collect();
        RarArchive::open_volumes(readers)
            .unwrap_or_else(|err| panic!("{name}: open_volumes: {err}"))
    };
    if let Some(password) = family.password {
        archive.set_password(password);
    }
    archive
}

fn options(family: &Family) -> ExtractOptions {
    ExtractOptions {
        verify: true,
        password: family.password.map(str::to_owned),
        restore_owners: false,
    }
}

/// Index, name and directory flag for every member, in archive order.
fn member_list(archive: &RarArchive) -> Vec<(usize, String, bool)> {
    archive
        .metadata()
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| (index, member.name.clone(), member.is_directory))
        .collect()
}

/// The reference bytes: one CRC-verified buffered pass in ascending order,
/// which is the extraction path the crate has always had.
fn reference_bytes(family: &Family) -> Vec<Vec<u8>> {
    let name = label(family);
    let mut archive = open(family);
    let opts = options(family);
    let mut references = Vec::new();
    for (index, member, is_directory) in member_list(&archive) {
        if is_directory {
            references.push(Vec::new());
            continue;
        }
        let bytes = archive
            .extract_member(index, &opts, None)
            .unwrap_or_else(|err| panic!("{name} member {index} ({member}): buffered: {err}"))
            .to_bytes()
            .unwrap_or_else(|err| panic!("{name} member {index} ({member}): to_bytes: {err}"));
        references.push(bytes);
    }
    references
}

/// A writer that borrows its sink, so it is neither `Send` nor `'static`.
struct BorrowedSink<'a>(&'a RefCell<Vec<u8>>);

impl Write for BorrowedSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A writer that counts bytes through a shared, non-`Send` cell.
struct CountingSink(Rc<Cell<u64>>);

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.set(self.0.get() + buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A writer that refuses every byte.
struct FailingSink;

impl Write for FailingSink {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("sink refused the member"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A writer that panics instead of accepting bytes.
struct PanickingSink;

impl Write for PanickingSink {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        panic!("sink panicked mid-member");
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `copy_to` on an archive holding its own volumes matches the buffered pass.
#[test]
fn copy_to_matches_the_buffered_reference_on_every_family() {
    for family in FAMILIES {
        let name = label(family);
        let references = reference_bytes(family);
        let mut archive = open(family);
        for (index, member, is_directory) in member_list(&archive) {
            if is_directory {
                continue;
            }
            let mut produced = Vec::new();
            archive
                .by_index(index)
                .unwrap_or_else(|err| panic!("{name} member {index} ({member}): by_index: {err}"))
                .copy_to(&mut produced)
                .unwrap_or_else(|err| panic!("{name} member {index} ({member}): copy_to: {err}"));
            assert_eq!(
                produced, references[index],
                "{name} member {index} ({member}): copy_to diverges from the buffered pass"
            );
        }
    }
}

/// `by_index_via` reads volumes from a provider instead of the archive's own,
/// and produces the same bytes.
#[test]
fn copy_to_over_a_volume_provider_matches_the_buffered_reference() {
    for family in FAMILIES {
        let name = label(family);
        let references = reference_bytes(family);
        let provider = StaticVolumeProvider::from_ordered(volume_paths(family));
        let mut archive = open(family);
        for (index, member, is_directory) in member_list(&archive) {
            if is_directory {
                continue;
            }
            let mut produced = Vec::new();
            archive
                .by_index_via(index, &provider)
                .unwrap_or_else(|err| {
                    panic!("{name} member {index} ({member}): by_index_via: {err}")
                })
                .copy_to(&mut produced)
                .unwrap_or_else(|err| {
                    panic!("{name} member {index} ({member}): streaming copy_to: {err}")
                });
            assert_eq!(
                produced, references[index],
                "{name} member {index} ({member}): streamed copy_to diverges from the buffered pass"
            );
        }
    }
}

/// Reading an entry as a `Read` produces the same bytes as extracting it.
#[test]
fn reading_an_entry_matches_the_buffered_reference_on_every_family() {
    for family in FAMILIES {
        let name = label(family);
        let references = reference_bytes(family);
        let mut archive = open(family);
        for (index, member, is_directory) in member_list(&archive) {
            if is_directory {
                continue;
            }
            let mut produced = Vec::new();
            let mut entry = archive
                .by_index(index)
                .unwrap_or_else(|err| panic!("{name} member {index} ({member}): by_index: {err}"));
            entry
                .read_to_end(&mut produced)
                .unwrap_or_else(|err| panic!("{name} member {index} ({member}): read: {err}"));
            assert_eq!(
                produced, references[index],
                "{name} member {index} ({member}): Read output diverges from the buffered pass"
            );
        }
    }
}

/// `unpack_to` writes the same bytes to disk that the buffered pass returns.
#[test]
fn unpack_to_matches_the_buffered_reference_on_every_family() {
    for family in FAMILIES {
        let name = label(family);
        let references = reference_bytes(family);
        let output = tempfile::tempdir().unwrap();
        let mut archive = open(family);
        for (index, member, is_directory) in member_list(&archive) {
            if is_directory {
                continue;
            }
            let path = output.path().join(format!("member-{index}"));
            let written = archive
                .by_index(index)
                .unwrap_or_else(|err| panic!("{name} member {index} ({member}): by_index: {err}"))
                .unpack_to(&path)
                .unwrap_or_else(|err| panic!("{name} member {index} ({member}): unpack_to: {err}"));
            let produced = std::fs::read(&path).unwrap();
            assert_eq!(
                produced, references[index],
                "{name} member {index} ({member}): unpack_to output diverges from the buffered pass"
            );
            assert_eq!(
                written as usize,
                references[index].len(),
                "{name} member {index} ({member}): unpack_to reported the wrong byte count"
            );
        }
    }
}

/// `copy_to_volumes` splits a member across per-volume writers and, taken
/// together, those writers receive exactly the member.
#[test]
fn copy_to_volumes_matches_the_buffered_reference_on_every_family() {
    for family in FAMILIES {
        let name = label(family);
        let references = reference_bytes(family);
        let provider = StaticVolumeProvider::from_ordered(volume_paths(family));
        let mut archive = open(family);
        let is_solid = archive.is_solid();
        for (index, member, is_directory) in member_list(&archive) {
            if is_directory {
                continue;
            }
            let sink = RefCell::new(Vec::new());
            // A solid archive keeps its dictionary in the attached volumes; a
            // non-solid one needs the provider to attribute output to volumes.
            let chunks = if is_solid {
                archive
                    .by_index(index)
                    .unwrap_or_else(|err| {
                        panic!("{name} member {index} ({member}): by_index: {err}")
                    })
                    .copy_to_volumes(|_| Ok(BorrowedSink(&sink)))
            } else {
                archive
                    .by_index_via(index, &provider)
                    .unwrap_or_else(|err| {
                        panic!("{name} member {index} ({member}): by_index_via: {err}")
                    })
                    .copy_to_volumes(|_| Ok(BorrowedSink(&sink)))
            }
            .unwrap_or_else(|err| {
                panic!("{name} member {index} ({member}): copy_to_volumes: {err}")
            });

            assert_eq!(
                sink.borrow().as_slice(),
                references[index].as_slice(),
                "{name} member {index} ({member}): chunked output diverges from the buffered pass"
            );
            let chunked_total: u64 = chunks.iter().map(|(_, written)| *written).sum();
            assert_eq!(
                chunked_total as usize,
                references[index].len(),
                "{name} member {index} ({member}): chunk totals do not add up to the member"
            );
        }
    }
}

/// A member that spans volumes is reported as more than one chunk, with the
/// volume numbers the archive itself states.
#[test]
fn copy_to_volumes_reports_one_chunk_per_volume_a_member_spans() {
    let family = &FAMILIES[3]; // rar5_mv_video, five volumes
    let name = label(family);
    let provider = StaticVolumeProvider::from_ordered(volume_paths(family));
    let mut archive = open(family);
    let members = member_list(&archive);
    let (index, member, _) = members
        .iter()
        .find(|(_, _, is_directory)| !is_directory)
        .expect("multi-volume fixture has a file member");

    let sink = RefCell::new(Vec::new());
    let chunks = archive
        .by_index_via(*index, &provider)
        .unwrap()
        .copy_to_volumes(|_| Ok(BorrowedSink(&sink)))
        .unwrap_or_else(|err| panic!("{name} member {index} ({member}): copy_to_volumes: {err}"));

    assert!(
        chunks.len() > 1,
        "{name} member {index} ({member}): expected a member spanning several volumes, got {chunks:?}"
    );
    let volumes: Vec<usize> = chunks.iter().map(|(volume, _)| *volume).collect();
    let mut ascending = volumes.clone();
    ascending.sort_unstable();
    ascending.dedup();
    assert_eq!(
        volumes, ascending,
        "{name}: chunk volume numbers are not strictly ascending"
    );
}

/// The handle and the older entry points produce byte-identical output.
#[test]
fn the_handle_and_the_older_entry_points_agree_byte_for_byte() {
    for family in FAMILIES {
        let name = label(family);
        let opts = options(family);
        let provider = StaticVolumeProvider::from_ordered(volume_paths(family));

        let mut legacy = open(family);
        let members = member_list(&legacy);
        let mut legacy_bytes = Vec::new();
        for (index, member, is_directory) in &members {
            if *is_directory {
                legacy_bytes.push(Vec::new());
                continue;
            }
            let mut produced = Vec::new();
            legacy
                .extract_member_streaming(*index, &opts, &provider, &mut produced)
                .unwrap_or_else(|err| {
                    panic!("{name} member {index} ({member}): extract_member_streaming: {err}")
                });
            legacy_bytes.push(produced);
        }

        let mut handled = open(family);
        for (index, member, is_directory) in &members {
            if *is_directory {
                continue;
            }
            let mut produced = Vec::new();
            handled
                .by_index_via(*index, &provider)
                .unwrap()
                .copy_to(&mut produced)
                .unwrap_or_else(|err| {
                    panic!("{name} member {index} ({member}): handle copy_to: {err}")
                });
            assert_eq!(
                produced, legacy_bytes[*index],
                "{name} member {index} ({member}): handle and legacy output differ"
            );
        }
    }
}

/// Solid members must be consumed in ascending order; asking for one the
/// archive has already passed is refused.
#[test]
fn a_solid_archive_refuses_a_backward_request() {
    let mut archive = open(SOLID);
    assert!(archive.is_solid(), "fixture is expected to be solid");

    let mut sink = Vec::new();
    archive.by_index(2).unwrap().copy_to(&mut sink).unwrap();

    let error = archive
        .by_index(1)
        .unwrap()
        .copy_to(&mut Vec::new())
        .expect_err("a backward solid request must be refused");
    assert!(
        matches!(error, RarError::SolidOrderViolation { .. }),
        "expected SolidOrderViolation, got {error:?}"
    );
}

/// Reaching forward past solid members decodes what the dictionary needs, so
/// selective extraction gives the same bytes as extracting everything.
#[test]
fn a_solid_member_can_be_taken_without_taking_the_ones_before_it() {
    let references = reference_bytes(SOLID);
    let target = 3;

    let mut archive = open(SOLID);
    let mut produced = Vec::new();
    archive
        .by_index(target)
        .unwrap()
        .copy_to(&mut produced)
        .unwrap();
    assert_eq!(
        produced, references[target],
        "reaching straight for a solid member diverges from the full pass"
    );

    // The same, spelled out with explicit skips.
    let mut archive = open(SOLID);
    for index in 0..target {
        archive.by_index(index).unwrap().skip().unwrap();
    }
    let mut produced = Vec::new();
    archive
        .by_index(target)
        .unwrap()
        .copy_to(&mut produced)
        .unwrap();
    assert_eq!(
        produced, references[target],
        "skipping to a solid member diverges from the full pass"
    );
}

/// An entry that is dropped without being consumed costs nothing: the next
/// member still extracts correctly.
#[test]
fn dropping_an_unconsumed_entry_leaves_the_next_member_intact() {
    let references = reference_bytes(SOLID);

    let mut archive = open(SOLID);
    let entry = archive.by_index(0).unwrap();
    drop(entry);

    let mut produced = Vec::new();
    archive.by_index(1).unwrap().copy_to(&mut produced).unwrap();
    assert_eq!(
        produced, references[1],
        "a dropped entry disturbed the member after it"
    );
}

/// A writer that fails partway leaves the solid dictionary mid-member, so the
/// archive refuses further solid work until it is reset.
#[test]
fn a_failed_solid_member_poisons_the_archive_until_it_is_reset() {
    let references = reference_bytes(SOLID);

    let mut archive = open(SOLID);
    let failure = archive
        .by_index(0)
        .unwrap()
        .copy_to(&mut FailingSink)
        .expect_err("a refusing writer must fail the extraction");
    assert!(
        !matches!(failure, RarError::SolidStatePoisoned { .. }),
        "the failure that poisons must report its own cause, got {failure:?}"
    );

    let poisoned = archive
        .by_index(1)
        .unwrap()
        .copy_to(&mut Vec::new())
        .expect_err("a poisoned solid archive must refuse further members");
    match poisoned {
        RarError::SolidStatePoisoned { member, detail } => {
            assert_eq!(member, "0", "the poison must name the member that left it");
            assert!(
                !detail.is_empty(),
                "the poison must carry the original failure"
            );
        }
        other => panic!("expected SolidStatePoisoned, got {other:?}"),
    }

    archive.reset_solid_state();
    for (index, expected) in references.iter().enumerate() {
        let mut produced = Vec::new();
        archive
            .by_index(index)
            .unwrap()
            .copy_to(&mut produced)
            .unwrap_or_else(|err| panic!("member {index} after reset: {err}"));
        assert_eq!(
            &produced, expected,
            "member {index} diverges after reset_solid_state"
        );
    }
}

/// A non-solid archive has no carried-over state, so a member whose writer
/// panics does not spoil the archive for anything else.
#[test]
fn a_panicking_writer_leaves_a_non_solid_archive_usable() {
    let references = reference_bytes(NON_SOLID);
    let mut archive = open(NON_SOLID);
    assert!(
        !archive.is_solid(),
        "this test needs a non-solid fixture, by construction"
    );

    let panicked = std::panic::catch_unwind(AssertUnwindSafe(|| {
        archive.by_index(0).unwrap().copy_to(&mut PanickingSink)
    }));
    assert!(panicked.is_err(), "the panicking writer must unwind");

    for (index, expected) in references.iter().enumerate() {
        let mut produced = Vec::new();
        archive
            .by_index(index)
            .unwrap()
            .copy_to(&mut produced)
            .unwrap_or_else(|err| panic!("member {index} after the panic: {err}"));
        assert_eq!(
            &produced, expected,
            "member {index} diverges after a writer panicked"
        );
    }
}

/// The per-volume writer type carries no `Send` or `'static` requirement, so
/// an `Rc<Cell<_>>` writer is accepted.
#[test]
fn copy_to_volumes_accepts_a_writer_that_is_neither_send_nor_static() {
    let references = reference_bytes(NON_SOLID);
    let provider = StaticVolumeProvider::from_ordered(volume_paths(NON_SOLID));
    let mut archive = open(NON_SOLID);

    let counter = Rc::new(Cell::new(0u64));
    archive
        .by_index_via(0, &provider)
        .unwrap()
        .copy_to_volumes(|_| Ok(CountingSink(Rc::clone(&counter))))
        .unwrap();

    assert_eq!(
        counter.get() as usize,
        references[0].len(),
        "the non-Send writer did not receive the whole member"
    );
}

/// The options builders read back what was set, and the archive's settings are
/// what an entry extracts under.
#[test]
fn options_can_be_built_and_set_on_the_archive() {
    let options = ExtractOptions::default()
        .with_password("hunter2")
        .with_verify(false)
        .with_restore_owners(true);
    assert_eq!(options.password(), Some("hunter2"));
    assert!(!options.verify());
    assert!(options.restore_owners());
    let debug = format!("{options:?}");
    assert!(
        !debug.contains("hunter2") && debug.contains("<redacted>"),
        "Debug must say a password is set without printing it: {debug}"
    );
    assert!(
        format!("{:?}", ExtractOptions::default()).contains("password: None"),
        "Debug must say when no password is set"
    );

    let mut archive = open(NON_SOLID);
    assert!(archive.verify(), "verification is on by default");
    assert!(
        !archive.restore_owners(),
        "owner restoration is off by default"
    );
    archive.set_verify(false);
    archive.set_restore_owners(true);
    assert!(!archive.verify());
    assert!(archive.restore_owners());
}

/// The listing surface agrees with the metadata the archive already exposed.
#[test]
fn the_listing_surface_agrees_with_the_archive_metadata() {
    for family in FAMILIES {
        let name = label(family);
        let archive = open(family);
        let expected: Vec<String> = archive
            .metadata()
            .members
            .iter()
            .map(|member| member.name.clone())
            .collect();

        assert_eq!(archive.len(), expected.len(), "{name}: len disagrees");
        assert_eq!(
            archive.is_empty(),
            expected.is_empty(),
            "{name}: is_empty disagrees"
        );
        let listed: Vec<String> = archive.entries().map(|member| member.name).collect();
        assert_eq!(listed, expected, "{name}: entries() disagrees");

        for (index, member) in expected.iter().enumerate() {
            let info = archive
                .entry_info(index)
                .unwrap_or_else(|| panic!("{name}: entry_info({index}) returned nothing"));
            assert_eq!(&info.name, member, "{name}: entry_info({index}) disagrees");
        }
        assert!(
            archive.entry_info(expected.len()).is_none(),
            "{name}: entry_info past the end must return nothing"
        );
    }
}

/// `by_name` resolves the same member `index_for_name` reports.
#[test]
fn by_name_resolves_the_member_index_for_name_reports() {
    let references = reference_bytes(NON_SOLID);
    let mut archive = open(NON_SOLID);
    let raw_name = archive.metadata().members[0].raw_name.clone();
    let index = archive
        .index_for_name(&raw_name)
        .expect("the archive's own member name must resolve");
    assert_eq!(index, 0);

    let mut produced = Vec::new();
    archive
        .by_name(&raw_name)
        .unwrap()
        .copy_to(&mut produced)
        .unwrap();
    assert_eq!(
        produced, references[0],
        "by_name extracted a different member"
    );

    let missing = archive
        .by_name("no-such-member-in-this-archive")
        .expect_err("an unknown name must be refused");
    assert!(
        matches!(missing, RarError::MemberNotFound { .. }),
        "expected MemberNotFound, got {missing:?}"
    );
}

/// An index the archive does not list is refused as such, not as corruption.
#[test]
fn an_index_past_the_end_is_refused_as_out_of_range() {
    let mut archive = open(NON_SOLID);
    let len = archive.len();
    let error = archive
        .by_index(len)
        .expect_err("an index past the end must be refused");
    assert!(
        matches!(error, RarError::MemberIndexOutOfRange { index, len: reported } if index == len && reported == len),
        "expected MemberIndexOutOfRange {{ index: {len}, len: {len} }}, got {error:?}"
    );
}

/// Per-volume extraction of a non-solid member without a provider is a usage
/// error with its own variant, not a corruption report.
#[test]
fn copy_to_volumes_without_a_provider_names_the_missing_provider() {
    let mut archive = open(NON_SOLID);
    assert!(!archive.is_solid(), "the fixture must be non-solid");
    let error = archive
        .by_index(0)
        .unwrap()
        .copy_to_volumes(|_| Ok(Vec::new()))
        .expect_err("a non-solid member needs a provider for per-volume output");
    assert!(
        matches!(error, RarError::VolumeProviderRequired { .. }),
        "expected VolumeProviderRequired, got {error:?}"
    );
}

/// What a progress handler sees across one member's extraction.
#[derive(Default)]
struct Events {
    starts: Cell<usize>,
    last_progress: Cell<Option<u64>>,
    completions: RefCell<Vec<bool>>,
}

impl unrar_rs::ProgressHandler for Events {
    fn on_member_start(&self, _member: &unrar_rs::MemberInfo) {
        self.starts.set(self.starts.get() + 1);
    }

    fn on_member_progress(&self, _member: &unrar_rs::MemberInfo, bytes_written: u64) {
        self.last_progress.set(Some(bytes_written));
    }

    fn on_member_complete(&self, _member: &unrar_rs::MemberInfo, result: &Result<(), RarError>) {
        self.completions.borrow_mut().push(result.is_ok());
    }
}

/// Every consuming call reports to the handler `with_progress` names: one
/// start, a running byte count that ends on the member's size, one completion.
#[test]
fn with_progress_reports_on_every_consuming_call() {
    let references = reference_bytes(NON_SOLID);
    let expected = references[0].len() as u64;

    let copy_to = Events::default();
    let mut archive = open(NON_SOLID);
    let mut produced = Vec::new();
    let written = archive
        .by_index(0)
        .unwrap()
        .with_progress(&copy_to)
        .copy_to(&mut produced)
        .unwrap();
    assert_eq!(written, expected);
    assert_eq!(copy_to.starts.get(), 1, "copy_to: one start event");
    assert_eq!(
        copy_to.last_progress.get(),
        Some(expected),
        "copy_to: the last progress report is the member's size"
    );
    assert_eq!(
        *copy_to.completions.borrow(),
        vec![true],
        "copy_to: one Ok completion"
    );

    let volumes = Events::default();
    let provider = StaticVolumeProvider::from_ordered(volume_paths(NON_SOLID));
    let mut archive = open(NON_SOLID);
    let chunks = archive
        .by_index_via(0, &provider)
        .unwrap()
        .with_progress(&volumes)
        .copy_to_volumes(|_| Ok(Vec::new()))
        .unwrap();
    assert_eq!(chunks.iter().map(|(_, bytes)| bytes).sum::<u64>(), expected);
    assert_eq!(volumes.starts.get(), 1, "copy_to_volumes: one start event");
    assert_eq!(
        volumes.last_progress.get(),
        Some(expected),
        "copy_to_volumes: the running count spans every volume's writer"
    );
    assert_eq!(*volumes.completions.borrow(), vec![true]);

    let unpack = Events::default();
    let dir = tempfile::tempdir().unwrap();
    let mut archive = open(NON_SOLID);
    archive
        .by_index(0)
        .unwrap()
        .with_progress(&unpack)
        .unpack_in(dir.path())
        .unwrap();
    assert_eq!(unpack.starts.get(), 1, "unpack_in: one start event");
    assert_eq!(*unpack.completions.borrow(), vec![true]);

    let skip = Events::default();
    let mut archive = open(SOLID);
    archive
        .by_index(0)
        .unwrap()
        .with_progress(&skip)
        .skip()
        .unwrap();
    assert_eq!(
        skip.starts.get(),
        1,
        "skip on a solid member: one start event"
    );
    assert_eq!(*skip.completions.borrow(), vec![true]);

    let failing = Events::default();
    let mut archive = open(NON_SOLID);
    let error = archive
        .by_index(0)
        .unwrap()
        .with_progress(&failing)
        .copy_to(&mut FailingSink)
        .expect_err("a failing writer fails the copy");
    assert!(matches!(error, RarError::Io(_)), "got {error:?}");
    assert_eq!(
        *failing.completions.borrow(),
        vec![false],
        "a failed copy completes with the failure"
    );
}
