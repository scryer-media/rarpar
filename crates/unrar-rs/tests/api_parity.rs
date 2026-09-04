#![cfg(feature = "slow-tests")]
//! Cross-API extraction parity sweep.
//!
//! Every archive must produce identical bytes through each extraction API:
//! `extract_member` (buffered solid-chain walk), `extract_member_streaming`
//! (per-member streaming), `extract_member_solid_chunked` (volume-chunked
//! solid path), and the [`Entry`](unrar_rs::Entry) handle through `copy_to`,
//! `copy_to_volumes` and `Read`. The RAR4 solid member-boundary bug shipped
//! because only one of these paths was exercised per fixture; this sweep pins
//! all of them to the CRC-verified `extract_member` output.
//!
//! The pre-0.9.0 entry points are deliberately still called here: holding them
//! to the same bytes as the handle is exactly what this file is for.
#![allow(deprecated)]

use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const PASSWORD: &str = "testpass123";
const HP_PASSWORD: &str = "secretpass";
const E2E_PASSWORD: &str = "e2e-test-password";

struct Case {
    dir: &'static str,
    volumes: &'static [&'static str],
    password: Option<&'static str>,
}

const CASES: &[Case] = &[
    Case {
        dir: "rar4",
        volumes: &["rar4_lz.rar"],
        password: None,
    },
    Case {
        dir: "rar4",
        volumes: &["rar4_store.rar"],
        password: None,
    },
    Case {
        dir: "rar4",
        volumes: &["rar4_multifile_lz.rar"],
        password: None,
    },
    Case {
        dir: "rar4",
        volumes: &["rar4_solid.rar"],
        password: None,
    },
    Case {
        dir: "rar4",
        volumes: &["rar4_lz_solid_mv.rar"],
        password: None,
    },
    Case {
        dir: "rar4",
        volumes: &["rar4_ppm_solid_mv.rar"],
        password: None,
    },
    Case {
        dir: "rar4",
        volumes: &["rar4_enc_lz.rar"],
        password: Some(PASSWORD),
    },
    Case {
        dir: "rar4",
        volumes: &["rar4_hp_lz.rar"],
        password: Some(HP_PASSWORD),
    },
    Case {
        dir: "rar4",
        volumes: &[
            "rar4_mv_video.part1.rar",
            "rar4_mv_video.part2.rar",
            "rar4_mv_video.part3.rar",
            "rar4_mv_video.part4.rar",
            "rar4_mv_video.part5.rar",
        ],
        password: None,
    },
    Case {
        dir: "rar4",
        volumes: &[
            "rar4_enc_mv_video.part1.rar",
            "rar4_enc_mv_video.part2.rar",
            "rar4_enc_mv_video.part3.rar",
            "rar4_enc_mv_video.part4.rar",
            "rar4_enc_mv_video.part5.rar",
        ],
        password: Some(PASSWORD),
    },
    Case {
        dir: "rar4",
        volumes: &[
            "rar4_tiny_volumes.part1.rar",
            "rar4_tiny_volumes.part2.rar",
            "rar4_tiny_volumes.part3.rar",
            "rar4_tiny_volumes.part4.rar",
            "rar4_tiny_volumes.part5.rar",
        ],
        password: None,
    },
    Case {
        dir: "rar5",
        volumes: &["rar5_lz.rar"],
        password: None,
    },
    Case {
        dir: "rar5",
        volumes: &["rar5_store.rar"],
        password: None,
    },
    Case {
        dir: "rar5",
        volumes: &["rar5_multifile_lz.rar"],
        password: None,
    },
    Case {
        dir: "rar5",
        volumes: &["rar5_solid.rar"],
        password: None,
    },
    Case {
        dir: "rar5",
        volumes: &["rar5_best.rar"],
        password: None,
    },
    Case {
        dir: "rar5",
        volumes: &["rar5_enc_lz.rar"],
        password: Some(PASSWORD),
    },
    Case {
        dir: "rar5",
        volumes: &["rar5_hp_lz.rar"],
        password: Some(HP_PASSWORD),
    },
    Case {
        dir: "rar5",
        volumes: &["rar5_solid_encrypted.rar"],
        password: Some(E2E_PASSWORD),
    },
    Case {
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
    Case {
        dir: "rar5",
        volumes: &[
            "rar5_enc_mv_video.part1.rar",
            "rar5_enc_mv_video.part2.rar",
            "rar5_enc_mv_video.part3.rar",
            "rar5_enc_mv_video.part4.rar",
            "rar5_enc_mv_video.part5.rar",
        ],
        password: Some(PASSWORD),
    },
    Case {
        dir: "rar5",
        volumes: &[
            "rar5_tiny_volumes.part1.rar",
            "rar5_tiny_volumes.part2.rar",
            "rar5_tiny_volumes.part3.rar",
            "rar5_tiny_volumes.part4.rar",
            "rar5_tiny_volumes.part5.rar",
        ],
        password: None,
    },
    Case {
        dir: "rar5",
        volumes: &[
            "test_read_format_rar5_multiarchive_solid.part01.rar",
            "test_read_format_rar5_multiarchive_solid.part02.rar",
            "test_read_format_rar5_multiarchive_solid.part03.rar",
            "test_read_format_rar5_multiarchive_solid.part04.rar",
        ],
        password: None,
    },
];

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn volume_paths(case: &Case) -> Vec<PathBuf> {
    case.volumes
        .iter()
        .map(|name| fixture_root().join(case.dir).join(name))
        .collect()
}

fn open_case(case: &Case) -> unrar_rs::RarArchive {
    let label = case.volumes[0];
    let paths = volume_paths(case);
    let mut archive = if paths.len() == 1 {
        let file = File::open(&paths[0]).unwrap();
        match case.password {
            // Header-encrypted archives need the password at open time.
            Some(password) => unrar_rs::RarArchive::open_with_password(file, password)
                .unwrap_or_else(|err| panic!("{label}: open_with_password: {err}")),
            None => unrar_rs::RarArchive::open(file)
                .unwrap_or_else(|err| panic!("{label}: open: {err}")),
        }
    } else {
        let readers: Vec<Box<dyn unrar_rs::ReadSeek>> = paths
            .iter()
            .map(|path| Box::new(File::open(path).unwrap()) as Box<dyn unrar_rs::ReadSeek>)
            .collect();
        unrar_rs::RarArchive::open_volumes(readers)
            .unwrap_or_else(|err| panic!("{label}: open_volumes: {err}"))
    };
    if let Some(password) = case.password {
        archive.set_password(password);
    }
    archive
}

fn options(case: &Case) -> unrar_rs::ExtractOptions {
    unrar_rs::ExtractOptions {
        verify: true,
        password: case.password.map(str::to_owned),
        restore_owners: false,
    }
}

/// A per-volume writer that borrows its sink, so it carries neither `Send` nor
/// `'static` — the shape the handle's `copy_to_volumes` exists to allow.
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

#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Solid archives enforce sequential extraction within one pass, so each API
/// runs as its own ascending pass with `reset_solid_state` in between (which
/// gives the public reset path coverage too).
#[test]
fn all_extraction_apis_agree_on_every_fixture_member() {
    for case in CASES {
        let label = case.volumes[0];
        let paths = volume_paths(case);
        let provider = unrar_rs::StaticVolumeProvider::from_ordered(paths.clone());
        let opts = options(case);

        let mut archive = open_case(case);
        let members: Vec<(usize, String, bool)> = archive
            .metadata()
            .members
            .iter()
            .enumerate()
            .map(|(index, member)| (index, member.name.clone(), member.is_directory))
            .collect();
        let is_solid = archive.is_solid();

        // Pass 1: buffered extraction (CRC-verified reference output).
        let mut references = Vec::new();
        for (index, name, is_directory) in &members {
            if *is_directory {
                references.push(Vec::new());
                continue;
            }
            let bytes = archive
                .extract_member(*index, &opts, None)
                .unwrap_or_else(|err| panic!("{label} member {index} ({name}): buffered: {err}"))
                .to_bytes()
                .unwrap();
            references.push(bytes);
        }

        // Pass 2: streaming extraction.
        archive.reset_solid_state();
        for (index, name, is_directory) in &members {
            if *is_directory {
                continue;
            }
            let mut streamed = Vec::new();
            archive
                .extract_member_streaming(*index, &opts, &provider, &mut streamed)
                .unwrap_or_else(|err| panic!("{label} member {index} ({name}): streaming: {err}"));
            assert_eq!(
                streamed, references[*index],
                "{label} member {index} ({name}): streaming output diverges from buffered"
            );
        }

        // Pass 3: volume-chunked solid extraction.
        if is_solid {
            archive.reset_solid_state();
            for (index, name, is_directory) in &members {
                if *is_directory {
                    continue;
                }
                let sink = SharedSink::default();
                let chunk_sink = sink.clone();
                archive
                    .extract_member_solid_chunked(*index, &opts, move |_| {
                        Ok(Box::new(chunk_sink.clone()) as Box<dyn Write>)
                    })
                    .unwrap_or_else(|err| {
                        panic!("{label} member {index} ({name}): solid chunked: {err}")
                    });
                let chunked = sink.0.lock().unwrap().clone();
                assert_eq!(
                    chunked, references[*index],
                    "{label} member {index} ({name}): chunked output diverges from buffered"
                );
            }
        }

        // Pass 4: the handle, writing straight into a borrowed writer.
        archive.reset_solid_state();
        for (index, name, is_directory) in &members {
            if *is_directory {
                continue;
            }
            let mut produced = Vec::new();
            archive
                .by_index(*index)
                .unwrap_or_else(|err| panic!("{label} member {index} ({name}): by_index: {err}"))
                .copy_to(&mut produced)
                .unwrap_or_else(|err| {
                    panic!("{label} member {index} ({name}): handle copy_to: {err}")
                });
            assert_eq!(
                produced, references[*index],
                "{label} member {index} ({name}): handle copy_to diverges from buffered"
            );
        }

        // Pass 5: the handle over a volume provider.
        archive.reset_solid_state();
        for (index, name, is_directory) in &members {
            if *is_directory {
                continue;
            }
            let mut produced = Vec::new();
            archive
                .by_index_via(*index, &provider)
                .unwrap_or_else(|err| {
                    panic!("{label} member {index} ({name}): by_index_via: {err}")
                })
                .copy_to(&mut produced)
                .unwrap_or_else(|err| {
                    panic!("{label} member {index} ({name}): handle streaming copy_to: {err}")
                });
            assert_eq!(
                produced, references[*index],
                "{label} member {index} ({name}): handle streaming copy_to diverges from buffered"
            );
        }

        // Pass 6: the handle read as a `Read`.
        archive.reset_solid_state();
        for (index, name, is_directory) in &members {
            if *is_directory {
                continue;
            }
            let mut produced = Vec::new();
            let mut entry = archive
                .by_index(*index)
                .unwrap_or_else(|err| panic!("{label} member {index} ({name}): by_index: {err}"));
            entry.read_to_end(&mut produced).unwrap_or_else(|err| {
                panic!("{label} member {index} ({name}): handle read: {err}")
            });
            assert_eq!(
                produced, references[*index],
                "{label} member {index} ({name}): handle Read output diverges from buffered"
            );
        }

        // Pass 7: the handle splitting output per volume, into a writer that is
        // neither `Send` nor `'static`.
        archive.reset_solid_state();
        for (index, name, is_directory) in &members {
            if *is_directory {
                continue;
            }
            let sink = RefCell::new(Vec::new());
            let chunks = if is_solid {
                archive
                    .by_index(*index)
                    .unwrap_or_else(|err| {
                        panic!("{label} member {index} ({name}): by_index: {err}")
                    })
                    .copy_to_volumes(|_| Ok(BorrowedSink(&sink)))
            } else {
                archive
                    .by_index_via(*index, &provider)
                    .unwrap_or_else(|err| {
                        panic!("{label} member {index} ({name}): by_index_via: {err}")
                    })
                    .copy_to_volumes(|_| Ok(BorrowedSink(&sink)))
            }
            .unwrap_or_else(|err| {
                panic!("{label} member {index} ({name}): handle copy_to_volumes: {err}")
            });
            assert_eq!(
                sink.borrow().as_slice(),
                references[*index].as_slice(),
                "{label} member {index} ({name}): handle chunked output diverges from buffered"
            );
            let total: u64 = chunks.iter().map(|(_, written)| *written).sum();
            assert_eq!(
                total as usize,
                references[*index].len(),
                "{label} member {index} ({name}): handle chunk totals do not add up"
            );
        }
    }
}
