#![cfg(feature = "slow-tests")]

//! The `slow-tests` half of the imported-corpus coverage.
//!
//! Split out of `imported_corpus.rs` so CI's `unrar-slow-tests` lane can select
//! the feature-gated delta with `--test slow_imported_corpus` instead of
//! re-running that target's other eleven tests, which `fixture-tests` already ran.
//!
//! `corpus_outcome` and its enum are small deliberate copies of
//! `imported_corpus.rs`'s, which still needs them for its ungated tests.

use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use unrar_rs::{ExtractOptions, RarArchive};

fn fixture(dir: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
        .join(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorpusOutcome {
    RejectedOnOpen,
    RejectedOnExtract,
    Completed,
}

fn corpus_outcome(dir: &str, filename: &str) -> CorpusOutcome {
    let data = std::fs::read(fixture(dir, filename)).unwrap();
    let mut archive = match RarArchive::open(Cursor::new(data)) {
        Ok(archive) => archive,
        Err(_) => return CorpusOutcome::RejectedOnOpen,
    };

    let member_count = archive.metadata().members.len();
    for index in 0..member_count {
        if archive
            .extract_member(index, &ExtractOptions::default(), None)
            .is_err()
        {
            return CorpusOutcome::RejectedOnExtract;
        }
    }

    CorpusOutcome::Completed
}

#[test]
fn imported_ppmd_transition_fixture_extracts_successfully() {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        corpus_outcome("rar4", "test_read_format_rar_ppmd_lzss_conversion.rar")
    }))
    .unwrap_or_else(|_| {
        panic!("fixture panicked during decode: rar4/test_read_format_rar_ppmd_lzss_conversion.rar")
    });
    assert_eq!(
        outcome,
        CorpusOutcome::Completed,
        "expected successful extract for rar4/test_read_format_rar_ppmd_lzss_conversion.rar"
    );
}
