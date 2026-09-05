//! The libFuzzer timeout artifacts, replayed as ordinary tests.
//!
//! Every input here came out of a ClusterFuzzLite `rar_extract` or
//! `rar_headers` batch run as a `timeout-*` artifact, and every one of them
//! either hung, panicked, or took seconds against the tree before the
//! header-validation and decode-termination guards landed. They are fuzzer
//! output, not archives: they live in `fuzz/corpus/<target>/` (seeds, and now
//! regressions) and never under `tests/fixtures/`, which is reserved for
//! images written by RARLAB tooling.
//!
//! What is asserted is deliberately weak — an `Err`, not a particular `Err`.
//! These are malformed archives; which guard catches one is an implementation
//! detail that should be free to change. What must not change is that opening
//! or extracting them returns, quickly, without panicking and without
//! inventing output.
//!
//! `include_bytes!` rather than a runtime read so a corpus file that goes
//! missing breaks the build instead of silently skipping. That is also why
//! this file is in the crate's `exclude` list: `fuzz/**` is not published, so
//! the published tarball must not carry a test that reads from it.

use std::io::Write;
use std::time::{Duration, Instant};

use unrar_rs::RarArchive;

/// Decoded bytes one input may produce before the replay calls it a failure.
///
/// Every one of these archives is under 2.6 KB and declares megabytes to
/// gigabytes of unpacked data. Anything that gets near this cap has started
/// manufacturing output again.
const MAX_OUTPUT_BYTES: u64 = 8 << 20;

/// Wall clock one input may take.
///
/// A true hang blocks the test binary whatever this says; the bound is here
/// for the softer regression — `timeout-8014be61` and `timeout-bc9f62eb` did
/// terminate before the fix, in 5.7 s and 1.8 s.
const MAX_ELAPSED: Duration = Duration::from_secs(5);

struct BoundedSink {
    written: u64,
}

impl Write for BoundedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written += buf.len() as u64;
        assert!(
            self.written <= MAX_OUTPUT_BYTES,
            "replay produced more than {MAX_OUTPUT_BYTES} bytes"
        );
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Open `bytes` and, if that succeeds, extract every member.
///
/// Returns the number of members that extracted without error; the callers
/// require zero. Panics on a runaway output volume or a slow replay.
fn replay(name: &str, bytes: &[u8]) -> usize {
    let started = Instant::now();
    let mut extracted_ok = 0usize;

    if let Ok(mut archive) = RarArchive::open(std::io::Cursor::new(bytes.to_vec())) {
        let members = archive.len();
        let mut sink = BoundedSink { written: 0 };
        for index in 0..members {
            let outcome = archive
                .by_index(index)
                .and_then(|entry| entry.copy_to(&mut sink));
            if outcome.is_ok() {
                extracted_ok += 1;
            }
        }
    }

    let elapsed = started.elapsed();
    assert!(
        elapsed < MAX_ELAPSED,
        "{name} took {elapsed:?}, over the {MAX_ELAPSED:?} budget"
    );
    extracted_ok
}

macro_rules! extract_timeout_regressions {
    ($($test:ident => $file:literal),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                let bytes = include_bytes!(concat!("../fuzz/corpus/rar_extract/", $file));
                let extracted_ok = replay($file, bytes);
                assert_eq!(
                    extracted_ok, 0,
                    "{} extracted {extracted_ok} member(s); every member of a \
                     fuzzer timeout artifact must fail cleanly",
                    $file
                );
            }
        )*
    };
}

// The nine that panicked on `ppmd/model.rs` `run_length` overflow, and the
// eight that hung or crawled inside the RAR4 header scan or decode loops.
extract_timeout_regressions! {
    timeout_063caae0 => "timeout-063caae0af5b2c32581f8e679cf67297c990c4d3",
    timeout_129b6693 => "timeout-129b66937d71a5d24506fa1aba68a007ea1b9562",
    timeout_2c9348e8 => "timeout-2c9348e8684e892b48838d2f3201d45b5b6f33b5",
    timeout_3b5f5167 => "timeout-3b5f5167df16871090c9245c9dc1c9b80a08c50d",
    timeout_63e28523 => "timeout-63e285232003fe3d92ff1c305dbf2359db8fb6ab",
    timeout_6eca40d0 => "timeout-6eca40d0d93902862331da96ff91ebfd981a42da",
    timeout_7cbe702a => "timeout-7cbe702aaa3e741b904757dae505c4a327999766",
    timeout_8014be61 => "timeout-8014be61447a8b6e83f58b47b9ae391668897a67",
    timeout_8cd4372e => "timeout-8cd4372e7625d1393cdf8936724246eb19af7fa5",
    timeout_93aa06f4 => "timeout-93aa06f45987efdf1b4e264274843e83228814e2",
    timeout_968b86a4 => "timeout-968b86a4e53dbf4572785abe3e440041b6749c5d",
    timeout_99eb7b42 => "timeout-99eb7b429488043d38982cc0f1e5965a7cb80f0d",
    timeout_b21e4ce5 => "timeout-b21e4ce58017ce4f533e93e187cec0da8b1a53e8",
    timeout_bc9f62eb => "timeout-bc9f62eb8b4f60535438f360caefca321e2ca0f1",
    timeout_e205a28f => "timeout-e205a28fcf8963f035ad95df18e45be11650cf90",
    timeout_ebb34d77 => "timeout-ebb34d7721e6c75dd6422d73e9cf8ebc650da832",
    timeout_f869e3ff => "timeout-f869e3ff3f08eaeceee3b951d9d0b8ebef03f069",
}

/// The `rar_headers` artifact: a file header at offset 2423 declaring
/// `packed_size = 2^64 - 80`, which as the `i64` `SeekFrom::Current` takes is
/// `-80`. The scan seeked backwards onto the same header and pushed a
/// `Rar4FileHeader` per cycle, ~28k a second, until memory ran out.
#[test]
fn timeout_a8693f23_header_scan_cannot_rewind() {
    let bytes = include_bytes!(
        "../fuzz/corpus/rar_headers/timeout-a8693f23db94ce99c54ad4b30e812abe0a806919"
    );
    let started = Instant::now();
    let opened = RarArchive::open(std::io::Cursor::new(bytes.to_vec()));
    let elapsed = started.elapsed();

    assert!(
        opened.is_err(),
        "a header declaring more packed bytes than the stream can hold must be rejected"
    );
    assert!(
        elapsed < MAX_ELAPSED,
        "header scan took {elapsed:?}, over the {MAX_ELAPSED:?} budget"
    );
}
