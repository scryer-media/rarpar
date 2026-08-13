#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use unrar_rs::RarArchive;

const MAX_INPUT_BYTES: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() <= MAX_INPUT_BYTES {
        let _ = RarArchive::open(Cursor::new(data.to_vec()));
    }
});
