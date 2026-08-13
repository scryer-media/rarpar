#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use par2_rs::scan_packets_from_path;

const MAX_INPUT_BYTES: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut file = tempfile::NamedTempFile::new().expect("temporary fuzz input");
    file.write_all(data).expect("write temporary fuzz input");
    let _ = scan_packets_from_path(file.path());
});
