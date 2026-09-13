//! Reader-frontier regressions using the pinned RARLAB fixture corpus.

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;
use unrar_rs::{RarArchive, ReadSeek, VolumeProvider, VolumeProviderError};

struct Input {
    bytes: Arc<[u8]>,
    available: Mutex<usize>,
    changed: Condvar,
}

impl Input {
    fn publish(&self, count: usize) {
        *self.available.lock().unwrap() = count.min(self.bytes.len());
        self.changed.notify_all();
    }
}

struct Reader {
    input: Arc<Input>,
    position: u64,
}

impl Read for Reader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.position >= self.input.bytes.len() as u64 {
            return Ok(0);
        }
        let available = self.input.available.lock().unwrap();
        let (available, timeout) = self
            .input
            .changed
            .wait_timeout_while(available, Duration::from_secs(10), |n| {
                self.position >= *n as u64
            })
            .unwrap();
        if timeout.timed_out() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test input was not published",
            ));
        }
        let start = self.position as usize;
        let count = out.len().min(*available - start);
        out[..count].copy_from_slice(&self.input.bytes[start..start + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Reader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.position = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
            SeekFrom::End(n) => (self.input.bytes.len() as u64).checked_add_signed(n),
        }
        .ok_or_else(|| io::Error::other("invalid test seek"))?;
        Ok(self.position)
    }
}

struct Provider(Vec<Arc<Input>>);
impl VolumeProvider for Provider {
    fn get_volume(&self, index: usize) -> Result<Box<dyn ReadSeek>, VolumeProviderError> {
        let input = self
            .0
            .get(index)
            .ok_or_else(|| VolumeProviderError::Unavailable {
                volume: index,
                reason: "no fixture volume".into(),
            })?;
        Ok(Box::new(Reader {
            input: Arc::clone(input),
            position: 0,
        }))
    }
}

struct Output {
    bytes: Vec<u8>,
    first: Option<mpsc::Sender<()>>,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !bytes.is_empty()
            && let Some(first) = self.first.take()
        {
            let _ = first.send(());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn fixture(format: &str, name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format)
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("hydrate fixture {}: {error}", path.display()))
}

fn before_tail(format: &str) {
    let bytes = fixture(format, &format!("{format}_lz.rar"));
    let mut reference = RarArchive::open(Cursor::new(bytes.clone())).unwrap();
    let headers = reference.export_headers();
    let segment = &headers.members[0].segments[0];
    let data_start = segment.data_offset as usize;
    let packed_end = data_start + segment.data_size as usize;
    assert!(packed_end < bytes.len());
    let input = Arc::new(Input {
        bytes: bytes.into(),
        available: Mutex::new(data_start),
        changed: Condvar::new(),
    });
    let provider = Provider(vec![Arc::clone(&input)]);
    let mut expected = Vec::new();
    reference
        .by_index(0)
        .unwrap()
        .copy_to(&mut expected)
        .unwrap();
    let (opened_tx, opened_rx) = mpsc::channel();
    let (output_tx, output_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut archive =
            RarArchive::open_prefix(provider.get_volume(0).unwrap(), None, NonZeroUsize::MIN)
                .unwrap();
        assert_eq!(archive.len(), 1);
        opened_tx.send(()).unwrap();
        let mut out = Output {
            bytes: Vec::new(),
            first: Some(output_tx),
        };
        archive
            .by_index_via(0, &provider)
            .unwrap()
            .copy_to(&mut out)
            .unwrap();
        out.bytes
    });
    let opened = opened_rx.recv_timeout(Duration::from_secs(3));
    input.publish(packed_end);
    let output = output_rx.recv_timeout(Duration::from_secs(3));
    // Always release the worker, including on an assertion failure.
    input.publish(input.bytes.len());
    let actual = worker.join().unwrap();
    opened.expect("opening must not read payload or tail headers");
    output.expect("decoded output must precede publication of tail headers");
    assert_eq!(actual, expected);
}

#[test]
fn rar4_extracts_before_tail_headers_arrive() {
    before_tail("rar4");
}

#[test]
fn rar5_extracts_before_tail_headers_arrive() {
    before_tail("rar5");
}

fn multivolume_before_tail(format: &str) {
    let mut inputs = Vec::new();
    let mut readers: Vec<Box<dyn ReadSeek>> = Vec::new();
    for n in 1..=7 {
        let bytes = fixture(
            format,
            &format!("generated_matrix_{format}_lz_plain.part{n}.rar"),
        );
        let archive = RarArchive::open(Cursor::new(bytes.clone())).unwrap();
        let headers = archive.export_headers();
        assert_eq!(headers.members.len(), 1);
        let segment = &headers.members[0].segments[0];
        let packed_end = (segment.data_offset + segment.data_size) as usize;
        assert!(packed_end < bytes.len());
        readers.push(Box::new(Cursor::new(bytes.clone())));
        inputs.push(Arc::new(Input {
            bytes: bytes.into(),
            available: Mutex::new(packed_end),
            changed: Condvar::new(),
        }));
    }
    let mut reference = RarArchive::open_volumes(readers).unwrap();
    let mut expected = Vec::new();
    reference
        .by_index(0)
        .unwrap()
        .copy_to(&mut expected)
        .unwrap();
    let provider = Provider(inputs.clone());
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut archive =
            RarArchive::open_prefix(provider.get_volume(0).unwrap(), None, NonZeroUsize::MIN)
                .unwrap();
        let mut output = Vec::new();
        let result = archive
            .by_index_via(0, &provider)
            .unwrap()
            .copy_to(&mut output);
        done_tx.send(result).unwrap();
        output
    });
    let done = done_rx.recv_timeout(Duration::from_secs(3));
    for input in &inputs {
        input.publish(input.bytes.len());
    }
    let actual = worker.join().unwrap();
    done.expect("continuation discovery must not scan volume tails")
        .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn rar4_continuations_do_not_wait_for_volume_tails() {
    multivolume_before_tail("rar4");
}

#[test]
fn rar5_continuations_do_not_wait_for_volume_tails() {
    multivolume_before_tail("rar5");
}

fn prefix_parity(format: &str, names: &[String], password: Option<&str>) {
    let bytes: Vec<_> = names.iter().map(|name| fixture(format, name)).collect();
    let mut reference = match password {
        Some(password) => RarArchive::open_with_password(Cursor::new(bytes[0].clone()), password),
        None => RarArchive::open(Cursor::new(bytes[0].clone())),
    }
    .unwrap();
    for (index, bytes) in bytes.iter().enumerate().skip(1) {
        reference
            .add_volume(index, Box::new(Cursor::new(bytes.clone())))
            .unwrap();
    }
    let mut expected = Vec::new();
    for index in 0..reference.len() {
        let info = reference.member_info(index).unwrap();
        let mut out = Vec::new();
        if !info.is_directory {
            reference
                .by_index(index)
                .unwrap()
                .copy_to(&mut out)
                .unwrap();
        }
        expected.push((info.name, out));
    }
    let provider = Provider(
        bytes
            .into_iter()
            .map(|bytes| {
                Arc::new(Input {
                    available: Mutex::new(bytes.len()),
                    bytes: bytes.into(),
                    changed: Condvar::new(),
                })
            })
            .collect(),
    );
    let mut archive =
        RarArchive::open_prefix(provider.get_volume(0).unwrap(), password, NonZeroUsize::MIN)
            .unwrap();
    let mut actual = Vec::new();
    for volume in 0..names.len() {
        let mut requested = NonZeroUsize::MIN;
        loop {
            let count = archive
                .extend_volume_prefix(volume, provider.get_volume(volume).unwrap(), requested)
                .unwrap();
            while actual.len() < archive.len() {
                let index = actual.len();
                let info = archive.member_info(index).unwrap();
                let mut out = Vec::new();
                if !info.is_directory {
                    archive
                        .by_index_via(index, &provider)
                        .unwrap()
                        .copy_to(&mut out)
                        .unwrap();
                }
                actual.push((info.name, out));
            }
            if count < requested.get() {
                break;
            }
            requested = requested.checked_add(1).unwrap();
        }
    }
    assert_eq!(actual, expected, "{}", names[0]);
}

#[test]
fn successive_prefixes_preserve_rar4_solid_and_encrypted_state() {
    for (name, password) in [
        ("rar4_multifile_lz.rar", None),
        ("rar4_solid.rar", None),
        ("rar4_ppm_solid_mv.rar", None),
        ("rar4_enc_lz.rar", Some("testpass123")),
        ("rar4_hp_lz.rar", Some("secretpass")),
    ] {
        prefix_parity("rar4", &[name.into()], password);
    }
}

#[test]
fn successive_prefixes_preserve_rar5_solid_and_encrypted_state() {
    for (name, password) in [
        ("rar5_multifile_lz.rar", None),
        ("rar5_solid.rar", None),
        ("rar5_enc_lz.rar", Some("testpass123")),
        ("rar5_hp_lz.rar", Some("secretpass")),
        ("rar5_solid_encrypted.rar", Some("e2e-test-password")),
    ] {
        prefix_parity("rar5", &[name.into()], password);
    }
}

#[test]
fn successive_prefixes_preserve_split_member_indices() {
    for format in ["rar4", "rar5"] {
        let names = (1..=5)
            .map(|n| format!("{format}_mv_video.part{n}.rar"))
            .collect::<Vec<_>>();
        prefix_parity(format, &names, None);
        let names = (1..=5)
            .map(|n| format!("{format}_enc_mv_video.part{n}.rar"))
            .collect::<Vec<_>>();
        prefix_parity(format, &names, Some("testpass123"));
    }
    let names = (1..=4)
        .map(|n| format!("test_read_format_rar5_multiarchive_solid.part{n:02}.rar"))
        .collect::<Vec<_>>();
    prefix_parity("rar5", &names, None);
}

struct UnknownLength(Reader);
impl Read for UnknownLength {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.0.read(out)
    }
}
impl Seek for UnknownLength {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if matches!(from, SeekFrom::End(_)) {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "length still arriving",
            ))
        } else {
            self.0.seek(from)
        }
    }
}

fn before_packed_tail(format: &str) {
    let bytes = fixture(format, &format!("{format}_hp_large.rar"));
    let password = "e2e-test-password";
    let mut reference =
        RarArchive::open_with_password(Cursor::new(bytes.clone()), password).unwrap();
    let header = reference.export_headers();
    let segment = &header.members[0].segments[0];
    let frontier = (segment.data_offset + segment.data_size / 2) as usize;
    let mut expected = Vec::new();
    reference
        .by_index(0)
        .unwrap()
        .copy_to(&mut expected)
        .unwrap();
    assert!(
        expected.len() > 8 * 1024 * 1024,
        "fixture must exceed decoder output buffering"
    );
    let input = Arc::new(Input {
        bytes: bytes.into(),
        available: Mutex::new(frontier),
        changed: Condvar::new(),
    });
    let provider = Provider(vec![Arc::clone(&input)]);
    let reader = UnknownLength(Reader {
        input: Arc::clone(&input),
        position: 0,
    });
    let (output_tx, output_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut archive =
            RarArchive::open_prefix(reader, Some(password), NonZeroUsize::MIN).unwrap();
        let mut out = Output {
            bytes: Vec::new(),
            first: Some(output_tx),
        };
        archive
            .by_index_via(0, &provider)
            .unwrap()
            .copy_to(&mut out)
            .unwrap();
        out.bytes
    });
    let early = output_rx.recv_timeout(Duration::from_secs(5));
    input.publish(input.bytes.len());
    let actual = worker.join().unwrap();
    early.expect("decoded output must arrive while half the packed member is unavailable");
    assert_eq!(actual, expected);
}

#[test]
fn rar4_decodes_with_partial_encrypted_payload_and_unknown_length() {
    before_packed_tail("rar4");
}

#[test]
fn rar5_decodes_with_partial_encrypted_payload_and_unknown_length() {
    before_packed_tail("rar5");
}
