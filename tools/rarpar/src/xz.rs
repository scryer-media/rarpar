//! `rarpar xz`: .xz compression, decompression, testing and listing through
//! lzma-turbo.

use std::cell::Cell;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use lzma_turbo::xz::{CheckType, XzError, XzOptions, XzParallelReader, XzReader, stream_table};
use lzma_turbo::{LzmaEncProps, MatchFinderKind, XzErrorKind, XzWriter};
use rarpar::cli::{
    Cli, XzCheck, XzCommand, XzCompressArgs, XzDecodeArgs, XzDecompressArgs, XzListArgs, XzTestArgs,
};
use serde_json::{Value, json};

use crate::error::{EXIT_DATA_FAILURE, EXIT_SUCCESS, RarparError};

const MIB: u64 = 1 << 20;
const IO_BUFFER: usize = 1 << 20;

pub fn run_command(cli: &Cli, command: XzCommand) -> Result<u8, RarparError> {
    if cli.delete_sources {
        return Err(RarparError::Usage(
            "--delete-sources does not apply to xz commands; their input is always kept".into(),
        ));
    }
    // A report never shares standard output with the data written there.
    let data_on_stdout = match &command {
        XzCommand::Compress(args) => {
            is_stdio(&args.input) && args.output.is_none()
                || args.output.as_deref().is_some_and(is_stdio)
        }
        XzCommand::Decompress(args) => {
            is_stdio(&args.input) && args.output.is_none()
                || args.output.as_deref().is_some_and(is_stdio)
        }
        XzCommand::Test(_) | XzCommand::List(_) => false,
    };
    let result = match command {
        XzCommand::Compress(args) => compress(cli, &args),
        XzCommand::Decompress(args) => decompress(cli, &args),
        XzCommand::Test(args) => test(&args),
        XzCommand::List(args) => list(&args),
    };
    match result {
        Ok(report) => {
            emit(cli, &report, data_on_stdout)?;
            Ok(if report["success"] == true {
                EXIT_SUCCESS
            } else {
                EXIT_DATA_FAILURE
            })
        }
        Err(error) => {
            if cli.json {
                let report = json!({"operation":"xz","success":false,
                    "error":error.to_string(),"exit_code":error.exit_code()});
                emit(cli, &report, data_on_stdout)?;
            }
            Err(error)
        }
    }
}

fn is_stdio(path: &Path) -> bool {
    path.as_os_str() == "-"
}

// ---------------------------------------------------------------------------
// Presets

/// The encoder settings of `xz -N` (with `extreme`, `xz -Ne`).
///
/// liblzma numbers its presets differently from the LZMA SDK levels that
/// [`LzmaEncProps::with_level`] takes, so the preset is built from explicit
/// settings: liblzma's dictionary, `lc`/`lp`/`pb`, parser mode, match finder,
/// nice length (fast bytes here) and search depth (match cycles here), with
/// the depth liblzma derives when the preset leaves it at zero. Preset 0's
/// three-byte hash chain has no counterpart in this encoder and gets the
/// four-byte one. lzma-turbo 0.7.0 provides this table as
/// `LzmaEncProps::xz_preset`; rarpar stays on the 0.6 line that sevenz-turbo
/// resolves, so it builds the same table here.
pub(crate) fn xz_preset(level: u32, extreme: bool) -> LzmaEncProps {
    const DICT_POW2: [u8; 10] = [18, 20, 21, 22, 22, 23, 23, 24, 25, 26];
    const FAST_DEPTH: [u32; 4] = [4, 8, 24, 48];
    let level = level.min(9);
    let (fast, kind, fast_bytes, cycles) = if extreme {
        if level == 3 || level == 5 {
            (false, MatchFinderKind::Bt4, 192, 16 + 192 / 2)
        } else {
            (false, MatchFinderKind::Bt4, 273, 512)
        }
    } else if level <= 3 {
        let fast_bytes = if level <= 1 { 128 } else { 273 };
        (
            true,
            MatchFinderKind::Hc4,
            fast_bytes,
            FAST_DEPTH[level as usize],
        )
    } else {
        let fast_bytes = match level {
            4 => 16,
            5 => 32,
            _ => 64,
        };
        // A binary tree's depth defaults to `16 + nice_len / 2`.
        (false, MatchFinderKind::Bt4, fast_bytes, 16 + fast_bytes / 2)
    };
    LzmaEncProps::new()
        .with_level(level)
        .with_dict_size(1u32 << DICT_POW2[level as usize])
        .with_lclppb(3, 0, 2)
        .with_fast_mode(fast)
        .with_match_finder(kind)
        .with_fast_bytes(fast_bytes)
        .with_match_cycles(cycles)
}

/// The dictionary size of a preset.
pub(crate) fn preset_dict_size(level: u32) -> u64 {
    const DICT_POW2: [u8; 10] = [18, 20, 21, 22, 22, 23, 23, 24, 25, 26];
    1u64 << DICT_POW2[level.min(9) as usize]
}

/// xz's threaded block size: three dictionaries, at least 1 MiB.
pub(crate) fn default_block_size(level: u32) -> u64 {
    (preset_dict_size(level) * 3).max(MIB)
}

/// What one block thread is estimated to hold: its encoder's match finder and
/// state, the block's input, and the block's compressed output.
fn per_thread_bytes(level: u32, extreme: bool, block_size: u64) -> u64 {
    let dict = preset_dict_size(level);
    let hash_chain = !extreme && level <= 3;
    let encoder = if hash_chain {
        dict * 15 / 2
    } else {
        dict * 23 / 2
    } + 4 * MIB;
    encoder.saturating_add(block_size.saturating_mul(2))
}

fn check_type(check: XzCheck) -> CheckType {
    match check {
        XzCheck::None => CheckType::None,
        XzCheck::Crc32 => CheckType::Crc32,
        XzCheck::Crc64 => CheckType::Crc64,
        XzCheck::Sha256 => CheckType::Sha256,
    }
}

fn check_name(check: CheckType) -> String {
    match check {
        CheckType::None => "none".into(),
        CheckType::Crc32 => "crc32".into(),
        CheckType::Crc64 => "crc64".into(),
        CheckType::Sha256 => "sha256".into(),
        CheckType::Reserved(id) => format!("unknown-{id}"),
    }
}

fn available_threads() -> u32 {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(256) as u32)
}

// ---------------------------------------------------------------------------
// Paths

/// Where the output of `input` goes when OUTPUT is absent or a directory.
fn resolve_output(
    cli: &Cli,
    input: &Path,
    output: Option<&Path>,
    default_name: impl FnOnce(&Path) -> Result<PathBuf, RarparError>,
) -> Result<Option<PathBuf>, RarparError> {
    match output {
        Some(path) if is_stdio(path) => Ok(None),
        Some(path) if !path.is_dir() => Ok(Some(path.to_path_buf())),
        Some(directory) => {
            if is_stdio(input) {
                return Err(RarparError::Usage(
                    "standard input has no name; give OUTPUT as a file path".into(),
                ));
            }
            Ok(Some(directory.join(default_name(input)?)))
        }
        None if is_stdio(input) => Ok(None),
        None => {
            let name = default_name(input)?;
            let directory = match &cli.output {
                Some(directory) => directory.clone(),
                None => input.parent().map(Path::to_path_buf).unwrap_or_default(),
            };
            Ok(Some(directory.join(name)))
        }
    }
}

fn compressed_name(input: &Path) -> Result<PathBuf, RarparError> {
    let name = input
        .file_name()
        .ok_or_else(|| RarparError::Usage(format!("not a file name: {}", input.display())))?;
    if has_xz_suffix(input) {
        return Err(RarparError::Usage(format!(
            "{} already has an .xz suffix; give OUTPUT to compress it again",
            input.display()
        )));
    }
    let mut name = name.to_os_string();
    name.push(".xz");
    Ok(PathBuf::from(name))
}

fn has_xz_suffix(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("xz") || extension.eq_ignore_ascii_case("txz")
    })
}

fn decompressed_name(input: &Path) -> Result<PathBuf, RarparError> {
    let stem = input.file_stem().filter(|stem| !stem.is_empty());
    match (input.extension(), stem) {
        (Some(extension), Some(stem)) if extension.eq_ignore_ascii_case("xz") => {
            Ok(PathBuf::from(stem))
        }
        (Some(extension), Some(stem)) if extension.eq_ignore_ascii_case("txz") => {
            let mut name = stem.to_os_string();
            name.push(".tar");
            Ok(PathBuf::from(name))
        }
        _ => Err(RarparError::Usage(format!(
            "{} has no .xz or .txz suffix; give OUTPUT",
            input.display()
        ))),
    }
}

/// Refuses an output that exists (without --overwrite) or is the input.
fn preflight_output(cli: &Cli, input: &Path, output: &Path) -> Result<(), RarparError> {
    if !output.exists() {
        return Ok(());
    }
    if !is_stdio(input) && same_file(input, output)? {
        return Err(RarparError::Unsafe(format!(
            "output is the input: {}",
            output.display()
        )));
    }
    if !cli.overwrite {
        return Err(RarparError::Unsafe(format!(
            "output exists; pass --overwrite to replace: {}",
            output.display()
        )));
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> Result<bool, RarparError> {
    Ok(a.canonicalize()? == b.canonicalize()?)
}

fn open_input(path: &Path) -> Result<File, RarparError> {
    if !path.exists() {
        return Err(RarparError::MissingInput(path.to_path_buf()));
    }
    if path.is_dir() {
        return Err(RarparError::Usage(format!(
            "input is a directory: {}",
            path.display()
        )));
    }
    Ok(File::open(path)?)
}

/// An output file staged beside its destination and installed whole.
struct Staged {
    file: tempfile::NamedTempFile,
    destination: PathBuf,
}

impl Staged {
    fn create(destination: &Path) -> Result<Self, RarparError> {
        let directory = match destination.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        std::fs::create_dir_all(&directory)?;
        let mut builder = tempfile::Builder::new();
        builder.prefix(".rarpar-xz-");
        // The output is an ordinary file, not a private temporary.
        #[cfg(unix)]
        builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o666));
        Ok(Self {
            file: builder.tempfile_in(&directory)?,
            destination: destination.to_path_buf(),
        })
    }

    /// Copies the input's permissions and times, then installs the file.
    fn install(self, cli: &Cli, input: Option<&std::fs::Metadata>) -> Result<(), RarparError> {
        if let Some(meta) = input {
            self.file
                .as_file()
                .set_permissions(meta.permissions())
                .or_else(|error| match error.kind() {
                    io::ErrorKind::PermissionDenied => Ok(()),
                    _ => Err(error),
                })?;
            let modified = filetime::FileTime::from_last_modification_time(meta);
            let accessed = filetime::FileTime::from_last_access_time(meta);
            filetime::set_file_handle_times(self.file.as_file(), Some(accessed), Some(modified))?;
        }
        let destination = self.destination;
        if cli.overwrite {
            self.file.persist(&destination)
        } else {
            self.file.persist_noclobber(&destination)
        }
        .map_err(|error| match error.error.kind() {
            io::ErrorKind::AlreadyExists if !cli.overwrite => RarparError::Unsafe(format!(
                "output exists; pass --overwrite to replace: {}",
                destination.display()
            )),
            _ => RarparError::Io(error.error),
        })?;
        Ok(())
    }
}

/// Counts the bytes that pass through a reader.
struct Counting<R> {
    inner: R,
    count: u64,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

/// Counts the bytes that pass through a writer.
struct CountingWriter<W> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Errors

/// Classifies a codec failure that reached us as an I/O error.
fn codec_error(error: io::Error) -> RarparError {
    if let Some(xz) = error.get_ref().and_then(|e| e.downcast_ref::<XzError>()) {
        return match xz.kind {
            XzErrorKind::MemoryLimit { needed, limit } => RarparError::Resource(format!(
                "the stream needs {} MiB of memory and --memory-mib allows {} MiB ({xz})",
                needed.div_ceil(MIB),
                limit / MIB
            )),
            _ => RarparError::Data(xz.to_string()),
        };
    }
    if let Some(codec) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<lzma_turbo::Error>())
    {
        return match codec {
            lzma_turbo::Error::Alloc => {
                RarparError::Resource("the encoder could not allocate its state".into())
            }
            lzma_turbo::Error::Param => {
                RarparError::Usage("the encoder refused these settings".into())
            }
            other => RarparError::Data(other.to_string()),
        };
    }
    RarparError::Io(error)
}

// ---------------------------------------------------------------------------
// compress

fn compress(cli: &Cli, args: &XzCompressArgs) -> Result<Value, RarparError> {
    let output = resolve_output(cli, &args.input, args.output.as_deref(), compressed_name)?;
    let block_size = args
        .block_size
        .unwrap_or_else(|| default_block_size(args.level));
    let requested = args.threads.unwrap_or_else(available_threads);
    let per_thread = per_thread_bytes(args.level, args.extreme, block_size);
    let threads = match args.memory_mib {
        None => requested,
        Some(mib) => {
            let limit = mib.saturating_mul(MIB);
            let affordable = limit.saturating_sub(block_size) / per_thread.max(1);
            if affordable == 0 {
                return Err(RarparError::Resource(format!(
                    "level {}{} with {block_size}-byte blocks needs about {} MiB; --memory-mib is {mib}",
                    args.level,
                    if args.extreme { " --extreme" } else { "" },
                    (per_thread + block_size).div_ceil(MIB)
                )));
            }
            requested.min(u32::try_from(affordable).unwrap_or(u32::MAX))
        }
    };
    let input_meta = if is_stdio(&args.input) {
        None
    } else {
        Some(open_input(&args.input)?.metadata()?)
    };
    // Threads beyond the number of blocks the input fills would idle.
    let threads = match &input_meta {
        Some(meta) => {
            threads.min(u32::try_from(meta.len().div_ceil(block_size).max(1)).unwrap_or(u32::MAX))
        }
        None => threads,
    };
    let memory_estimate = per_thread
        .saturating_mul(u64::from(threads))
        .saturating_add(block_size);
    if let Some(output) = &output {
        preflight_output(cli, &args.input, output)?;
    } else if io::stdout().is_terminal() {
        return Err(RarparError::Usage(
            "compressed data is not written to a terminal; give OUTPUT or redirect".into(),
        ));
    }
    let mut report = json!({"operation":"xz_compress","success":true,"dry_run":cli.dry_run,
        "input":display(&args.input),"output":output.as_deref().map_or("-".into(), display),
        "level":args.level,"extreme":args.extreme,"check":check_name(check_type(args.check)),
        "block_size":block_size,"threads":threads,"memory_estimate_bytes":memory_estimate});
    if cli.dry_run {
        return Ok(report);
    }

    let props = xz_preset(args.level, args.extreme);
    let source: Box<dyn Read> = if is_stdio(&args.input) {
        Box::new(io::stdin().lock())
    } else {
        Box::new(open_input(&args.input)?)
    };
    let mut source = Counting {
        inner: BufReader::with_capacity(IO_BUFFER, source),
        count: 0,
    };
    let encode = |sink: &mut dyn Write, source: &mut dyn Read| -> Result<u64, RarparError> {
        let mut counter = CountingWriter {
            inner: sink,
            count: 0,
        };
        let mut writer = XzWriter::new(&mut counter, &props)
            .map_err(|error| codec_error(io::Error::other(error)))?;
        writer
            .set_check(check_type(args.check))
            .map_err(|error| codec_error(io::Error::other(error)))?;
        writer.set_block_size(block_size);
        writer.set_threads(threads as usize);
        io::copy(source, &mut writer).map_err(codec_error)?;
        writer.finish().map_err(codec_error)?;
        Ok(counter.count)
    };
    let written = match &output {
        None => {
            let stdout = io::stdout();
            let mut sink = BufWriter::with_capacity(IO_BUFFER, stdout.lock());
            let written = encode(&mut sink, &mut source)?;
            sink.flush()?;
            written
        }
        Some(path) => {
            let staged = Staged::create(path)?;
            let written = {
                let mut sink = BufWriter::with_capacity(IO_BUFFER, staged.file.as_file());
                let written = encode(&mut sink, &mut source)?;
                sink.flush()?;
                written
            };
            staged.install(cli, input_meta.as_ref())?;
            written
        }
    };
    report["input_bytes"] = json!(source.count);
    report["output_bytes"] = json!(written);
    report["ratio"] = json!(ratio(written, source.count));
    Ok(report)
}

fn ratio(compressed: u64, uncompressed: u64) -> Value {
    if uncompressed == 0 {
        Value::Null
    } else {
        json!((compressed as f64 / uncompressed as f64 * 1000.0).round() / 1000.0)
    }
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

// ---------------------------------------------------------------------------
// decompress / test

/// A decode of one input: the reader, how it was chosen, and its input size.
struct Decode {
    reader: Box<dyn Read>,
    decoder: &'static str,
    threads: usize,
    blocks: Option<usize>,
    compressed: Compressed,
}

/// The compressed size: a file's length, or what was read from a pipe.
enum Compressed {
    Known(u64),
    Consumed(Rc<Cell<u64>>),
}

impl Compressed {
    fn bytes(&self) -> u64 {
        match self {
            Self::Known(bytes) => *bytes,
            Self::Consumed(count) => count.get(),
        }
    }
}

/// Counts what a reader it no longer owns has read.
struct Tally<R> {
    inner: R,
    count: Rc<Cell<u64>>,
}

impl<R: Read> Read for Tally<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.set(self.count.get() + n as u64);
        Ok(n)
    }
}

fn decode_options(args: &XzDecodeArgs, threads: usize) -> XzOptions {
    XzOptions::default()
        .with_threads(threads)
        .with_memory_limit(args.memory_mib.saturating_mul(MIB))
}

/// Opens `input` for decoding: in parallel when it is a seekable file with
/// more than one block and more than one thread is allowed, otherwise in one
/// sequential pass. A file the parallel reader cannot map is decoded
/// sequentially, which is the authoritative validator of its structure.
fn open_decode(input: &Path, args: &XzDecodeArgs) -> Result<Decode, RarparError> {
    let threads = args.threads.unwrap_or_else(available_threads) as usize;
    if is_stdio(input) {
        let consumed = Rc::new(Cell::new(0));
        let source = Tally {
            inner: io::stdin().lock(),
            count: Rc::clone(&consumed),
        };
        let reader = XzReader::with_options(
            BufReader::with_capacity(IO_BUFFER, source),
            decode_options(args, 1),
        );
        return Ok(Decode {
            reader: Box::new(reader),
            decoder: "sequential",
            threads: 1,
            blocks: None,
            compressed: Compressed::Consumed(consumed),
        });
    }
    let file = open_input(input)?;
    let compressed = file.metadata()?.len();
    if threads > 1 {
        match XzParallelReader::with_options(file.try_clone()?, decode_options(args, threads)) {
            Ok(reader) if reader.block_count() > 1 => {
                let (threads, blocks) = (reader.threads(), reader.block_count());
                return Ok(Decode {
                    reader: Box::new(reader),
                    decoder: "parallel",
                    threads,
                    blocks: Some(blocks),
                    compressed: Compressed::Known(compressed),
                });
            }
            Ok(_) | Err(_) => {}
        }
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0))?;
    let reader = XzReader::with_options(
        BufReader::with_capacity(IO_BUFFER, file),
        decode_options(args, 1),
    );
    Ok(Decode {
        reader: Box::new(reader),
        decoder: "sequential",
        threads: 1,
        blocks: None,
        compressed: Compressed::Known(compressed),
    })
}

fn decompress(cli: &Cli, args: &XzDecompressArgs) -> Result<Value, RarparError> {
    let output = resolve_output(cli, &args.input, args.output.as_deref(), decompressed_name)?;
    if let Some(output) = &output {
        preflight_output(cli, &args.input, output)?;
    }
    let input_meta = if is_stdio(&args.input) {
        None
    } else {
        Some(open_input(&args.input)?.metadata()?)
    };
    let mut report = json!({"operation":"xz_decompress","success":true,"dry_run":cli.dry_run,
        "input":display(&args.input),"output":output.as_deref().map_or("-".into(), display)});
    if cli.dry_run {
        return Ok(report);
    }
    let mut decode = open_decode(&args.input, &args.decode)?;
    let written = match &output {
        None => {
            let stdout = io::stdout();
            let mut sink = BufWriter::with_capacity(IO_BUFFER, stdout.lock());
            let written = io::copy(&mut decode.reader, &mut sink).map_err(codec_error)?;
            sink.flush()?;
            written
        }
        Some(path) => {
            let staged = Staged::create(path)?;
            let written = {
                let mut sink = BufWriter::with_capacity(IO_BUFFER, staged.file.as_file());
                let written = io::copy(&mut decode.reader, &mut sink).map_err(codec_error)?;
                sink.flush()?;
                written
            };
            staged.install(cli, input_meta.as_ref())?;
            written
        }
    };
    report["input_bytes"] = json!(decode.compressed.bytes());
    report["output_bytes"] = json!(written);
    report["decoder"] = json!(decode.decoder);
    report["threads"] = json!(decode.threads);
    report["blocks"] = json!(decode.blocks);
    Ok(report)
}

fn test(args: &XzTestArgs) -> Result<Value, RarparError> {
    let mut decode = open_decode(&args.input, &args.decode)?;
    let decoded = io::copy(&mut decode.reader, &mut io::sink()).map_err(codec_error)?;
    Ok(
        json!({"operation":"xz_test","success":true,"status":"ok","input":display(&args.input),
        "input_bytes":decode.compressed.bytes(),"output_bytes":decoded,"decoder":decode.decoder,
        "threads":decode.threads,"blocks":decode.blocks}),
    )
}

// ---------------------------------------------------------------------------
// list

fn list(args: &XzListArgs) -> Result<Value, RarparError> {
    if is_stdio(&args.input) {
        return Err(RarparError::Usage(
            "xz list reads the index from the end of the file; standard input is not seekable"
                .into(),
        ));
    }
    let mut file = open_input(&args.input)?;
    let file_bytes = file.metadata()?.len();
    let streams = stream_table(&mut file, u64::MAX).map_err(|error| codec_error(error.into()))?;
    let mut rows = Vec::with_capacity(streams.len());
    let (mut blocks_total, mut uncompressed_total) = (0usize, 0u64);
    let mut checks: Vec<String> = Vec::new();
    for (index, stream) in streams.iter().enumerate() {
        let end = stream.stream_offset + stream.stream_size;
        let next = streams
            .get(index + 1)
            .map_or(file_bytes, |next| next.stream_offset);
        let blocks = stream.index.blocks(stream.stream_offset).ok_or_else(|| {
            RarparError::Data(format!("stream {index}: the index sizes overflow"))
        })?;
        let uncompressed = stream.index.uncompressed_size().ok_or_else(|| {
            RarparError::Data(format!("stream {index}: the index sizes overflow"))
        })?;
        let check = check_name(stream.header.flags.check);
        if !checks.contains(&check) {
            checks.push(check.clone());
        }
        blocks_total += blocks.len();
        uncompressed_total = uncompressed_total.saturating_add(uncompressed);
        let block_rows: Vec<Value> = blocks
            .iter()
            .enumerate()
            .map(|(number, block)| {
                json!({"index":number,"offset":block.file_offset,
                    "uncompressed_offset":block.uncompressed_offset,
                    "compressed_bytes":block.record.unpadded_size,
                    "uncompressed_bytes":block.record.uncompressed_size,
                    "ratio":ratio(block.record.unpadded_size, block.record.uncompressed_size)})
            })
            .collect();
        rows.push(json!({"index":index,"offset":stream.stream_offset,
            "compressed_bytes":stream.stream_size,"uncompressed_bytes":uncompressed,
            "padding_bytes":next - end,"check":check,"block_count":blocks.len(),
            "ratio":ratio(stream.stream_size, uncompressed),"blocks":block_rows}));
    }
    Ok(
        json!({"operation":"xz_list","success":true,"input":display(&args.input),
        "compressed_bytes":file_bytes,"uncompressed_bytes":uncompressed_total,
        "ratio":ratio(file_bytes, uncompressed_total),"stream_count":streams.len(),
        "block_count":blocks_total,"checks":checks,"streams":rows}),
    )
}

// ---------------------------------------------------------------------------
// Reports

fn emit(cli: &Cli, report: &Value, data_on_stdout: bool) -> Result<(), RarparError> {
    let mut out: Box<dyn Write> = if data_on_stdout {
        Box::new(io::stderr().lock())
    } else {
        Box::new(io::stdout().lock())
    };
    if cli.json {
        writeln!(out, "{}", serde_json::to_string_pretty(report)?)?;
        return Ok(());
    }
    if cli.quiet || report["success"] != true {
        return Ok(());
    }
    let dry = if report["dry_run"] == true {
        " (dry run)"
    } else {
        ""
    };
    let operation = report["operation"].as_str().unwrap_or("xz");
    match operation {
        "xz_compress" | "xz_decompress" => {
            writeln!(
                out,
                "{operation}: {} -> {}{dry}",
                report["input"].as_str().unwrap_or_default(),
                report["output"].as_str().unwrap_or_default()
            )?;
            if report["dry_run"] != true {
                writeln!(
                    out,
                    "  {} bytes in, {} bytes out{}",
                    report["input_bytes"],
                    report["output_bytes"],
                    match report["ratio"].as_f64() {
                        Some(ratio) => format!(", ratio {ratio:.3}"),
                        None => String::new(),
                    }
                )?;
            }
        }
        "xz_test" => writeln!(
            out,
            "xz_test: {} ok, {} bytes decoded",
            report["input"].as_str().unwrap_or_default(),
            report["output_bytes"]
        )?,
        "xz_list" => {
            writeln!(
                out,
                "{}: {} stream(s), {} block(s), check {}",
                report["input"].as_str().unwrap_or_default(),
                report["stream_count"],
                report["block_count"],
                report["checks"]
                    .as_array()
                    .map(|checks| checks
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","))
                    .unwrap_or_default()
            )?;
            writeln!(
                out,
                "  {} bytes compressed, {} bytes uncompressed{}",
                report["compressed_bytes"],
                report["uncompressed_bytes"],
                match report["ratio"].as_f64() {
                    Some(ratio) => format!(", ratio {ratio:.3}"),
                    None => String::new(),
                }
            )?;
            for stream in report["streams"].as_array().into_iter().flatten() {
                writeln!(
                    out,
                    "  stream {}: offset {}, {} block(s), {} -> {} bytes, check {}, padding {}",
                    stream["index"],
                    stream["offset"],
                    stream["block_count"],
                    stream["compressed_bytes"],
                    stream["uncompressed_bytes"],
                    stream["check"].as_str().unwrap_or_default(),
                    stream["padding_bytes"]
                )?;
                for block in stream["blocks"].as_array().into_iter().flatten() {
                    writeln!(
                        out,
                        "    block {}: offset {}, {} -> {} bytes",
                        block["index"],
                        block["offset"],
                        block["compressed_bytes"],
                        block["uncompressed_bytes"]
                    )?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_follow_liblzma_dictionaries() {
        let mib = |n: u64| n * MIB;
        let expected = [
            256 << 10,
            mib(1),
            mib(2),
            mib(4),
            mib(4),
            mib(8),
            mib(8),
            mib(16),
            mib(32),
            mib(64),
        ];
        for (level, dict) in expected.into_iter().enumerate() {
            assert_eq!(preset_dict_size(level as u32), dict, "level {level}");
            assert_eq!(
                u64::from(xz_preset(level as u32, false).dict_size()),
                dict,
                "level {level}"
            );
            assert_eq!(
                u64::from(xz_preset(level as u32, true).dict_size()),
                dict,
                "level {level} extreme"
            );
        }
    }

    #[test]
    fn default_block_size_is_three_dictionaries_at_least_one_mebibyte() {
        assert_eq!(default_block_size(0), MIB);
        assert_eq!(default_block_size(1), 3 * MIB);
        assert_eq!(default_block_size(6), 24 * MIB);
        assert_eq!(default_block_size(9), 192 * MIB);
    }

    #[test]
    fn default_names_follow_the_suffix() {
        assert_eq!(
            compressed_name(Path::new("dir/data.tar")).unwrap(),
            PathBuf::from("data.tar.xz")
        );
        assert!(compressed_name(Path::new("data.tar.xz")).is_err());
        assert_eq!(
            decompressed_name(Path::new("dir/data.tar.xz")).unwrap(),
            PathBuf::from("data.tar")
        );
        assert_eq!(
            decompressed_name(Path::new("data.TXZ")).unwrap(),
            PathBuf::from("data.tar")
        );
        assert!(decompressed_name(Path::new("data.bin")).is_err());
        assert!(decompressed_name(Path::new(".xz")).is_err());
    }
}
