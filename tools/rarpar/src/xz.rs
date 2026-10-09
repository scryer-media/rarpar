//! `rarpar xz`: .xz compression, decompression, testing and listing through
//! lzma-turbo.

use std::cell::Cell;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use lzma_turbo::xz::{
    CheckType, StreamHeader, XzError, XzOptions, XzParallelReader, XzReader, stream_table,
};
use lzma_turbo::{Checksum, ChecksumPlan, LzmaEncProps, MatchFinderKind, XzErrorKind, XzWriter};
use rarpar::cli::{
    Cli, SidecarArgs, XzCheck, XzCommand, XzCompressArgs, XzDecodeArgs, XzDecompressArgs,
    XzListArgs, XzTestArgs,
};
use serde_json::{Value, json};

use crate::error::{EXIT_DATA_FAILURE, EXIT_SUCCESS, RarparError};
use crate::sidecar::{self, SidecarPlan, SidecarWriter};
use crate::streams::{
    CountingWriter, IO_BUFFER, Input, Tally, input_or_stdin, is_stdio, preflight_output,
    refuse_terminal_stdout, regular_file_metadata, report_writer, resolve_output, write_output,
};

const MIB: u64 = 1 << 20;
const STREAM_HEADER_SIZE: usize = 12;

pub fn run_command(cli: &Cli, command: XzCommand) -> Result<u8, RarparError> {
    if cli.delete_sources {
        return Err(RarparError::Usage(
            "--delete-sources does not apply to xz commands; their input is always kept".into(),
        ));
    }
    // A report never shares standard output with the data written there.
    let (input, data_on_stdout) = match &command {
        XzCommand::Compress(XzCompressArgs { input, output, .. })
        | XzCommand::Decompress(XzDecompressArgs { input, output, .. }) => {
            let input = input_or_stdin(input.as_deref())?;
            let on_stdout = output.as_deref().map_or_else(|| is_stdio(&input), is_stdio);
            (input, on_stdout)
        }
        XzCommand::Test(XzTestArgs { input, .. }) | XzCommand::List(XzListArgs { input, .. }) => {
            (input_or_stdin(input.as_deref())?, false)
        }
    };
    let result = match command {
        XzCommand::Compress(args) => compress(cli, &input, &args),
        XzCommand::Decompress(args) => decompress(cli, &input, &args),
        XzCommand::Test(args) => test(&input, &args.decode),
        XzCommand::List(args) => list(&input, &args),
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
        // With --json the failure report is the whole output: returning the
        // error as well would add a plain-text line after it, on standard
        // error too when the data holds standard output.
        Err(error) if cli.json => {
            let report = json!({"operation":"xz","success":false,
                "error":error.to_string(),"exit_code":error.exit_code()});
            emit(cli, &report, data_on_stdout)?;
            Ok(error.exit_code())
        }
        Err(error) => Err(error),
    }
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
/// state for a `dict`-byte dictionary, the block's input, and the block's
/// compressed output.
fn per_thread_bytes(dict: u64, hash_chain: bool, block_size: u64) -> u64 {
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

fn compress(cli: &Cli, input: &Path, args: &XzCompressArgs) -> Result<Value, RarparError> {
    let output = resolve_output(cli, input, args.output.as_deref(), compressed_name)?;
    let block_size = args
        .block_size
        .unwrap_or_else(|| default_block_size(args.level));
    let input_meta = regular_file_metadata(input)?;
    // A block never holds more than this, so a larger dictionary would only
    // cost memory: the encoder shrinks it to fit, as 7-Zip's does.
    let largest_block = input_meta
        .as_ref()
        .map_or(block_size, |meta| meta.len().min(block_size));
    let props = xz_preset(args.level, args.extreme).with_reduce_size(largest_block);
    let per_thread = per_thread_bytes(
        u64::from(props.dict_size()),
        !args.extreme && args.level <= 3,
        largest_block,
    );
    let mut threads = args.threads.unwrap_or_else(available_threads);
    // Threads beyond the number of blocks the input fills would idle.
    if let Some(meta) = &input_meta {
        let blocks = meta.len().div_ceil(block_size).max(1);
        threads = threads.min(u32::try_from(blocks).unwrap_or(u32::MAX));
    }
    if let Some(mib) = args.memory_mib {
        let limit = mib.saturating_mul(MIB);
        let affordable = limit.saturating_sub(largest_block) / per_thread.max(1);
        if affordable == 0 {
            return Err(RarparError::Resource(format!(
                "level {}{} with {block_size}-byte blocks needs about {} MiB; --memory-mib is {mib}",
                args.level,
                if args.extreme { " --extreme" } else { "" },
                (per_thread + largest_block).div_ceil(MIB)
            )));
        }
        threads = threads.min(u32::try_from(affordable).unwrap_or(u32::MAX));
    }
    let memory_estimate = per_thread
        .saturating_mul(u64::from(threads))
        .saturating_add(largest_block);
    match &output {
        Some(output) => preflight_output(cli, input, output)?,
        None => refuse_terminal_stdout("compressed data")?,
    }
    let sidecar = sidecar_target(cli, output.as_deref(), &args.sidecar)?;
    let memory_estimate = memory_estimate.saturating_add(
        sidecar
            .as_ref()
            .map_or(0, |(plan, _, _)| plan.memory_estimate()),
    );
    let mut report = json!({"operation":"xz_compress","success":true,"dry_run":cli.dry_run,
        "input":display(input),"output":output.as_deref().map_or("-".into(), display),
        "level":args.level,"extreme":args.extreme,"check":check_name(check_type(args.check)),
        "block_size":block_size,"dictionary_bytes":props.dict_size(),"threads":threads,
        "memory_estimate_bytes":memory_estimate});
    if let Some((plan, name, stem)) = &sidecar {
        report["sidecar"] = json!({"format":sidecar::format_name(plan.format),"name":name,
            "block_size":plan.block_size,"recovery_blocks":plan.rows,
            "outputs":plan.paths(stem)});
    }
    if cli.dry_run {
        return Ok(report);
    }

    let (source, consumed) = Tally::new(Input::open(input)?.into_reader());
    let mut source = BufReader::with_capacity(IO_BUFFER, source);
    let mut set = sidecar
        .as_ref()
        .map(|(plan, _, _)| plan.start())
        .transpose()?;
    let written = write_output(
        cli,
        output.as_deref(),
        input_meta.as_ref(),
        ".rarpar-xz-",
        |sink| {
            let sink: Box<dyn Write + '_> = match set.as_mut() {
                Some(sidecar) => Box::new(SidecarWriter {
                    inner: sink,
                    sidecar,
                }),
                None => Box::new(sink),
            };
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
            io::copy(&mut source, &mut writer).map_err(codec_error)?;
            writer.finish().map_err(codec_error)?;
            Ok(counter.count)
        },
    )?;
    let consumed = consumed.get();
    report["input_bytes"] = json!(consumed);
    report["output_bytes"] = json!(written);
    report["ratio"] = json!(ratio(written, consumed));
    if let (Some(set), Some((_, name, stem))) = (set, &sidecar) {
        // The archive is installed; its set follows it, staged then renamed
        // like the archive.
        if let Some(directory) = stem
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(directory)?;
        }
        let finished = set.finish(
            name,
            stem,
            cli.overwrite,
            crate::par3_stream::Durability::Sync,
        )?;
        let mut summary = finished.report.clone();
        let (outputs, sizes) = finished.install()?;
        summary["name"] = json!(name);
        summary["outputs"] = json!(outputs);
        summary["output_sizes"] = json!(sizes);
        report["sidecar"] = summary;
    }
    Ok(report)
}

/// The sidecar set `--sidecar` asks for: its plan, the name it records and
/// the stem its files are named by. A file output names both; standard
/// output has no name, so `--sidecar-name` gives the one the operator will
/// save it under. Every file the set will be written to is checked now,
/// before a byte is read.
fn sidecar_target(
    cli: &Cli,
    output: Option<&Path>,
    args: &SidecarArgs,
) -> Result<Option<(SidecarPlan, String, PathBuf)>, RarparError> {
    let Some(plan) = sidecar::plan_from_args(args)? else {
        return Ok(None);
    };
    let stem = match (output, &args.sidecar_name) {
        (Some(_), Some(_)) => {
            return Err(RarparError::Usage(
                "--sidecar-name is for standard output; a file output names its own set".into(),
            ));
        }
        (Some(output), None) => output.to_path_buf(),
        (None, Some(name)) => cli.place_output(Path::new(name)),
        (None, None) => {
            return Err(RarparError::Usage(
                "--sidecar on standard output needs --sidecar-name: the set records the name the output will be saved under".into(),
            ));
        }
    };
    let name = stem
        .file_name()
        .filter(|name| !is_stdio(Path::new(name)))
        .ok_or_else(|| {
            RarparError::Usage(format!(
                "--sidecar-name must name a file, not {}",
                stem.display()
            ))
        })?
        // The set records the name as UTF-8 and is named after it, so a
        // name that is not UTF-8 would give a set for a different path.
        .to_str()
        .ok_or_else(|| {
            RarparError::Usage(format!(
                "a sidecar set records its file's name as UTF-8; {} is not",
                stem.display()
            ))
        })?
        .to_owned();
    // An output named like its own set's index (`archive.par2` with a PAR2
    // set) would have the set installed over it, as `par3 archive` refuses.
    if let Some(alias) = plan.paths(&stem).into_iter().find(|path| {
        path.file_name()
            .zip(stem.file_name())
            .is_some_and(|(set, output)| set.eq_ignore_ascii_case(output))
    }) {
        return Err(RarparError::Usage(format!(
            "the output and its {} set would both be written to {}; give the output a name that does not end in .{}",
            sidecar::format_name(plan.format),
            alias.display(),
            sidecar::format_name(plan.format)
        )));
    }
    crate::par3::reject_symlinks(&stem)?;
    sidecar::preflight_set(cli, &plan, &stem)?;
    plan.check_budget(cli.par3_memory_mib)?;
    Ok(Some((plan, name, stem)))
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

fn decode_options(args: &XzDecodeArgs, threads: usize) -> XzOptions {
    XzOptions::default()
        .with_threads(threads)
        .with_memory_limit(args.memory_mib.saturating_mul(MIB))
}

/// Opens `input` for decoding.
///
/// A regular file with more than one block is decoded by the parallel reader,
/// which maps every block from the index first; one it cannot map is decoded
/// sequentially, which is the authoritative validator of its structure. A
/// stream (standard input, a pipe, a device) is read forward only: on several
/// threads, blocks whose headers declare their sizes go to workers as soon as
/// they have arrived; on one, in a single sequential pass.
fn open_decode(input: &Path, args: &XzDecodeArgs) -> Result<Decode, RarparError> {
    let threads = args.threads.unwrap_or_else(available_threads) as usize;
    let file = match Input::open(input)? {
        Input::File { file, .. } => file,
        Input::Stream(inner) => {
            let (source, consumed) = Tally::new(inner);
            let (reader, decoder): (Box<dyn Read>, _) = if threads > 1 {
                (
                    Box::new(StreamDecoder::new(source, decode_options(args, threads))),
                    "stream-parallel",
                )
            } else {
                (
                    Box::new(XzReader::with_options(
                        BufReader::with_capacity(IO_BUFFER, source),
                        decode_options(args, 1),
                    )),
                    "sequential",
                )
            };
            return Ok(Decode {
                reader,
                decoder,
                threads,
                blocks: None,
                compressed: Compressed::Consumed(consumed),
            });
        }
    };
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

/// The most compressed input a stream decode reads ahead of the blocks its
/// workers hold, unless the memory limit is lower.
const READ_AHEAD: u64 = 64 * MIB;

/// A `Read` over an .xz stream that arrives forward only, decoded by
/// lzma-turbo's fed decoder.
///
/// Memory is bounded by the decoder's memory limit and by what one `read`
/// asks for, never by the stream's length: input is fed only when the
/// decoder can do nothing more without it, at most [`READ_AHEAD`] beyond
/// what workers hold, and output is drained only as far as the caller reads,
/// so a slow consumer stalls the producer instead of growing a buffer.
struct StreamDecoder<R> {
    source: R,
    decoder: lzma_turbo::XzAdaptiveDecoder,
    input: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    output: Vec<u8>,
    taken: usize,
    finished: bool,
    read_ahead: u64,
}

impl<R: Read> StreamDecoder<R> {
    fn new(source: R, options: XzOptions) -> Self {
        let read_ahead = READ_AHEAD.min(options.memory_limit);
        Self {
            source,
            decoder: lzma_turbo::XzAdaptiveDecoder::new(options),
            input: vec![0; IO_BUFFER],
            start: 0,
            end: 0,
            eof: false,
            output: Vec::new(),
            taken: 0,
            finished: false,
            read_ahead,
        }
    }

    /// Gives the decoder what it needs to make progress: more input, or the
    /// next finished block when enough is already in flight.
    fn advance(&mut self) -> io::Result<()> {
        if self.decoder.in_flight_bytes() >= self.read_ahead && self.decoder.wait_for_worker() {
            return Ok(());
        }
        if self.start == self.end && !self.eof {
            self.start = 0;
            self.end = loop {
                match self.source.read(&mut self.input) {
                    Ok(n) => break n,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            };
            if self.end == 0 {
                self.eof = true;
                self.decoder.end_of_input();
            }
        }
        if self.start < self.end {
            let fed = self
                .decoder
                .feed(&self.input[self.start..self.end])
                .map_err(io::Error::from)?;
            self.start += fed;
            if fed > 0 || self.decoder.wait_for_worker() {
                return Ok(());
            }
            return Err(io::Error::from(XzError::at(
                XzErrorKind::MemoryLimit {
                    needed: self.decoder.in_flight_bytes() + (self.end - self.start) as u64,
                    limit: self.read_ahead,
                },
                0,
                0,
            )));
        }
        if self.decoder.wait_for_worker() {
            return Ok(());
        }
        // All input is in and nothing is outstanding, yet the decoder wants
        // more: the stream stops short.
        Err(io::Error::from(XzError::at(
            XzErrorKind::TruncatedInput,
            0,
            0,
        )))
    }
}

impl<R: Read> Read for StreamDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.taken < self.output.len() {
                let n = buf.len().min(self.output.len() - self.taken);
                buf[..n].copy_from_slice(&self.output[self.taken..self.taken + n]);
                self.taken += n;
                return Ok(n);
            }
            if self.finished {
                return Ok(0);
            }
            self.output.clear();
            self.taken = 0;
            let output = &mut self.output;
            let status = self
                .decoder
                .drain_upto(buf.len(), |_, bytes| output.extend_from_slice(bytes))
                .map_err(io::Error::from)?;
            match status {
                lzma_turbo::DrainStatus::Finished => self.finished = true,
                lzma_turbo::DrainStatus::Progress => {}
                lzma_turbo::DrainStatus::NeedsMoreInput if self.output.is_empty() => {
                    self.advance()?;
                }
                lzma_turbo::DrainStatus::NeedsMoreInput => {}
            }
        }
    }
}

fn decompress(cli: &Cli, input: &Path, args: &XzDecompressArgs) -> Result<Value, RarparError> {
    let output = resolve_output(cli, input, args.output.as_deref(), decompressed_name)?;
    if let Some(output) = &output {
        preflight_output(cli, input, output)?;
    }
    let input_meta = regular_file_metadata(input)?;
    let mut report = json!({"operation":"xz_decompress","success":true,"dry_run":cli.dry_run,
        "input":display(input),"output":output.as_deref().map_or("-".into(), display)});
    if cli.dry_run {
        return Ok(report);
    }
    let mut decode = open_decode(input, &args.decode)?;
    let written = write_output(
        cli,
        output.as_deref(),
        input_meta.as_ref(),
        ".rarpar-xz-",
        |sink| io::copy(&mut decode.reader, sink).map_err(codec_error),
    )?;
    report["input_bytes"] = json!(decode.compressed.bytes());
    report["output_bytes"] = json!(written);
    report["decoder"] = json!(decode.decoder);
    report["threads"] = json!(decode.threads);
    report["blocks"] = json!(decode.blocks);
    Ok(report)
}

fn test(input: &Path, args: &XzDecodeArgs) -> Result<Value, RarparError> {
    let mut decode = open_decode(input, args)?;
    let decoded = io::copy(&mut decode.reader, &mut io::sink()).map_err(codec_error)?;
    Ok(
        json!({"operation":"xz_test","success":true,"status":"ok","input":display(input),
        "input_bytes":decode.compressed.bytes(),"output_bytes":decoded,"decoder":decode.decoder,
        "threads":decode.threads,"blocks":decode.blocks}),
    )
}

// ---------------------------------------------------------------------------
// list

fn list(input: &Path, args: &XzListArgs) -> Result<Value, RarparError> {
    let (mut file, file_bytes) = match Input::open(input)? {
        Input::File { file, meta } => (file, meta.len()),
        Input::Stream(source) => return list_stream(input, source, args),
    };
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
        json!({"operation":"xz_list","success":true,"input":display(input),
        "compressed_bytes":file_bytes,"uncompressed_bytes":uncompressed_total,
        "ratio":ratio(file_bytes, uncompressed_total),"stream_count":streams.len(),
        "block_count":blocks_total,"checks":checks,"streams":rows}),
    )
}

/// Lists a forward-only input by decoding it once: the index that holds each
/// block's compressed size sits after the blocks, and the stream boundaries
/// are only found by decoding up to them.
fn list_stream(
    input: &Path,
    source: Box<dyn Read>,
    args: &XzListArgs,
) -> Result<Value, RarparError> {
    let (mut source, consumed) = Tally::new(BufReader::with_capacity(IO_BUFFER, source));
    let mut head = [0u8; STREAM_HEADER_SIZE];
    source
        .read_exact(&mut head)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => {
                RarparError::Data(XzError::at(XzErrorKind::TruncatedInput, 0, 0).to_string())
            }
            _ => RarparError::Io(error),
        })?;
    let header = StreamHeader::parse(&head)
        .map_err(|kind| RarparError::Data(XzError::at(kind, 0, 0).to_string()))?;
    let options = XzOptions::default()
        .with_threads(1)
        .with_memory_limit(args.memory_mib.saturating_mul(MIB))
        .with_plan(ChecksumPlan::new(Checksum::Crc32));
    let mut reader = XzReader::with_options(io::Cursor::new(head).chain(source), options);
    let decoded = io::copy(&mut reader, &mut io::sink()).map_err(codec_error)?;
    let blocks: Vec<Value> = reader
        .block_checks()
        .iter()
        .enumerate()
        .map(|(index, block)| {
            json!({"index":index,"uncompressed_offset":block.unpacked_offset,
                "uncompressed_bytes":block.len})
        })
        .collect();
    let compressed = consumed.get();
    let check = check_name(header.flags.check);
    // The reader counts a stream once its footer is verified, so at the end
    // of the input its stream index is the number of streams.
    let streams = reader.stream_index();
    Ok(
        json!({"operation":"xz_list","success":true,"input":display(input),"seekable":false,
        "compressed_bytes":compressed,"uncompressed_bytes":decoded,
        "ratio":ratio(compressed, decoded),"stream_count":streams,
        "block_count":blocks.len(),"checks":[check],"blocks":blocks,
        "unknown":["stream offsets, sizes and padding","block offsets and compressed sizes",
            "the checks of streams after the first"]}),
    )
}

// ---------------------------------------------------------------------------
// Reports

fn emit(cli: &Cli, report: &Value, data_on_stdout: bool) -> Result<(), RarparError> {
    let mut out = report_writer(data_on_stdout);
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
            let sidecar = &report["sidecar"];
            if !sidecar.is_null() {
                let files = sidecar["outputs"].as_array().map_or(0, Vec::len);
                writeln!(
                    out,
                    "  sidecar {} for {}: {} recovery block(s) of {} bytes in {files} file(s)",
                    sidecar["format"].as_str().unwrap_or_default(),
                    sidecar["name"].as_str().unwrap_or_default(),
                    sidecar["recovery_blocks"],
                    sidecar["block_size"],
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
            if report["seekable"] == false {
                for block in report["blocks"].as_array().into_iter().flatten() {
                    writeln!(
                        out,
                        "  block {}: uncompressed offset {}, {} bytes",
                        block["index"], block["uncompressed_offset"], block["uncompressed_bytes"]
                    )?;
                }
                let unknown: Vec<&str> = report["unknown"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                writeln!(out, "  read forward once; unknown: {}", unknown.join("; "))?;
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
