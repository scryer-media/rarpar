//! `par3rs` — an example, not a tool.
//!
//! This is a small demonstration of the `par3-rs` API: how to scan `.par3`
//! files into packets, assemble them into a set, and then list, verify, create
//! or repair. It exists so the crate's entry points can be tried from a shell
//! without writing a program first. It is **not** a product, it is **not**
//! official PAR3 tooling, and it is not affiliated with the Parchive project or
//! its reference implementation, `par3cmdline`. Do not use it on data you care
//! about.
//!
//! It uses nothing but the standard library and this crate: the argument
//! parsing below is deliberately crude, because a real front-end would use a
//! real parser and that is not what this file is for.
//!
//! ```text
//! cargo run --example par3rs -- list archive.par3
//! ```

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use par3_rs::create::{CreateOptions, InputSpec, RecoveryAmount, create};
use par3_rs::repair::{RepairOptions, plan_repair, repair_set};
use par3_rs::{Packet, Par3Set, scan_packets_from_path, verify_set};

/// Errors are reported as text: this is an example, not a library.
type Outcome<T> = std::result::Result<T, String>;

const USAGE: &str = "\
par3rs — an example front-end for the par3-rs crate (not official PAR3 tooling)

Usage:
  par3rs create <base> <out.par3> [-s <bytes>] [-c <count> | -r <percent>] <file>...
  par3rs verify <base> <index.par3> [<more.par3>...]
  par3rs repair <base> <index.par3> [<more.par3>...]
  par3rs list   <index.par3> [<more.par3>...]

Options for create:
  -s <bytes>     input block size; without it, the size the reference
                 implementation would suggest for these files is used
  -c <count>     compute exactly this many recovery blocks (default 0)
  -r <percent>   compute this percentage of the input block count instead

Paths:
  <base>         the directory the protected files are named relative to
  <file>...      protected files, each relative to <base>

Exit status:
  0  the command succeeded, and any verification came out complete
  1  the set is not complete: files are missing, damaged, or could not be
     repaired with the recovery blocks on hand
  2  the command could not be carried out at all
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("par3rs: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Outcome<ExitCode> {
    let Some(command) = args.first() else {
        print!("{USAGE}");
        return Ok(ExitCode::from(2));
    };
    let rest = &args[1..];
    match command.as_str() {
        "create" => cmd_create(rest),
        "verify" => cmd_verify(rest),
        "repair" => cmd_repair(rest),
        "list" => cmd_list(rest),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command `{other}`; try `help`")),
    }
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

fn cmd_create(args: &[String]) -> Outcome<ExitCode> {
    if args.len() < 3 {
        return Err("create needs <base> <out.par3> and at least one file".to_string());
    }
    let base = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);

    let mut block_size: Option<u64> = None;
    let mut recovery = RecoveryAmount::default();
    let mut files: Vec<PathBuf> = Vec::new();

    let mut index = 2;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-s" | "-c" | "-r" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("{arg} needs a value"))?;
                match arg {
                    "-s" => block_size = Some(parse_u64(value, "block size")?),
                    "-c" => recovery = RecoveryAmount::Blocks(parse_u64(value, "block count")?),
                    _ => {
                        let percent = parse_u64(value, "percentage")?;
                        let percent = u32::try_from(percent)
                            .map_err(|_| format!("percentage out of range: {percent}"))?;
                        recovery = RecoveryAmount::Percent(percent);
                    }
                }
                index += 2;
            }
            _ => {
                files.push(PathBuf::from(arg));
                index += 1;
            }
        }
    }

    if files.is_empty() {
        return Err("create needs at least one file".to_string());
    }

    let mut options = CreateOptions::default().with_recovery(recovery);
    if let Some(bytes) = block_size {
        options = options.with_block_size(bytes);
    }

    let report = create(&InputSpec::new(&base, &files), &output, &options)
        .map_err(|error| format!("create failed: {error}"))?;

    println!("set {}", report.set_id);
    println!(
        "{} input blocks of {} bytes, {} packed tails",
        report.block_count, report.block_size, report.packed_tails
    );
    println!(
        "{} recovery blocks in {}",
        report.recovery_count,
        field_name(report.field.size)
    );
    for path in &report.files_written {
        println!("wrote {}", path.display());
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn cmd_verify(args: &[String]) -> Outcome<ExitCode> {
    let (base, sources) = split_base(args, "verify")?;
    let sets = load_sets(sources)?;

    let mut all_complete = true;
    for set in &sets {
        println!("set {}", set.input_set_id());
        let report = verify_set(set, &base).map_err(|error| format!("verify failed: {error}"))?;
        for file in report.files() {
            let verdict = file.verdict();
            if verdict.is_complete() {
                println!("  complete     {}", file.path());
            } else if verdict.is_missing() {
                println!("  missing      {}", file.path());
            } else if verdict.is_damaged() {
                println!(
                    "  damaged      {} ({} blocks, {} tail blocks)",
                    file.path(),
                    verdict.damaged_blocks().len(),
                    verdict.damaged_tail_blocks().len()
                );
            } else {
                println!("  unverifiable {}", file.path());
            }
        }
        println!(
            "  {} complete, {} damaged, {} missing, of {}",
            report.complete_count(),
            report.damaged_count(),
            report.missing_count(),
            report.files().len()
        );
        all_complete &= report.is_complete();
    }

    Ok(if all_complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

// ---------------------------------------------------------------------------
// repair
// ---------------------------------------------------------------------------

fn cmd_repair(args: &[String]) -> Outcome<ExitCode> {
    let (base, sources) = split_base(args, "repair")?;
    let sets = load_sets(sources)?;

    let options = RepairOptions::default();
    let mut all_complete = true;
    for set in &sets {
        println!("set {}", set.input_set_id());

        // The dry run first, so a set that cannot be repaired is reported
        // rather than attempted.
        let plan = plan_repair(set, &base, &options.limits)
            .map_err(|error| format!("cannot plan a repair: {error}"))?;
        if !plan.needs_repair() {
            println!("  nothing to do: every file is complete");
            continue;
        }
        if !plan.is_possible() {
            println!(
                "  {} input blocks lost, {} recovery blocks on hand: {} more needed",
                plan.lost_blocks().len(),
                plan.available_recovery(),
                plan.missing_recovery_blocks()
            );
            all_complete = false;
            continue;
        }

        let report =
            repair_set(set, &base, &options).map_err(|error| format!("repair failed: {error}"))?;
        let plan = report.plan();

        for file in report.repaired() {
            let state = if file.verified() {
                "rebuilt"
            } else {
                "FAILED "
            };
            match file.backup() {
                Some(backup) => println!(
                    "  {state} {} (damaged file kept as {})",
                    file.path(),
                    backup.display()
                ),
                None => println!("  {state} {}", file.path()),
            }
        }
        println!(
            "  {} input blocks rebuilt from {} recovery blocks",
            plan.lost_blocks().len(),
            plan.recovery_to_use().len()
        );
        all_complete &= report.is_complete();
    }

    Ok(if all_complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn cmd_list(args: &[String]) -> Outcome<ExitCode> {
    if args.is_empty() {
        return Err("list needs at least one .par3 file".to_string());
    }
    let sets = load_sets(args)?;

    for set in &sets {
        println!("set {}", set.input_set_id());
        println!(
            "  {} input blocks of {} bytes, {}",
            set.block_count(),
            set.block_size(),
            field_name(set.galois_field().size)
        );
        if let Some(parent) = set.parent_input_set_id() {
            println!("  parent set {parent} (not followed)");
        }

        println!("  files:");
        for file in set.files() {
            println!("    {} ({} bytes)", file.path(), file.size());
        }
        if !set.directories().is_empty() {
            println!("  directories:");
            for directory in set.directories() {
                println!("    {}/", directory.path());
            }
        }

        let blocks = set.recovery_blocks();
        println!("  recovery blocks: {}", blocks.len());
        for block in blocks {
            println!(
                "    index {} from matrix {} ({}), {} bytes",
                block.index(),
                hex(&block.matrix_hash()),
                if block.matrix_present() {
                    "present"
                } else {
                    "absent"
                },
                block.data_len()
            );
        }
        let conflicting = set.conflicting_recovery_packet_count();
        if conflicting != 0 {
            println!("  {conflicting} recovery packets contradict each other and were dropped");
        }
        let foreign = set.foreign_recovery_packets().len();
        if foreign != 0 {
            println!("  {foreign} recovery packets belong to another root");
        }
    }

    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Read every named `.par3` file and assemble whatever sets its packets make.
fn load_sets(sources: &[String]) -> Outcome<Vec<Par3Set>> {
    if sources.is_empty() {
        return Err("no .par3 file given".to_string());
    }
    let mut packets: Vec<Packet> = Vec::new();
    for source in sources {
        let found = scan_packets_from_path(Path::new(source))
            .map_err(|error| format!("cannot read {source}: {error}"))?;
        packets.extend(found.into_iter().map(|(_offset, packet)| packet));
    }
    let sets = Par3Set::from_packets(packets)
        .map_err(|error| format!("cannot assemble a set: {error}"))?;
    if sets.is_empty() {
        return Err("no complete input set was found in those files".to_string());
    }
    Ok(sets)
}

/// `<base> <index.par3> [more…]`, which `verify` and `repair` share.
fn split_base<'a>(args: &'a [String], command: &str) -> Outcome<(PathBuf, &'a [String])> {
    if args.len() < 2 {
        return Err(format!(
            "{command} needs <base> and at least one .par3 file"
        ));
    }
    Ok((PathBuf::from(&args[0]), &args[1..]))
}

fn parse_u64(value: &str, what: &str) -> Outcome<u64> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{what} is not a number: {value}"))
}

/// The field a Start packet's size byte names, in words.
fn field_name(size: u8) -> String {
    match size {
        0 => "no Galois field (XOR)".to_string(),
        1 => "GF(2^8)".to_string(),
        2 => "GF(2^16)".to_string(),
        other => format!("a {other}-byte Galois field"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
