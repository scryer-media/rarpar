use std::fs::File;
use std::io;
use std::path::PathBuf;

use weaver_unrar::{ExtractOptions, Limits, RarArchive, StaticVolumeProvider};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut password: Option<String> = None;
    let mut max_dict_mib: Option<u64> = None;
    let mut paths: Vec<PathBuf> = Vec::new();

    while let Some(arg) = args.next() {
        if arg == "--password" {
            let value = args.next().ok_or("missing value after --password")?;
            password = Some(value);
            continue;
        }
        if arg == "--max-dict-mib" {
            let value = args.next().ok_or("missing value after --max-dict-mib")?;
            max_dict_mib = Some(value.parse().map_err(|_| "--max-dict-mib must be an integer")?);
            continue;
        }

        paths.push(PathBuf::from(arg));
    }

    if paths.is_empty() {
        return Err(
            "usage: stream_to_sink [--password PASSWORD] [--max-dict-mib N] <archive> [more-volumes...]".into(),
        );
    }

    let first = File::open(&paths[0])?;
    let mut archive = if let Some(ref pwd) = password {
        RarArchive::open_with_password(first, pwd)?
    } else {
        RarArchive::open(first)?
    };

    if let Some(ref pwd) = password {
        archive.set_password(pwd);
    }

    if let Some(mib) = max_dict_mib {
        let limits = Limits {
            max_dict_size: mib * 1024 * 1024,
            ..Limits::default()
        };
        archive.set_limits(limits);
    }

    for (index, path) in paths.iter().enumerate().skip(1) {
        archive.add_volume(index, Box::new(File::open(path)?))?;
    }

    let provider = StaticVolumeProvider::from_ordered(paths.clone());
    let options = ExtractOptions {
        verify: true,
        password,
        restore_owners: false,
    };

    let member_count = archive.metadata().members.len();
    if archive.is_solid() {
        for member_index in 0..member_count {
            archive.extract_member_solid_chunked(member_index, &options, |_| {
                Ok(Box::new(io::sink()))
            })?;
        }
    } else {
        let mut sink = io::sink();
        for member_index in 0..member_count {
            archive.extract_member_streaming(member_index, &options, &provider, &mut sink)?;
        }
    }

    Ok(())
}
