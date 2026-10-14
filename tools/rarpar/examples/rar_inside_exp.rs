// EXPERIMENTAL: driver for `par3_rs::inside::rar4`, used to produce
// compatibility facts. It is not a supported command and is not installed.
//
// usage: rar_inside_exp [--password PW] walk ARCHIVE...
//        rar_inside_exp [--password PW] insert --layout service|trailing [-r PERCENT] -d OUT ARCHIVE...
//        rar_inside_exp [--password PW] verify FILE...
//        rar_inside_exp [--password PW] repair -d OUT FILE...
//        rar_inside_exp [--password PW] remove -d OUT FILE...

#[cfg(feature = "runtime")]
mod driver {
    use std::path::PathBuf;
    use std::sync::Arc;

    use par3_rs::creation::CreationOptions;
    use par3_rs::inside::rar4::{self, Crypto, Layout, RarCipher};
    use par3_rs::inside::rar5::{Rar5Placement, placement_counts};
    use par3_rs::runtime::ExecutionOptions;
    use par3_rs::source::{DiskSourceAccess, SourceId};

    struct Unrar(String);

    impl RarCipher for Unrar {
        fn rar4_key(&self, salt: &[u8; 8]) -> ([u8; 16], [u8; 16]) {
            unrar_rs::crypto::rar4_derive_key(&self.0, Some(salt))
        }
        fn rar5_key(&self, salt: &[u8; 16], lg2: u8) -> [u8; 32] {
            unrar_rs::crypto::derive_key(&self.0, salt, lg2)
                .expect("rar5 kdf")
                .0
        }
        fn cbc_encrypt(&self, key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
            match key.len() {
                16 => {
                    unrar_rs::crypto::encrypt_cipher_range_rar4(key.try_into().unwrap(), iv, data)
                }
                _ => unrar_rs::crypto::encrypt_cipher_range(key.try_into().unwrap(), iv, data),
            }
            .expect("aes")
        }
        fn cbc_decrypt(&self, key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
            match key.len() {
                16 => {
                    unrar_rs::crypto::decrypt_cipher_range_rar4(key.try_into().unwrap(), iv, data)
                }
                _ => unrar_rs::crypto::decrypt_cipher_range(key.try_into().unwrap(), iv, data),
            }
            .expect("aes")
        }
    }

    type Error = Box<dyn std::error::Error>;

    pub fn main() -> Result<i32, Error> {
        let mut args: Vec<String> = std::env::args().skip(1).collect();
        let mut password = None;
        let mut layout = Layout::Service;
        let mut out: Option<PathBuf> = None;
        let mut percent: u64 = 5;
        let mut rest = Vec::new();
        let mut command = None;
        while !args.is_empty() {
            let arg = args.remove(0);
            match arg.as_str() {
                "--password" => password = Some(args.remove(0)),
                "--layout" => {
                    layout = match args.remove(0).as_str() {
                        "service" => Layout::Service,
                        "trailing" => Layout::Trailing,
                        other => return Err(format!("unknown layout {other}").into()),
                    }
                }
                "-d" => out = Some(PathBuf::from(args.remove(0))),
                "-r" => percent = args.remove(0).parse()?,
                _ if command.is_none() => command = Some(arg),
                _ => rest.push(PathBuf::from(arg)),
            }
        }
        let crypto = password.map(|pw| Crypto::new(Box::new(Unrar(pw))));
        let execution = ExecutionOptions::default();
        match command.as_deref() {
            Some("walk") => {
                let mut disk = DiskSourceAccess::with_options(execution.clone());
                for (index, path) in rest.iter().enumerate() {
                    disk.insert(SourceId(index as u64), path.clone());
                }
                for (index, path) in rest.iter().enumerate() {
                    let frame = rar4::inspect(
                        &disk,
                        SourceId(index as u64),
                        &execution,
                        crypto.as_deref(),
                    )?;
                    println!("{}: {:#?}", path.display(), frame);
                }
                Ok(0)
            }
            Some("insert") => {
                let out = out.ok_or("-d required")?;
                std::fs::create_dir_all(&out)?;
                let (spec, hosts) =
                    rar4::prepare_hosts(&rest, layout, &execution, crypto.as_deref())?;
                let total: u64 = hosts.iter().map(|host| host.frame.length).sum();
                let mut block_size = 4096u64;
                while total.div_ceil(block_size) > 2048 {
                    block_size *= 2;
                }
                let blocks: u64 = hosts
                    .iter()
                    .map(|host| host.frame.length.div_ceil(block_size) + 1)
                    .sum();
                let count = (blocks * percent).div_ceil(100).max(1);
                let counts = placement_counts(Rar5Placement::Spread, hosts.len(), count)?;
                let outputs: Vec<PathBuf> = hosts.iter().map(|host| out.join(&host.name)).collect();
                let scratch = tempfile::tempdir_in(&out)?;
                let options = CreationOptions {
                    execution: execution.clone(),
                    block_size,
                    recovery_count: count,
                    ..CreationOptions::default()
                };
                let inserted = rar4::insert_set(
                    &hosts,
                    &outputs,
                    &counts,
                    spec,
                    options,
                    scratch.path(),
                    crypto.as_deref(),
                )?;
                println!("spec {spec:?} block_size {block_size} recovery {count}");
                for entry in inserted {
                    println!(
                        "inserted {} region_bytes={} recovery_packets={}",
                        entry.path.display(),
                        entry.region_bytes,
                        entry.recovery_packets
                    );
                }
                Ok(0)
            }
            Some(command @ ("verify" | "repair" | "remove")) => {
                let sets = rar4::open(&rest, &execution, crypto.clone())?;
                let mut code = 0;
                for mut set in sets {
                    println!(
                        "set {:02x?} spec {:?} status {:?} lost_blocks {} additional {} recovery_available {}",
                        set.id.0,
                        set.spec,
                        set.status,
                        set.lost_blocks,
                        set.additional,
                        set.recovery_available
                    );
                    for host in &set.hosts {
                        println!(
                            "  host {} path {:?} matched_by {:?} complete {} region_intact {} packets {}/{} unresolved {:?}",
                            host.name,
                            host.path,
                            host.matched_by,
                            host.complete,
                            host.region_intact,
                            host.packets_found,
                            host.packets_expected,
                            host.unresolved
                        );
                    }
                    match command {
                        "verify" => {
                            if !set.needs_repair().is_empty() {
                                code = 1;
                            }
                        }
                        "repair" => {
                            let out = out.clone().ok_or("-d required")?;
                            std::fs::create_dir_all(&out)?;
                            let destinations: Vec<PathBuf> =
                                set.hosts.iter().map(|host| out.join(&host.name)).collect();
                            let scratch = tempfile::tempdir_in(&out)?;
                            let report = set.repair(&destinations, scratch.path())?;
                            if report.is_empty() {
                                println!("  nothing to repair");
                            }
                            for entry in report {
                                println!(
                                    "  repaired {} data_rebuilt {} regenerated {} restoration {:?}",
                                    entry.path.display(),
                                    entry.data_rebuilt,
                                    entry.regenerated,
                                    entry.restoration
                                );
                            }
                        }
                        _ => {
                            let out = out.clone().ok_or("-d required")?;
                            std::fs::create_dir_all(&out)?;
                            let destinations: Vec<PathBuf> =
                                set.hosts.iter().map(|host| out.join(&host.name)).collect();
                            for path in set.remove(&destinations)? {
                                println!("  removed -> {}", path.display());
                            }
                        }
                    }
                }
                Ok(code)
            }
            _ => Err(
                "usage: rar_inside_exp [--password PW] walk|insert|verify|repair|remove ...".into(),
            ),
        }
    }

    #[allow(dead_code)]
    fn _assert_send(_: Arc<Crypto>) {}
}

fn main() {
    #[cfg(feature = "runtime")]
    match driver::main() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }
}
