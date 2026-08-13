use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const WARMUPS: usize = 2;
const SAMPLES: usize = 15;
const MAX_RELATIVE_MAD: f64 = 0.05;
const MAX_UNRAR_RATIO: f64 = 1.05;

const CASES: [(&str, &str); 3] = [
    ("restart", "rar4_ppm_solid_restart.rar"),
    ("solid-multi-member", "rar4_ppm_solid_mv.rar"),
    ("order16-32m", "rar4_ppm_order16_32m.rar"),
];

struct CaseResult {
    name: &'static str,
    archive: String,
    rarpar_seconds: Vec<f64>,
    unrar_seconds: Vec<f64>,
    rarpar_median_seconds: f64,
    unrar_median_seconds: f64,
    rarpar_relative_mad: f64,
    unrar_relative_mad: f64,
    rarpar_to_unrar_ratio: f64,
    retried_for_noise: bool,
}

struct Report {
    schema_version: u32,
    platform: String,
    unrar_version: &'static str,
    warmups: usize,
    samples: usize,
    maximum_relative_mad: f64,
    maximum_unrar_ratio: f64,
    cases: Vec<CaseResult>,
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => write!(output, "\\u{:04x}", ch as u32).unwrap(),
            ch => output.push(ch),
        }
    }
    output.push('"');
    output
}

fn json_numbers(values: &[f64]) -> String {
    let values = values
        .iter()
        .map(|value| format!("{value:.9}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

impl Report {
    fn to_json(&self) -> String {
        let mut output = String::new();
        writeln!(output, "{{").unwrap();
        writeln!(output, "  \"schema_version\": {},", self.schema_version).unwrap();
        writeln!(output, "  \"platform\": {},", json_string(&self.platform)).unwrap();
        writeln!(
            output,
            "  \"unrar_version\": {},",
            json_string(self.unrar_version)
        )
        .unwrap();
        writeln!(output, "  \"warmups\": {},", self.warmups).unwrap();
        writeln!(output, "  \"samples\": {},", self.samples).unwrap();
        writeln!(
            output,
            "  \"maximum_relative_mad\": {:.3},",
            self.maximum_relative_mad
        )
        .unwrap();
        writeln!(
            output,
            "  \"maximum_unrar_ratio\": {:.3},",
            self.maximum_unrar_ratio
        )
        .unwrap();
        writeln!(output, "  \"cases\": [").unwrap();
        for (index, case) in self.cases.iter().enumerate() {
            writeln!(output, "    {{").unwrap();
            writeln!(output, "      \"name\": {},", json_string(case.name)).unwrap();
            writeln!(output, "      \"archive\": {},", json_string(&case.archive)).unwrap();
            writeln!(
                output,
                "      \"rarpar_seconds\": {},",
                json_numbers(&case.rarpar_seconds)
            )
            .unwrap();
            writeln!(
                output,
                "      \"unrar_seconds\": {},",
                json_numbers(&case.unrar_seconds)
            )
            .unwrap();
            writeln!(
                output,
                "      \"rarpar_median_seconds\": {:.9},",
                case.rarpar_median_seconds
            )
            .unwrap();
            writeln!(
                output,
                "      \"unrar_median_seconds\": {:.9},",
                case.unrar_median_seconds
            )
            .unwrap();
            writeln!(
                output,
                "      \"rarpar_relative_mad\": {:.9},",
                case.rarpar_relative_mad
            )
            .unwrap();
            writeln!(
                output,
                "      \"unrar_relative_mad\": {:.9},",
                case.unrar_relative_mad
            )
            .unwrap();
            writeln!(
                output,
                "      \"rarpar_to_unrar_ratio\": {:.9},",
                case.rarpar_to_unrar_ratio
            )
            .unwrap();
            writeln!(
                output,
                "      \"retried_for_noise\": {}",
                case.retried_for_noise
            )
            .unwrap();
            writeln!(
                output,
                "    }}{}",
                if index + 1 == self.cases.len() {
                    ""
                } else {
                    ","
                }
            )
            .unwrap();
        }
        writeln!(output, "  ]").unwrap();
        write!(output, "}}").unwrap();
        output
    }
}

fn required() -> bool {
    env::var("WEAVER_REQUIRE_PPMD_PERF")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn configured_binary(name: &str) -> Result<Option<PathBuf>, Box<dyn Error>> {
    match env::var_os(name) {
        Some(value) => {
            let path = PathBuf::from(value);
            if path.is_file() {
                Ok(Some(path))
            } else {
                Err(format!("{name} does not name a file: {}", path.display()).into())
            }
        }
        None if required() => Err(format!("{name} is required by WEAVER_REQUIRE_PPMD_PERF").into()),
        None => Ok(None),
    }
}

fn command(binary: &Path, args: &[&OsStr]) -> Command {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env(
            "LANG",
            if cfg!(target_os = "macos") {
                "en_US.UTF-8"
            } else {
                "C.UTF-8"
            },
        )
        .env(
            "LC_ALL",
            if cfg!(target_os = "macos") {
                "en_US.UTF-8"
            } else {
                "C.UTF-8"
            },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn run_timed(binary: &Path, args: &[&OsStr]) -> Result<f64, Box<dyn Error>> {
    let started = Instant::now();
    let status = command(binary, args).status()?;
    let elapsed = started.elapsed().as_secs_f64();
    if !status.success() {
        return Err(format!("{} exited with {status}", binary.display()).into());
    }
    Ok(elapsed)
}

fn rarpar_args<'a>(archive: &'a Path, destination: &'a Path) -> [&'a OsStr; 6] {
    [
        OsStr::new("x"),
        OsStr::new("-idp"),
        OsStr::new("-p-"),
        OsStr::new("-o+"),
        archive.as_os_str(),
        destination.as_os_str(),
    ]
}

fn unrar_args<'a>(archive: &'a Path, destination: &'a Path) -> [&'a OsStr; 6] {
    [
        OsStr::new("x"),
        OsStr::new("-inul"),
        OsStr::new("-p-"),
        OsStr::new("-o+"),
        archive.as_os_str(),
        destination.as_os_str(),
    ]
}

fn verify_unrar_723(unrar: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(unrar).output()?;
    let mut banner = String::from_utf8_lossy(&output.stdout).into_owned();
    banner.push_str(&String::from_utf8_lossy(&output.stderr));
    if !banner
        .lines()
        .any(|line| line.starts_with("UNRAR 7.23 freeware"))
    {
        return Err(format!(
            "{} is not the version-pinned RARLAB UnRAR 7.23 oracle: {banner}",
            unrar.display()
        )
        .into());
    }
    Ok(())
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn relative_mad(values: &[f64]) -> f64 {
    let center = median(values);
    if center == 0.0 {
        return 0.0;
    }
    let deviations = values
        .iter()
        .map(|value| (value - center).abs())
        .collect::<Vec<_>>();
    median(&deviations) / center
}

fn sample_batch(
    rarpar: &Path,
    unrar: &Path,
    archive: &Path,
) -> Result<(Vec<f64>, Vec<f64>), Box<dyn Error>> {
    let output_root = tempfile::tempdir()?;
    let rarpar_destination = output_root.path().join("rarpar");
    let unrar_destination = output_root.path().join("unrar");
    std::fs::create_dir_all(&rarpar_destination)?;
    std::fs::create_dir_all(&unrar_destination)?;
    let rarpar_args = rarpar_args(archive, &rarpar_destination);
    let unrar_args = unrar_args(archive, &unrar_destination);
    for _ in 0..WARMUPS {
        run_timed(rarpar, &rarpar_args)?;
        run_timed(unrar, &unrar_args)?;
    }

    let mut rarpar_samples = Vec::with_capacity(SAMPLES);
    let mut unrar_samples = Vec::with_capacity(SAMPLES);
    for index in 0..SAMPLES {
        if index.is_multiple_of(2) {
            rarpar_samples.push(run_timed(rarpar, &rarpar_args)?);
            unrar_samples.push(run_timed(unrar, &unrar_args)?);
        } else {
            unrar_samples.push(run_timed(unrar, &unrar_args)?);
            rarpar_samples.push(run_timed(rarpar, &rarpar_args)?);
        }
    }
    Ok((rarpar_samples, unrar_samples))
}

fn measure_case(
    name: &'static str,
    archive: &Path,
    rarpar: &Path,
    unrar: &Path,
) -> Result<CaseResult, Box<dyn Error>> {
    let isolated_input = tempfile::tempdir()?;
    let archive_name = archive
        .file_name()
        .ok_or_else(|| format!("fixture has no file name: {}", archive.display()))?;
    let isolated_archive = isolated_input.path().join(archive_name);
    if std::fs::hard_link(archive, &isolated_archive).is_err() {
        std::fs::copy(archive, &isolated_archive)?;
    }

    let (mut rarpar_samples, mut unrar_samples) = sample_batch(rarpar, unrar, &isolated_archive)?;
    let mut rarpar_mad = relative_mad(&rarpar_samples);
    let mut unrar_mad = relative_mad(&unrar_samples);
    let retried = rarpar_mad > MAX_RELATIVE_MAD || unrar_mad > MAX_RELATIVE_MAD;
    if retried {
        (rarpar_samples, unrar_samples) = sample_batch(rarpar, unrar, &isolated_archive)?;
        rarpar_mad = relative_mad(&rarpar_samples);
        unrar_mad = relative_mad(&unrar_samples);
    }
    if rarpar_mad > MAX_RELATIVE_MAD || unrar_mad > MAX_RELATIVE_MAD {
        return Err(format!(
            "{name}: unstable measurements after retry (rarpar MAD {rarpar_mad:.3}, UnRAR MAD {unrar_mad:.3})"
        )
        .into());
    }

    let rarpar_median = median(&rarpar_samples);
    let unrar_median = median(&unrar_samples);
    Ok(CaseResult {
        name,
        archive: archive.display().to_string(),
        rarpar_seconds: rarpar_samples,
        unrar_seconds: unrar_samples,
        rarpar_median_seconds: rarpar_median,
        unrar_median_seconds: unrar_median,
        rarpar_relative_mad: rarpar_mad,
        unrar_relative_mad: unrar_mad,
        rarpar_to_unrar_ratio: rarpar_median / unrar_median,
        retried_for_noise: retried,
    })
}

fn run() -> Result<(), Box<dyn Error>> {
    let Some(rarpar) = configured_binary("RARPAR_BIN")? else {
        eprintln!("ppmd_compare skipped: set RARPAR_BIN and UNRAR_BIN to run the oracle gate");
        return Ok(());
    };
    let Some(unrar) = configured_binary("UNRAR_BIN")? else {
        eprintln!("ppmd_compare skipped: set RARPAR_BIN and UNRAR_BIN to run the oracle gate");
        return Ok(());
    };
    verify_unrar_723(&unrar)?;

    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4");
    let mut cases = Vec::with_capacity(CASES.len());
    for (name, filename) in CASES {
        let archive = fixture_root.join(filename);
        if !archive.is_file() {
            return Err(format!("missing PPMd performance fixture: {}", archive.display()).into());
        }
        let result = measure_case(name, &archive, &rarpar, &unrar)?;
        eprintln!(
            "{name}: rarpar {:.3}s, UnRAR {:.3}s, ratio {:.3}",
            result.rarpar_median_seconds, result.unrar_median_seconds, result.rarpar_to_unrar_ratio
        );
        cases.push(result);
    }

    let failed = cases
        .iter()
        .filter(|case| case.rarpar_to_unrar_ratio > MAX_UNRAR_RATIO)
        .map(|case| format!("{}={:.3}", case.name, case.rarpar_to_unrar_ratio))
        .collect::<Vec<_>>();
    let report = Report {
        schema_version: 1,
        platform: format!("{}-{}", env::consts::OS, env::consts::ARCH),
        unrar_version: "7.23",
        warmups: WARMUPS,
        samples: SAMPLES,
        maximum_relative_mad: MAX_RELATIVE_MAD,
        maximum_unrar_ratio: MAX_UNRAR_RATIO,
        cases,
    };
    let json = report.to_json();
    println!("{json}");
    if let Some(path) = env::var_os("PPMD_PERF_JSON") {
        std::fs::write(path, format!("{json}\n"))?;
    }

    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "RAR4 PPMd parity gate exceeded {MAX_UNRAR_RATIO:.2}: {}",
            failed.join(", ")
        )
        .into())
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ppmd_compare: {error}");
        std::process::exit(1);
    }
}
