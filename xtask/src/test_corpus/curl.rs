//! HTTP through `curl`.
//!
//! The corpus tooling has two network needs: public reads (manifest, bundle,
//! objects) and, in the publish workflow only, SigV4-authenticated conditional
//! writes to R2's S3 endpoint. Both go through the system `curl`, which every
//! CI runner and developer machine already has and which speaks SigV4
//! natively (`--aws-sigv4`), so this crate carries no HTTP stack and no
//! request signing of its own. Credentials are handed to curl on stdin as a
//! config file, never on the command line.
//!
//! SHA-256 appears here only inside SigV4 (`AWS4-HMAC-SHA256`,
//! `x-amz-content-sha256`), because AWS Signature Version 4 specifies that
//! hash. It is curl's computation, it never leaves the request, and it says
//! nothing about how the corpus addresses or verifies an object — that is
//! BLAKE3 throughout.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{Result, error, fail};

/// Environment override for the curl executable (tests point it at a stub).
pub(crate) const CURL_ENV: &str = "RARPAR_CURL";

/// Environment override for the allowed protocols. Production is `=https`
/// only; the tests' fake server speaks plain http on loopback.
pub(crate) const CURL_PROTO_ENV: &str = "RARPAR_CURL_PROTO";

fn allowed_protocols() -> String {
    std::env::var(CURL_PROTO_ENV).unwrap_or_else(|_| "=https".to_owned())
}

pub(crate) fn curl_binary() -> String {
    std::env::var(CURL_ENV).unwrap_or_else(|_| "curl".to_owned())
}

/// Options every transfer shares: TLS only, no redirects (the bucket domain
/// serves objects directly; a redirect would mean something else answered),
/// bounded retries on transient failures, quiet unless something fails.
fn common_args() -> Vec<String> {
    vec![
        "--silent".into(),
        "--show-error".into(),
        "--proto".into(),
        allowed_protocols(),
        "--tlsv1.2".into(),
        "--retry".into(),
        "3".into(),
        "--retry-delay".into(),
        "1".into(),
        "--connect-timeout".into(),
        "20".into(),
    ]
}

/// The status of one HTTP transfer as curl saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Transfer {
    pub(crate) url: String,
    pub(crate) status: u16,
}

/// GET one URL to a file. Fails on any non-2xx status; the caller verifies the
/// bytes it asked for, this only moves them.
pub(crate) fn get_to_file(url: &str, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut command = Command::new(curl_binary());
    command
        .args(common_args())
        .arg("--fail")
        .arg("--output")
        .arg(destination)
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|source| error(format!("run curl: {source}")))?;
    if !output.status.success() {
        let _ = fs::remove_file(destination);
        return fail(format!(
            "GET {url} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// GET one URL into memory (small documents: manifest, bundle, provenance).
pub(crate) fn get_to_vec(url: &str) -> Result<Vec<u8>> {
    let temp = std::env::temp_dir().join(format!(
        "rarpar-corpus-get-{}-{}",
        std::process::id(),
        sequence()
    ));
    get_to_file(url, &temp)?;
    let bytes = fs::read(&temp)?;
    let _ = fs::remove_file(&temp);
    Ok(bytes)
}

fn sequence() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// One planned download for `get_many`.
#[derive(Debug, Clone)]
pub(crate) struct Download {
    pub(crate) url: String,
    pub(crate) destination: PathBuf,
}

/// GET many URLs in one curl process with bounded parallelism. Returns the
/// destinations curl reported a 2xx for; the caller treats everything else as
/// missing and verifies every returned file's digest itself.
pub(crate) fn get_many(downloads: &[Download], parallel: usize) -> Result<Vec<Transfer>> {
    if downloads.is_empty() {
        return Ok(Vec::new());
    }
    for download in downloads {
        if let Some(parent) = download.destination.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    let config = render_download_config(downloads);
    let mut command = Command::new(curl_binary());
    command
        .args(common_args())
        .arg("--parallel")
        .arg("--parallel-max")
        .arg(parallel.clamp(1, 16).to_string())
        // Report every transfer's status; do not --fail, so one 404 does not
        // abort the batch and each file's fate is known.
        .arg("--write-out")
        .arg("%{url}\t%{http_code}\n")
        .arg("--config")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|source| error(format!("run curl: {source}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| error("curl stdin unavailable"))?
        .write_all(config.as_bytes())?;
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut transfers = Vec::new();
    for line in stdout.lines() {
        if let Some((url, code)) = line.rsplit_once('\t')
            && let Ok(status) = code.trim().parse::<u16>()
        {
            transfers.push(Transfer {
                url: url.to_owned(),
                status,
            });
        }
    }
    if !output.status.success() && transfers.is_empty() {
        return fail(format!(
            "curl batch failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(transfers)
}

/// The curl config for a batch: one `url`/`output` pair per download. Values
/// are double-quoted with curl's escaping (backslash and double quote), so
/// Windows paths survive.
pub(crate) fn render_download_config(downloads: &[Download]) -> String {
    let mut config = String::new();
    for download in downloads {
        config.push_str("url = ");
        config.push_str(&quote(&download.url));
        config.push('\n');
        config.push_str("output = ");
        config.push_str(&quote(&download.destination.to_string_lossy()));
        config.push('\n');
    }
    config
}

fn quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// S3-compatible credentials for R2. The secret only ever travels to curl on
/// stdin.
#[derive(Clone)]
pub(crate) struct S3Credentials {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "S3Credentials(access_key_id={}, secret=<redacted>)",
            self.access_key_id
        )
    }
}

/// The argument vector for a conditional SigV4 PUT, without the credentials.
/// Pure, so tests can assert what curl is asked to do.
pub(crate) fn put_args(file: &Path, url: &str, content_type: &str) -> Vec<String> {
    let mut args = common_args();
    args.extend([
        "--aws-sigv4".into(),
        "aws:amz:auto:s3".into(),
        "--upload-file".into(),
        file.to_string_lossy().into_owned(),
        "--header".into(),
        "If-None-Match: *".into(),
        "--header".into(),
        format!("Content-Type: {content_type}"),
        "--output".into(),
        if cfg!(windows) {
            "NUL".into()
        } else {
            "/dev/null".into()
        },
        "--write-out".into(),
        "%{http_code}".into(),
        "--config".into(),
        "-".into(),
        "--".into(),
        url.into(),
    ]);
    args
}

/// PUT a file with `If-None-Match: *`. Returns the HTTP status: 200/201 on
/// creation, 412 when the key already exists (the caller reads it back and
/// compares), anything else is the caller's error to raise. Transient
/// failures (no status at all, or 5xx) are retried a bounded number of times.
pub(crate) fn put_conditional(
    file: &Path,
    url: &str,
    content_type: &str,
    credentials: &S3Credentials,
) -> Result<u16> {
    let mut last_error = String::new();
    for attempt in 1..=3 {
        let mut command = Command::new(curl_binary());
        command
            .args(put_args(file, url, content_type))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|source| error(format!("run curl: {source}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| error("curl stdin unavailable"))?
            .write_all(
                format!(
                    "user = {}\n",
                    quote(&format!(
                        "{}:{}",
                        credentials.access_key_id, credentials.secret_access_key
                    ))
                )
                .as_bytes(),
            )?;
        let output = child.wait_with_output()?;
        let status_text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        match status_text.parse::<u16>() {
            Ok(status) if (200..300).contains(&status) || status == 412 => return Ok(status),
            Ok(status) if status >= 500 => {
                last_error = format!("PUT {url}: HTTP {status} (attempt {attempt})");
            }
            Ok(status) => return Ok(status),
            Err(_) => {
                last_error = format!(
                    "PUT {url}: no HTTP status (attempt {attempt}, curl {}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(attempt));
    }
    fail(last_error)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// (method, path, headers) as the fake server saw them.
    pub(crate) type SeenRequest = (String, String, Vec<String>);
    /// (method, path) → (status, body).
    pub(crate) type Route = ((&'static str, &'static str), (u16, Vec<u8>));

    /// A one-thread HTTP server that answers each request from a table and
    /// records what it saw. `curl` is real; only the far end is fake.
    pub(crate) struct FakeServer {
        pub(crate) base_url: String,
        pub(crate) requests: Arc<Mutex<Vec<SeenRequest>>>,
        handle: Option<std::thread::JoinHandle<()>>,
        stop: Arc<Mutex<bool>>,
    }

    impl FakeServer {
        /// `routes`: (method, path) → (status, body). Unknown paths get 404.
        pub(crate) fn start(routes: Vec<Route>) -> FakeServer {
            FakeServer::start_with_store(routes, None)
        }

        /// A stateful variant: a PUT whose path starts with `write_prefix`
        /// stores its body under the path minus that prefix, and a GET with no
        /// static route is answered from the store. This is enough of an object
        /// store to exercise publish-then-read-back and republish flows.
        pub(crate) fn start_stateful(routes: Vec<Route>, write_prefix: &str) -> FakeServer {
            FakeServer::start_with_store(routes, Some(write_prefix.to_owned()))
        }

        fn start_with_store(routes: Vec<Route>, write_prefix: Option<String>) -> FakeServer {
            let store: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>> =
                Arc::new(Mutex::new(std::collections::HashMap::new()));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let requests: Arc<Mutex<Vec<SeenRequest>>> = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(Mutex::new(false));
            let seen = requests.clone();
            let stop_flag = stop.clone();
            let handle = std::thread::spawn(move || {
                loop {
                    if *stop_flag.lock().unwrap() {
                        break;
                    }
                    let (mut stream, _) = match listener.accept() {
                        Ok(accepted) => accepted,
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => break,
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                        continue;
                    }
                    let mut headers = Vec::new();
                    let mut content_length = 0usize;
                    let mut expect_continue = false;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err()
                            || line == "\r\n"
                            || line == "\n"
                            || line.is_empty()
                        {
                            break;
                        }
                        let lower = line.to_ascii_lowercase();
                        if let Some(value) = lower.strip_prefix("content-length:") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                        if lower.starts_with("expect:") && lower.contains("100-continue") {
                            expect_continue = true;
                        }
                        headers.push(line.trim_end().to_owned());
                    }
                    if expect_continue {
                        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                    }
                    let mut body = vec![0u8; content_length];
                    if content_length > 0 {
                        let _ = reader.read_exact(&mut body);
                    }
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_owned();
                    let path = parts.next().unwrap_or("").to_owned();
                    seen.lock()
                        .unwrap()
                        .push((method.clone(), path.clone(), headers));
                    let static_route = routes
                        .iter()
                        .find(|((m, p), _)| *m == method && *p == path)
                        .map(|(_, response)| response.clone());
                    let (status, response_body) = match (&write_prefix, static_route) {
                        (Some(prefix), stored_status)
                            if method == "PUT" && path.starts_with(prefix.as_str()) =>
                        {
                            let key = path[prefix.len()..].to_owned();
                            let (status, reply) = stored_status.unwrap_or((200, Vec::new()));
                            if (200..300).contains(&status) {
                                store.lock().unwrap().insert(key, body.clone());
                            }
                            (status, reply)
                        }
                        (Some(_), None) if method == "GET" => {
                            match store.lock().unwrap().get(&path) {
                                Some(stored) => (200, stored.clone()),
                                None => (404, b"not found".to_vec()),
                            }
                        }
                        (_, Some(found)) => found,
                        (_, None) => (404, b"not found".to_vec()),
                    };
                    let reason = match status {
                        200 => "OK",
                        201 => "Created",
                        404 => "Not Found",
                        412 => "Precondition Failed",
                        500 => "Internal Server Error",
                        _ => "Status",
                    };
                    let head = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response_body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&response_body);
                    let _ = stream.flush();
                }
            });
            FakeServer {
                base_url: format!("http://127.0.0.1:{port}"),
                requests,
                handle: Some(handle),
                stop,
            }
        }
    }

    impl Drop for FakeServer {
        fn drop(&mut self) {
            *self.stop.lock().unwrap() = true;
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn curl_available() -> bool {
        Command::new(curl_binary())
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn download_config_quotes_paths_and_urls() {
        let config = render_download_config(&[Download {
            url: "https://h/o?x=\"y\"".into(),
            destination: PathBuf::from(r"C:\tmp\a b\file.rar"),
        }]);
        assert_eq!(
            config,
            "url = \"https://h/o?x=\\\"y\\\"\"\noutput = \"C:\\\\tmp\\\\a b\\\\file.rar\"\n"
        );
    }

    #[test]
    fn put_arguments_are_conditional_sigv4_and_carry_no_secret() {
        // put_args reads the protocol override; hold the env lock so a
        // concurrent loopback test's `=http,https` cannot leak in.
        let _guard = ENV_LOCK.lock().unwrap();
        let args = put_args(
            Path::new("/tmp/object"),
            "https://acct.r2.cloudflarestorage.com/bucket/key",
            "application/octet-stream",
        );
        let joined = args.join(" ");
        assert!(joined.contains("--aws-sigv4 aws:amz:auto:s3"));
        assert!(joined.contains("--header If-None-Match: *"));
        assert!(joined.contains("--upload-file /tmp/object"));
        assert!(joined.contains("--config -"), "credentials come from stdin");
        assert!(joined.contains("--proto =https"));
        assert!(!joined.contains("--fail"), "412 must be observable");
        assert!(
            !joined.contains("--user"),
            "no credential on the command line"
        );
        assert!(joined.ends_with("-- https://acct.r2.cloudflarestorage.com/bucket/key"));
        let debug = format!(
            "{:?}",
            S3Credentials {
                access_key_id: "AKID".into(),
                secret_access_key: "s3cr3t".into()
            }
        );
        assert!(debug.contains("AKID") && !debug.contains("s3cr3t"));
    }

    #[test]
    fn get_and_put_round_trip_through_a_real_curl() {
        if !curl_available() {
            eprintln!("skipping: curl not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("xtask-corpus-curl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let server = FakeServer::start(vec![
            (("GET", "/objects/a"), (200, b"alpha".to_vec())),
            (("GET", "/objects/b"), (200, b"bravo".to_vec())),
            (("PUT", "/bucket/new"), (200, Vec::new())),
            (("PUT", "/bucket/existing"), (412, b"precondition".to_vec())),
        ]);
        // SAFETY: tests in this module run single-threaded with respect to this
        // variable only if the harness is; guard with a lock to be sure.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var(CURL_PROTO_ENV, "=http,https") };

        let single = dir.join("single");
        get_to_file(&format!("{}/objects/a", server.base_url), &single).unwrap();
        assert_eq!(fs::read(&single).unwrap(), b"alpha");
        assert!(
            get_to_file(
                &format!("{}/objects/missing", server.base_url),
                &dir.join("missing")
            )
            .is_err()
        );
        assert!(
            !dir.join("missing").exists(),
            "a failed GET leaves no file behind"
        );
        assert_eq!(
            get_to_vec(&format!("{}/objects/b", server.base_url)).unwrap(),
            b"bravo"
        );

        let batch = vec![
            Download {
                url: format!("{}/objects/a", server.base_url),
                destination: dir.join("batch/a"),
            },
            Download {
                url: format!("{}/objects/b", server.base_url),
                destination: dir.join("batch/b"),
            },
            Download {
                url: format!("{}/objects/nope", server.base_url),
                destination: dir.join("batch/nope"),
            },
        ];
        let transfers = get_many(&batch, 4).unwrap();
        let status = |suffix: &str| {
            transfers
                .iter()
                .find(|t| t.url.ends_with(suffix))
                .map(|t| t.status)
        };
        assert_eq!(status("/objects/a"), Some(200));
        assert_eq!(status("/objects/b"), Some(200));
        assert_eq!(status("/objects/nope"), Some(404));
        assert_eq!(fs::read(dir.join("batch/a")).unwrap(), b"alpha");
        assert_eq!(fs::read(dir.join("batch/b")).unwrap(), b"bravo");

        let payload = dir.join("payload");
        fs::write(&payload, b"payload-bytes").unwrap();
        let credentials = S3Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "topsecret".into(),
        };
        assert_eq!(
            put_conditional(
                &payload,
                &format!("{}/bucket/new", server.base_url),
                "application/octet-stream",
                &credentials
            )
            .unwrap(),
            200
        );
        assert_eq!(
            put_conditional(
                &payload,
                &format!("{}/bucket/existing", server.base_url),
                "application/octet-stream",
                &credentials
            )
            .unwrap(),
            412
        );
        unsafe { std::env::remove_var(CURL_PROTO_ENV) };

        let requests = server.requests.lock().unwrap();
        let put = requests
            .iter()
            .find(|(m, p, _)| m == "PUT" && p == "/bucket/new")
            .expect("PUT observed");
        let headers = put.2.join("\n").to_ascii_lowercase();
        assert!(
            headers.contains("authorization: aws4-hmac-sha256"),
            "SigV4 signed: {headers}"
        );
        assert!(
            headers.contains("credential=akidexample/"),
            "access key id in credential scope: {headers}"
        );
        assert!(
            headers.contains("if-none-match: *"),
            "conditional write: {headers}"
        );
        assert!(
            headers.contains("x-amz-content-sha256:"),
            "payload hash: {headers}"
        );
        assert!(
            !headers.contains("topsecret"),
            "secret never leaves the signature"
        );
        assert!(headers.contains("content-type: application/octet-stream"));
        drop(requests);
        let _ = fs::remove_dir_all(&dir);
    }

    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
}
