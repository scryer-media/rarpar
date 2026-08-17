//! HTTP for the corpus tooling: a client in this process, not a subprocess.
//!
//! Two network needs: public reads (manifest, bundle, objects) and, in the
//! publish workflow only, SigV4-authenticated conditional writes to R2's S3
//! endpoint. Both go through `ureq` over `rustls` — a blocking client with no
//! runtime, no system TLS library and no `openssl` — rather than through the
//! system `curl`.
//!
//! Tooling moves bytes and credentials, so it does it in code it owns: the
//! transport policy (https only, no redirects, bounded retries, a connect
//! timeout) is stated and tested here rather than inherited from whichever
//! `curl` the host happens to carry, a response status is a number rather than
//! text parsed back out of another program's stdout, and the R2 secret is an
//! HMAC key in this process's memory rather than something handed to another
//! program at all.
//!
//! A URL is sent as the caller spelled it, query string included. Read-backs
//! carry a cache-busting token in the query (see `Publisher::fresh_public_url`),
//! and a transport that normalised or dropped it would quietly reintroduce the
//! cached-absence failure it exists to defeat.
//!
//! Signing lives in [`super::sigv4`]; this module decides what to send and what
//! to make of the answer. Signatures *over the corpus* are still `cosign`'s, in
//! a subprocess: the bundle format is the interop contract.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ureq::Agent;
use ureq::http::Uri;

use super::sigv4::{self, S3Credentials, Signable};
use super::{Result, error, fail};

/// Environment override that permits plain http to a loopback address. The
/// tests' fake server speaks http on 127.0.0.1; production is https only, and
/// stays https only whatever this is set to for any other host.
pub(crate) const ALLOW_PLAIN_HTTP_ENV: &str = "RARPAR_CORPUS_ALLOW_PLAIN_HTTP";

/// Environment override for the user agent every transfer presents.
pub(crate) const USER_AGENT_ENV: &str = "RARPAR_CORPUS_USER_AGENT";

/// Attempts per transfer, and the pause between them: a transient refusal or a
/// 5xx is retried a bounded number of times, and then it is an answer.
const ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// A ceiling on any one response body, so a server that streams forever is a
/// failed transfer rather than an exhausted machine. The largest object in the
/// corpus is a little over 100 MiB.
const MAX_BODY_BYTES: u64 = 1 << 30;

/// The user agent every transfer presents.
///
/// The corpus domain sits behind this project's own bot defence, which refuses
/// the default agents of HTTP libraries — and a refusal is indistinguishable
/// from the object being absent, so hydration fails for every CI lane and every
/// contributor. A browser user agent is what that defence admits, so it is what
/// the busiest reader of the corpus sends.
///
/// `RARPAR_CORPUS_USER_AGENT` overrides it, so the value can follow whatever
/// the far end accepts without waiting for a release.
pub(crate) const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

/// The user agent for this transfer: the override when it is set and not
/// empty, the browser default otherwise.
pub(crate) fn user_agent() -> String {
    match std::env::var(USER_AGENT_ENV) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => DEFAULT_USER_AGENT.to_owned(),
    }
}

fn plain_http_allowed() -> bool {
    matches!(std::env::var(ALLOW_PLAIN_HTTP_ENV), Ok(value) if !value.trim().is_empty())
}

fn is_loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// The URL, parsed, with the one transport rule that is not negotiable applied
/// first: https, unless the escape hatch is set *and* the far end is this
/// machine.
fn checked_uri(url: &str) -> Result<Uri> {
    let uri: Uri = url
        .parse()
        .map_err(|source| error(format!("not a URL: {url}: {source}")))?;
    let host = uri.host().unwrap_or_default();
    match uri.scheme_str() {
        Some("https") => Ok(uri),
        Some("http") if plain_http_allowed() && is_loopback(host) => Ok(uri),
        _ => fail(format!(
            "refusing a non-https transfer: {url} (set {ALLOW_PLAIN_HTTP_ENV} for plain http to a loopback address)"
        )),
    }
}

/// The `Host` header for a URI, as HTTP/1.1 spells it: the port only when it is
/// not the scheme's default. This is signed, so it is computed here rather than
/// left to the client to fill in.
fn host_header(uri: &Uri) -> Result<String> {
    let host = uri
        .host()
        .ok_or_else(|| error(format!("URL has no host: {uri}")))?;
    let default_port = match uri.scheme_str() {
        Some("http") => 80,
        _ => 443,
    };
    Ok(match uri.port_u16() {
        Some(port) if port != default_port => format!("{host}:{port}"),
        _ => host.to_owned(),
    })
}

/// The client every transfer runs through: TLS only, no redirects (the bucket
/// domain serves objects directly, so a redirect means something else
/// answered — `max_redirects(0)` hands the 3xx back as a status, and every
/// caller here treats a non-2xx as a failure), a bounded connect, and every
/// status reported rather than raised, because a 412 from a conditional PUT is
/// an answer this tooling acts on.
fn agent() -> Agent {
    Agent::new_with_config(
        Agent::config_builder()
            .https_only(!plain_http_allowed())
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent(user_agent())
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .build(),
    )
}

/// Statuses worth trying again: the far end is unavailable or is asking for a
/// pause, not answering the question.
fn transient(status: u16) -> bool {
    status >= 500 || status == 408 || status == 429
}

/// The status of one HTTP transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Transfer {
    pub(crate) url: String,
    pub(crate) status: u16,
}

/// One planned download for `get_many`.
#[derive(Debug, Clone)]
pub(crate) struct Download {
    pub(crate) url: String,
    pub(crate) destination: PathBuf,
}

/// GET one URL, retried a bounded number of times on a transient failure. The
/// response is returned whatever its status; the caller decides what a status
/// means.
fn get(agent: &Agent, url: &str) -> Result<ureq::http::Response<ureq::Body>> {
    checked_uri(url)?;
    let mut last = format!("GET {url}: no attempt was made");
    for attempt in 1..=ATTEMPTS {
        match agent.get(url).call() {
            Ok(response) if !transient(response.status().as_u16()) => return Ok(response),
            Ok(response) => {
                last = format!("GET {url}: HTTP {} (attempt {attempt})", response.status());
            }
            Err(source) => last = format!("GET {url}: {source} (attempt {attempt})"),
        }
        if attempt < ATTEMPTS {
            std::thread::sleep(RETRY_DELAY);
        }
    }
    fail(last)
}

/// Stream a response body to a file. A body that fails midway leaves no file:
/// a partial fixture that looks present is worse than an absent one.
fn write_body(response: &mut ureq::http::Response<ureq::Body>, destination: &Path) -> Result<()> {
    let mut file = fs::File::create(destination)
        .map_err(|source| error(format!("create {}: {source}", destination.display())))?;
    let mut reader = response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .reader();
    let copied = std::io::copy(&mut reader, &mut file);
    drop(file);
    match copied {
        Ok(_) => Ok(()),
        Err(source) => {
            let _ = fs::remove_file(destination);
            fail(format!("write {}: {source}", destination.display()))
        }
    }
}

/// GET one URL to a file. Fails on any non-2xx status; the caller verifies the
/// bytes it asked for, this only moves them.
pub(crate) fn get_to_file(url: &str, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let agent = agent();
    let mut response = get(&agent, url)?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return fail(format!("GET {url} failed (HTTP {status})"));
    }
    write_body(&mut response, destination)
}

/// GET one URL into memory (small documents: manifest, bundle, provenance).
pub(crate) fn get_to_vec(url: &str) -> Result<Vec<u8>> {
    let agent = agent();
    let mut response = get(&agent, url)?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return fail(format!("GET {url} failed (HTTP {status})"));
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_vec()
        .map_err(|source| error(format!("GET {url}: {source}")))
}

/// GET many URLs with bounded parallelism, over one connection pool. Returns
/// the status of every transfer that got one — one 404 does not abort the
/// batch, because the caller treats a missing object as missing and verifies
/// every object it did get by digest.
pub(crate) fn get_many(downloads: &[Download], parallel: usize) -> Result<Vec<Transfer>> {
    if downloads.is_empty() {
        return Ok(Vec::new());
    }
    for download in downloads {
        if let Some(parent) = download.destination.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    let agent = agent();
    let workers = parallel.clamp(1, 16).min(downloads.len());
    let next = AtomicUsize::new(0);
    let mut outcomes: Vec<Option<std::result::Result<u16, String>>> =
        downloads.iter().map(|_| None).collect();
    let slots = Mutex::new(&mut outcomes);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(download) = downloads.get(index) else {
                        return;
                    };
                    let outcome = fetch_one(&agent, download).map_err(|err| err.to_string());
                    slots.lock().expect("download result lock")[index] = Some(outcome);
                }
            });
        }
    });

    let mut transfers = Vec::with_capacity(downloads.len());
    let mut failures = Vec::new();
    for (download, outcome) in downloads.iter().zip(outcomes) {
        match outcome {
            Some(Ok(status)) => transfers.push(Transfer {
                url: download.url.clone(),
                status,
            }),
            // No status at all: the caller sees a missing transfer result, and
            // the reason is on stderr rather than lost.
            Some(Err(message)) => {
                eprintln!("test-corpus: {message}");
                failures.push(message);
            }
            None => failures.push(format!("{}: never attempted", download.url)),
        }
    }
    if transfers.is_empty() && !failures.is_empty() {
        return fail(format!(
            "no transfer in a batch of {} succeeded: {}",
            downloads.len(),
            failures.join("; ")
        ));
    }
    Ok(transfers)
}

/// One download: the body lands on disk only when the status says there is
/// one, so a 404's error page never sits where a fixture belongs.
fn fetch_one(agent: &Agent, download: &Download) -> Result<u16> {
    let mut response = get(agent, &download.url)?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        write_body(&mut response, &download.destination)?;
    }
    Ok(status)
}

/// The headers a conditional SigV4 PUT carries, computed without touching the
/// network. Pure, so tests can assert exactly what is sent — and that the
/// secret is not part of it.
pub(crate) fn put_headers(
    url: &str,
    content_type: &str,
    payload_sha256: &str,
    credentials: &S3Credentials,
    timestamp: &str,
) -> Result<Vec<(String, String)>> {
    let uri = checked_uri(url)?;
    let mut headers = vec![
        ("content-type".to_owned(), content_type.to_owned()),
        ("host".to_owned(), host_header(&uri)?),
        // The write is conditional: a key is created at most once, and an
        // existing key answers 412 instead of being overwritten.
        ("if-none-match".to_owned(), "*".to_owned()),
        ("x-amz-content-sha256".to_owned(), payload_sha256.to_owned()),
        ("x-amz-date".to_owned(), timestamp.to_owned()),
    ];
    let authorization = Signable {
        method: "PUT",
        path: uri.path(),
        query: uri.query().unwrap_or_default(),
        headers: &headers,
        payload_sha256,
        timestamp,
        region: sigv4::REGION,
        service: sigv4::SERVICE,
    }
    .authorization(credentials)?;
    headers.push(("authorization".to_owned(), authorization));
    Ok(headers)
}

/// PUT a file with `If-None-Match: *`. Returns the HTTP status: 200/201 on
/// creation, 412 when the key already exists (the caller reads it back and
/// compares), anything else is the caller's error to raise. Transient failures
/// (no status at all, or 5xx) are retried a bounded number of times.
pub(crate) fn put_conditional(
    file: &Path,
    url: &str,
    content_type: &str,
    credentials: &S3Credentials,
) -> Result<u16> {
    let payload_sha256 = sigv4::sha256_file(file)?;
    let agent = agent();
    let mut last_error = String::new();
    for attempt in 1..=ATTEMPTS {
        // A fresh stamp and a fresh signature per attempt: a signature is only
        // good for a window, and a retry is a new request.
        let headers = put_headers(
            url,
            content_type,
            &payload_sha256,
            credentials,
            &sigv4::timestamp_now(),
        )?;
        let body = fs::File::open(file)
            .map_err(|source| error(format!("open {}: {source}", file.display())))?;
        let mut request = agent.put(url);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        match request.send(body) {
            Ok(response) => {
                let status = response.status().as_u16();
                if !transient(status) {
                    return Ok(status);
                }
                last_error = format!("PUT {url}: HTTP {status} (attempt {attempt})");
            }
            Err(source) => {
                last_error = format!("PUT {url}: {source} (attempt {attempt})");
            }
        }
        if attempt < ATTEMPTS {
            std::thread::sleep(Duration::from_secs(u64::from(attempt)));
        }
    }
    fail(last_error)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    /// (method, path, headers) as the fake server saw them.
    pub(crate) type SeenRequest = (String, String, Vec<String>);
    /// (method, path) → (status, body).
    pub(crate) type Route = ((&'static str, &'static str), (u16, Vec<u8>));

    /// A one-thread HTTP server that answers each request from a table and
    /// records what it saw. The client is the real one; only the far end is
    /// fake.
    pub(crate) struct FakeServer {
        pub(crate) base_url: String,
        pub(crate) requests: Arc<Mutex<Vec<SeenRequest>>>,
        /// When set, every GET on a *bare* URL is answered "absent", whatever
        /// the store holds — a CDN that cached the miss before the object
        /// existed, which is what a publication reading its own writes has to
        /// survive. A request carrying a query string still reaches the store.
        absent_on_bare_url: Arc<Mutex<bool>>,
        handle: Option<std::thread::JoinHandle<()>>,
        stop: Arc<Mutex<bool>>,
    }

    impl FakeServer {
        /// Simulate an edge that already answered "absent" for every key,
        /// before this run stored anything.
        pub(crate) fn cache_every_absence(&self) {
            *self.absent_on_bare_url.lock().unwrap() = true;
        }
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
            // See FakeServer::cache_every_absence.
            let absent_on_bare_url = Arc::new(Mutex::new(false));
            let absent_flag = absent_on_bare_url.clone();
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
                    // The query string is not part of the object's identity —
                    // a real bucket routes on the path and ignores the rest.
                    // Read-backs carry a cache-busting query, so a server that
                    // matched the whole target would miss its own objects.
                    let target = parts.next().unwrap_or("");
                    let had_query = target.contains('?');
                    let path = target
                        .split_once('?')
                        .map_or(target, |(path, _)| path)
                        .to_owned();
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
                            // A CDN in front of the bucket: a path that has
                            // once been answered "absent" keeps being answered
                            // that way on its bare URL, however long ago the
                            // object was actually stored. A request carrying a
                            // query string is a different cache key and
                            // reaches the bucket. This is what a publication
                            // reading its own writes has to survive.
                            if !had_query && *absent_flag.lock().unwrap() {
                                (404, b"not found (cached absence)".to_vec())
                            } else {
                                match store.lock().unwrap().get(&path) {
                                    Some(stored) => (200, stored.clone()),
                                    None => (404, b"not found".to_vec()),
                                }
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
                absent_on_bare_url,
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

    /// Hydration is the busiest reader of the published corpus, and the domain
    /// serving it refuses a library's default user agent — a refusal that reads
    /// as a failed download in every CI lane. Every transfer presents a browser
    /// user agent, and the environment can change it without a release.
    #[test]
    fn transfers_present_a_browser_user_agent() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(USER_AGENT_ENV) };
        assert_eq!(user_agent(), DEFAULT_USER_AGENT);
        assert!(user_agent().starts_with("Mozilla/5.0 "));
        assert!(user_agent().contains("Chrome/"));
        assert!(!user_agent().contains("ureq"));

        unsafe { std::env::set_var(USER_AGENT_ENV, "corpus-reader/9") };
        assert_eq!(user_agent(), "corpus-reader/9");
        // An empty override is not an override: a blank value would otherwise
        // send no user agent at all, which is what the default exists to avoid.
        unsafe { std::env::set_var(USER_AGENT_ENV, "   ") };
        assert_eq!(user_agent(), DEFAULT_USER_AGENT);
        unsafe { std::env::remove_var(USER_AGENT_ENV) };
    }

    /// Every transfer is https, and the one exception is a loopback address
    /// with the test escape hatch set. Plain http to anywhere else is refused
    /// whether or not the hatch is open.
    #[test]
    fn plain_http_is_refused_off_loopback() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(ALLOW_PLAIN_HTTP_ENV) };
        assert!(checked_uri("https://corpus.example.net/o").is_ok());
        assert!(checked_uri("http://127.0.0.1:8080/o").is_err());
        assert!(checked_uri("file:///etc/passwd").is_err());
        unsafe { std::env::set_var(ALLOW_PLAIN_HTTP_ENV, "1") };
        assert!(checked_uri("http://127.0.0.1:8080/o").is_ok());
        assert!(checked_uri("http://localhost:8080/o").is_ok());
        assert!(
            checked_uri("http://corpus.example.net/o").is_err(),
            "the hatch is for this machine, never for the network"
        );
        unsafe { std::env::remove_var(ALLOW_PLAIN_HTTP_ENV) };
        assert_eq!(
            host_header(&"https://acct.r2.cloudflarestorage.com/b/k".parse().unwrap()).unwrap(),
            "acct.r2.cloudflarestorage.com",
            "the default port is not in the Host header"
        );
        assert_eq!(
            host_header(&"http://127.0.0.1:8080/o".parse().unwrap()).unwrap(),
            "127.0.0.1:8080"
        );
    }

    /// What a conditional PUT carries, asserted without a network: a SigV4
    /// signature, the `If-None-Match: *` that makes the write conditional, the
    /// payload hash SigV4 requires — and no credential anywhere. There is no
    /// command line to leak one onto any more, so the guarantee is stated over
    /// the request itself, over the error a refused request produces, and over
    /// the `Debug` of the type that holds it.
    #[test]
    fn the_conditional_put_is_sigv4_and_carries_no_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(ALLOW_PLAIN_HTTP_ENV) };
        let credentials = S3Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "topsecret".into(),
        };
        let payload_sha256 = sigv4::sha256_hex(b"payload-bytes");
        let headers = put_headers(
            "https://acct.r2.cloudflarestorage.com/bucket/key",
            "application/octet-stream",
            &payload_sha256,
            &credentials,
            "20260817T101112Z",
        )
        .unwrap();
        let by_name = |name: &str| {
            headers
                .iter()
                .find(|(header, _)| header == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(by_name("if-none-match"), Some("*"));
        assert_eq!(by_name("content-type"), Some("application/octet-stream"));
        assert_eq!(by_name("host"), Some("acct.r2.cloudflarestorage.com"));
        assert_eq!(by_name("x-amz-content-sha256"), Some(&payload_sha256[..]));
        assert_eq!(by_name("x-amz-date"), Some("20260817T101112Z"));
        let authorization = by_name("authorization").expect("signed");
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert!(authorization.contains("/auto/s3/aws4_request"));
        assert!(authorization.contains(
            "SignedHeaders=content-type;host;if-none-match;x-amz-content-sha256;x-amz-date"
        ));
        // The secret is in no header, in no error, and in no Debug output.
        for (name, value) in &headers {
            assert!(!value.contains("topsecret"), "{name}: {value}");
        }
        let payload = std::env::temp_dir().join(format!(
            "xtask-corpus-put-headers-{}.bin",
            std::process::id()
        ));
        fs::write(&payload, b"payload-bytes").unwrap();
        let refused = put_conditional(
            &payload,
            "http://corpus.example.net/bucket/key",
            "application/octet-stream",
            &credentials,
        )
        .unwrap_err()
        .to_string();
        assert!(
            refused.contains("refusing a non-https transfer"),
            "{refused}"
        );
        assert!(!refused.contains("topsecret"), "{refused}");
        let _ = fs::remove_file(&payload);
        let debug = format!("{credentials:?}");
        assert!(
            debug.contains("AKIDEXAMPLE") && !debug.contains("topsecret"),
            "{debug}"
        );
    }

    /// Every transport property this tooling depends on, over a real socket:
    /// a single GET, a failed GET that leaves nothing behind, a parallel batch
    /// whose 404 does not abort it, a read-back past a cache-busting query, a
    /// conditional PUT that creates, and a conditional PUT that is refused with
    /// 412 and must stay a status rather than become an error.
    #[test]
    fn get_and_put_round_trip_over_loopback() {
        let dir = std::env::temp_dir().join(format!("xtask-corpus-http-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let server = FakeServer::start(vec![
            (("GET", "/objects/a"), (200, b"alpha".to_vec())),
            (("GET", "/objects/b"), (200, b"bravo".to_vec())),
            (("PUT", "/bucket/new"), (200, Vec::new())),
            (("PUT", "/bucket/existing"), (412, b"precondition".to_vec())),
        ]);
        // SAFETY: the environment is process-wide, so every test that reads it
        // holds this lock for the duration.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var(ALLOW_PLAIN_HTTP_ENV, "1") };

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
        // A read-back carries a cache-busting query; the client sends the URL
        // as it was spelled and the bucket, routing on the path, answers with
        // the object anyway.
        assert_eq!(
            get_to_vec(&format!(
                "{}/objects/a?rarpar-read-back={}-0",
                server.base_url,
                std::process::id()
            ))
            .unwrap(),
            b"alpha"
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
        assert!(
            !dir.join("batch/nope").exists(),
            "a 404's body is not a fixture"
        );

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
            412,
            "an existing key is an answer, not an error"
        );
        unsafe { std::env::remove_var(ALLOW_PLAIN_HTTP_ENV) };

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
            headers.contains(&format!("content-length: {}", b"payload-bytes".len())),
            "the body is length-delimited, not chunked: {headers}"
        );
        assert!(
            !headers.contains("topsecret"),
            "secret never leaves the signature"
        );
        assert!(headers.contains("content-type: application/octet-stream"));
        let get = requests
            .iter()
            .find(|(m, p, _)| m == "GET" && p == "/objects/a")
            .expect("GET observed");
        assert!(
            get.2
                .join("\n")
                .to_ascii_lowercase()
                .contains("user-agent: mozilla/5.0"),
            "the browser user agent reaches the far end: {:?}",
            get.2
        );
        drop(requests);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The cache-busting query has to survive the client, or the fix it belongs
    /// to is undone silently. A store that answers "absent" on every bare URL —
    /// the CDN behaviour a real publication hit — serves the object only to a
    /// request that still carries its token, so this passes exactly when the
    /// query string reaches the far end unaltered.
    #[test]
    fn a_cache_busting_query_reaches_the_far_end_intact() {
        let dir = std::env::temp_dir().join(format!("xtask-corpus-bust-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let server = FakeServer::start_stateful(Vec::new(), "/bucket");
        server.cache_every_absence();
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var(ALLOW_PLAIN_HTTP_ENV, "1") };

        let payload = dir.join("payload");
        fs::write(&payload, b"stored-bytes").unwrap();
        let credentials = S3Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "topsecret".into(),
        };
        let status = put_conditional(
            &payload,
            &format!("{}/bucket/objects/o", server.base_url),
            "application/octet-stream",
            &credentials,
        )
        .unwrap();
        assert_eq!(status, 200);

        let bare = format!("{}/objects/o", server.base_url);
        assert!(
            get_to_vec(&bare).is_err(),
            "the bare URL is served the cached absence"
        );
        let fresh = format!("{bare}?rarpar-read-back={}-7", std::process::id());
        assert_eq!(get_to_vec(&fresh).unwrap(), b"stored-bytes");
        unsafe { std::env::remove_var(ALLOW_PLAIN_HTTP_ENV) };

        // And the query arrived spelled the way it was written, not re-encoded
        // or dropped: the far end saw exactly one request whose path was the
        // object's, twice — once bare, once with the token.
        let requests = server.requests.lock().unwrap();
        let gets = requests
            .iter()
            .filter(|(m, p, _)| m == "GET" && p == "/objects/o")
            .count();
        assert_eq!(gets, 2, "{requests:?}");
        drop(requests);
        let _ = fs::remove_dir_all(&dir);
    }

    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
}
