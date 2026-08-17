//! AWS Signature Version 4, for the one request shape this tooling signs: a
//! conditional PUT of one object to R2's S3 endpoint.
//!
//! SHA-256 appears here because Signature Version 4 specifies it and nothing
//! else does: the algorithm is named `AWS4-HMAC-SHA256`, the payload hash
//! travels as `x-amz-content-sha256`, and the signing chain is HMAC-SHA256.
//! It says nothing about how the corpus addresses or verifies an object —
//! that is BLAKE3 throughout.
//!
//! The secret is an HMAC key inside this process and nothing else. It is never
//! an argument to a program, never a header value, never part of an error
//! message, and never in `S3Credentials`' `Debug` output.

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};

use super::{Result, error, fail, hex, utc_now_seconds, utc_parts};

/// R2 signs in the `auto` region, with S3's service name.
pub(crate) const REGION: &str = "auto";
pub(crate) const SERVICE: &str = "s3";

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// S3-compatible credentials for R2. The secret reaches exactly one place —
/// the HMAC that derives the signing key — and no other.
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

/// The `YYYYMMDDTHHMMSSZ` stamp SigV4 signs and sends as `x-amz-date`.
pub(crate) fn timestamp(unix_seconds: u64) -> String {
    let (year, month, day, hour, minute, second) = utc_parts(unix_seconds);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

pub(crate) fn timestamp_now() -> String {
    timestamp(utc_now_seconds())
}

/// The hex SHA-256 of some bytes, as `x-amz-content-sha256` carries it.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The hex SHA-256 of a file, streamed so a 100 MiB object never sits in
/// memory just to be hashed.
pub(crate) fn sha256_file(path: &std::path::Path) -> Result<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)
        .map_err(|source| error(format!("open {}: {source}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| error(format!("read {}: {source}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

/// One request to sign. `headers` are the (lowercase name, value) pairs the
/// caller will actually send: every one of them is signed, and nothing that is
/// not listed here is.
pub(crate) struct Signable<'a> {
    pub(crate) method: &'a str,
    pub(crate) path: &'a str,
    pub(crate) query: &'a str,
    pub(crate) headers: &'a [(String, String)],
    pub(crate) payload_sha256: &'a str,
    pub(crate) timestamp: &'a str,
    pub(crate) region: &'a str,
    pub(crate) service: &'a str,
}

impl Signable<'_> {
    /// The headers as the canonical request needs them: lowercase names,
    /// trimmed values, sorted by name.
    fn sorted_headers(&self) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = self
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        headers.sort();
        headers
    }

    /// The `SignedHeaders` list: exactly the headers that are signed.
    pub(crate) fn signed_headers(&self) -> String {
        self.sorted_headers()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";")
    }

    /// The canonical request: the document whose digest is signed.
    pub(crate) fn canonical_request(&self) -> Result<String> {
        let mut canonical = String::new();
        canonical.push_str(self.method);
        canonical.push('\n');
        canonical.push_str(&canonical_path(self.path)?);
        canonical.push('\n');
        canonical.push_str(&canonical_query(self.query));
        canonical.push('\n');
        for (name, value) in self.sorted_headers() {
            canonical.push_str(&name);
            canonical.push(':');
            canonical.push_str(&value);
            canonical.push('\n');
        }
        canonical.push('\n');
        canonical.push_str(&self.signed_headers());
        canonical.push('\n');
        canonical.push_str(self.payload_sha256);
        Ok(canonical)
    }

    /// `YYYYMMDD` out of the stamp, with the stamp's shape checked: a signature
    /// over a malformed date is a signature the far end rejects for a reason
    /// nobody can see.
    fn date(&self) -> Result<&str> {
        let stamp = self.timestamp;
        let valid = stamp.len() == 16
            && stamp.is_char_boundary(8)
            && stamp.as_bytes()[8] == b'T'
            && stamp.ends_with('Z')
            && stamp[..8].bytes().all(|byte| byte.is_ascii_digit())
            && stamp[9..15].bytes().all(|byte| byte.is_ascii_digit());
        if !valid {
            return fail(format!("not an x-amz-date stamp: {stamp:?}"));
        }
        Ok(&stamp[..8])
    }

    /// The credential scope: `<date>/<region>/<service>/aws4_request`.
    pub(crate) fn scope(&self) -> Result<String> {
        Ok(format!(
            "{}/{}/{}/aws4_request",
            self.date()?,
            self.region,
            self.service
        ))
    }

    /// The string to sign: algorithm, stamp, scope, canonical request digest.
    pub(crate) fn string_to_sign(&self) -> Result<String> {
        Ok(format!(
            "{ALGORITHM}\n{}\n{}\n{}",
            self.timestamp,
            self.scope()?,
            sha256_hex(self.canonical_request()?.as_bytes())
        ))
    }

    /// The `Authorization` header value. The secret is consumed here as an
    /// HMAC key; what comes back is a signature, and the signature is all the
    /// request carries.
    pub(crate) fn authorization(&self, credentials: &S3Credentials) -> Result<String> {
        let signing_key = signing_key(
            &credentials.secret_access_key,
            self.date()?,
            self.region,
            self.service,
        );
        let signature = hex(&hmac_sha256(
            &signing_key,
            self.string_to_sign()?.as_bytes(),
        ));
        Ok(format!(
            "{ALGORITHM} Credential={}/{}, SignedHeaders={}, Signature={signature}",
            credentials.access_key_id,
            self.scope()?,
            self.signed_headers()
        ))
    }
}

/// The canonical URI: the path, percent-encoded the way SigV4 specifies for S3
/// (which encodes once, not twice).
///
/// Every key this tooling writes is `test-corpus/...` — unreserved characters
/// and `/`. A path that already carries a percent escape cannot be encoded
/// again without guessing what the far end will decode, so it fails closed
/// instead of being signed into a request the bucket would read differently.
fn canonical_path(path: &str) -> Result<String> {
    if path.contains('%') {
        return fail(format!("refusing to sign a percent-escaped path: {path}"));
    }
    if path.is_empty() {
        return Ok("/".to_owned());
    }
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte == b'/' || is_unreserved(byte) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&hex(&[byte]).to_ascii_uppercase());
        }
    }
    Ok(encoded)
}

/// The canonical query string: the URL's own pairs, sorted. The values are
/// taken as the URL already spells them, so nothing is encoded twice. Nothing
/// this tooling signs carries a query at all — a signed PUT is a bare object
/// key — so this exists to be correct rather than to be exercised.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .collect();
    pairs.sort_unstable();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// The SigV4 signing key: the secret, walked through date, region, service and
/// terminator, so the key that signs a request is useless for any other date,
/// region or service.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let mut key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    key = hmac_sha256(&key, region.as_bytes());
    key = hmac_sha256(&key, service.as_bytes());
    hmac_sha256(&key, b"aws4_request")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// AWS publishes a signing test suite; `get-vanilla` is its simplest case.
    /// Reproducing its published `Authorization` proves this implementation
    /// against something other than itself: canonical request, string to sign,
    /// the four-step key derivation and the final HMAC all have to be right for
    /// the last 64 characters to come out.
    #[test]
    fn the_published_aws_test_vector_signs_byte_for_byte() {
        let signed = headers(&[
            ("host", "example.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ]);
        let request = Signable {
            method: "GET",
            path: "/",
            query: "",
            headers: &signed,
            payload_sha256: &sha256_hex(b""),
            timestamp: "20150830T123600Z",
            region: "us-east-1",
            service: "service",
        };
        assert_eq!(
            request.canonical_request().unwrap(),
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n\
             host;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            request.string_to_sign().unwrap(),
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );
        let credentials = S3Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        };
        assert_eq!(
            request.authorization(&credentials).unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    /// The corpus publisher's own request shape, pinned: fixed key, fixed
    /// stamp, fixed payload. A refactor that changes what is signed — one more
    /// header, a different order, a dropped `if-none-match` — moves the
    /// signature, and a signature nobody pinned would move silently.
    #[test]
    fn the_conditional_put_signature_is_pinned() {
        let payload_sha256 = sha256_hex(b"payload-bytes");
        assert_eq!(
            payload_sha256,
            "808b59664b6adb9274e3bbd0766e7aec9659786c22fdb825c49ca7fda1c6236e"
        );
        let signed = headers(&[
            ("content-type", "application/octet-stream"),
            ("host", "acct.r2.cloudflarestorage.com"),
            ("if-none-match", "*"),
            ("x-amz-content-sha256", &payload_sha256),
            ("x-amz-date", "20260817T101112Z"),
        ]);
        let request = Signable {
            method: "PUT",
            path: "/corpus/test-corpus/objects/blake3/\
                   af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            query: "",
            headers: &signed,
            payload_sha256: &payload_sha256,
            timestamp: "20260817T101112Z",
            region: REGION,
            service: SERVICE,
        };
        assert_eq!(
            request.canonical_request().unwrap(),
            "PUT\n\
             /corpus/test-corpus/objects/blake3/\
             af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\n\
             \n\
             content-type:application/octet-stream\n\
             host:acct.r2.cloudflarestorage.com\n\
             if-none-match:*\n\
             x-amz-content-sha256:\
             808b59664b6adb9274e3bbd0766e7aec9659786c22fdb825c49ca7fda1c6236e\n\
             x-amz-date:20260817T101112Z\n\
             \n\
             content-type;host;if-none-match;x-amz-content-sha256;x-amz-date\n\
             808b59664b6adb9274e3bbd0766e7aec9659786c22fdb825c49ca7fda1c6236e"
        );
        assert_eq!(
            request.string_to_sign().unwrap(),
            "AWS4-HMAC-SHA256\n20260817T101112Z\n20260817/auto/s3/aws4_request\n\
             3d096de03aa7dc99e1d208857d9eb3e27b63ca914b922dab1ad99d7209dfbb7c"
        );
        let credentials = S3Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        };
        let authorization = request.authorization(&credentials).unwrap();
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260817/auto/s3/aws4_request, \
             SignedHeaders=content-type;host;if-none-match;x-amz-content-sha256;x-amz-date, \
             Signature=4a26e8d1c29a4dbc8e926ef548281a395f63d834493f00688e79226b4c7d4331"
        );
        // The signature is what travels; the secret is not in it, and it is not
        // in the type that carries it either.
        assert!(!authorization.contains("wJalrXUtnFEMI"));
        let debug = format!("{credentials:?}");
        assert!(
            debug.contains("AKIDEXAMPLE") && !debug.contains("wJalrXUtnFEMI"),
            "{debug}"
        );
    }

    #[test]
    fn stamps_and_paths_are_checked_before_anything_is_signed() {
        assert_eq!(timestamp(1_440_938_160), "20150830T123600Z");
        let signed = headers(&[("host", "h")]);
        let with_stamp = |stamp: &'static str| Signable {
            method: "PUT",
            path: "/key",
            query: "",
            headers: &signed,
            payload_sha256: "",
            timestamp: stamp,
            region: REGION,
            service: SERVICE,
        };
        assert_eq!(
            with_stamp("20150830T123600Z").scope().unwrap(),
            "20150830/auto/s3/aws4_request"
        );
        for bad in ["", "20150830", "20150830T123600", "2015083.T123600Z"] {
            assert!(with_stamp(bad).scope().is_err(), "{bad}");
        }
        // A path is encoded once, and a path that is already encoded is refused
        // rather than encoded twice into something the bucket reads differently.
        assert_eq!(canonical_path("/a b/c+d").unwrap(), "/a%20b/c%2Bd");
        assert_eq!(canonical_path("").unwrap(), "/");
        assert!(canonical_path("/already%20encoded").is_err());
        // Query pairs are sorted, and taken as the URL spells them.
        assert_eq!(canonical_query(""), "");
        assert_eq!(canonical_query("b=2&a=1&a=0"), "a=0&a=1&b=2");
    }
}
