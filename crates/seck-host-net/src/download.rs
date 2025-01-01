//! Streaming download with SHA3-256 verification and a host allowlist.

use crate::pin;
use std::io::Read;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum DlError {
    #[error("disallowed host: {0}")]
    DisallowedHost(String),
    #[error("sha3-256 mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },
    #[error("placeholder hash refused: {0}")]
    PlaceholderHash(String),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("url: {0}")]
    Url(String),
}

pub fn download_verified(
    url: &str,
    expected_sha3_256_hex: &str,
    dest: &Path,
) -> Result<(), DlError> {
    if expected_sha3_256_hex.to_uppercase().contains("REPLACE_AT_RELEASE") {
        return Err(DlError::PlaceholderHash(expected_sha3_256_hex.into()));
    }
    let parsed = url::Url::parse(url).map_err(|e| DlError::Url(e.to_string()))?;
    let host = parsed.host_str().ok_or_else(|| DlError::Url("no host".into()))?;
    if !pin::is_allowed(host) {
        return Err(DlError::DisallowedHost(host.into()));
    }

    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .build()?;
    let mut resp = client.get(url).send()?.error_for_status()?;
    let mut hasher = seck_crypto::hash::Hasher::new();
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(dest.parent().unwrap_or(Path::new(".")))?;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = resp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        use std::io::Write;
        tmp.write_all(&buf[..n])?;
    }
    let got = hex::encode(hasher.finalize());
    if got != expected_sha3_256_hex.to_lowercase() {
        return Err(DlError::HashMismatch {
            expected: expected_sha3_256_hex.into(),
            got,
        });
    }
    tmp.persist(dest).map_err(|e| DlError::Io(e.error))?;
    Ok(())
}
