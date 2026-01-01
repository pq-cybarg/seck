//! SHA3-256 verification of a downloaded / side-loaded model file.

use std::path::Path;

pub fn verify_file(path: &Path, expected_sha3_256_hex: &str) -> bool {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let got = hex::encode(seck_crypto::hash::sha3_256(&bytes));
    got == expected_sha3_256_hex.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_correct_hash_and_reject_tampered() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), b"hello").unwrap();
        let real = hex::encode(seck_crypto::hash::sha3_256(b"hello"));
        assert!(verify_file(f.path(), &real));
        std::fs::write(f.path(), b"world").unwrap();
        assert!(!verify_file(f.path(), &real));
    }
}
