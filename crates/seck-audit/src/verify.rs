use crate::record::Record;
use serde_json::json;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("hash chain broken at record {0}")]
    ChainBreak(usize),
    #[error("hash mismatch at record {0}")]
    HashMismatch(usize),
    #[error("signature invalid at record {0}")]
    BadSig(usize),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Walks the chain in `path`, verifying:
///   * each record's `prev_sha3_256` matches the previous record's
///     `this_sha3_256` (or the genesis sentinel `0`×64 for the first
///     record);
///   * each record's `this_sha3_256` is SHA3-256 of the canonical body;
///   * each record's `ml_dsa_signature_hex` verifies under `pk`.
///
/// Returns the chain tip hash on success.
pub fn verify_chain(path: &Path, pk: &[u8]) -> Result<String, VerifyError> {
    let content = std::fs::read_to_string(path)?;
    let mut prev = "0".repeat(64);
    let mut tip = prev.clone();
    for (i, line) in content.lines().enumerate() {
        let rec: Record = serde_json::from_str(line)?;
        if rec.prev_sha3_256 != prev {
            return Err(VerifyError::ChainBreak(i));
        }
        let body = json!({
            "timestamp": rec.timestamp,
            "event": rec.event,
            "fields": rec.fields,
            "prev_sha3_256": prev,
        });
        let body_bytes = serde_json::to_vec(&body)?;
        let computed = hex::encode(seck_crypto::hash::sha3_256(&body_bytes));
        if computed != rec.this_sha3_256 {
            return Err(VerifyError::HashMismatch(i));
        }
        let sig = hex::decode(&rec.ml_dsa_signature_hex).map_err(|_| VerifyError::BadSig(i))?;
        if !seck_crypto::sign::ml_dsa_verify(&pk.to_vec(), &body_bytes, &sig) {
            return Err(VerifyError::BadSig(i));
        }
        prev = rec.this_sha3_256.clone();
        tip = prev.clone();
    }
    Ok(tip)
}
