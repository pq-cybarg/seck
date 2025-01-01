use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub timestamp: String,
    pub event: String,
    pub fields: BTreeMap<String, String>,
    pub prev_sha3_256: String,
    pub this_sha3_256: String,
    pub ml_dsa_signature_hex: String,
}
