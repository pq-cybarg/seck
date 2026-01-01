//! Report JSON schema (Plan 01 subset; Plan 06 extends with three-pass fields).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub invocation: Invocation,
    pub inputs: Vec<Input>,
    pub findings: Vec<Finding>,
    pub sandbox_attestation: Attestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invocation {
    pub nonce_sha3_256: String,
    pub started_at: String,
    pub finished_at: String,
    pub sandbox_mode: String,
    pub backend: String,
    pub model: String,
    pub model_sha3_256: String,
    pub temperature: f32,
    pub seed: u64,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Input {
    pub path: String,
    pub sha3_256: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub summary: String,
    pub files: Vec<String>,
    pub category: String,
    pub confidence: String,
    pub evidence_quote: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub platform: String,
    pub sandbox_mode: String,
    pub profile_sha3_256: String,
    pub binary_sha3_256: String,
}
