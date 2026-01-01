use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub base_arch: String,
    pub params_billion: f32,
    pub gguf_url: String,
    pub sha3_256: String,
    pub recommended_min_ram_gb: u32,
    pub license: String,
    pub source: String,
}
