use crate::entry::Entry;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub entries: Vec<Entry>,
}

pub fn parse(toml_str: &str) -> Result<Manifest, toml::de::Error> {
    toml::from_str(toml_str)
}

pub fn serialize(m: &Manifest) -> Result<String, toml::ser::Error> {
    toml::to_string(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let m = Manifest {
            version: "0.1.0".into(),
            entries: vec![Entry {
                name: "qwen3-coder-30b".into(),
                base_arch: "qwen3".into(),
                params_billion: 30.0,
                gguf_url:
                    "https://huggingface.co/Qwen/Qwen3-Coder-30B-Instruct-GGUF/resolve/main/qwen3-coder-30b-instruct-q4_k_m.gguf"
                        .into(),
                sha3_256: "0".repeat(64),
                recommended_min_ram_gb: 24,
                license: "Apache-2.0".into(),
                source: "Alibaba Qwen team".into(),
            }],
        };
        let s = serialize(&m).unwrap();
        let m2 = parse(&s).unwrap();
        assert_eq!(m.entries.len(), m2.entries.len());
        assert_eq!(m.entries[0].name, m2.entries[0].name);
    }
}
