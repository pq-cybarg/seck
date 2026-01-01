use crate::entry::Entry;
use crate::manifest::Manifest;

pub fn list(m: &Manifest) -> &[Entry] {
    &m.entries
}

/// Pick the largest model whose recommended_min_ram_gb fits the given
/// available RAM. Returns None if no model fits.
pub fn recommend_for_ram(m: &Manifest, ram_gb: u32) -> Option<&Entry> {
    m.entries
        .iter()
        .filter(|e| e.recommended_min_ram_gb <= ram_gb)
        .max_by(|a, b| {
            a.params_billion
                .partial_cmp(&b.params_billion)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Entry;

    fn fixture() -> Manifest {
        Manifest {
            version: "0.1.0".into(),
            entries: vec![
                Entry {
                    name: "small".into(),
                    base_arch: "x".into(),
                    params_billion: 1.5,
                    gguf_url: "u".into(),
                    sha3_256: "0".repeat(64),
                    recommended_min_ram_gb: 4,
                    license: "x".into(),
                    source: "x".into(),
                },
                Entry {
                    name: "medium".into(),
                    base_arch: "x".into(),
                    params_billion: 8.0,
                    gguf_url: "u".into(),
                    sha3_256: "0".repeat(64),
                    recommended_min_ram_gb: 12,
                    license: "x".into(),
                    source: "x".into(),
                },
                Entry {
                    name: "large".into(),
                    base_arch: "x".into(),
                    params_billion: 30.0,
                    gguf_url: "u".into(),
                    sha3_256: "0".repeat(64),
                    recommended_min_ram_gb: 24,
                    license: "x".into(),
                    source: "x".into(),
                },
            ],
        }
    }

    #[test]
    fn picks_largest_that_fits() {
        let m = fixture();
        assert_eq!(recommend_for_ram(&m, 4).unwrap().name, "small");
        assert_eq!(recommend_for_ram(&m, 16).unwrap().name, "medium");
        assert_eq!(recommend_for_ram(&m, 32).unwrap().name, "large");
        assert!(recommend_for_ram(&m, 2).is_none());
    }
}
