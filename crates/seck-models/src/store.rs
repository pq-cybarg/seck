//! Model cache layout:
//!   Unix:    `$XDG_CACHE_HOME/seck/models/<sha3-prefix>/<basename>`
//!            (falls back to `/tmp/seck-models` if XDG isn't usable).
//!   Windows: `%LOCALAPPDATA%/seck/models/<sha3-prefix>/<basename>`
//!            (falls back to `C:\Temp\seck-models`).

use std::path::PathBuf;

#[cfg(unix)]
fn cache_root() -> PathBuf {
    xdg::BaseDirectories::new()
        .ok()
        .and_then(|b| b.create_cache_directory("seck/models").ok())
        .unwrap_or_else(|| PathBuf::from("/tmp/seck-models"))
}

#[cfg(windows)]
fn cache_root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|p| p.join("seck").join("models"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Temp\seck-models"))
}

pub fn store_path(sha3_256_hex: &str, gguf_url: &str) -> PathBuf {
    let base = cache_root();
    let prefix = &sha3_256_hex.get(..16).unwrap_or(sha3_256_hex);
    let basename = gguf_url.rsplit('/').next().unwrap_or("model.gguf");
    base.join(prefix).join(basename)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_uses_prefix_and_basename() {
        let p = store_path(
            "abcdef0123456789aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://example.com/path/to/model.gguf",
        );
        assert!(p.to_string_lossy().contains("abcdef0123456789"));
        assert!(p.file_name().unwrap().to_string_lossy() == "model.gguf");
    }
}
