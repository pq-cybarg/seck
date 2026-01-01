//! Host allowlist for model downloads. Refuses any URL whose host doesn't
//! match (or is a subdomain of) one of these.

pub const ALLOWED_HOSTS: &[&str] = &[
    "huggingface.co",
    "cdn-lfs.huggingface.co",
    "cdn-lfs-us-1.hf.co",
    "cdn-lfs-eu-1.hf.co",
    "github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

pub fn is_allowed(host: &str) -> bool {
    ALLOWED_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hosts_pass() {
        assert!(is_allowed("huggingface.co"));
        assert!(is_allowed("cdn-lfs.huggingface.co"));
        assert!(is_allowed("subdomain.huggingface.co"));
    }

    #[test]
    fn unknown_hosts_refused() {
        assert!(!is_allowed("evil.example"));
        assert!(!is_allowed("huggingface.co.evil.example"));
        assert!(!is_allowed(""));
    }
}
