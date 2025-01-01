//! Per-pass deterministic seed: SHA3-256(invocation_nonce || role_tag).

#[derive(Debug, Clone, Copy)]
pub enum PassRole {
    Analyst,
    Auditor,
    AuditorParanoid,
    Judge,
}

impl PassRole {
    fn tag(self) -> &'static [u8] {
        match self {
            PassRole::Analyst => b"analyst",
            PassRole::Auditor => b"auditor",
            PassRole::AuditorParanoid => b"auditor-paranoid",
            PassRole::Judge => b"judge",
        }
    }
}

pub fn derive_pass_seed(nonce: &[u8; 32], role: PassRole) -> u64 {
    let mut h = seck_crypto::hash::Hasher::new();
    h.update(nonce);
    h.update(role.tag());
    let out = h.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&out[..8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_distinct_per_role() {
        let nonce = [42u8; 32];
        let a = derive_pass_seed(&nonce, PassRole::Analyst);
        let b = derive_pass_seed(&nonce, PassRole::Analyst);
        assert_eq!(a, b);
        let c = derive_pass_seed(&nonce, PassRole::Auditor);
        assert_ne!(a, c);
        let d = derive_pass_seed(&nonce, PassRole::AuditorParanoid);
        assert_ne!(c, d);
        let e = derive_pass_seed(&nonce, PassRole::Judge);
        assert_ne!(a, e);
        assert_ne!(c, e);
        assert_ne!(d, e);
    }
}
