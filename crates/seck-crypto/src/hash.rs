//! SHA3-256 (Keccak) hashing. SHA-2 is intentionally not exposed.

use sha3::{Digest, Sha3_256};

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub struct Hasher(Sha3_256);

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self(Sha3_256::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finalize(self) -> [u8; 32] {
        let out = self.0.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST KAT for SHA3-256("").
    #[test]
    fn kat_empty() {
        let h = sha3_256(b"");
        assert_eq!(
            hex::encode(h),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    /// NIST KAT for SHA3-256("abc").
    #[test]
    fn kat_abc() {
        let h = sha3_256(b"abc");
        assert_eq!(
            hex::encode(h),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }
}
