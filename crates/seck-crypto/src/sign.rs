//! Post-quantum signature schemes.
//!
//! SLH-DSA = SPHINCS+ (NIST FIPS 205) — hash-based, conservative. Used for
//! release signing where signature size doesn't matter and we want the
//! lowest possible cryptographic assumption.
//!
//! ML-DSA-65 = Dilithium (NIST FIPS 204) — lattice-based, fast. Used for
//! the runtime audit log where signatures are created frequently.

use pqcrypto_mldsa::mldsa65 as mldsa;
use pqcrypto_sphincsplus::sphincsshake128ssimple as slh;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

pub type SlhPublicKey = Vec<u8>;
pub type SlhSecretKey = Vec<u8>;
pub type SlhSignature = Vec<u8>;
pub type MlPublicKey = Vec<u8>;
pub type MlSecretKey = Vec<u8>;
pub type MlSignature = Vec<u8>;

pub fn slh_dsa_keypair() -> (SlhPublicKey, SlhSecretKey) {
    let (pk, sk) = slh::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn slh_dsa_sign(sk: &SlhSecretKey, msg: &[u8]) -> SlhSignature {
    let sk = slh::SecretKey::from_bytes(sk).expect("valid sk");
    slh::detached_sign(msg, &sk).as_bytes().to_vec()
}

pub fn slh_dsa_verify(pk: &SlhPublicKey, msg: &[u8], sig: &SlhSignature) -> bool {
    let pk = match slh::PublicKey::from_bytes(pk) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match slh::DetachedSignature::from_bytes(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    slh::verify_detached_signature(&sig, msg, &pk).is_ok()
}

pub fn ml_dsa_keypair() -> (MlPublicKey, MlSecretKey) {
    let (pk, sk) = mldsa::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn ml_dsa_sign(sk: &MlSecretKey, msg: &[u8]) -> MlSignature {
    let sk = mldsa::SecretKey::from_bytes(sk).expect("valid sk");
    mldsa::detached_sign(msg, &sk).as_bytes().to_vec()
}

pub fn ml_dsa_verify(pk: &MlPublicKey, msg: &[u8], sig: &MlSignature) -> bool {
    let pk = match mldsa::PublicKey::from_bytes(pk) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match mldsa::DetachedSignature::from_bytes(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    mldsa::verify_detached_signature(&sig, msg, &pk).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slh_dsa_round_trip() {
        let (pk, sk) = slh_dsa_keypair();
        let msg = b"release: seck v0.1.0";
        let sig = slh_dsa_sign(&sk, msg);
        assert!(slh_dsa_verify(&pk, msg, &sig));
        // Tamper a byte; verification must fail.
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!slh_dsa_verify(&pk, msg, &bad));
    }

    #[test]
    fn ml_dsa_round_trip() {
        let (pk, sk) = ml_dsa_keypair();
        let msg = b"audit-record-42";
        let sig = ml_dsa_sign(&sk, msg);
        assert!(ml_dsa_verify(&pk, msg, &sig));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!ml_dsa_verify(&pk, msg, &bad));
    }
}
