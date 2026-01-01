//! ML-KEM-768 (Kyber, NIST FIPS 203). Reserved slot — not used in the
//! current analysis path (no network during analyze), but available for
//! future hybrid TLS handshakes in `seck models pull`.

use pqcrypto_mlkem::mlkem768 as kem;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

pub fn mlkem768_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kem::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn mlkem768_encapsulate(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk = kem::PublicKey::from_bytes(pk).expect("pk");
    let (ss, ct) = kem::encapsulate(&pk);
    (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
}

pub fn mlkem768_decapsulate(sk: &[u8], ct: &[u8]) -> Vec<u8> {
    let sk = kem::SecretKey::from_bytes(sk).expect("sk");
    let ct = kem::Ciphertext::from_bytes(ct).expect("ct");
    kem::decapsulate(&ct, &sk).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (pk, sk) = mlkem768_keypair();
        let (ss1, ct) = mlkem768_encapsulate(&pk);
        let ss2 = mlkem768_decapsulate(&sk, &ct);
        assert_eq!(ss1, ss2);
    }
}
