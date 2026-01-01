//! Symmetric AEAD ciphers. 256-bit keys for Grover-resistance.

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

#[derive(Debug, thiserror::Error)]
pub enum SymError {
    #[error("aead: {0}")]
    Aead(String),
}

pub fn aes256gcmsiv_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    pt: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SymError> {
    let cipher = Aes256GcmSiv::new(key.into());
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|e| SymError::Aead(e.to_string()))
}

pub fn aes256gcmsiv_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SymError> {
    let cipher = Aes256GcmSiv::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|e| SymError::Aead(e.to_string()))
}

pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    pt: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SymError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|e| SymError::Aead(e.to_string()))
}

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SymError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|e| SymError::Aead(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256gcmsiv_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let pt = b"secret";
        let aad = b"context";
        let ct = aes256gcmsiv_encrypt(&key, &nonce, pt, aad).unwrap();
        let pt2 = aes256gcmsiv_decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, pt2.as_slice());
    }

    #[test]
    fn xchacha20poly1305_round_trip() {
        let key = [0x99u8; 32];
        let nonce = [0x33u8; 24];
        let pt = b"secret";
        let aad = b"context";
        let ct = xchacha20poly1305_encrypt(&key, &nonce, pt, aad).unwrap();
        let pt2 = xchacha20poly1305_decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, pt2.as_slice());
    }
}
