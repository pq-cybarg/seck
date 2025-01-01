//! Post-quantum crypto primitives for seck. Every cryptographic operation
//! in the project routes through this crate. Algorithms:
//!
//!   * Hashing: SHA3-256 (Keccak)
//!   * Release signatures: SLH-DSA-SHAKE-128s (SPHINCS+, FIPS 205)
//!   * Runtime signatures: ML-DSA-65 (Dilithium, FIPS 204)
//!   * KEM: ML-KEM-768 (Kyber, FIPS 203) — reserved
//!   * Memory-hard KDF: Argon2id (m≥512 MiB, t≥4, p≥4)
//!   * Symmetric AEAD: AES-256-GCM-SIV, XChaCha20-Poly1305

pub mod device_key;
pub mod fips;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod sign;
pub mod sym;
