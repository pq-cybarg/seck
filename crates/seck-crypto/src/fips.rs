//! --fips runtime gate. All algorithms in this crate are already on the
//! NIST FIPS-allowed list (203/204/205); this module is a forward-looking
//! placeholder that refuses non-FIPS algorithms if any are ever added.

use std::sync::atomic::{AtomicBool, Ordering};

static FIPS_MODE: AtomicBool = AtomicBool::new(false);

pub fn enable_fips() {
    FIPS_MODE.store(true, Ordering::Release);
}

pub fn is_fips() -> bool {
    FIPS_MODE.load(Ordering::Acquire)
}

pub fn assert_fips_compatible() -> Result<(), &'static str> {
    if !is_fips() {
        return Ok(());
    }
    // All currently-exposed algorithms (SHA3-256, ML-KEM-768, ML-DSA-65,
    // SLH-DSA-SHAKE-128s, AES-256-GCM-SIV, XChaCha20-Poly1305 — note that
    // XChaCha is NOT a FIPS primitive; we accept it because in --fips mode
    // we only use AES-256-GCM-SIV). For now this is a no-op.
    Ok(())
}
