//! Argon2id — memory-hard key derivation.
//!
//! Parameters: m≥512 MiB memory cost, t≥4 iterations, p≥4 parallelism.
//! The `argon2id_safe` variant clamps each parameter to the floor, so an
//! attacker who controls the inputs cannot downgrade.

use argon2::{Algorithm, Argon2, Params, Version};

/// Default memory cost in kibibytes (524288 KiB = 512 MiB).
pub const DEFAULT_M_KIB: u32 = 524288;
/// Default time cost (iterations).
pub const DEFAULT_T: u32 = 4;
/// Default parallelism.
pub const DEFAULT_P: u32 = 4;

pub fn argon2id(pass: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> [u8; 32] {
    let params = Params::new(m_kib, t, p, Some(32)).expect("valid params");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(pass, salt, &mut out).expect("KDF");
    out
}

/// Clamp each parameter to the safe floor. Callers can pass higher values
/// but never lower.
pub fn argon2id_safe(pass: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> [u8; 32] {
    let m = m_kib.max(DEFAULT_M_KIB);
    let t = t.max(DEFAULT_T);
    let p = p.max(DEFAULT_P);
    argon2id(pass, salt, m, t, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_inputs() {
        let s1 = argon2id(b"passphrase", b"saltsaltsaltsalt", 16, 1, 1);
        let s2 = argon2id(b"passphrase", b"saltsaltsaltsalt", 16, 1, 1);
        assert_eq!(s1, s2);
    }

    #[test]
    fn distinct_for_distinct_salts() {
        let s1 = argon2id(b"pw", b"saltA-padded-16!", 16, 1, 1);
        let s2 = argon2id(b"pw", b"saltB-padded-16!", 16, 1, 1);
        assert_ne!(s1, s2);
    }

    /// argon2id_safe clamps below-floor params upward.
    #[test]
    fn safe_clamps_low_params_upward() {
        // The clamped result MUST equal the result of running with the
        // floor values, not the user-supplied small ones.
        let result_safe = argon2id_safe(b"pw", b"saltsaltsaltsalt", 1, 1, 1);
        let result_floor =
            argon2id(b"pw", b"saltsaltsaltsalt", DEFAULT_M_KIB, DEFAULT_T, DEFAULT_P);
        assert_eq!(result_safe, result_floor);
    }
}
