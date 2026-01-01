//! Single-use 256-bit capability token. Each successful hit rotates the
//! token so the URL is one-shot.

use rand::TryRngCore;
use std::sync::Mutex;

pub struct TokenStore {
    current: Mutex<String>,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    pub fn new() -> Self {
        let mut t = [0u8; 32];
        rand::rng().try_fill_bytes(&mut t).expect("CSPRNG");
        Self {
            current: Mutex::new(hex::encode(t)),
        }
    }

    pub fn current_token(&self) -> String {
        self.current.lock().unwrap().clone()
    }

    pub fn check_and_rotate(&self, supplied: &str) -> bool {
        let mut g = self.current.lock().unwrap();
        if g.as_str() == supplied {
            let mut t = [0u8; 32];
            rand::rng().try_fill_bytes(&mut t).expect("CSPRNG");
            *g = hex::encode(t);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_succeeds_then_rotates() {
        let s = TokenStore::new();
        let t = s.current_token();
        assert!(s.check_and_rotate(&t));
        assert!(!s.check_and_rotate(&t)); // rotated; old token no longer valid
    }

    #[test]
    fn wrong_token_refused_and_does_not_rotate() {
        let s = TokenStore::new();
        let t = s.current_token();
        assert!(!s.check_and_rotate("not-the-token"));
        // The real token still works.
        assert!(s.check_and_rotate(&t));
    }
}
