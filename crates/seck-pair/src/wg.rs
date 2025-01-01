//! WireGuard endpoint bound to a LAN/loopback address. Holds the host
//! keypair, the peer's expected public key (zero until pairing
//! completes), and the pre-shared key.

use rand::TryRngCore;
use x25519_dalek::{PublicKey, StaticSecret};

fn rand_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rng().try_fill_bytes(&mut b).expect("CSPRNG");
    b
}

/// A LAN-bound WireGuard endpoint. Single-peer by design.
pub struct WgEndpoint {
    pub host_private: [u8; 32],
    pub host_public: [u8; 32],
    /// All-zero until `set_peer` is called after fingerprint confirmation.
    pub peer_public: [u8; 32],
    pub psk: [u8; 32],
    pub bind_addr: std::net::SocketAddr,
}

impl WgEndpoint {
    /// Generate a fresh keypair + PSK and bind to `bind_addr`.
    pub fn new_random(bind_addr: std::net::SocketAddr) -> Self {
        // We fill 32 random bytes ourselves with the workspace's rand 0.9
        // RNG, then construct the X25519 secret from the byte array. This
        // avoids the rand_core version skew between rand 0.9 and the
        // x25519-dalek pin (rc.3) that boringtun 0.6 brings in.
        let host_private = StaticSecret::from(rand_32());
        let host_public = PublicKey::from(&host_private);
        Self {
            host_private: host_private.to_bytes(),
            host_public: host_public.to_bytes(),
            peer_public: [0u8; 32],
            psk: rand_32(),
            bind_addr,
        }
    }

    /// Authorise a paired peer after the user has confirmed the
    /// fingerprint. Refuses to overwrite an existing peer (to make
    /// re-pairing an explicit recreate-the-endpoint operation).
    pub fn set_peer(&mut self, peer_public: [u8; 32]) -> anyhow::Result<()> {
        if self.peer_public != [0u8; 32] {
            anyhow::bail!("endpoint already paired; recreate to re-pair");
        }
        if peer_public == [0u8; 32] {
            anyhow::bail!("refusing all-zero peer public key");
        }
        self.peer_public = peer_public;
        Ok(())
    }

    pub fn is_paired(&self) -> bool {
        self.peer_public != [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn distinct_keypairs() {
        let a = WgEndpoint::new_random(loopback());
        let b = WgEndpoint::new_random(loopback());
        assert_ne!(a.host_public, b.host_public);
        assert_ne!(a.psk, b.psk);
    }

    #[test]
    fn refuses_zero_peer() {
        let mut e = WgEndpoint::new_random(loopback());
        assert!(e.set_peer([0u8; 32]).is_err());
        assert!(!e.is_paired());
    }

    #[test]
    fn refuses_repair_without_recreate() {
        let mut e = WgEndpoint::new_random(loopback());
        e.set_peer([1u8; 32]).unwrap();
        assert!(e.set_peer([2u8; 32]).is_err());
    }
}
