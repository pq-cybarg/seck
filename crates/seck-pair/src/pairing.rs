//! Pairing protocol:
//!
//! 1. Desktop generates host keypair + PSK (`WgEndpoint::new_random`).
//! 2. Desktop displays a QR with `PairingBundle` JSON.
//! 3. Mobile scans, generates its own peer keypair, computes the same
//!    `fingerprint_sha3_256`, shows it to the user.
//! 4. User confirms the fingerprint matches on the desktop.
//! 5. Desktop calls `WgEndpoint::set_peer(peer_pub)`.
//!
//! The `host_endpoint` field is enforced LAN-only: if `lan_ip()` fails
//! to produce an RFC1918 / loopback address, pairing refuses to start
//! (we will never expose the desktop's WG endpoint to the open internet).

use crate::wg::WgEndpoint;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Serialize, Deserialize)]
pub struct PairingBundle {
    pub host_public_hex: String,
    pub psk_hex: String,
    /// `ip:port`, where `ip` is RFC1918, RFC4193, RFC6598, or loopback.
    pub host_endpoint: String,
    /// SHA3-256 of `host_public ‖ psk`. The mobile recomputes; the user
    /// confirms by comparing the displayed digit groups.
    pub fingerprint_sha3_256: String,
}

/// Test-friendly core: build a bundle for an explicit LAN IP.
/// Returns an error if the IP is not private/loopback.
pub fn build_bundle_with_ip(
    ep: &WgEndpoint,
    ip: std::net::IpAddr,
) -> anyhow::Result<PairingBundle> {
    if !is_private_ip(&ip) {
        anyhow::bail!("refusing to publish pairing bundle: IP {ip} is not in any private range");
    }
    let endpoint = format!("{ip}:{}", ep.bind_addr.port());
    let mut h = Sha3_256::new();
    h.update(ep.host_public);
    h.update(ep.psk);
    Ok(PairingBundle {
        host_public_hex: hex::encode(ep.host_public),
        psk_hex: hex::encode(ep.psk),
        host_endpoint: endpoint,
        fingerprint_sha3_256: hex::encode(h.finalize()),
    })
}

/// CLI entry: resolve the LAN IP from $SECK_PAIR_LAN_IP or default
/// to loopback, then call `build_bundle_with_ip`.
pub fn build_bundle(ep: &WgEndpoint) -> anyhow::Result<PairingBundle> {
    let ip = lan_ip()?;
    build_bundle_with_ip(ep, ip)
}

fn lan_ip() -> anyhow::Result<std::net::IpAddr> {
    // Permit override for headless setups + integration tests.
    if let Ok(s) = std::env::var("SECK_PAIR_LAN_IP") {
        return Ok(s.parse()?);
    }
    // Default to loopback. Real LAN discovery is a follow-up that would
    // call getifaddrs(3); for v1 the user can set SECK_PAIR_LAN_IP.
    Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

/// RFC1918 + RFC4193 + RFC6598 + loopback. Refuses public IPs.
pub fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || matches!(v4.octets(), [100, b, _, _] if (64..=127).contains(&b))
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7
        }
    }
}

/// User-facing fingerprint formatting: 64 hex chars → 8 groups of 8.
pub fn format_fingerprint(hex: &str) -> String {
    hex.as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep() -> WgEndpoint {
        WgEndpoint::new_random("127.0.0.1:51820".parse().unwrap())
    }

    #[test]
    fn builds_bundle_on_loopback() {
        let b = build_bundle_with_ip(&ep(), "127.0.0.1".parse().unwrap()).unwrap();
        assert!(b.host_endpoint.starts_with("127.0.0.1:"));
        assert_eq!(b.fingerprint_sha3_256.len(), 64);
    }

    #[test]
    fn refuses_public_ip() {
        assert!(build_bundle_with_ip(&ep(), "8.8.8.8".parse().unwrap()).is_err());
        assert!(build_bundle_with_ip(&ep(), "1.1.1.1".parse().unwrap()).is_err());
        assert!(build_bundle_with_ip(&ep(), "2606:4700:4700::1111".parse().unwrap()).is_err());
    }

    #[test]
    fn accepts_rfc1918() {
        assert!(build_bundle_with_ip(&ep(), "192.168.1.5".parse().unwrap()).is_ok());
        assert!(build_bundle_with_ip(&ep(), "10.0.0.5".parse().unwrap()).is_ok());
        assert!(build_bundle_with_ip(&ep(), "172.16.0.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn accepts_unique_local_ipv6() {
        assert!(build_bundle_with_ip(&ep(), "fd00::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn fingerprint_is_deterministic_per_endpoint() {
        let e = ep();
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let a = build_bundle_with_ip(&e, ip).unwrap().fingerprint_sha3_256;
        let b = build_bundle_with_ip(&e, ip).unwrap().fingerprint_sha3_256;
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_changes_per_endpoint() {
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let a = build_bundle_with_ip(&ep(), ip)
            .unwrap()
            .fingerprint_sha3_256;
        let b = build_bundle_with_ip(&ep(), ip)
            .unwrap()
            .fingerprint_sha3_256;
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_groups_to_8x8() {
        let f = format_fingerprint(&"a".repeat(64));
        assert_eq!(f.split(' ').count(), 8);
    }
}
