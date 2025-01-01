//! Plan-17 handshake test: two endpoints generate distinct keys + PSKs,
//! and the round-trip JSON encoding of the pairing bundle preserves
//! every field.

use seck_pair::pairing::{build_bundle_with_ip, PairingBundle};
use seck_pair::wg::WgEndpoint;

#[test]
fn endpoint_generates_unique_keys() {
    let a = WgEndpoint::new_random("127.0.0.1:0".parse().unwrap());
    let b = WgEndpoint::new_random("127.0.0.1:0".parse().unwrap());
    assert_ne!(a.host_public, b.host_public, "host_public collision");
    assert_ne!(a.psk, b.psk, "PSK collision");
    assert_ne!(a.host_private, b.host_private, "host_private collision");
}

#[test]
fn bundle_json_round_trip() {
    let ep = WgEndpoint::new_random("127.0.0.1:51820".parse().unwrap());
    let b = build_bundle_with_ip(&ep, "10.0.0.5".parse().unwrap()).unwrap();
    let json = serde_json::to_string(&b).unwrap();
    let back: PairingBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(b.host_public_hex, back.host_public_hex);
    assert_eq!(b.psk_hex, back.psk_hex);
    assert_eq!(b.host_endpoint, back.host_endpoint);
    assert_eq!(b.fingerprint_sha3_256, back.fingerprint_sha3_256);
}

#[test]
fn bundle_fingerprint_is_64_hex_chars() {
    let ep = WgEndpoint::new_random("127.0.0.1:0".parse().unwrap());
    let b = build_bundle_with_ip(&ep, "10.0.0.5".parse().unwrap()).unwrap();
    assert_eq!(b.fingerprint_sha3_256.len(), 64);
    assert!(b.fingerprint_sha3_256.chars().all(|c| c.is_ascii_hexdigit()));
}
