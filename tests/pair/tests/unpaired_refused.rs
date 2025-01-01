//! Plan-17: an endpoint must refuse to set an all-zero peer key
//! (the sentinel that means "unpaired") and must refuse to re-pair
//! without explicitly recreating the endpoint.

use seck_pair::wg::WgEndpoint;

#[test]
fn refuses_zero_peer() {
    let mut e = WgEndpoint::new_random("127.0.0.1:0".parse().unwrap());
    assert!(e.set_peer([0u8; 32]).is_err());
    assert!(!e.is_paired());
}

#[test]
fn refuses_silent_repair() {
    let mut e = WgEndpoint::new_random("127.0.0.1:0".parse().unwrap());
    e.set_peer([1u8; 32]).unwrap();
    assert!(e.is_paired());
    // Trying to swap the peer must be rejected; re-pair = recreate.
    assert!(e.set_peer([2u8; 32]).is_err());
}

#[test]
fn new_endpoint_is_unpaired() {
    let e = WgEndpoint::new_random("127.0.0.1:0".parse().unwrap());
    assert!(!e.is_paired());
    assert_eq!(e.peer_public, [0u8; 32]);
}
