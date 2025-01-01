//! Plan-17: the pairing bundle must only ever advertise a
//! private/loopback host endpoint. A public IP is a refusal — pairing
//! over the open internet is not supported.

use seck_pair::pairing::{build_bundle_with_ip, is_private_ip};
use seck_pair::wg::WgEndpoint;

fn ep() -> WgEndpoint {
    WgEndpoint::new_random("127.0.0.1:51820".parse().unwrap())
}

#[test]
fn private_ips_accepted() {
    for ip_str in [
        "127.0.0.1", "192.168.1.5", "10.0.0.5", "172.16.0.1",
        "169.254.1.1", "100.64.0.1",
    ] {
        let ip: std::net::IpAddr = ip_str.parse().unwrap();
        assert!(is_private_ip(&ip), "{ip_str} should be private");
        assert!(
            build_bundle_with_ip(&ep(), ip).is_ok(),
            "bundle for {ip_str} should build"
        );
    }
}

#[test]
fn public_ips_refused() {
    for ip_str in [
        "8.8.8.8", "1.1.1.1", "208.67.222.222",
        "2606:4700:4700::1111", "2001:db8::1",
    ] {
        let ip: std::net::IpAddr = ip_str.parse().unwrap();
        assert!(!is_private_ip(&ip), "{ip_str} should be public");
        assert!(
            build_bundle_with_ip(&ep(), ip).is_err(),
            "bundle for {ip_str} should be refused"
        );
    }
}

#[test]
fn ipv6_loopback_and_ula_accepted() {
    let lo: std::net::IpAddr = "::1".parse().unwrap();
    let ula: std::net::IpAddr = "fd00::1".parse().unwrap();
    assert!(is_private_ip(&lo));
    assert!(is_private_ip(&ula));
    assert!(build_bundle_with_ip(&ep(), lo).is_ok());
    assert!(build_bundle_with_ip(&ep(), ula).is_ok());
}
