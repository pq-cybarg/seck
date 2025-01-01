//! Loopback-only bind resolver. Refuses 0.0.0.0, [::], LAN addresses,
//! or anything else that isn't 127.0.0.0/8 or ::1.

use std::net::{IpAddr, SocketAddr};

#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("not a loopback address: {0}")]
    NotLoopback(String),
    #[error("parse: {0}")]
    Parse(String),
}

pub fn resolve_bind(s: &str) -> Result<SocketAddr, BindError> {
    let addr: SocketAddr = s
        .parse()
        .map_err(|e: std::net::AddrParseError| BindError::Parse(e.to_string()))?;
    if !is_loopback(&addr.ip()) {
        return Err(BindError::NotLoopback(addr.to_string()));
    }
    Ok(addr)
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_loopback_ok() {
        let r = resolve_bind("127.0.0.1:0").unwrap();
        assert_eq!(r.ip(), IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn ipv6_localhost_ok() {
        let r = resolve_bind("[::1]:0").unwrap();
        assert!(r.ip().is_loopback());
    }

    #[test]
    fn refuses_0_0_0_0() {
        assert!(matches!(
            resolve_bind("0.0.0.0:0"),
            Err(BindError::NotLoopback(_))
        ));
    }

    #[test]
    fn refuses_ipv6_unspecified() {
        assert!(matches!(
            resolve_bind("[::]:0"),
            Err(BindError::NotLoopback(_))
        ));
    }

    #[test]
    fn refuses_lan() {
        assert!(matches!(
            resolve_bind("192.168.1.1:0"),
            Err(BindError::NotLoopback(_))
        ));
        assert!(matches!(
            resolve_bind("10.0.0.1:0"),
            Err(BindError::NotLoopback(_))
        ));
    }

    #[test]
    fn refuses_public() {
        assert!(matches!(
            resolve_bind("8.8.8.8:0"),
            Err(BindError::NotLoopback(_))
        ));
    }
}
