//! Plan-17 pairing service: a WireGuard endpoint on the desktop that
//! accepts exactly one paired mobile peer (a phone running the iOS
//! Share Extension or the Android share-target Activity).
//!
//! The pairing bundle is encoded as JSON and rendered as a QR code on
//! the desktop. The mobile scans, derives the same fingerprint, and the
//! user confirms-by-comparing-numbers before the desktop adds the
//! mobile's public key to the endpoint's allow-list.
//!
//! There is no cloud relay. The endpoint binds to a LAN address (or
//! loopback) only; if the LAN-detector returns a public IP, pairing
//! refuses to start. The mobile must reach the desktop directly.

pub mod pairing;
pub mod qr;
pub mod wg;

pub use pairing::PairingBundle;
pub use wg::WgEndpoint;
