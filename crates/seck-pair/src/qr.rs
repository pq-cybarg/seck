//! Render a string as a terminal-ready QR code (Unicode half-block).
//! Used by the `seck pair` CLI to display the `PairingBundle` for the
//! mobile to scan.

use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

pub fn render(s: &str) -> String {
    let code = QrCode::new(s.as_bytes()).expect("encode");
    code.render::<Dense1x2>().quiet_zone(true).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_non_empty() {
        let q = render("test");
        assert!(!q.is_empty());
    }

    #[test]
    fn renders_json_bundle() {
        // Just a smoke test: encode some bundle-shaped JSON.
        let q = render(
            r#"{"host_public_hex":"aa..","psk_hex":"bb..","host_endpoint":"127.0.0.1:51820"}"#,
        );
        assert!(q.lines().count() > 4);
    }
}
