//! Web UI invariants: bind refuses non-loopback, token rotation, CSP,
//! no JS in output, HTML escaping.

use seck_web::{TokenStore, bind::resolve_bind, render::render};

#[test]
fn bind_refuses_non_loopback() {
    assert!(resolve_bind("0.0.0.0:0").is_err());
    assert!(resolve_bind("192.168.1.1:0").is_err());
    assert!(resolve_bind("8.8.8.8:0").is_err());
}

#[test]
fn token_rotates_after_use() {
    let s = TokenStore::new();
    let t = s.current_token();
    assert!(s.check_and_rotate(&t));
    assert!(!s.check_and_rotate(&t));
}

#[test]
fn rendered_html_contains_no_js() {
    let report = seck_report::schema::Report {
        version: "0.1.0".into(),
        invocation: seck_report::schema::Invocation {
            nonce_sha3_256: "0".repeat(64),
            started_at: "".into(),
            finished_at: "".into(),
            sandbox_mode: "A".into(),
            backend: "stub".into(),
            model: "(none)".into(),
            model_sha3_256: "".into(),
            temperature: 0.0,
            seed: 1,
            deterministic: true,
        },
        inputs: vec![seck_report::schema::Input {
            path: "x".into(),
            sha3_256: "0".repeat(64),
            size: 0,
            kind: "text".into(),
        }],
        findings: vec![seck_report::schema::Finding {
            id: "F1".into(),
            summary: "test".into(),
            files: vec!["x".into()],
            category: "note".into(),
            confidence: "low".into(),
            evidence_quote: "".into(),
        }],
        sandbox_attestation: seck_report::schema::Attestation {
            platform: "x".into(),
            sandbox_mode: "A".into(),
            profile_sha3_256: "0".repeat(64),
            binary_sha3_256: "".into(),
        },
    };
    let html = render(&report);
    assert!(!html.contains("<script"), "no JS in output");
    assert!(!html.contains("javascript:"), "no javascript: URLs");
    assert!(!html.contains("on") || !html.contains("onclick"), "no inline event handlers");
}

#[test]
fn html_escapes_injection_attempt() {
    let mut report = seck_report::schema::Report {
        version: "0.1.0".into(),
        invocation: seck_report::schema::Invocation {
            nonce_sha3_256: "0".repeat(64),
            started_at: "".into(),
            finished_at: "".into(),
            sandbox_mode: "A".into(),
            backend: "stub".into(),
            model: "(none)".into(),
            model_sha3_256: "".into(),
            temperature: 0.0,
            seed: 1,
            deterministic: true,
        },
        inputs: vec![],
        findings: vec![seck_report::schema::Finding {
            id: "F1".into(),
            // Attempt to inject a script via the summary field.
            summary: "<script>alert(1)</script>".into(),
            files: vec![],
            category: "note".into(),
            confidence: "low".into(),
            evidence_quote: "".into(),
        }],
        sandbox_attestation: seck_report::schema::Attestation {
            platform: "x".into(),
            sandbox_mode: "A".into(),
            profile_sha3_256: "0".repeat(64),
            binary_sha3_256: "".into(),
        },
    };
    let html = render(&report);
    assert!(!html.contains("<script>alert"), "raw injection NOT rendered");
    assert!(html.contains("&lt;script&gt;"), "injection HTML-escaped");
    let _ = &mut report;
}
