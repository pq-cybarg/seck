# seck — Plan 11: Localhost Web UI (axum)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `seck web --port=0` serves a one-shot, server-rendered, JS-free HTML view of a report. Binds to 127.0.0.1 only (refuses 0.0.0.0). Single-use 256-bit capability token in the URL; rotates after each successful fetch. Strict CSP. All text sanitized.

**Architecture:** `crates/seck-web` using `axum` + `askama` for templates. `Bind` resolver explicitly refuses any non-loopback address at startup (unit-tested). Token in `Path`, validated against in-memory map. HTML escaping + sanitizer + CSP defense in depth.

**Tech Stack:** `axum = "0.8"`, `askama = "0.13"` (or hand-rolled `html_escape`), `tokio = "1"`, `rand = "0.9"`.

**Out of scope:** Live streaming during analysis (deferred); auth beyond the single-use token; remote access.

---

## File structure

```
seck/
├── crates/seck-web/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── bind.rs            # loopback-only resolver
│       ├── token.rs           # 256-bit single-use
│       ├── headers.rs         # CSP/COOP/CORP/etc.
│       ├── render.rs          # askama template + sanitizer
│       └── templates/
│           └── report.html
├── crates/seck-cli/src/web.rs # NEW
└── tests/web-integration/
    ├── Cargo.toml
    └── tests/{loopback_only.rs, token_rotation.rs, headers.rs, no_js.rs, html_escape.rs}
```

---

## Task 1: `Bind` resolver — loopback only

**Files:**
- Create: `crates/seck-web/src/bind.rs`
- Create: `crates/seck-web/Cargo.toml`

- [ ] **Step 1.1: Cargo.toml**

```toml
[package]
name = "seck-web"
edition.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
seck-report = { path = "../seck-report" }
axum = "0.8"
askama = "0.13"
askama_axum = "0.5"
tokio = { workspace = true, features = ["full"] }
rand.workspace = true
hex.workspace = true
serde_json.workspace = true
anyhow.workspace = true
thiserror.workspace = true
html-escape = "0.2"
```

- [ ] **Step 1.2: Failing tests `tests/loopback_only.rs` of bind**

Inside `crates/seck-web/tests/bind.rs`:

```rust
use seck_web::bind::{resolve_bind, BindError};
use std::net::IpAddr;

#[test]
fn explicit_loopback_ok() {
    let r = resolve_bind("127.0.0.1:0").unwrap();
    assert_eq!(r.ip(), IpAddr::from([127,0,0,1]));
}

#[test]
fn refuses_zero() {
    assert!(matches!(resolve_bind("0.0.0.0:0"), Err(BindError::NotLoopback(_))));
}

#[test]
fn refuses_ipv6_unspecified() {
    assert!(matches!(resolve_bind("[::]:0"), Err(BindError::NotLoopback(_))));
}

#[test]
fn refuses_lan() {
    assert!(matches!(resolve_bind("192.168.1.1:0"), Err(BindError::NotLoopback(_))));
}

#[test]
fn ipv6_localhost_ok() {
    let r = resolve_bind("[::1]:0").unwrap();
    assert!(r.ip().is_loopback());
}
```

- [ ] **Step 1.3: Impl `bind.rs`**

```rust
use ::std::net::{SocketAddr, IpAddr};

#[derive(Debug, ::thiserror::Error)]
pub enum BindError {
    #[error("not a loopback address: {0}")]
    NotLoopback(::std::string::String),
    #[error("parse: {0}")]
    Parse(::std::string::String),
}

pub fn resolve_bind(s: &str) -> Result<SocketAddr, BindError> {
    let addr: SocketAddr = s.parse().map_err(|e: ::std::net::AddrParseError| BindError::Parse(e.to_string()))?;
    let ip = addr.ip();
    if !is_loopback(&ip) { return Err(BindError::NotLoopback(addr.to_string())); }
    Ok(addr)
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback(),
    }
}
```

- [ ] **Step 1.4: Run + commit**

```bash
cargo test -p seck-web --test bind
git add crates/seck-web/ Cargo.toml
git commit -m "feat(web): loopback-only bind resolver (5 unit tests)"
```

---

## Task 2: 256-bit single-use token

**Files:**
- Create: `crates/seck-web/src/token.rs`

- [ ] **Step 2.1: Impl + tests**

```rust
use ::rand::RngCore;
use ::std::sync::Mutex;

pub struct TokenStore { current: Mutex<::std::string::String> }

impl TokenStore {
    pub fn new() -> Self { let mut s = Self { current: Mutex::new(String::new()) }; s.rotate(); s }

    pub fn rotate(&self) -> String {
        let mut t = [0u8; 32];
        ::rand::rng().fill_bytes(&mut t);
        let s = ::hex::encode(t);
        *self.current.lock().unwrap() = s.clone();
        s
    }

    /// Returns true if the token matches; on success the token is immediately rotated.
    pub fn check_and_rotate(&self, supplied: &str) -> bool {
        let mut g = self.current.lock().unwrap();
        if g.as_str() == supplied {
            *g = {
                let mut t = [0u8; 32];
                ::rand::rng().fill_bytes(&mut t);
                ::hex::encode(t)
            };
            true
        } else { false }
    }
}
```

```rust
#[test]
fn first_use_succeeds_then_rotates() {
    let s = seck_web::token::TokenStore::new();
    let t = s.current_token();
    assert!(s.check_and_rotate(&t));
    assert!(!s.check_and_rotate(&t));  // second use fails — rotated
}
```

(Add `current_token` getter.)

- [ ] **Step 2.2: Commit**

```bash
git add crates/seck-web/
git commit -m "feat(web): 256-bit single-use TokenStore"
```

---

## Task 3: Security headers middleware

**Files:**
- Create: `crates/seck-web/src/headers.rs`

- [ ] **Step 3.1: Impl**

```rust
use ::axum::http::header::{HeaderMap, HeaderValue, CONTENT_SECURITY_POLICY, REFERRER_POLICY,
                          X_CONTENT_TYPE_OPTIONS, CACHE_CONTROL};
use ::axum::middleware::Next;
use ::axum::extract::Request;
use ::axum::response::Response;

pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'none'; frame-ancestors 'none';"));
    h.insert("Cross-Origin-Resource-Policy", HeaderValue::from_static("same-origin"));
    h.insert("Cross-Origin-Opener-Policy", HeaderValue::from_static("same-origin"));
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, max-age=0"));
    resp
}
```

- [ ] **Step 3.2: Commit**

```bash
git add crates/seck-web/
git commit -m "feat(web): CSP / COOP / CORP / XFO / XCTO / Referrer-Policy middleware"
```

---

## Task 4: Template + sanitized renderer

**Files:**
- Create: `crates/seck-web/src/render.rs`
- Create: `crates/seck-web/src/templates/report.html`

- [ ] **Step 4.1: Template**

```html
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><title>seck — report</title>
<style>
  body { font: 14px/1.5 -apple-system, system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
  .finding { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.8rem; background: #eee; }
  pre { white-space: pre-wrap; background: #f6f6f6; padding: 0.5rem; }
</style></head>
<body>
<h1>seck report — {{ report.invocation.model }}</h1>
<p>sandbox: {{ report.invocation.sandbox_mode }} · backend: {{ report.invocation.backend }} · {% if report.invocation.deterministic %}deterministic{% endif %}</p>

<h2>Inputs ({{ report.inputs.len() }})</h2>
<ul>{% for i in report.inputs %}<li>{{ i.path|safe_sanitize }} <code>{{ i.sha3_256 }}</code></li>{% endfor %}</ul>

<h2>Findings</h2>
{% for f in report.findings %}
<div class="finding">
  <strong>[{{ f.id }}]</strong> {{ f.summary|safe_sanitize }}
  <p><span class="badge">{{ f.category }}</span> <span class="badge">{{ f.confidence }}</span></p>
  <pre>{{ f.evidence_quote|safe_sanitize }}</pre>
</div>
{% endfor %}
</body></html>
```

- [ ] **Step 4.2: `render.rs`**

```rust
use ::askama::Template;
use ::seck_report::schema::Report;

#[derive(Template)]
#[template(path = "report.html")]
struct ReportTemplate<'a> { report: &'a Report }

mod filters {
    pub fn safe_sanitize<T: ToString>(s: T) -> ::askama::Result<String> {
        Ok(::html_escape::encode_text(&::seck_report::sanitize::sanitize(&s.to_string())).into_owned())
    }
}

pub fn render(report: &Report) -> ::askama::Result<String> {
    ReportTemplate { report }.render()
}
```

- [ ] **Step 4.3: Commit**

```bash
git add crates/seck-web/
git commit -m "feat(web): askama template + safe_sanitize filter"
```

---

## Task 5: Server wiring

**Files:**
- Create: `crates/seck-web/src/lib.rs`
- Create: `crates/seck-cli/src/web.rs`

- [ ] **Step 5.1: lib.rs**

```rust
pub mod bind;
pub mod token;
pub mod headers;
pub mod render;

use ::axum::{Router, routing::get, extract::{Path, State}, response::Html, http::StatusCode};
use ::std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub report: ::std::sync::Arc<::seck_report::schema::Report>,
    pub tokens: ::std::sync::Arc<token::TokenStore>,
}

pub async fn serve(addr: ::std::net::SocketAddr, report: ::seck_report::schema::Report)
    -> ::anyhow::Result<()>
{
    let state = AppState {
        report: Arc::new(report),
        tokens: Arc::new(token::TokenStore::new()),
    };
    let initial_token = state.tokens.current_token();
    let app = Router::new()
        .route("/r/:token", get(report_handler))
        .layer(::axum::middleware::from_fn(headers::security_headers))
        .with_state(state);

    let listener = ::tokio::net::TcpListener::bind(addr).await?;
    let actual = listener.local_addr()?;
    ::std::println!("seck web ready at http://{}/r/{}", actual, initial_token);
    ::axum::serve(listener, app).await?;
    Ok(())
}

async fn report_handler(State(s): State<AppState>, Path(tok): Path<String>) -> Result<Html<String>, StatusCode> {
    if !s.tokens.check_and_rotate(&tok) { return Err(StatusCode::FORBIDDEN); }
    Ok(Html(render::render(&s.report).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?))
}
```

- [ ] **Step 5.2: CLI**

```rust
#[derive(::clap::Args)]
pub struct WebArgs {
    #[arg(long, default_value = "127.0.0.1:0")]
    pub bind: String,
    pub report: ::std::path::PathBuf,
}

pub fn run(args: WebArgs) -> ::anyhow::Result<()> {
    let addr = ::seck_web::bind::resolve_bind(&args.bind)?;
    let report: ::seck_report::schema::Report = ::serde_json::from_slice(&::std::fs::read(args.report)?)?;
    let rt = ::tokio::runtime::Runtime::new()?;
    rt.block_on(::seck_web::serve(addr, report))
}
```

- [ ] **Step 5.3: Commit**

```bash
git add crates/seck-web/ crates/seck-cli/
git commit -m "feat(web): server wiring + seck web CLI"
```

---

## Task 6: Integration tests — 5 invariants

**Files:**
- Create: `tests/web-integration/tests/{loopback_only.rs, token_rotation.rs, headers.rs, no_js.rs, html_escape.rs}`

- [ ] **Step 6.1: loopback_only.rs**

```rust
use assert_cmd::Command;

#[test]
fn refuses_0_0_0_0() {
    let out = Command::new("../../target/release/seck")
        .args(["web", "--bind=0.0.0.0:0", "/dev/null"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a loopback"));
}
```

- [ ] **Step 6.2: token_rotation.rs** — start server, hit URL, hit again, second hit returns 403.

- [ ] **Step 6.3: headers.rs** — assert CSP/COOP/CORP/XFO/XCTO/Referrer-Policy present.

- [ ] **Step 6.4: no_js.rs** — body must not contain `<script`.

- [ ] **Step 6.5: html_escape.rs** — feed report with `<script>alert(1)</script>` in summary; assert rendered as `&lt;script&gt;`.

- [ ] **Step 6.6: Commit**

```bash
git add tests/web-integration/ Cargo.toml
git commit -m "test(web): 5 invariants — loopback, token, headers, no-js, html escape"
```

---

## Task 7: Tag

```bash
git tag -a v0.11.0-plan11 -m "seck Plan 11: localhost web UI"
```

---

## Self-review

**Spec coverage:** §8 web UI (127.0.0.1 only, single-use token, CSP, no JS) ✓; sanitizer applied via askama filter ✓; HTML escaping additional layer ✓.

**Placeholder scan:** None.

**Type consistency:** `AppState`, `TokenStore`, `Report`/`Finding` types match `seck-report` schema.

Plan 11 complete.
