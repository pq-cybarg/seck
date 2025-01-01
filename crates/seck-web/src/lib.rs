//! Localhost-only web UI for seck reports. Strict CSP, no JS, single-use
//! capability token, refuses any non-loopback bind address.

pub mod bind;
pub mod headers;
pub mod render;
pub mod token;

pub use bind::{BindError, resolve_bind};
pub use token::TokenStore;

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Html,
    routing::get,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub report: Arc<seck_report::schema::Report>,
    pub tokens: Arc<TokenStore>,
}

pub async fn serve(
    addr: std::net::SocketAddr,
    report: seck_report::schema::Report,
) -> anyhow::Result<()> {
    let state = AppState {
        report: Arc::new(report),
        tokens: Arc::new(TokenStore::new()),
    };
    let initial = state.tokens.current_token();
    let app = Router::new()
        .route("/r/{token}", get(report_handler))
        .layer(axum::middleware::from_fn(headers::security_headers))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual = listener.local_addr()?;
    eprintln!("seck web ready at http://{actual}/r/{initial} (loopback only, single-use)");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn report_handler(
    State(s): State<AppState>,
    Path(tok): Path<String>,
) -> Result<Html<String>, StatusCode> {
    if !s.tokens.check_and_rotate(&tok) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Html(render::render(&s.report)))
}
