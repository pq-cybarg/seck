//! Strict security headers middleware.

use axum::{
    extract::Request,
    http::header::{CACHE_CONTROL, HeaderValue, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS},
    middleware::Next,
    response::Response,
};

pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             script-src 'none'; frame-ancestors 'none';",
        ),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, max-age=0"));
    resp
}
