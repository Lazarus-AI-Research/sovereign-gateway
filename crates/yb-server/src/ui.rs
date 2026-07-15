//! The bundled admin UI — a Preact + TSX single-page app, compiled by `rolldown`
//! at build time (see `build.rs`) into one ES module and embedded via
//! `include_str!`, so deployment is a single executable (no Docker, no separate
//! static assets, no CDN, no Node at runtime).
//!
//! Two routes, mounted only in `Selfhosted` mode:
//! - `GET /` → the SPA shell (`frontend/index.html`)
//! - `GET /ui/app.js` → the bundled Preact app (`$OUT_DIR/app.js`)
//!
//! The SPA talks to the existing `/admin/v1/*` JSON API with the admin-password
//! bearer the operator types in.

use axum::http::header;
use axum::response::{IntoResponse, Response};

/// The SPA shell (HTML + CSS). Loads `/ui/app.js`.
const INDEX_HTML: &str = include_str!("../frontend/index.html");

/// The rolldown-bundled Preact app (TSX + vendored preact, one ES module).
const APP_JS: &str = include_str!(concat!(env!("OUT_DIR"), "/app.js"));

/// `GET /` — serve the admin SPA shell.
pub async fn index() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
        .into_response()
}

/// `GET /ui/app.js` — serve the bundled admin app.
pub async fn app_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        APP_JS,
    )
        .into_response()
}
