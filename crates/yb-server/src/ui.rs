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
use std::sync::LazyLock;

/// The SPA shell (HTML + CSS). Loads `/ui/app.js`.
const INDEX_HTML: &str = include_str!("../frontend/index.html");

/// The rolldown-bundled Preact app (TSX + vendored preact, one ES module).
const APP_JS: &str = include_str!(concat!(env!("OUT_DIR"), "/app.js"));

/// A short content hash of the bundle, used as its cache-busting version.
static APP_HASH: LazyLock<String> =
    LazyLock::new(|| crate::hex_sha256(APP_JS)[..12].to_string());

/// The shell with the bundle's `src` pinned to the current build's hash.
///
/// `no-cache` on the script is not enough on its own: a CDN in front of the
/// gateway may rewrite it (Cloudflare's default Browser Cache TTL replaces it
/// with `max-age=14400`), and the browser then holds a stale bundle for hours
/// after a deploy while the shell — uncached, because it is HTML — keeps
/// pointing at the same URL. Naming the bundle by its content makes a new build
/// a new URL, so no cache anywhere can serve the old one.
static INDEX_WITH_VERSION: LazyLock<String> =
    LazyLock::new(|| INDEX_HTML.replace("/ui/app.js", &format!("/ui/app.js?v={}", *APP_HASH)));

/// `GET /` — serve the admin SPA shell.
pub async fn index() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // The shell carries the bundle's version, so it must never be stale.
            (header::CACHE_CONTROL, "no-cache"),
        ],
        INDEX_WITH_VERSION.as_str(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_pins_the_bundle_to_its_content_hash() {
        // The shell must not reference the bare URL: an unversioned src is
        // exactly what lets a CDN serve a stale bundle after a deploy.
        assert!(INDEX_HTML.contains("/ui/app.js"), "shell loads the bundle");
        let versioned = format!("/ui/app.js?v={}", *APP_HASH);
        assert!(INDEX_WITH_VERSION.contains(&versioned));
        assert!(!INDEX_WITH_VERSION.contains("\"/ui/app.js\""));

        // The hash is the bundle's, so it changes whenever the bundle does.
        assert_eq!(APP_HASH.len(), 12);
        assert!(crate::hex_sha256(APP_JS).starts_with(APP_HASH.as_str()));
    }
}
