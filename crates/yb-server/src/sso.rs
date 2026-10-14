//! Client for the external identity provider's **direct, non-SAML** login API,
//! spoken over SPIFFE mTLS.
//!
//! The IdP ("SSO identity service, no JWT") exposes a small server-to-server
//! contract on its mTLS listener only. The gateway is a *relying party*: it
//! presents its own X.509-SVID (via greater-spire), the IdP maps that SPIFFE id
//! to a service name which must equal the body's `client_id`, and on success the
//! gateway maps the returned identity onto a local user + its own `yb_session`
//! cookie. There is no shared secret anywhere on the wire; the gateway in turn
//! verifies that the server presents the SPIFFE id named in `[peers.sso]`.
//!
//! Wire contract (all JSON, no JWT — every IdP token is an opaque DB string):
//! - `POST /api/login/start`  `{client_id, email, callback_base}`
//!   → `200 {ok:true, dev_link?, dev_code?}`. Emails a magic link
//!   (`{callback_base}/auth/verify?lt=<token>`) **and** a 6-digit code to a known
//!   active user; always `ok:true` (no account enumeration).
//! - `POST /api/login/code`   `{client_id, email, code}`
//!   → `{user:{id,email,name}, role}` or `400 {error:"invalid_code"|"expired"|...}`.
//! - `POST /api/login/verify` `{client_id, token}` (the emailed link token)
//!   → same success shape.
//! - `POST /api/session/introspect` / `logout` `{client_id, session}`.
//! - `POST /api/users/invite` `{client_id, email, name?}`.
//!
//! The transport is greater-spire's [`HttpClient`]: bound to the one configured
//! origin, pins `Host`, and refuses a server whose SVID is not the expected
//! SPIFFE id. Its request timeout ends at response headers, so the body read is
//! bounded here (size and time) before it is parsed.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use greater_spire::{HttpClient, IdentityRuntime, IdentityStatus};
use http_body_util::{BodyExt, Full};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::watch;
use yb_core::config::SsoAuthConfig;
use yb_core::{Error, Result};

/// The name of the IdP in the identity file's `[peers.*]` table.
pub const SSO_PEER: &str = "sso";
/// The service name greater-spire uses for `/etc/greater-spire/<service>.toml`
/// discovery; the gateway always names its file explicitly, so this is only a
/// label.
const SERVICE_NAME: &str = "gateway";
/// Largest IdP response body read; anything bigger is an error, not a hang.
const MAX_BODY_BYTES: usize = 64 * 1024;
/// One bound for the whole exchange: connect, handshake, headers, and body.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The gateway's own SPIFFE identity: the greater-spire runtime that loads and
/// refreshes the SVID every outbound SSO connection presents. Exactly one lives
/// for the life of the process (in [`crate::AppState`]) and is shut down at exit;
/// shutting it down invalidates every [`SsoClient`] built from it.
pub struct SsoIdentity {
    runtime: Mutex<Option<IdentityRuntime>>,
    status: watch::Receiver<IdentityStatus>,
}

impl std::fmt::Debug for SsoIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoIdentity")
            .field("usable", &self.status().usable)
            .finish()
    }
}

impl SsoIdentity {
    /// Load the identity file and start refreshing credentials from it. Fails
    /// closed: a missing or invalid file, or an SVID that does not match the
    /// configured SPIFFE id, is an error here rather than at the first login.
    pub async fn start(identity_config: &Path) -> Result<SsoIdentity> {
        let config = greater_spire::Config::load(SERVICE_NAME, Some(identity_config))
            .map_err(|e| Error::Config(format!("sso identity_config: {e}")))?;
        if !config.peers.contains_key(SSO_PEER) {
            return Err(Error::Config(format!(
                "sso identity_config {}: no [peers.{SSO_PEER}] table (the SSO's mTLS url and SPIFFE id)",
                identity_config.display()
            )));
        }
        let runtime = IdentityRuntime::start(config)
            .await
            .map_err(|e| Error::Config(format!("sso identity: {e}")))?;
        let status = runtime.watch();
        Ok(SsoIdentity {
            runtime: Mutex::new(Some(runtime)),
            status,
        })
    }

    /// A pooled client for the `sso` peer, verifying its SPIFFE id on connect.
    pub fn http_client(&self) -> Result<HttpClient> {
        let guard = self
            .runtime
            .lock()
            .map_err(|_| Error::Internal("sso identity lock poisoned".into()))?;
        guard
            .as_ref()
            .ok_or_else(|| Error::Internal("sso identity has been shut down".into()))?
            .http_client(SSO_PEER)
            .map_err(|e| Error::Config(format!("sso peer: {e}")))
    }

    /// Current credential usability and refresh health (for logs/readiness).
    pub fn status(&self) -> IdentityStatus {
        self.status.borrow().clone()
    }

    /// Stop credential refresh and invalidate transport handles. Idempotent.
    /// Call after the HTTP server has stopped serving.
    pub async fn shutdown(&self) {
        let runtime = match self.runtime.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(mut runtime) = runtime {
            runtime.shutdown().await;
        }
    }
}

/// A configured relying-party client for one IdP.
#[derive(Clone)]
pub struct SsoClient {
    http: HttpClient,
    client_id: String,
    callback_base: String,
}

impl std::fmt::Debug for SsoClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoClient")
            .field("peer", self.http.expected_peer())
            .field("client_id", &self.client_id)
            .field("callback_base", &self.callback_base)
            .finish()
    }
}

/// The identity the IdP resolved for a completed login. Note: the IdP's own
/// `role` field is intentionally **not** consumed — the gateway owns authorization
/// (roles are managed in the gateway, not derived from the IdP). `session` carries
/// the unified cross-app session token the IdP minted, if any.
#[derive(Debug, Clone)]
pub struct SsoUser {
    pub email: String,
    pub name: Option<String>,
    /// The IdP-issued shared session token (for the `lzr_session` cookie).
    pub session: Option<String>,
}

/// The outcome of `start`: `ok` plus, in the IdP's dev mode, the code/link it
/// would have emailed (so headless smoke tests can complete the flow).
#[derive(Debug, Clone, Default)]
pub struct StartOutcome {
    pub dev_code: Option<String>,
    pub dev_link: Option<String>,
}

impl SsoClient {
    /// Start the gateway's SPIFFE identity from `[auth.sso]` and build the
    /// client over it. Returns `Ok(None)` when the config is incomplete (no
    /// `identity_config` or `client_id`), so the provider is simply treated as
    /// unavailable; an identity file that cannot be loaded is an error.
    pub async fn connect(cfg: &SsoAuthConfig) -> Result<Option<(SsoIdentity, SsoClient)>> {
        if !cfg.is_complete() {
            return Ok(None);
        }
        let identity = SsoIdentity::start(Path::new(&cfg.identity_config)).await?;
        let client = match identity.http_client() {
            Ok(http) => SsoClient::new(http, cfg),
            Err(e) => {
                identity.shutdown().await;
                return Err(e);
            }
        };
        Ok(Some((identity, client)))
    }

    /// Build a client over an already-started identity's `sso` peer client.
    pub fn new(http: HttpClient, cfg: &SsoAuthConfig) -> SsoClient {
        SsoClient {
            http,
            client_id: cfg.client_id.clone(),
            callback_base: cfg.callback_base.trim_end_matches('/').to_string(),
        }
    }

    /// `POST /api/login/start` — ask the IdP to email a code + magic link to
    /// `email`. Always succeeds for a known client (no enumeration); surfaces the
    /// IdP's dev passthrough when present. `turnstile_token` is forwarded to the
    /// IdP (which validates it when the client requires a bot check).
    pub async fn start(&self, email: &str, turnstile_token: Option<&str>) -> Result<StartOutcome> {
        let mut body = json!({
            "email": email,
            "callback_base": self.callback_base,
        });
        if let Some(tok) = turnstile_token {
            body["turnstile_token"] = json!(tok);
        }
        let v = self.post_json("/api/login/start", body).await?;
        // A bad client / disallowed callback_base / failed bot check comes back
        // as {error: ...}.
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            return Err(Error::Unauthorized(format!("sso start rejected: {err}")));
        }
        Ok(StartOutcome {
            dev_code: v
                .get("dev_code")
                .and_then(|c| c.as_str())
                .map(str::to_string),
            dev_link: v
                .get("dev_link")
                .and_then(|c| c.as_str())
                .map(str::to_string),
        })
    }

    /// `POST /api/login/code` — complete a login with the typed 6-digit code.
    pub async fn code(&self, email: &str, code: &str) -> Result<SsoUser> {
        let body = json!({
            "email": email,
            "code": code,
        });
        self.complete("/api/login/code", body).await
    }

    /// `POST /api/login/verify` — complete a login with the emailed link token.
    pub async fn verify(&self, token: &str) -> Result<SsoUser> {
        let body = json!({
            "token": token,
        });
        self.complete("/api/login/verify", body).await
    }

    /// Shared success/error handling for the two completion endpoints.
    async fn complete(&self, path: &str, body: serde_json::Value) -> Result<SsoUser> {
        let v = self.post_json(path, body).await?;
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            // invalid_code / expired / invalid_token / invalid_client — all 401 to the client.
            return Err(Error::Unauthorized(format!("sso login failed: {err}")));
        }
        #[derive(Deserialize)]
        struct UserRole {
            user: UserObj,
            #[serde(default)]
            session: Option<String>,
        }
        #[derive(Deserialize)]
        struct UserObj {
            email: String,
            #[serde(default)]
            name: Option<String>,
        }
        let parsed: UserRole = serde_json::from_value(v)
            .map_err(|e| Error::Internal(format!("sso response shape: {e}")))?;
        Ok(SsoUser {
            email: parsed.user.email,
            name: parsed.user.name,
            session: parsed.session,
        })
    }

    /// `POST /api/session/introspect` — validate a unified `lzr_session` token
    /// and return the identity behind it. `Err(Unauthorized)` when the session is
    /// invalid/expired.
    pub async fn introspect(&self, session: &str) -> Result<SsoUser> {
        let body = json!({
            "session": session,
        });
        let v = self.post_json("/api/session/introspect", body).await?;
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            return Err(Error::Unauthorized(format!("sso session invalid: {err}")));
        }
        #[derive(Deserialize)]
        struct IntrospectResp {
            user: UserObj,
        }
        #[derive(Deserialize)]
        struct UserObj {
            email: String,
            #[serde(default)]
            name: Option<String>,
        }
        let parsed: IntrospectResp = serde_json::from_value(v)
            .map_err(|e| Error::Internal(format!("sso introspect shape: {e}")))?;
        Ok(SsoUser {
            email: parsed.user.email,
            name: parsed.user.name,
            session: Some(session.to_string()),
        })
    }

    /// `POST /api/session/logout` — invalidate a unified session globally.
    pub async fn logout(&self, session: &str) -> Result<()> {
        let body = json!({
            "session": session,
        });
        self.post_json("/api/session/logout", body).await?;
        Ok(())
    }

    /// `POST /api/users/invite` — provision a user in the IdP so they can sign in
    /// (the server-to-server "invite"). Idempotent.
    pub async fn invite(&self, email: &str, name: Option<&str>) -> Result<()> {
        let mut body = json!({
            "email": email,
        });
        if let Some(n) = name {
            body["name"] = json!(n);
        }
        let v = self.post_json("/api/users/invite", body).await?;
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            return Err(Error::BadRequest(format!("sso invite failed: {err}")));
        }
        Ok(())
    }

    /// POST a JSON body (with `client_id` added — the only client credential on
    /// the wire; the rest is the SVID) and decode the JSON response regardless of
    /// HTTP status: the IdP signals login failures as `400 {error:...}`, which we
    /// read as data. Transport failures — the IdP unreachable, a TLS handshake
    /// refused because the server is not the expected SPIFFE id, a timeout — are
    /// `Upstream 502`; an unparsable or oversized body is `Internal`.
    async fn post_json(
        &self,
        path: &str,
        mut body: serde_json::Value,
    ) -> Result<serde_json::Value> {
        body["client_id"] = json!(self.client_id);
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(path)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_vec(&body).map_err(
                |e| Error::Internal(format!("sso request encode: {e}")),
            )?)))
            .map_err(|e| Error::Internal(format!("sso request build: {e}")))?;
        let unreachable = |what: String| Error::Upstream {
            provider: "sso".to_string(),
            status: 502,
            message: format!("sso unreachable: {what}"),
        };
        let bytes = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let response = self
                .http
                .request(request)
                .await
                .map_err(|e| unreachable(e.to_string()))?;
            bounded_body(response.into_body(), MAX_BODY_BYTES).await
        })
        .await
        .map_err(|_| unreachable("timed out".to_string()))??;
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| Error::Internal(format!("sso response not JSON: {e}")))
    }
}

/// Collect a response body enforcing `limit` while reading, not after an
/// unbounded collect. Content-Length is not trusted. The caller bounds time.
async fn bounded_body<B>(body: B, limit: usize) -> Result<Bytes>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    tokio::pin!(body);
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| Error::Upstream {
            provider: "sso".to_string(),
            status: 502,
            message: format!("sso response interrupted: {e}"),
        })?;
        if let Ok(data) = frame.into_data() {
            if data.len() > limit.saturating_sub(bytes.len()) {
                return Err(Error::Internal(format!(
                    "sso response body exceeded the {limit} byte limit"
                )));
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Frame;
    use http_body_util::StreamBody;
    use std::convert::Infallible;

    #[tokio::test]
    async fn bounded_body_accepts_exact_limit_and_rejects_excess() {
        assert_eq!(
            bounded_body(Full::new(Bytes::from_static(b"abcd")), 4)
                .await
                .unwrap(),
            b"abcd"[..]
        );
        assert!(matches!(
            bounded_body(Full::new(Bytes::from_static(b"abcde")), 4).await,
            Err(Error::Internal(_))
        ));
        // The cap is on the total, not on any one frame.
        let frames = futures::stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::data(Bytes::from_static(b"de"))),
        ]);
        assert!(matches!(
            bounded_body(StreamBody::new(frames), 4).await,
            Err(Error::Internal(_))
        ));
    }

    #[tokio::test]
    async fn bounded_body_reports_an_interrupted_stream_as_upstream() {
        let frames = futures::stream::iter([
            Ok(Frame::data(Bytes::from_static(b"partial"))),
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated",
            )),
        ]);
        assert!(matches!(
            bounded_body(StreamBody::new(frames), 100).await,
            Err(Error::Upstream { status: 502, .. })
        ));
    }
}
