//! Client for the external identity provider's **direct, non-SAML** login API.
//!
//! The IdP ("SSO identity service, no JWT") exposes a small, client-authenticated,
//! server-to-server contract. The gateway is a *relying party*: it holds a
//! `client_id` + `client_secret`, calls these endpoints from the backend (the
//! secret never reaches the browser), and on success maps the returned identity
//! onto a local user + its own `yb_session` cookie.
//!
//! Wire contract (all JSON, no JWT — every IdP token is an opaque DB string):
//! - `POST /api/login/start`  `{client_id, client_secret, email, callback_base}`
//!   → `200 {ok:true, dev_link?, dev_code?}`. Emails a magic link
//!   (`{callback_base}/auth/verify?lt=<token>`) **and** a 6-digit code to a known
//!   active user; always `ok:true` (no account enumeration).
//! - `POST /api/login/code`   `{client_id, client_secret, email, code}`
//!   → `{user:{id,email,name}, role}` or `400 {error:"invalid_code"|"expired"|...}`.
//! - `POST /api/login/verify` `{client_id, client_secret, token}` (the emailed
//!   link token) → same success shape.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use yb_core::config::SsoAuthConfig;
use yb_core::{Error, Result};

/// A configured relying-party client for one IdP.
#[derive(Clone)]
pub struct SsoClient {
    http: reqwest::Client,
    base_url: String,
    client_id: String,
    client_secret: String,
    callback_base: String,
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
    /// Build a client from `[auth.sso]` config. Returns `None` when the config
    /// is incomplete (so the provider is simply treated as unavailable).
    pub fn from_config(cfg: &SsoAuthConfig) -> Option<SsoClient> {
        if cfg.base_url.is_empty() || cfg.client_id.is_empty() || cfg.client_secret.is_empty() {
            return None;
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .ok()?;
        Some(SsoClient {
            http,
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            client_id: cfg.client_id.clone(),
            client_secret: cfg.client_secret.clone(),
            callback_base: cfg.callback_base.trim_end_matches('/').to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `POST /api/login/start` — ask the IdP to email a code + magic link to
    /// `email`. Always succeeds for a known client (no enumeration); surfaces the
    /// IdP's dev passthrough when present. `turnstile_token` is forwarded to the
    /// IdP (which validates it when the client requires a bot check).
    pub async fn start(&self, email: &str, turnstile_token: Option<&str>) -> Result<StartOutcome> {
        let mut body = json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
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
            dev_code: v.get("dev_code").and_then(|c| c.as_str()).map(str::to_string),
            dev_link: v.get("dev_link").and_then(|c| c.as_str()).map(str::to_string),
        })
    }

    /// `POST /api/login/code` — complete a login with the typed 6-digit code.
    pub async fn code(&self, email: &str, code: &str) -> Result<SsoUser> {
        let body = json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "email": email,
            "code": code,
        });
        self.complete("/api/login/code", body).await
    }

    /// `POST /api/login/verify` — complete a login with the emailed link token.
    pub async fn verify(&self, token: &str) -> Result<SsoUser> {
        let body = json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
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
            "client_id": self.client_id,
            "client_secret": self.client_secret,
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
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "session": session,
        });
        self.post_json("/api/session/logout", body).await?;
        Ok(())
    }

    /// `POST /api/users/invite` — provision a user in the IdP so they can sign in
    /// (the server-to-server "invite"). Idempotent.
    pub async fn invite(&self, email: &str, name: Option<&str>) -> Result<()> {
        let mut body = json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
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

    /// POST a JSON body and decode the JSON response (any HTTP status — the IdP
    /// signals login failures as `400 {error:...}`, which we read as data).
    async fn post_json(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let resp = self
            .http
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Upstream {
                provider: "sso".to_string(),
                status: 502,
                message: format!("sso unreachable: {e}"),
            })?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| Error::Internal(format!("sso response not JSON: {e}")))
    }
}
