//! Configuration value types (deserialized from `gateway.toml`).
//!
//! The config file is the single source of truth for how the process boots:
//! database backend, bind address, secrets, request-logging, feature flags, and
//! routing policy. There are no `GATEWAY_*` environment variables, and no
//! environment indirection for upstream keys — each deployment carries its own
//! `api_key` directly. The model list is **not** here: it lives in the database,
//! loaded with `gateway import <models-file>` (see [`ModelsFile`]).

use crate::catalog::ModelPrice;
use crate::routing::UpstreamFormat;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The whole process configuration, parsed from `gateway.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub auth: AuthConfig,
    pub reqlog: ReqlogSettings,
    pub telemetry: TelemetryConfig,
    pub features: FeaturesConfig,
    pub upstream: UpstreamConfig,
    pub routing: RoutingConfig,
}

/// Listener + deployment-mode settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    pub deployment_mode: DeploymentMode,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind: "0.0.0.0:8080".to_string(),
            deployment_mode: DeploymentMode::Selfhosted,
        }
    }
}

/// Deployment mode: `selfhosted` mounts the admin API; `managed` drops it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    #[default]
    Selfhosted,
    Managed,
}

/// Which persistence backend to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DbBackend {
    #[default]
    Sqlite,
    Postgres,
}

/// Database selection. `backend = "sqlite"` uses `path`; `backend = "postgres"`
/// uses `dsn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub backend: DbBackend,
    pub path: String,
    pub dsn: Option<String>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            backend: DbBackend::Sqlite,
            path: "./gateway.db".to_string(),
            dsn: None,
        }
    }
}

/// Secrets. All optional; absent secrets degrade safely (random session secret,
/// no-op BYOK encryption, admin API requiring a configured password to use).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// 32-byte AES-256-GCM key (base64 or hex) for BYOK secret-at-rest.
    pub byok_key: Option<String>,
}

/// Which admin-console login methods are available, and their settings.
///
/// The admin console (`/admin/v1/auth/*`) can authenticate humans by any subset
/// of: `local` (the gateway's own username/password users), `sso` (an external
/// identity provider spoken over a client-authenticated server-to-server JSON
/// API — the "direct", non-SAML flow), and `saml`. `yb_` API keys are a separate
/// mechanism and are unaffected by this. Defaults to `local` only, so existing
/// configs behave exactly as before.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// The enabled login methods (any subset; order is display order).
    pub providers: Vec<AuthProvider>,
    /// Settings for the `sso` provider (required when `sso` is enabled).
    pub sso: Option<SsoAuthConfig>,
    /// Settings for the `saml` provider (seam; SP flow is a follow-up).
    pub saml: Option<SamlAuthConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            providers: vec![AuthProvider::Local],
            sso: None,
            saml: None,
        }
    }
}

impl AuthConfig {
    /// Whether a given provider is enabled.
    pub fn has(&self, p: AuthProvider) -> bool {
        self.providers.contains(&p)
    }
}

/// An admin-console login method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    /// The gateway's own username/password users.
    Local,
    /// External identity provider, direct (non-SAML) server-to-server flow.
    Sso,
    /// SAML SP (config/UI seam this round; backend flow is a follow-up).
    Saml,
}

impl AuthProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthProvider::Local => "local",
            AuthProvider::Sso => "sso",
            AuthProvider::Saml => "saml",
        }
    }
}

/// Settings for the `sso` provider: how to reach the identity provider's
/// client-authenticated login API and what to send it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SsoAuthConfig {
    /// Base URL of the IdP backend, reached server-to-server (e.g. an internal
    /// `http://127.0.0.1:1411`). No trailing slash required.
    pub base_url: String,
    /// The relying-party client id registered with the IdP.
    pub client_id: String,
    /// The relying-party client secret (kept server-side; never sent to the browser).
    pub client_secret: String,
    /// The origin the IdP embeds in the emailed magic link (this app's public
    /// URL, e.g. `https://gateway.lzrlab.dev`). Must be in the client's IdP
    /// origin allow-list.
    pub callback_base: String,
    /// Cloudflare Turnstile **sitekey** (public) for the login widget. When set,
    /// the login UI renders a Turnstile challenge and forwards its token to the
    /// IdP, which validates it before emailing. Empty/unset disables the widget.
    #[serde(default)]
    pub turnstile_sitekey: Option<String>,
    /// The unified cross-app session cookie name (default `lzr_session`). This is
    /// the cookie the IdP-issued session lands in, shared across `*.lzrlab.dev`.
    #[serde(default)]
    pub session_cookie: Option<String>,
    /// The `Domain` for the unified cookie (e.g. `lzrlab.dev`). **When set, SSO is
    /// on:** a successful sso login sets this domain-scoped cookie, and the admin
    /// console authenticates it by introspecting against the IdP. Unset ⇒ the
    /// gateway keeps only its own host-only `yb_session` (no cross-app SSO).
    #[serde(default)]
    pub session_cookie_domain: Option<String>,
}

/// Settings for the `saml` provider. Present as a config seam; the SP backend
/// flow (AuthnRequest / ACS / signature verification) is a follow-up.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SamlAuthConfig {
    /// IdP SSO (HTTP-Redirect) endpoint URL.
    pub idp_sso_url: Option<String>,
    /// Path to the IdP signing certificate (PEM).
    pub idp_cert: Option<String>,
    /// This SP's entity id.
    pub sp_entity_id: Option<String>,
    /// The Assertion Consumer Service URL.
    pub acs_url: Option<String>,
}

/// DuckDB request/response logging for training-data capture. Off unless
/// `enabled = true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReqlogSettings {
    pub enabled: bool,
    pub dir: String,
    pub queue_size: usize,
    pub shard_max_bytes: u64,
    pub rotate_secs: u64,
    pub retention_days: u32,
    pub max_body_bytes: usize,
    /// Optional shell command run after each shard is sealed (backup hook). The
    /// `{shard}` and `{dir}` placeholders are substituted before it runs.
    #[serde(default)]
    pub on_roll: Option<String>,
}

impl Default for ReqlogSettings {
    fn default() -> Self {
        ReqlogSettings {
            enabled: false,
            dir: "./reqlog".to_string(),
            queue_size: 4096,
            shard_max_bytes: 256 * 1024 * 1024,
            rotate_secs: 3600,
            retention_days: 30,
            max_body_bytes: 256 * 1024,
            on_roll: None,
        }
    }
}

/// OpenTelemetry export. Off unless `enabled = true`. Exports structured turn
/// metadata only — never request/response bodies (those are the reqlog's job):
/// - **metrics** — aggregates, pushed via OTLP and/or scraped from `/metrics`,
/// - **events** — one OTLP log record per turn (ids, models, tokens, cost,
///   latency, status),
/// - **spans** — one OTLP span per turn, honoring a client-supplied trace id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    pub enabled: bool,
    /// OTLP/HTTP base endpoint (e.g. `http://localhost:4318`). Push (metrics +
    /// events + spans to `/v1/{metrics,logs,traces}`) is disabled when unset.
    pub otlp_endpoint: Option<String>,
    /// Seconds between OTLP pushes.
    pub push_interval_secs: u64,
    /// Serve Prometheus text exposition at `GET /metrics` (pull).
    pub prometheus: bool,
    /// `service.name` resource attribute.
    pub service_name: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        TelemetryConfig {
            enabled: false,
            otlp_endpoint: None,
            push_interval_secs: 15,
            prometheus: true,
            service_name: "gateway".to_string(),
        }
    }
}

/// Admission feature flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FeaturesConfig {
    pub budgets_enabled: bool,
    pub ratelimit_enabled: bool,
    pub ratelimit_window_secs: u64,
}

impl Default for FeaturesConfig {
    fn default() -> Self {
        FeaturesConfig {
            budgets_enabled: false,
            ratelimit_enabled: false,
            ratelimit_window_secs: 60,
        }
    }
}

/// Upstream client mode. `mock` replays canned responses for fully offline runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    #[default]
    Http,
    Mock,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamConfig {
    pub mode: UpstreamMode,
    /// The Cloudflare Access service token used by any deployment that sets the
    /// `cloudflare_access` extra-header flag. Configured **here and only here**:
    /// the credential is file-owned and immutable at runtime — never written to
    /// the database, never returned by the admin API, never editable in the UI.
    /// Absent ⇒ deployments carrying the flag are treated as misconfigured.
    pub cloudflare_access: Option<CloudflareAccessConfig>,
}

/// A Cloudflare Access **service token** (client id + secret), sent as the
/// `CF-Access-Client-Id` / `CF-Access-Client-Secret` header pair so a
/// machine-to-machine request satisfies a Zero Trust application policy.
///
/// This authenticates to the Cloudflare *edge* — it is unrelated to, and
/// composes with, the deployment's own upstream `api_key` for the origin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CloudflareAccessConfig {
    pub client_id: String,
    pub client_secret: String,
}

impl CloudflareAccessConfig {
    /// Usable only when both halves of the service token are present.
    pub fn is_complete(&self) -> bool {
        !self.client_id.trim().is_empty() && !self.client_secret.trim().is_empty()
    }
}

/// Deployment-selection strategy across a model's candidate deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// Weighted shuffle (default), respecting per-deployment `weight`.
    #[default]
    Simple,
    /// Strict round-robin.
    RoundRobin,
    /// Fewest in-flight requests first.
    LeastBusy,
}

/// One deployment entry in the seed model list (config shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub provider: String,
    pub upstream_model: String,
    #[serde(default)]
    pub api_base: Option<String>,
    /// The upstream provider api key for this deployment.
    #[serde(default)]
    pub api_key: Option<String>,
    /// The upstream wire format — the single "adapter shape" used to call this
    /// deployment (`anthropic`, `openai_chat`, `openai_responses`, `gemini`).
    pub upstream_format: UpstreamFormat,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub pricing: Option<ModelPrice>,
    /// How to health-check this backend (independent of `upstream_format`).
    #[serde(default)]
    pub health_check: crate::routing::HealthCheck,
    /// URL for `http_ok` checks: absolute, or relative to `api_base`'s origin.
    #[serde(default)]
    pub health_path: Option<String>,
    /// Open-ended per-deployment extras, e.g.
    /// `extra = { cloudflare_access = true }`. The flag selects a credential;
    /// the credential itself comes from `[upstream.cloudflare_access]`.
    #[serde(default)]
    pub extra: crate::routing::Extra,
}

fn default_weight() -> u32 {
    1
}

/// A public model name mapped to one or more deployments (seed shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub model_name: String,
    pub deployments: Vec<DeploymentConfig>,
    /// Other public names that resolve to this model (e.g. `["gpt-4", "fast"]`).
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// A standalone models file, parsed by `gateway import <file>` to upsert the
/// live model list into the database. Deliberately separate from the serve
/// config ([`Config`]): models live in the DB, configured in exactly one place,
/// One upstream endpoint: its base URL, its credential, and its edge settings.
///
/// Credentials live here rather than on each deployment because they describe
/// the endpoint — two models behind one OpenAI account are one key, not two.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderConfig {
    pub name: String,
    /// `None` means the wire format's default base.
    pub api_base: Option<String>,
    pub api_key: Option<String>,
    /// `extra = { cloudflare_access = true, headers = { … } }` — edge concerns
    /// of this endpoint. The Cloudflare token itself is file-owned, in
    /// `[upstream.cloudflare_access]`; this flag only selects it.
    pub extra: crate::routing::Extra,
}

/// and the import file is just a convenient bulk loader.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelsFile {
    /// Upstream endpoints and their credentials. A deployment names one of
    /// these; a name that is not declared here is created credential-less.
    #[serde(rename = "provider", default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(rename = "model")]
    pub models: Vec<ModelConfig>,
    /// Public model aliases (`alias` → `target` model name), seeded into the DB.
    pub aliases: HashMap<String, String>,
}

/// Routing policy: deployment-selection strategy and per-model fallback chains.
/// The model list itself lives in the database (see [`ModelsFile`]), never here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    pub strategy: Strategy,
    /// Per-model fallback chains (public model name → ordered fallbacks).
    pub fallbacks: HashMap<String, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_defaults_to_local_only() {
        // Missing [auth] section → local provider only (back-compat).
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.auth.providers, vec![AuthProvider::Local]);
        assert!(cfg.auth.has(AuthProvider::Local));
        assert!(!cfg.auth.has(AuthProvider::Sso));
        assert!(cfg.auth.sso.is_none());
    }

    #[test]
    fn cloudflare_access_is_file_only_and_optional() {
        // Absent by default — the feature is off unless configured.
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.upstream.cloudflare_access.is_none());

        let cfg: Config = toml::from_str(
            r#"
[upstream.cloudflare_access]
client_id = "abc.access"
client_secret = "s3cret"
"#,
        )
        .unwrap();
        let cf = cfg.upstream.cloudflare_access.clone().expect("configured");
        assert_eq!(cf.client_id, "abc.access");
        assert!(cf.is_complete());

        // A half-filled token is not usable.
        let cfg: Config = toml::from_str(
            r#"
[upstream.cloudflare_access]
client_id = "abc.access"
"#,
        )
        .unwrap();
        assert!(!cfg.upstream.cloudflare_access.unwrap().is_complete());
    }

    #[test]
    fn deployment_extra_defaults_empty_and_parses_open_shape() {
        let dc: DeploymentConfig = toml::from_str(
            r#"
provider = "vllm"
upstream_model = "Qwen3.8-27B"
upstream_format = "openai_chat"
"#,
        )
        .unwrap();
        assert!(dc.extra.is_empty());

        let dc: DeploymentConfig = toml::from_str(
            r#"
provider = "vllm"
upstream_model = "Qwen3.8-27B"
upstream_format = "openai_chat"
extra = { cloudflare_access = true, headers = { "X-Tenant" = "acme" } }
"#,
        )
        .unwrap();
        assert!(dc.extra.cloudflare_access);
        assert_eq!(dc.extra.headers.get("X-Tenant").map(String::as_str), Some("acme"));
        assert!(!dc.extra.is_empty());

        // An unrecognized key is kept rather than rejected, so a value written by
        // a newer build survives a round-trip through this one.
        let dc: DeploymentConfig = toml::from_str(
            r#"
provider = "vllm"
upstream_model = "Qwen3.8-27B"
upstream_format = "openai_chat"
extra = { future_knob = 7 }
"#,
        )
        .unwrap();
        assert!(!dc.extra.is_empty());
        assert_eq!(dc.extra.rest.get("future_knob").and_then(|v| v.as_i64()), Some(7));
    }

    #[test]
    fn auth_section_roundtrips() {
        let toml = r#"
[auth]
providers = ["local", "sso"]

[auth.sso]
base_url = "http://127.0.0.1:1411"
client_id = "gateway"
client_secret = "s3cret"
callback_base = "https://gateway.lzrlab.dev"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            cfg.auth.providers,
            vec![AuthProvider::Local, AuthProvider::Sso]
        );
        assert!(cfg.auth.has(AuthProvider::Sso));
        let sso = cfg.auth.sso.clone().expect("sso config present");
        assert_eq!(sso.client_id, "gateway");
        assert_eq!(sso.base_url, "http://127.0.0.1:1411");
        assert_eq!(sso.callback_base, "https://gateway.lzrlab.dev");

        // Re-serialize and re-parse: providers survive the round trip.
        let back = toml::to_string(&cfg).unwrap();
        let cfg2: Config = toml::from_str(&back).unwrap();
        assert_eq!(cfg2.auth.providers, cfg.auth.providers);
    }
}
