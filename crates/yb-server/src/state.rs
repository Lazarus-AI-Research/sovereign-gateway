//! The shared application state threaded through every handler.
//!
//! [`AppState`] bundles the adapter trait objects (`Store`, `Encryptor`,
//! `PasswordHasher`), the orchestration [`Gateway`], the in-process rate
//! [`Limiter`], and the static configuration the HTTP surface needs (deployment
//! mode, feature toggles, session signing secret). It is cheap to clone — every
//! owned field is an [`Arc`] or a small value — so axum can hand a fresh copy to
//! each request without contention.

use std::sync::Arc;

use yb_core::config::{AuthConfig, DeploymentMode};
use yb_core::crypto::{Encryptor, PasswordHasher};
use yb_core::ratelimit::Limiter;
use yb_core::{Observer, Store};
use yb_gateway::{DeploymentRouter, Gateway};

use crate::sso::SsoClient;

/// Process-wide state shared by all routes. Clone is `Arc`-cheap.
#[derive(Clone)]
pub struct AppState {
    /// Persistence (keys, users, teams, telemetry, spend, budgets).
    pub store: Arc<dyn Store>,
    /// The request-orchestration service (parse → route → dispatch → translate).
    pub gateway: Arc<Gateway>,
    /// The live routing table, swapped in place when `/admin/v1/models` mutates
    /// the database. Shares the same instance the [`Gateway`] resolves against.
    pub router: Arc<DeploymentRouter>,
    /// In-process token-bucket rate limiter.
    pub limiter: Arc<Limiter>,
    /// BYOK secret-at-rest encryptor (used by external-key admin flows).
    pub encryptor: Arc<dyn Encryptor>,
    /// Password hasher for user login.
    pub hasher: Arc<dyn PasswordHasher>,
    /// Observability sink; `GET /metrics` renders its Prometheus view when
    /// enabled (`NullObserver` renders nothing → the route 404s).
    pub observer: Arc<dyn Observer>,
    /// Deployment mode; the admin surface mounts only under `Selfhosted`.
    pub mode: DeploymentMode,
    /// Enabled admin-console login methods + their settings.
    pub auth: Arc<AuthConfig>,
    /// External IdP client for the `sso` login provider — `Some` iff `sso` is
    /// enabled and configured. Built once from `auth.sso`.
    pub sso: Option<Arc<SsoClient>>,
    /// When false, budget enforcement on the inference path is skipped.
    pub budgets_enabled: bool,
    /// When false, rate-limit enforcement on the inference path is skipped.
    pub ratelimit_enabled: bool,
}

impl AppState {
    /// Rebuild the in-memory routing table from the current database
    /// deployments. Call after any `/admin/v1/models` mutation.
    pub async fn reload_models(&self) -> yb_core::Result<()> {
        let deployments = self.store.list_deployments().await?;
        let aliases = self
            .store
            .list_aliases()
            .await?
            .into_iter()
            .map(|a| (a.alias, a.target))
            .collect();
        self.router.reload(&deployments, aliases);
        Ok(())
    }
}
