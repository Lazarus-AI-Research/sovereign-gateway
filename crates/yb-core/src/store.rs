//! The storage-agnostic persistence contract.
//!
//! A single `Store` trait aggregates every repository operation. Concrete
//! adapters (`SqliteStore`, `PostgresStore` in `yb-store`) implement it; all
//! downstream code consumes `Arc<dyn Store>` and never knows the backend.
//!
//! Identity model: **users** own **keys**; users group into **teams**. There is
//! no tenancy ("installation") layer. Spend/budgets attach to a key, user, or team.

use crate::ids::{Micros, Timestamp};
use crate::model::{
    AccessPolicy, ApiKey, ExternalKey, ModelAlias, Role, Session, Team, TeamMembership,
    TelemetryRecord, User,
};
use crate::principal::KeyAuth;
use crate::routing::DeploymentRecord;
use crate::spend::{Budget, Period, RollupDelta, SpendRow, SubjectType};
use async_trait::async_trait;

/// Nullable per-subject rate limits, as stored on keys/users.
#[derive(Debug, Clone, Copy, Default)]
pub struct LimitColumns {
    pub rpm: Option<i64>,
    pub tpm: Option<i64>,
    pub max_concurrent: Option<i64>,
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Apply all pending schema migrations for this backend.
    async fn migrate(&self) -> crate::Result<()>;

    // ---- users (login accounts; own keys) -----------------------------
    async fn create_user(&self, user: &User) -> crate::Result<()>;
    async fn get_user(&self, id: &str) -> crate::Result<Option<User>>;
    async fn get_user_by_username(&self, username: &str) -> crate::Result<Option<User>>;
    async fn list_users(&self) -> crate::Result<Vec<User>>;
    async fn set_user_password(&self, id: &str, password_hash: &str) -> crate::Result<()>;
    async fn set_user_role(&self, id: &str, role: Role) -> crate::Result<()>;
    async fn set_user_limits(&self, id: &str, limits: LimitColumns) -> crate::Result<()>;
    async fn mark_user_login(&self, id: &str) -> crate::Result<()>;
    async fn delete_user(&self, id: &str) -> crate::Result<()>;
    async fn count_users(&self) -> crate::Result<i64>;
    /// Active admin users (for the last-admin guard).
    async fn count_admins(&self) -> crate::Result<i64>;

    // ---- web sessions (cookie token → user) ---------------------------
    async fn create_session(&self, session: &Session) -> crate::Result<()>;
    /// Resolve a session token to its (unexpired) row; `None` if missing/expired.
    async fn get_session(&self, token: &str) -> crate::Result<Option<Session>>;
    async fn delete_session(&self, token: &str) -> crate::Result<()>;

    // ---- api keys (owned by users) ------------------------------------
    async fn create_api_key(&self, key: &ApiKey) -> crate::Result<()>;
    /// Hot auth path: resolve a key (and its owner user) by the hex SHA-256 of
    /// its token.
    async fn verify_api_key(&self, token_hash: &str) -> crate::Result<Option<KeyAuth>>;
    async fn get_api_key(&self, id: &str) -> crate::Result<Option<ApiKey>>;
    /// All keys (admin view).
    async fn list_api_keys(&self) -> crate::Result<Vec<ApiKey>>;
    /// Keys owned by one user.
    async fn list_api_keys_for_user(&self, user_id: &str) -> crate::Result<Vec<ApiKey>>;
    async fn mark_api_key_used(&self, id: &str) -> crate::Result<()>;
    async fn delete_api_key(&self, id: &str) -> crate::Result<()>;
    async fn update_api_key_access(&self, id: &str, policy: &AccessPolicy) -> crate::Result<()>;
    async fn update_api_key_limits(&self, id: &str, limits: LimitColumns) -> crate::Result<()>;

    // ---- external (BYOK) keys, per user -------------------------------
    async fn upsert_external_key(&self, key: &ExternalKey) -> crate::Result<()>;
    async fn list_external_keys(&self, user_id: &str) -> crate::Result<Vec<ExternalKey>>;
    async fn delete_external_key(&self, user_id: &str, provider: &str) -> crate::Result<()>;

    // ---- teams & memberships (many-to-many) ---------------------------
    async fn create_team(&self, team: &Team) -> crate::Result<()>;
    async fn get_team(&self, id: &str) -> crate::Result<Option<Team>>;
    async fn list_teams(&self) -> crate::Result<Vec<Team>>;
    async fn delete_team(&self, id: &str) -> crate::Result<()>;
    async fn update_team_access(&self, id: &str, policy: &AccessPolicy) -> crate::Result<()>;
    async fn upsert_membership(&self, m: &TeamMembership) -> crate::Result<()>;
    async fn list_memberships_for_user(&self, user_id: &str)
        -> crate::Result<Vec<TeamMembership>>;
    async fn list_team_members(&self, team_id: &str) -> crate::Result<Vec<TeamMembership>>;
    async fn delete_membership(&self, team_id: &str, user_id: &str) -> crate::Result<()>;

    // ---- telemetry -----------------------------------------------------
    async fn insert_telemetry(&self, rec: &TelemetryRecord) -> crate::Result<()>;

    // ---- spend & budgets (subject = key | user | team) ----------------
    async fn upsert_rollup(&self, delta: &RollupDelta) -> crate::Result<()>;
    async fn period_spend(
        &self,
        subject_type: SubjectType,
        subject_id: &str,
        period: Period,
        period_start: Timestamp,
    ) -> crate::Result<Micros>;
    async fn list_budgets(
        &self,
        subject_type: SubjectType,
        subject_id: &str,
    ) -> crate::Result<Vec<Budget>>;
    /// All budgets (admin overview).
    async fn list_all_budgets(&self) -> crate::Result<Vec<Budget>>;
    async fn upsert_budget(&self, budget: &Budget) -> crate::Result<()>;
    async fn delete_budget(&self, id: &str) -> crate::Result<()>;
    async fn spend_rows(&self) -> crate::Result<Vec<SpendRow>>;

    // ---- rate-limit counters (db backend, multi-replica) --------------
    async fn incr_rate_counter(
        &self,
        scope: &str,
        dimension: &str,
        window_start: Timestamp,
        n: i64,
    ) -> crate::Result<i64>;

    // ---- deployments (the live model list) ----------------------------
    async fn list_deployments(&self) -> crate::Result<Vec<DeploymentRecord>>;
    async fn get_deployment(&self, id: &str) -> crate::Result<Option<DeploymentRecord>>;
    async fn create_deployment(&self, dep: &DeploymentRecord) -> crate::Result<()>;
    async fn delete_deployment(&self, id: &str) -> crate::Result<()>;
    /// Idempotently seed a deployment by its natural key. Returns `true` if a new
    /// row was inserted. Projects the file's seed `model_list` into the DB.
    async fn seed_deployment(&self, dep: &DeploymentRecord) -> crate::Result<bool>;

    // ---- model aliases (public name -> public name) -------------------
    async fn list_aliases(&self) -> crate::Result<Vec<ModelAlias>>;
    /// Insert or replace an alias (keyed on `alias`).
    async fn upsert_alias(&self, alias: &ModelAlias) -> crate::Result<()>;
    async fn delete_alias(&self, alias: &str) -> crate::Result<()>;
}
