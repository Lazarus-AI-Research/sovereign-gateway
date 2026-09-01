//! Postgres-backed [`Store`] implementation.
//!
//! Mirrors [`crate::sqlite::SqliteStore`] but uses `$N` placeholders, native
//! `TIMESTAMPTZ`/`BOOLEAN`/`BYTEA` columns, and `BIGINT` micro-dollar money.
//! `Vec<String>`/`AccessPolicy` are persisted as JSON text. Untested here (no
//! server in CI) but compiled and kept in lockstep with the SQLite backend.

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;

use yb_core::model::{
    AccessPolicy, ApiKey, ExternalKey, KeyScope, ModelAlias, Role, Session, Team, TeamMembership,
    TelemetryRecord, User,
};
use yb_core::principal::KeyAuth;
use yb_core::routing::{DeploymentRecord, ModelRecord, NewDeployment};
use yb_core::spend::{Budget, BudgetAction, Period, RollupDelta, SpendRow, SubjectType};
use yb_core::{new_id, now, Error, LimitColumns, Micros, Result, Store, Timestamp};

use crate::common::{dec_access, enc_access, storage_err};

/// A Postgres [`Store`]. Cheap to clone (wraps an `Arc`-backed pool).
#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connect to Postgres using a standard `postgres://…` DSN.
    pub async fn connect(dsn: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(dsn)
            .await
            .map_err(storage_err)?;
        Ok(Self { pool })
    }

    /// Wrap an existing pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Borrow the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// ---- BudgetAction <-> text (no core parser) ---------------------------

fn parse_action(s: &str) -> Result<BudgetAction> {
    match s {
        "block" => Ok(BudgetAction::Block),
        "alert" => Ok(BudgetAction::Alert),
        o => Err(Error::Storage(format!("bad budget action: {o}"))),
    }
}
fn action_str(a: BudgetAction) -> &'static str {
    match a {
        BudgetAction::Block => "block",
        BudgetAction::Alert => "alert",
    }
}

/// Encode a small serde enum (`WireFormat`) as a JSON string.
fn enc_enum<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// Encode a deployment's extra-header flags as a JSON object (`{}` when none).
/// The explicit column list for `deployments` reads.
///
/// Deliberately not `SELECT *`. `migrate` adds columns to already-deployed
/// databases with `ALTER TABLE`, which appends them at the end, so a migrated
/// database and a freshly created one order their columns differently. Worse, a
/// star select against a table altered earlier in the same process can panic
/// inside sqlx: the cached column metadata and the live statement's column count
/// disagree, and the row is indexed with the wrong one. Naming the columns keeps
/// reads pinned to the shape this code expects.
const DEPLOYMENT_COLS: &str = "d.id, d.model_id, m.name AS model_name, d.provider, \
     d.upstream_model, d.api_base, d.api_key, d.upstream_format, d.weight, d.pricing, \
     d.health_check, d.health_path, d.extra, d.created_at, d.updated_at, d.deleted_at";

/// The join every deployment read goes through, paired with [`DEPLOYMENT_COLS`].
const DEPLOYMENT_FROM: &str = "FROM deployments d JOIN models m ON m.id = d.model_id";

/// Column list for `models` reads.
const MODEL_COLS: &str = "id, name, created_at, updated_at";

/// Encode a deployment's `extra` object as JSON (`{}` when empty).
fn enc_extra(x: &yb_core::Extra) -> String {
    serde_json::to_string(x).unwrap_or_else(|_| "{}".to_string())
}

/// Decode the `extra` column. A NULL/blank/unparseable value means "no extras"
/// rather than a hard error, so one bad row cannot take down the whole model
/// list.
fn dec_extra(raw: Option<String>) -> yb_core::Extra {
    raw.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Encode optional pricing as JSON text (`None` → SQL NULL).
fn enc_pricing(p: &Option<yb_core::catalog::ModelPrice>) -> Option<String> {
    p.as_ref().map(|p| serde_json::to_string(p).unwrap_or_default())
}

// ---- row mappers -------------------------------------------------------

fn map_user(r: &PgRow) -> Result<User> {
    Ok(User {
        id: r.try_get("id").map_err(storage_err)?,
        username: r.try_get("username").map_err(storage_err)?,
        password_hash: r.try_get("password_hash").map_err(storage_err)?,
        role: Role::parse(&r.try_get::<String, _>("role").map_err(storage_err)?)?,
        rpm_limit: r.try_get("rpm_limit").map_err(storage_err)?,
        tpm_limit: r.try_get("tpm_limit").map_err(storage_err)?,
        max_concurrent: r.try_get("max_concurrent").map_err(storage_err)?,
        created_at: r.try_get("created_at").map_err(storage_err)?,
        last_login_at: r.try_get("last_login_at").map_err(storage_err)?,
        deleted_at: r.try_get("deleted_at").map_err(storage_err)?,
    })
}

fn map_api_key(r: &PgRow) -> Result<ApiKey> {
    Ok(ApiKey {
        id: r.try_get("id").map_err(storage_err)?,
        owner_user_id: r.try_get("owner_user_id").map_err(storage_err)?,
        team_id: r.try_get("team_id").map_err(storage_err)?,
        hash: r.try_get("hash").map_err(storage_err)?,
        key_prefix: r.try_get("key_prefix").map_err(storage_err)?,
        key_suffix: r.try_get("key_suffix").map_err(storage_err)?,
        name: r.try_get("name").map_err(storage_err)?,
        scopes: KeyScope::parse_set(&r.try_get::<String, _>("scope").map_err(storage_err)?)?,
        access: dec_access(&r.try_get::<String, _>("access").map_err(storage_err)?),
        rpm_limit: r.try_get("rpm_limit").map_err(storage_err)?,
        tpm_limit: r.try_get("tpm_limit").map_err(storage_err)?,
        max_concurrent: r.try_get("max_concurrent").map_err(storage_err)?,
        created_at: r.try_get("created_at").map_err(storage_err)?,
        last_used_at: r.try_get("last_used_at").map_err(storage_err)?,
        deleted_at: r.try_get("deleted_at").map_err(storage_err)?,
    })
}

fn map_external_key(r: &PgRow) -> Result<ExternalKey> {
    Ok(ExternalKey {
        id: r.try_get("id").map_err(storage_err)?,
        user_id: r.try_get("user_id").map_err(storage_err)?,
        provider: r.try_get("provider").map_err(storage_err)?,
        ciphertext: r.try_get("ciphertext").map_err(storage_err)?,
        key_prefix: r.try_get("key_prefix").map_err(storage_err)?,
        key_suffix: r.try_get("key_suffix").map_err(storage_err)?,
        created_at: r.try_get("created_at").map_err(storage_err)?,
        last_used_at: r.try_get("last_used_at").map_err(storage_err)?,
    })
}

fn map_team(r: &PgRow) -> Result<Team> {
    Ok(Team {
        id: r.try_get("id").map_err(storage_err)?,
        name: r.try_get("name").map_err(storage_err)?,
        access: dec_access(&r.try_get::<String, _>("access").map_err(storage_err)?),
        created_at: r.try_get("created_at").map_err(storage_err)?,
        updated_at: r.try_get("updated_at").map_err(storage_err)?,
        deleted_at: r.try_get("deleted_at").map_err(storage_err)?,
        created_by: r.try_get("created_by").map_err(storage_err)?,
    })
}

fn map_membership(r: &PgRow) -> Result<TeamMembership> {
    Ok(TeamMembership {
        id: r.try_get("id").map_err(storage_err)?,
        team_id: r.try_get("team_id").map_err(storage_err)?,
        user_id: r.try_get("user_id").map_err(storage_err)?,
        created_at: r.try_get("created_at").map_err(storage_err)?,
    })
}

fn map_budget(r: &PgRow) -> Result<Budget> {
    Ok(Budget {
        id: r.try_get("id").map_err(storage_err)?,
        subject_type: SubjectType::parse(
            &r.try_get::<String, _>("subject_type").map_err(storage_err)?,
        )?,
        subject_id: r.try_get("subject_id").map_err(storage_err)?,
        period: Period::parse(&r.try_get::<String, _>("period").map_err(storage_err)?)?,
        hard_limit_micros: r.try_get("hard_limit_micros").map_err(storage_err)?,
        soft_limit_micros: r.try_get("soft_limit_micros").map_err(storage_err)?,
        action: parse_action(&r.try_get::<String, _>("action").map_err(storage_err)?)?,
        enabled: r.try_get("enabled").map_err(storage_err)?,
        created_at: r.try_get("created_at").map_err(storage_err)?,
        updated_at: r.try_get("updated_at").map_err(storage_err)?,
        deleted_at: r.try_get("deleted_at").map_err(storage_err)?,
    })
}

fn map_spend_row(r: &PgRow) -> Result<SpendRow> {
    Ok(SpendRow {
        subject_type: r.try_get("subject_type").map_err(storage_err)?,
        subject_id: r.try_get("subject_id").map_err(storage_err)?,
        period: r.try_get("period").map_err(storage_err)?,
        period_start: r.try_get("period_start").map_err(storage_err)?,
        spend_micros: r.try_get("spend_micros").map_err(storage_err)?,
        request_count: r.try_get("request_count").map_err(storage_err)?,
        input_tokens: r.try_get("input_tokens").map_err(storage_err)?,
        output_tokens: r.try_get("output_tokens").map_err(storage_err)?,
    })
}

/// Map a `deployments` row to a [`DeploymentRecord`].
/// Map a `models` row to a [`ModelRecord`].
fn map_model(r: &PgRow) -> Result<ModelRecord> {
    Ok(ModelRecord {
        id: r.try_get("id").map_err(storage_err)?,
        name: r.try_get("name").map_err(storage_err)?,
        created_at: r.try_get("created_at").map_err(storage_err)?,
        updated_at: r.try_get("updated_at").map_err(storage_err)?,
    })
}

/// Map a joined `model_aliases` row. `target` is the model's current name.
fn map_alias(r: &PgRow) -> Result<ModelAlias> {
    Ok(ModelAlias {
        alias: r.try_get("alias").map_err(storage_err)?,
        model_id: r.try_get("model_id").map_err(storage_err)?,
        target: r.try_get("target").map_err(storage_err)?,
        created_at: r.try_get("created_at").map_err(storage_err)?,
    })
}

fn map_deployment(r: &PgRow) -> Result<DeploymentRecord> {
    let fmt_s: String = r.try_get("upstream_format").map_err(storage_err)?;
    let pricing_s: Option<String> = r.try_get("pricing").map_err(storage_err)?;
    let weight: i32 = r.try_get("weight").map_err(storage_err)?;
    Ok(DeploymentRecord {
        id: r.try_get("id").map_err(storage_err)?,
        model_id: r.try_get("model_id").map_err(storage_err)?,
        model_name: r.try_get("model_name").map_err(storage_err)?,
        provider: r.try_get("provider").map_err(storage_err)?,
        upstream_model: r.try_get("upstream_model").map_err(storage_err)?,
        api_base: r.try_get("api_base").map_err(storage_err)?,
        api_key: r.try_get("api_key").map_err(storage_err)?,
        upstream_format: serde_json::from_str(&fmt_s).map_err(storage_err)?,
        weight: weight.max(0) as u32,
        pricing: match pricing_s {
            Some(s) => serde_json::from_str(&s).map_err(storage_err)?,
            None => None,
        },
        health_check: serde_json::from_value(serde_json::Value::String(
            r.try_get::<String, _>("health_check").map_err(storage_err)?,
        ))
        .map_err(storage_err)?,
        health_path: r.try_get("health_path").map_err(storage_err)?,
        extra: dec_extra(r.try_get("extra").ok()),
        created_at: r.try_get("created_at").map_err(storage_err)?,
        updated_at: r.try_get("updated_at").map_err(storage_err)?,
        deleted_at: r.try_get("deleted_at").map_err(storage_err)?,
    })
}

#[async_trait]
impl Store for PostgresStore {
    async fn migrate(&self) -> Result<()> {
        crate::schema::POSTGRES_MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| yb_core::Error::Storage(e.to_string()))
    }

    // ---- users (login accounts; own keys) -----------------------------
    async fn create_user(&self, user: &User) -> Result<()> {
        sqlx::query(
            "INSERT INTO users \
             (id, username, password_hash, role, rpm_limit, tpm_limit, max_concurrent, \
              created_at, last_login_at, deleted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.role.as_str())
        .bind(user.rpm_limit)
        .bind(user.tpm_limit)
        .bind(user.max_concurrent)
        .bind(user.created_at)
        .bind(user.last_login_at)
        .bind(user.deleted_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn get_user(&self, id: &str) -> Result<Option<User>> {
        let row = sqlx::query("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.as_ref().map(map_user).transpose()
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query("SELECT * FROM users WHERE username = $1 AND deleted_at IS NULL")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.as_ref().map(map_user).transpose()
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query("SELECT * FROM users WHERE deleted_at IS NULL ORDER BY username")
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;
        rows.iter().map(map_user).collect()
    }

    async fn set_user_password(&self, id: &str, password_hash: &str) -> Result<()> {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(password_hash)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn set_user_role(&self, id: &str, role: Role) -> Result<()> {
        sqlx::query("UPDATE users SET role = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(role.as_str())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn set_user_limits(&self, id: &str, limits: LimitColumns) -> Result<()> {
        sqlx::query(
            "UPDATE users SET rpm_limit = $1, tpm_limit = $2, max_concurrent = $3 \
             WHERE id = $4 AND deleted_at IS NULL",
        )
        .bind(limits.rpm)
        .bind(limits.tpm)
        .bind(limits.max_concurrent)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn mark_user_login(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE users SET last_login_at = $1 WHERE id = $2")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_user(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE users SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn count_users(&self) -> Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
            .fetch_one(&self.pool)
            .await
            .map_err(storage_err)
    }

    async fn count_admins(&self) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND deleted_at IS NULL",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(storage_err)
    }

    // ---- web sessions (cookie token → user) ---------------------------
    async fn create_session(&self, session: &Session) -> Result<()> {
        sqlx::query(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES ($1,$2,$3,$4)",
        )
        .bind(&session.token)
        .bind(&session.user_id)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn get_session(&self, token: &str) -> Result<Option<Session>> {
        let row = sqlx::query("SELECT * FROM sessions WHERE token = $1 AND expires_at > $2")
            .bind(token)
            .bind(now())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(Session {
                token: r.try_get("token").map_err(storage_err)?,
                user_id: r.try_get("user_id").map_err(storage_err)?,
                created_at: r.try_get("created_at").map_err(storage_err)?,
                expires_at: r.try_get("expires_at").map_err(storage_err)?,
            })),
        }
    }

    async fn delete_session(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    // ---- api keys (owned by users) ------------------------------------
    async fn create_api_key(&self, key: &ApiKey) -> Result<()> {
        sqlx::query(
            "INSERT INTO api_keys \
             (id, owner_user_id, team_id, hash, key_prefix, key_suffix, name, scope, access, \
              rpm_limit, tpm_limit, max_concurrent, created_at, last_used_at, deleted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(&key.id)
        .bind(&key.owner_user_id)
        .bind(&key.team_id)
        .bind(&key.hash)
        .bind(&key.key_prefix)
        .bind(&key.key_suffix)
        .bind(&key.name)
        .bind(KeyScope::render_set(&key.scopes))
        .bind(enc_access(&key.access))
        .bind(key.rpm_limit)
        .bind(key.tpm_limit)
        .bind(key.max_concurrent)
        .bind(key.created_at)
        .bind(key.last_used_at)
        .bind(key.deleted_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn verify_api_key(&self, token_hash: &str) -> Result<Option<KeyAuth>> {
        let key_row = sqlx::query("SELECT * FROM api_keys WHERE hash = $1 AND deleted_at IS NULL")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        let api_key = match key_row.as_ref().map(map_api_key).transpose()? {
            Some(k) => k,
            None => return Ok(None),
        };
        match self.get_user(&api_key.owner_user_id).await? {
            Some(user) => Ok(Some(KeyAuth { user, api_key })),
            None => Ok(None),
        }
    }

    async fn get_api_key(&self, id: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query("SELECT * FROM api_keys WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.as_ref().map(map_api_key).transpose()
    }

    async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        let rows =
            sqlx::query("SELECT * FROM api_keys WHERE deleted_at IS NULL ORDER BY created_at")
                .fetch_all(&self.pool)
                .await
                .map_err(storage_err)?;
        rows.iter().map(map_api_key).collect()
    }

    async fn list_api_keys_for_user(&self, user_id: &str) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query(
            "SELECT * FROM api_keys WHERE owner_user_id = $1 AND deleted_at IS NULL \
             ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(map_api_key).collect()
    }

    async fn mark_api_key_used(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE api_keys SET last_used_at = $1 WHERE id = $2")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_api_key(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE api_keys SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn update_api_key_access(&self, id: &str, policy: &AccessPolicy) -> Result<()> {
        sqlx::query("UPDATE api_keys SET access = $1 WHERE id = $2")
            .bind(enc_access(policy))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn update_api_key_limits(&self, id: &str, limits: LimitColumns) -> Result<()> {
        sqlx::query(
            "UPDATE api_keys SET rpm_limit = $1, tpm_limit = $2, max_concurrent = $3 WHERE id = $4",
        )
        .bind(limits.rpm)
        .bind(limits.tpm)
        .bind(limits.max_concurrent)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    // ---- external (BYOK) keys, per user -------------------------------
    async fn upsert_external_key(&self, key: &ExternalKey) -> Result<()> {
        sqlx::query(
            "INSERT INTO external_keys \
             (id, user_id, provider, ciphertext, key_prefix, key_suffix, created_at, last_used_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
             ON CONFLICT(user_id, provider) DO UPDATE SET \
               ciphertext = excluded.ciphertext, key_prefix = excluded.key_prefix, \
               key_suffix = excluded.key_suffix",
        )
        .bind(&key.id)
        .bind(&key.user_id)
        .bind(&key.provider)
        .bind(&key.ciphertext)
        .bind(&key.key_prefix)
        .bind(&key.key_suffix)
        .bind(key.created_at)
        .bind(key.last_used_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn list_external_keys(&self, user_id: &str) -> Result<Vec<ExternalKey>> {
        let rows = sqlx::query("SELECT * FROM external_keys WHERE user_id = $1 ORDER BY provider")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;
        rows.iter().map(map_external_key).collect()
    }

    async fn delete_external_key(&self, user_id: &str, provider: &str) -> Result<()> {
        sqlx::query("DELETE FROM external_keys WHERE user_id = $1 AND provider = $2")
            .bind(user_id)
            .bind(provider)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    // ---- teams & memberships ------------------------------------------
    async fn create_team(&self, team: &Team) -> Result<()> {
        sqlx::query(
            "INSERT INTO teams \
             (id, name, access, created_at, updated_at, deleted_at, created_by) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(&team.id)
        .bind(&team.name)
        .bind(enc_access(&team.access))
        .bind(team.created_at)
        .bind(team.updated_at)
        .bind(team.deleted_at)
        .bind(&team.created_by)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn get_team(&self, id: &str) -> Result<Option<Team>> {
        let row = sqlx::query("SELECT * FROM teams WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.as_ref().map(map_team).transpose()
    }

    async fn list_teams(&self) -> Result<Vec<Team>> {
        let rows = sqlx::query("SELECT * FROM teams WHERE deleted_at IS NULL ORDER BY created_at")
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;
        rows.iter().map(map_team).collect()
    }

    async fn delete_team(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE teams SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn update_team_access(&self, id: &str, policy: &AccessPolicy) -> Result<()> {
        sqlx::query("UPDATE teams SET access = $1, updated_at = $2 WHERE id = $3")
            .bind(enc_access(policy))
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn upsert_membership(&self, m: &TeamMembership) -> Result<()> {
        sqlx::query(
            "INSERT INTO team_memberships (id, team_id, user_id, created_at) \
             VALUES ($1,$2,$3,$4) \
             ON CONFLICT(team_id, user_id) DO NOTHING",
        )
        .bind(&m.id)
        .bind(&m.team_id)
        .bind(&m.user_id)
        .bind(m.created_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn list_memberships_for_user(&self, user_id: &str) -> Result<Vec<TeamMembership>> {
        let rows =
            sqlx::query("SELECT * FROM team_memberships WHERE user_id = $1 ORDER BY created_at")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_err)?;
        rows.iter().map(map_membership).collect()
    }

    async fn list_team_members(&self, team_id: &str) -> Result<Vec<TeamMembership>> {
        let rows =
            sqlx::query("SELECT * FROM team_memberships WHERE team_id = $1 ORDER BY created_at")
                .bind(team_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_err)?;
        rows.iter().map(map_membership).collect()
    }

    async fn delete_membership(&self, team_id: &str, user_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM team_memberships WHERE team_id = $1 AND user_id = $2")
            .bind(team_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    // ---- telemetry -----------------------------------------------------
    async fn insert_telemetry(&self, rec: &TelemetryRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO request_telemetry \
             (id, request_id, trace_id, api_key_id, user_id, team_id, surface, \
              requested_model, decision_model, decision_provider, input_tokens, output_tokens, \
              cache_read_tokens, cache_write_tokens, cost_micros, status, is_error, latency_ms, \
              created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        )
        .bind(&rec.id)
        .bind(&rec.request_id)
        .bind(&rec.trace_id)
        .bind(&rec.api_key_id)
        .bind(&rec.user_id)
        .bind(&rec.team_id)
        .bind(&rec.surface)
        .bind(&rec.requested_model)
        .bind(&rec.decision_model)
        .bind(&rec.decision_provider)
        .bind(rec.input_tokens)
        .bind(rec.output_tokens)
        .bind(rec.cache_read_tokens)
        .bind(rec.cache_write_tokens)
        .bind(rec.cost_micros)
        .bind(rec.status)
        .bind(rec.is_error)
        .bind(rec.latency_ms)
        .bind(rec.created_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    // ---- spend & budgets (subject = key | user | team) ----------------
    async fn upsert_rollup(&self, delta: &RollupDelta) -> Result<()> {
        sqlx::query(
            "INSERT INTO spend_rollup \
             (subject_type, subject_id, period, period_start, spend_micros, \
              request_count, input_tokens, output_tokens) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
             ON CONFLICT(subject_type, subject_id, period, period_start) \
             DO UPDATE SET \
               spend_micros = spend_rollup.spend_micros + excluded.spend_micros, \
               request_count = spend_rollup.request_count + excluded.request_count, \
               input_tokens = spend_rollup.input_tokens + excluded.input_tokens, \
               output_tokens = spend_rollup.output_tokens + excluded.output_tokens",
        )
        .bind(delta.subject_type.as_str())
        .bind(&delta.subject_id)
        .bind(delta.period.as_str())
        .bind(delta.period_start)
        .bind(delta.spend_micros)
        .bind(delta.request_count)
        .bind(delta.input_tokens)
        .bind(delta.output_tokens)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn period_spend(
        &self,
        subject_type: SubjectType,
        subject_id: &str,
        period: Period,
        period_start: Timestamp,
    ) -> Result<Micros> {
        let row = sqlx::query(
            "SELECT spend_micros FROM spend_rollup \
             WHERE subject_type = $1 AND subject_id = $2 AND period = $3 AND period_start = $4",
        )
        .bind(subject_type.as_str())
        .bind(subject_id)
        .bind(period.as_str())
        .bind(period_start)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;
        match row {
            Some(r) => r.try_get("spend_micros").map_err(storage_err),
            None => Ok(0),
        }
    }

    async fn list_budgets(
        &self,
        subject_type: SubjectType,
        subject_id: &str,
    ) -> Result<Vec<Budget>> {
        let rows = sqlx::query(
            "SELECT * FROM budgets \
             WHERE subject_type = $1 AND subject_id = $2 AND deleted_at IS NULL \
             ORDER BY created_at",
        )
        .bind(subject_type.as_str())
        .bind(subject_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(map_budget).collect()
    }

    async fn list_all_budgets(&self) -> Result<Vec<Budget>> {
        let rows = sqlx::query(
            "SELECT * FROM budgets WHERE deleted_at IS NULL \
             ORDER BY subject_type, subject_id, created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(map_budget).collect()
    }

    async fn upsert_budget(&self, budget: &Budget) -> Result<()> {
        sqlx::query(
            "INSERT INTO budgets \
             (id, subject_type, subject_id, period, hard_limit_micros, \
              soft_limit_micros, action, enabled, created_at, updated_at, deleted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
             ON CONFLICT(id) DO UPDATE SET \
               subject_type = excluded.subject_type, subject_id = excluded.subject_id, \
               period = excluded.period, hard_limit_micros = excluded.hard_limit_micros, \
               soft_limit_micros = excluded.soft_limit_micros, action = excluded.action, \
               enabled = excluded.enabled, updated_at = excluded.updated_at, \
               deleted_at = excluded.deleted_at",
        )
        .bind(&budget.id)
        .bind(budget.subject_type.as_str())
        .bind(&budget.subject_id)
        .bind(budget.period.as_str())
        .bind(budget.hard_limit_micros)
        .bind(budget.soft_limit_micros)
        .bind(action_str(budget.action))
        .bind(budget.enabled)
        .bind(budget.created_at)
        .bind(budget.updated_at)
        .bind(budget.deleted_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_budget(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE budgets SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn spend_rows(&self) -> Result<Vec<SpendRow>> {
        let rows = sqlx::query(
            "SELECT subject_type, subject_id, period, period_start, spend_micros, request_count, \
                    input_tokens, output_tokens \
             FROM spend_rollup \
             ORDER BY period_start DESC, subject_type, subject_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(map_spend_row).collect()
    }

    // ---- rate-limit counters ------------------------------------------
    async fn incr_rate_counter(
        &self,
        scope: &str,
        dimension: &str,
        window_start: Timestamp,
        n: i64,
    ) -> Result<i64> {
        let row = sqlx::query(
            "INSERT INTO rate_limit_counters (scope, dimension, window_start, count) \
             VALUES ($1,$2,$3,$4) \
             ON CONFLICT(scope, dimension, window_start) \
             DO UPDATE SET count = rate_limit_counters.count + excluded.count \
             RETURNING count",
        )
        .bind(scope)
        .bind(dimension)
        .bind(window_start)
        .bind(n)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_err)?;
        row.try_get("count").map_err(storage_err)
    }

    // ---- models (the entity behind a public model name) ----------------
    async fn list_models(&self) -> Result<Vec<ModelRecord>> {
        let rows = sqlx::query(&format!("SELECT {MODEL_COLS} FROM models ORDER BY name"))
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;
        rows.iter().map(map_model).collect()
    }

    async fn get_model(&self, id: &str) -> Result<Option<ModelRecord>> {
        let row = sqlx::query(&format!("SELECT {MODEL_COLS} FROM models WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.as_ref().map(map_model).transpose()
    }

    async fn get_model_by_name(&self, name: &str) -> Result<Option<ModelRecord>> {
        let row = sqlx::query(&format!("SELECT {MODEL_COLS} FROM models WHERE name = $1"))
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.as_ref().map(map_model).transpose()
    }

    async fn ensure_model(&self, name: &str) -> Result<ModelRecord> {
        // One statement, so there is no read-then-write race. The no-op
        // `DO UPDATE` is what makes RETURNING fire on the conflict path —
        // `DO NOTHING` returns zero rows.
        let row = sqlx::query(&format!(
            "INSERT INTO models (id, name, created_at, updated_at) VALUES ($1,$2,$3,$4) \
             ON CONFLICT(name) DO UPDATE SET updated_at = models.updated_at \
             RETURNING {MODEL_COLS}"
        ))
        .bind(new_id())
        .bind(name)
        .bind(now())
        .bind(now())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_err)?;
        map_model(&row)
    }

    async fn rename_model(&self, id: &str, new_name: &str) -> Result<ModelRecord> {
        let mut tx = self.pool.begin().await.map_err(storage_err)?;

        let current = sqlx::query(&format!("SELECT {MODEL_COLS} FROM models WHERE id = $1"))
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_err)?;
        let current = match current {
            Some(r) => map_model(&r)?,
            None => return Err(Error::NotFound("model".into())),
        };
        if current.name == new_name {
            return Ok(current);
        }

        let taken = sqlx::query("SELECT 1 FROM models WHERE name = $1 AND id <> $2")
            .bind(new_name)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_err)?;
        if taken.is_some() {
            return Err(Error::Conflict(format!("model \"{new_name}\" already exists")));
        }

        // An alias of *this* model is consumed rather than conflicting, so
        // renaming A->B->A leaves no A->A behind.
        let alias_owner: Option<String> =
            sqlx::query("SELECT model_id FROM model_aliases WHERE alias = $1")
                .bind(new_name)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_err)?
                .map(|r| r.get("model_id"));
        match alias_owner.as_deref() {
            Some(owner) if owner != id => {
                return Err(Error::Conflict(format!(
                    "\"{new_name}\" is already an alias of another model"
                )))
            }
            Some(_) => {
                sqlx::query("DELETE FROM model_aliases WHERE alias = $1")
                    .bind(new_name)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage_err)?;
            }
            None => {}
        }

        sqlx::query("UPDATE models SET name = $1, updated_at = $2 WHERE id = $3")
            .bind(new_name)
            .bind(now())
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;

        // Leave the old name behind, so clients still sending it keep resolving.
        sqlx::query(
            "INSERT INTO model_aliases (alias, model_id, created_at) VALUES ($1,$2,$3) \
             ON CONFLICT(alias) DO UPDATE SET model_id = excluded.model_id",
        )
        .bind(&current.name)
        .bind(id)
        .bind(now())
        .execute(&mut *tx)
        .await
        .map_err(storage_err)?;

        tx.commit().await.map_err(storage_err)?;
        self.get_model(id)
            .await?
            .ok_or_else(|| Error::NotFound("model".into()))
    }

    // ---- deployments (one model's upstream fan-out) --------------------
    async fn list_deployments(&self) -> Result<Vec<DeploymentRecord>> {
        let rows = sqlx::query(&format!(
            "SELECT {DEPLOYMENT_COLS} {DEPLOYMENT_FROM} WHERE d.deleted_at IS NULL \
             ORDER BY m.name, d.provider, d.upstream_model"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(map_deployment).collect()
    }

    async fn get_deployment(&self, id: &str) -> Result<Option<DeploymentRecord>> {
        let row = sqlx::query(&format!(
            "SELECT {DEPLOYMENT_COLS} {DEPLOYMENT_FROM} WHERE d.id = $1 AND d.deleted_at IS NULL"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;
        row.as_ref().map(map_deployment).transpose()
    }

    async fn create_deployment(&self, dep: &NewDeployment) -> Result<DeploymentRecord> {
        let model = self.ensure_model(&dep.model_name).await?;
        let id = new_id();
        sqlx::query(
            "INSERT INTO deployments (id, model_id, provider, upstream_model, \
             api_base, api_key, upstream_format, weight, pricing, health_check, health_path, \
             extra, created_at, updated_at, deleted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL)",
        )
        .bind(&id)
        .bind(&model.id)
        .bind(&dep.provider)
        .bind(&dep.upstream_model)
        .bind(&dep.api_base)
        .bind(&dep.api_key)
        .bind(enc_enum(&dep.upstream_format))
        .bind(dep.weight as i32)
        .bind(enc_pricing(&dep.pricing))
        .bind(dep.health_check.as_str())
        .bind(&dep.health_path)
        .bind(enc_extra(&dep.extra))
        .bind(now())
        .bind(now())
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        self.get_deployment(&id)
            .await?
            .ok_or_else(|| Error::NotFound("deployment".into()))
    }

    async fn delete_deployment(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE deployments SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn seed_deployment(&self, dep: &NewDeployment) -> Result<bool> {
        let model = self.ensure_model(&dep.model_name).await?;
        // Mirrors `deployments_identity_uq`. COALESCE is required, not
        // cosmetic: NULL != NULL, so comparing api_base directly would miss
        // every deployment that omits it — most of them — and each import
        // would insert a second copy.
        let exists = sqlx::query(
            "SELECT 1 FROM deployments WHERE model_id = $1 AND provider = $2 \
             AND upstream_model = $3 AND COALESCE(api_base,'') = COALESCE($4,'') \
             AND deleted_at IS NULL",
        )
        .bind(&model.id)
        .bind(&dep.provider)
        .bind(&dep.upstream_model)
        .bind(&dep.api_base)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;
        if exists.is_some() {
            return Ok(false);
        }
        self.create_deployment(dep).await?;
        Ok(true)
    }

    // ---- model aliases (extra public name -> model) --------------------
    async fn list_aliases(&self) -> Result<Vec<ModelAlias>> {
        let rows = sqlx::query(
            "SELECT a.alias, a.model_id, m.name AS target, a.created_at \
             FROM model_aliases a JOIN models m ON m.id = a.model_id ORDER BY a.alias",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(map_alias).collect()
    }

    async fn upsert_alias(&self, alias: &str, model_id: &str) -> Result<ModelAlias> {
        sqlx::query(
            "INSERT INTO model_aliases (alias, model_id, created_at) VALUES ($1,$2,$3) \
             ON CONFLICT(alias) DO UPDATE SET model_id = excluded.model_id",
        )
        .bind(alias)
        .bind(model_id)
        .bind(now())
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        let row = sqlx::query(
            "SELECT a.alias, a.model_id, m.name AS target, a.created_at \
             FROM model_aliases a JOIN models m ON m.id = a.model_id WHERE a.alias = $1",
        )
        .bind(alias)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_err)?;
        map_alias(&row)
    }

    async fn delete_alias(&self, alias: &str) -> Result<()> {
        sqlx::query("DELETE FROM model_aliases WHERE alias = $1")
            .bind(alias)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }
}
