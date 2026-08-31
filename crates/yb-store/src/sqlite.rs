//! SQLite-backed [`Store`] implementation.
//!
//! Connection pragmas (WAL, `busy_timeout=5000`, `foreign_keys=ON`) are applied
//! per-connection. ids and timestamps are stored as TEXT (RFC3339 UTC), money
//! as INTEGER micro-dollars, `Vec<String>`/`AccessPolicy` as JSON text, and
//! BYOK ciphertext as BLOB. Rows are mapped by hand against runtime queries.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::sqlite::{
    SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::Row;

use yb_core::model::{
    AccessPolicy, ApiKey, ExternalKey, KeyScope, ModelAlias, Role, Session, Team, TeamMembership,
    TelemetryRecord, User,
};
use yb_core::principal::KeyAuth;
use yb_core::routing::DeploymentRecord;
use yb_core::spend::{Budget, BudgetAction, Period, RollupDelta, SpendRow, SubjectType};
use yb_core::{now, Error, LimitColumns, Micros, Result, Store, Timestamp};

use crate::common::{dec_access, enc_access, parse_ts, parse_ts_opt, storage_err};
use crate::schema::SQLITE_SCHEMA;

/// A SQLite [`Store`]. Cheap to clone (wraps an `Arc`-backed pool).
#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

/// RFC3339 rendering used for every timestamp column.
fn ts(t: &Timestamp) -> String {
    t.to_rfc3339()
}
fn ts_opt(t: &Option<Timestamp>) -> Option<String> {
    t.as_ref().map(ts)
}

/// Encode a small serde enum (`WireFormat`) as a JSON string.
fn enc_enum<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// The explicit column list for `deployments` reads.
///
/// Deliberately not `SELECT *`. `migrate` adds columns to already-deployed
/// databases with `ALTER TABLE`, which appends them at the end, so a migrated
/// database and a freshly created one order their columns differently. Worse, a
/// star select against a table altered earlier in the same process can panic
/// inside sqlx: the cached column metadata and the live statement's column count
/// disagree, and the row is indexed with the wrong one. Naming the columns keeps
/// reads pinned to the shape this code expects.
const DEPLOYMENT_COLS: &str = "id, model_name, provider, upstream_model, api_base, api_key, \
     upstream_format, weight, pricing, health_check, health_path, extra, natural_key, \
     created_at, updated_at, deleted_at";

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

/// Map a `deployments` row to a [`DeploymentRecord`].
fn map_deployment(row: &SqliteRow) -> Result<DeploymentRecord> {
    let fmt_s: String = row.get("upstream_format");
    let pricing_s: Option<String> = row.get("pricing");
    let weight: i64 = row.get("weight");
    Ok(DeploymentRecord {
        id: row.get("id"),
        model_name: row.get("model_name"),
        provider: row.get("provider"),
        upstream_model: row.get("upstream_model"),
        api_base: row.get("api_base"),
        api_key: row.get("api_key"),
        upstream_format: serde_json::from_str(&fmt_s).map_err(storage_err)?,
        weight: weight.max(0) as u32,
        pricing: match pricing_s {
            Some(s) => serde_json::from_str(&s).map_err(storage_err)?,
            None => None,
        },
        health_check: serde_json::from_value(serde_json::Value::String(
            row.get::<String, _>("health_check"),
        ))
        .map_err(storage_err)?,
        health_path: row.get("health_path"),
        extra: dec_extra(row.get("extra")),
        created_at: parse_ts(&row.get::<String, _>("created_at"))?,
        updated_at: parse_ts(&row.get::<String, _>("updated_at"))?,
        deleted_at: parse_ts_opt(row.get("deleted_at"))?,
    })
}

impl SqliteStore {
    /// Open (creating if missing) a SQLite database at `path` with the
    /// contract pragmas. Pass a real file path — `:memory:` databases are not
    /// shared across pool connections.
    pub async fn connect(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_millis(5000))
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .map_err(storage_err)?;
        Ok(Self { pool })
    }

    /// Wrap an existing pool (used by tests/embedders that build their own).
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Borrow the underlying pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

// ---- row mappers -------------------------------------------------------

fn map_user(r: &SqliteRow) -> Result<User> {
    Ok(User {
        id: r.try_get("id").map_err(storage_err)?,
        username: r.try_get("username").map_err(storage_err)?,
        password_hash: r.try_get("password_hash").map_err(storage_err)?,
        role: Role::parse(&r.try_get::<String, _>("role").map_err(storage_err)?)?,
        rpm_limit: r.try_get("rpm_limit").map_err(storage_err)?,
        tpm_limit: r.try_get("tpm_limit").map_err(storage_err)?,
        max_concurrent: r.try_get("max_concurrent").map_err(storage_err)?,
        created_at: parse_ts(&r.try_get::<String, _>("created_at").map_err(storage_err)?)?,
        last_login_at: parse_ts_opt(r.try_get("last_login_at").map_err(storage_err)?)?,
        deleted_at: parse_ts_opt(r.try_get("deleted_at").map_err(storage_err)?)?,
    })
}

fn map_api_key(r: &SqliteRow) -> Result<ApiKey> {
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
        created_at: parse_ts(&r.try_get::<String, _>("created_at").map_err(storage_err)?)?,
        last_used_at: parse_ts_opt(r.try_get("last_used_at").map_err(storage_err)?)?,
        deleted_at: parse_ts_opt(r.try_get("deleted_at").map_err(storage_err)?)?,
    })
}

fn map_external_key(r: &SqliteRow) -> Result<ExternalKey> {
    Ok(ExternalKey {
        id: r.try_get("id").map_err(storage_err)?,
        user_id: r.try_get("user_id").map_err(storage_err)?,
        provider: r.try_get("provider").map_err(storage_err)?,
        ciphertext: r.try_get("ciphertext").map_err(storage_err)?,
        key_prefix: r.try_get("key_prefix").map_err(storage_err)?,
        key_suffix: r.try_get("key_suffix").map_err(storage_err)?,
        created_at: parse_ts(&r.try_get::<String, _>("created_at").map_err(storage_err)?)?,
        last_used_at: parse_ts_opt(r.try_get("last_used_at").map_err(storage_err)?)?,
    })
}

fn map_team(r: &SqliteRow) -> Result<Team> {
    Ok(Team {
        id: r.try_get("id").map_err(storage_err)?,
        name: r.try_get("name").map_err(storage_err)?,
        access: dec_access(&r.try_get::<String, _>("access").map_err(storage_err)?),
        created_at: parse_ts(&r.try_get::<String, _>("created_at").map_err(storage_err)?)?,
        updated_at: parse_ts(&r.try_get::<String, _>("updated_at").map_err(storage_err)?)?,
        deleted_at: parse_ts_opt(r.try_get("deleted_at").map_err(storage_err)?)?,
        created_by: r.try_get("created_by").map_err(storage_err)?,
    })
}

fn map_membership(r: &SqliteRow) -> Result<TeamMembership> {
    Ok(TeamMembership {
        id: r.try_get("id").map_err(storage_err)?,
        team_id: r.try_get("team_id").map_err(storage_err)?,
        user_id: r.try_get("user_id").map_err(storage_err)?,
        created_at: parse_ts(&r.try_get::<String, _>("created_at").map_err(storage_err)?)?,
    })
}

fn map_budget(r: &SqliteRow) -> Result<Budget> {
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
        created_at: parse_ts(&r.try_get::<String, _>("created_at").map_err(storage_err)?)?,
        updated_at: parse_ts(&r.try_get::<String, _>("updated_at").map_err(storage_err)?)?,
        deleted_at: parse_ts_opt(r.try_get("deleted_at").map_err(storage_err)?)?,
    })
}

fn map_spend_row(r: &SqliteRow) -> Result<SpendRow> {
    Ok(SpendRow {
        subject_type: r.try_get("subject_type").map_err(storage_err)?,
        subject_id: r.try_get("subject_id").map_err(storage_err)?,
        period: r.try_get("period").map_err(storage_err)?,
        period_start: parse_ts(&r.try_get::<String, _>("period_start").map_err(storage_err)?)?,
        spend_micros: r.try_get("spend_micros").map_err(storage_err)?,
        request_count: r.try_get("request_count").map_err(storage_err)?,
        input_tokens: r.try_get("input_tokens").map_err(storage_err)?,
        output_tokens: r.try_get("output_tokens").map_err(storage_err)?,
    })
}

/// `BudgetAction` has no string parser in core; we keep one local to storage.
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

#[async_trait]
impl Store for SqliteStore {
    async fn migrate(&self) -> Result<()> {
        sqlx::raw_sql(SQLITE_SCHEMA)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        // Additive column migrations for pre-existing databases. Best-effort:
        // "duplicate column" failures mean the column is already there.
        for ddl in [
            "ALTER TABLE api_keys ADD COLUMN scope TEXT NOT NULL DEFAULT 'inference'",
            "ALTER TABLE deployments ADD COLUMN health_check TEXT NOT NULL DEFAULT 'none'",
            "ALTER TABLE deployments ADD COLUMN health_path TEXT",
            "ALTER TABLE deployments ADD COLUMN extra TEXT NOT NULL DEFAULT '{}'",
        ] {
            let _ = sqlx::raw_sql(ddl).execute(&self.pool).await;
        }
        Ok(())
    }

    // ---- users (login accounts; own keys) -----------------------------
    async fn create_user(&self, user: &User) -> Result<()> {
        sqlx::query(
            "INSERT INTO users \
             (id, username, password_hash, role, rpm_limit, tpm_limit, max_concurrent, \
              created_at, last_login_at, deleted_at) \
             VALUES (?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.role.as_str())
        .bind(user.rpm_limit)
        .bind(user.tpm_limit)
        .bind(user.max_concurrent)
        .bind(ts(&user.created_at))
        .bind(ts_opt(&user.last_login_at))
        .bind(ts_opt(&user.deleted_at))
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn get_user(&self, id: &str) -> Result<Option<User>> {
        let row = sqlx::query("SELECT * FROM users WHERE id = ? AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.as_ref().map(map_user).transpose()
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query("SELECT * FROM users WHERE username = ? AND deleted_at IS NULL")
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
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ? AND deleted_at IS NULL")
            .bind(password_hash)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn set_user_role(&self, id: &str, role: Role) -> Result<()> {
        sqlx::query("UPDATE users SET role = ? WHERE id = ? AND deleted_at IS NULL")
            .bind(role.as_str())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn set_user_limits(&self, id: &str, limits: LimitColumns) -> Result<()> {
        sqlx::query(
            "UPDATE users SET rpm_limit = ?, tpm_limit = ?, max_concurrent = ? \
             WHERE id = ? AND deleted_at IS NULL",
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
        sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
            .bind(ts(&now()))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_user(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE users SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL")
            .bind(ts(&now()))
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
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
        )
        .bind(&session.token)
        .bind(&session.user_id)
        .bind(ts(&session.created_at))
        .bind(ts(&session.expires_at))
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn get_session(&self, token: &str) -> Result<Option<Session>> {
        let row = sqlx::query("SELECT * FROM sessions WHERE token = ? AND expires_at > ?")
            .bind(token)
            .bind(ts(&now()))
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(Session {
                token: r.try_get("token").map_err(storage_err)?,
                user_id: r.try_get("user_id").map_err(storage_err)?,
                created_at: parse_ts(&r.try_get::<String, _>("created_at").map_err(storage_err)?)?,
                expires_at: parse_ts(&r.try_get::<String, _>("expires_at").map_err(storage_err)?)?,
            })),
        }
    }

    async fn delete_session(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token = ?")
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
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
        .bind(ts(&key.created_at))
        .bind(ts_opt(&key.last_used_at))
        .bind(ts_opt(&key.deleted_at))
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn verify_api_key(&self, token_hash: &str) -> Result<Option<KeyAuth>> {
        let key_row = sqlx::query("SELECT * FROM api_keys WHERE hash = ? AND deleted_at IS NULL")
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
        let row = sqlx::query("SELECT * FROM api_keys WHERE id = ?")
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
            "SELECT * FROM api_keys WHERE owner_user_id = ? AND deleted_at IS NULL \
             ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(map_api_key).collect()
    }

    async fn mark_api_key_used(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(ts(&now()))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_api_key(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE api_keys SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL")
            .bind(ts(&now()))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn update_api_key_access(&self, id: &str, policy: &AccessPolicy) -> Result<()> {
        sqlx::query("UPDATE api_keys SET access = ? WHERE id = ?")
            .bind(enc_access(policy))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn update_api_key_limits(&self, id: &str, limits: LimitColumns) -> Result<()> {
        sqlx::query(
            "UPDATE api_keys SET rpm_limit = ?, tpm_limit = ?, max_concurrent = ? WHERE id = ?",
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
             VALUES (?,?,?,?,?,?,?,?) \
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
        .bind(ts(&key.created_at))
        .bind(ts_opt(&key.last_used_at))
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn list_external_keys(&self, user_id: &str) -> Result<Vec<ExternalKey>> {
        let rows = sqlx::query("SELECT * FROM external_keys WHERE user_id = ? ORDER BY provider")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;
        rows.iter().map(map_external_key).collect()
    }

    async fn delete_external_key(&self, user_id: &str, provider: &str) -> Result<()> {
        sqlx::query("DELETE FROM external_keys WHERE user_id = ? AND provider = ?")
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
             VALUES (?,?,?,?,?,?,?)",
        )
        .bind(&team.id)
        .bind(&team.name)
        .bind(enc_access(&team.access))
        .bind(ts(&team.created_at))
        .bind(ts(&team.updated_at))
        .bind(ts_opt(&team.deleted_at))
        .bind(&team.created_by)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn get_team(&self, id: &str) -> Result<Option<Team>> {
        let row = sqlx::query("SELECT * FROM teams WHERE id = ?")
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
        sqlx::query("UPDATE teams SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL")
            .bind(ts(&now()))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn update_team_access(&self, id: &str, policy: &AccessPolicy) -> Result<()> {
        sqlx::query("UPDATE teams SET access = ?, updated_at = ? WHERE id = ?")
            .bind(enc_access(policy))
            .bind(ts(&now()))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn upsert_membership(&self, m: &TeamMembership) -> Result<()> {
        sqlx::query(
            "INSERT INTO team_memberships (id, team_id, user_id, created_at) \
             VALUES (?,?,?,?) \
             ON CONFLICT(team_id, user_id) DO NOTHING",
        )
        .bind(&m.id)
        .bind(&m.team_id)
        .bind(&m.user_id)
        .bind(ts(&m.created_at))
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn list_memberships_for_user(&self, user_id: &str) -> Result<Vec<TeamMembership>> {
        let rows =
            sqlx::query("SELECT * FROM team_memberships WHERE user_id = ? ORDER BY created_at")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_err)?;
        rows.iter().map(map_membership).collect()
    }

    async fn list_team_members(&self, team_id: &str) -> Result<Vec<TeamMembership>> {
        let rows =
            sqlx::query("SELECT * FROM team_memberships WHERE team_id = ? ORDER BY created_at")
                .bind(team_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_err)?;
        rows.iter().map(map_membership).collect()
    }

    async fn delete_membership(&self, team_id: &str, user_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM team_memberships WHERE team_id = ? AND user_id = ?")
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
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
        .bind(ts(&rec.created_at))
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
             VALUES (?,?,?,?,?,?,?,?) \
             ON CONFLICT(subject_type, subject_id, period, period_start) \
             DO UPDATE SET \
               spend_micros = spend_micros + excluded.spend_micros, \
               request_count = request_count + excluded.request_count, \
               input_tokens = input_tokens + excluded.input_tokens, \
               output_tokens = output_tokens + excluded.output_tokens",
        )
        .bind(delta.subject_type.as_str())
        .bind(&delta.subject_id)
        .bind(delta.period.as_str())
        .bind(ts(&delta.period_start))
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
             WHERE subject_type = ? AND subject_id = ? AND period = ? AND period_start = ?",
        )
        .bind(subject_type.as_str())
        .bind(subject_id)
        .bind(period.as_str())
        .bind(ts(&period_start))
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
             WHERE subject_type = ? AND subject_id = ? AND deleted_at IS NULL \
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
             VALUES (?,?,?,?,?,?,?,?,?,?,?) \
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
        .bind(ts(&budget.created_at))
        .bind(ts(&budget.updated_at))
        .bind(ts_opt(&budget.deleted_at))
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_budget(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE budgets SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL")
            .bind(ts(&now()))
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
             VALUES (?,?,?,?) \
             ON CONFLICT(scope, dimension, window_start) \
             DO UPDATE SET count = count + excluded.count \
             RETURNING count",
        )
        .bind(scope)
        .bind(dimension)
        .bind(ts(&window_start))
        .bind(n)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_err)?;
        row.try_get("count").map_err(storage_err)
    }

    // ---- deployments (the live model list) ----------------------------
    async fn list_deployments(&self) -> Result<Vec<DeploymentRecord>> {
        let rows = sqlx::query(&format!(
            "SELECT {DEPLOYMENT_COLS} FROM deployments WHERE deleted_at IS NULL \
             ORDER BY model_name, provider, upstream_model"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(map_deployment).collect()
    }

    async fn get_deployment(&self, id: &str) -> Result<Option<DeploymentRecord>> {
        let row = sqlx::query(&format!(
            "SELECT {DEPLOYMENT_COLS} FROM deployments WHERE id = ? AND deleted_at IS NULL"
        ))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.as_ref().map(map_deployment).transpose()
    }

    async fn create_deployment(&self, dep: &DeploymentRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO deployments (id, model_name, provider, upstream_model, \
             api_base, api_key, upstream_format, weight, pricing, health_check, health_path, \
             extra, natural_key, created_at, updated_at, deleted_at) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
        )
        .bind(&dep.id)
        .bind(&dep.model_name)
        .bind(&dep.provider)
        .bind(&dep.upstream_model)
        .bind(&dep.api_base)
        .bind(&dep.api_key)
        .bind(enc_enum(&dep.upstream_format))
        .bind(dep.weight as i64)
        .bind(enc_pricing(&dep.pricing))
        .bind(dep.health_check.as_str())
        .bind(&dep.health_path)
        .bind(enc_extra(&dep.extra))
        .bind(dep.natural_key())
        .bind(ts(&dep.created_at))
        .bind(ts(&dep.updated_at))
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_deployment(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE deployments SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL")
            .bind(ts(&now()))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn seed_deployment(&self, dep: &DeploymentRecord) -> Result<bool> {
        let exists =
            sqlx::query("SELECT 1 FROM deployments WHERE natural_key = ? AND deleted_at IS NULL")
                .bind(dep.natural_key())
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_err)?;
        if exists.is_some() {
            return Ok(false);
        }
        self.create_deployment(dep).await?;
        Ok(true)
    }

    // ---- model aliases ------------------------------------------------
    async fn list_aliases(&self) -> Result<Vec<ModelAlias>> {
        let rows = sqlx::query("SELECT alias, target, created_at FROM model_aliases ORDER BY alias")
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;
        rows.iter()
            .map(|r| {
                Ok(ModelAlias {
                    alias: r.try_get("alias").map_err(storage_err)?,
                    target: r.try_get("target").map_err(storage_err)?,
                    created_at: parse_ts(
                        &r.try_get::<String, _>("created_at").map_err(storage_err)?,
                    )?,
                })
            })
            .collect()
    }

    async fn upsert_alias(&self, alias: &ModelAlias) -> Result<()> {
        sqlx::query(
            "INSERT INTO model_aliases (alias, target, created_at) VALUES (?,?,?) \
             ON CONFLICT(alias) DO UPDATE SET target = excluded.target",
        )
        .bind(&alias.alias)
        .bind(&alias.target)
        .bind(ts(&alias.created_at))
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_alias(&self, alias: &str) -> Result<()> {
        sqlx::query("DELETE FROM model_aliases WHERE alias = ?")
            .bind(alias)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }
}
