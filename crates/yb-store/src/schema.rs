//! Embedded, idempotent migration SQL — one body per dialect.
//!
//! Tables are unprefixed (the database is already the namespace). Every
//! statement is `CREATE TABLE/INDEX IF NOT EXISTS`, so [`crate::Store::migrate`]
//! can be called repeatedly without harm.
//!
//! Identity model: **users** own **keys**; users group into **teams**. There is
//! no tenancy ("installation") layer, so no `installation_id` column appears.
//!
//! Type deltas between dialects:
//! - ids / JSON columns: `TEXT` in both (JSON is stored as text, not jsonb,
//!   to avoid pulling in the sqlx `json` feature).
//! - timestamps: RFC3339 `TEXT` in SQLite, `TIMESTAMPTZ` in Postgres.
//! - money: `BIGINT` micro-dollars in both.
//! - ciphertext: `BLOB` in SQLite, `BYTEA` in Postgres.
//! - booleans: `INTEGER` 0/1 in SQLite, `BOOLEAN` in Postgres.

/// SQLite DDL. ids/timestamps as TEXT, money as INTEGER, blobs as BLOB.
pub const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL,
    rpm_limit           INTEGER,
    tpm_limit           INTEGER,
    max_concurrent      INTEGER,
    created_at          TEXT NOT NULL,
    last_login_at       TEXT,
    deleted_at          TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_uq
    ON users(username) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS api_keys (
    id                  TEXT PRIMARY KEY,
    owner_user_id       TEXT NOT NULL,
    team_id             TEXT,
    hash                TEXT NOT NULL,
    key_prefix          TEXT NOT NULL,
    key_suffix          TEXT NOT NULL,
    name                TEXT,
    scope               TEXT NOT NULL DEFAULT 'inference',
    access              TEXT NOT NULL DEFAULT '{}',
    rpm_limit           INTEGER,
    tpm_limit           INTEGER,
    max_concurrent      INTEGER,
    created_at          TEXT NOT NULL,
    last_used_at        TEXT,
    deleted_at          TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS api_keys_hash_idx ON api_keys(hash);
CREATE INDEX IF NOT EXISTS api_keys_owner_idx ON api_keys(owner_user_id);

CREATE TABLE IF NOT EXISTS external_keys (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    provider            TEXT NOT NULL,
    ciphertext          BLOB NOT NULL,
    key_prefix          TEXT NOT NULL,
    key_suffix          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    last_used_at        TEXT,
    UNIQUE(user_id, provider)
);

CREATE TABLE IF NOT EXISTS teams (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    access              TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT,
    created_by          TEXT
);

CREATE TABLE IF NOT EXISTS team_memberships (
    id                  TEXT PRIMARY KEY,
    team_id             TEXT NOT NULL,
    user_id             TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    UNIQUE(team_id, user_id)
);

CREATE TABLE IF NOT EXISTS request_telemetry (
    id                  TEXT PRIMARY KEY,
    request_id          TEXT NOT NULL,
    trace_id            TEXT,
    api_key_id          TEXT,
    user_id             TEXT,
    team_id             TEXT,
    surface             TEXT NOT NULL,
    requested_model     TEXT NOT NULL,
    decision_model      TEXT NOT NULL,
    decision_provider   TEXT NOT NULL,
    input_tokens        INTEGER NOT NULL,
    output_tokens       INTEGER NOT NULL,
    cache_read_tokens   INTEGER NOT NULL,
    cache_write_tokens  INTEGER NOT NULL,
    cost_micros         INTEGER NOT NULL,
    status              INTEGER NOT NULL,
    is_error            INTEGER NOT NULL,
    latency_ms          INTEGER NOT NULL,
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS telemetry_created_idx
    ON request_telemetry(created_at);
CREATE INDEX IF NOT EXISTS telemetry_api_key_idx
    ON request_telemetry(api_key_id, created_at);

CREATE TABLE IF NOT EXISTS spend_rollup (
    subject_type        TEXT NOT NULL,
    subject_id          TEXT NOT NULL,
    period              TEXT NOT NULL,
    period_start        TEXT NOT NULL,
    spend_micros        INTEGER NOT NULL DEFAULT 0,
    request_count       INTEGER NOT NULL DEFAULT 0,
    input_tokens        INTEGER NOT NULL DEFAULT 0,
    output_tokens       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (subject_type, subject_id, period, period_start)
);

CREATE TABLE IF NOT EXISTS budgets (
    id                  TEXT PRIMARY KEY,
    subject_type        TEXT NOT NULL,
    subject_id          TEXT NOT NULL,
    period              TEXT NOT NULL,
    hard_limit_micros   INTEGER NOT NULL,
    soft_limit_micros   INTEGER,
    action              TEXT NOT NULL,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT
);
CREATE INDEX IF NOT EXISTS budgets_subject_idx
    ON budgets(subject_type, subject_id);

CREATE TABLE IF NOT EXISTS rate_limit_counters (
    scope               TEXT NOT NULL,
    dimension           TEXT NOT NULL,
    window_start        TEXT NOT NULL,
    count               INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, dimension, window_start)
);

CREATE TABLE IF NOT EXISTS deployments (
    id                  TEXT PRIMARY KEY,
    model_name          TEXT NOT NULL,
    provider            TEXT NOT NULL,
    upstream_model      TEXT NOT NULL,
    api_base            TEXT,
    api_key             TEXT,
    upstream_format     TEXT NOT NULL,
    weight              INTEGER NOT NULL DEFAULT 1,
    pricing             TEXT,
    health_check        TEXT NOT NULL DEFAULT 'none',
    health_path         TEXT,
    natural_key         TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT
);
CREATE INDEX IF NOT EXISTS deployments_model_idx
    ON deployments(model_name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS deployments_natural_key_uq
    ON deployments(natural_key) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS sessions (
    token               TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);

CREATE TABLE IF NOT EXISTS model_aliases (
    alias               TEXT PRIMARY KEY,
    target              TEXT NOT NULL,
    created_at          TEXT NOT NULL
);
"#;

/// Postgres DDL. ids/JSON as TEXT, timestamps TIMESTAMPTZ, money BIGINT,
/// ciphertext BYTEA, booleans BOOLEAN.
pub const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL,
    rpm_limit           BIGINT,
    tpm_limit           BIGINT,
    max_concurrent      BIGINT,
    created_at          TIMESTAMPTZ NOT NULL,
    last_login_at       TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_uq
    ON users(username) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS api_keys (
    id                  TEXT PRIMARY KEY,
    owner_user_id       TEXT NOT NULL,
    team_id             TEXT,
    hash                TEXT NOT NULL,
    key_prefix          TEXT NOT NULL,
    key_suffix          TEXT NOT NULL,
    name                TEXT,
    scope               TEXT NOT NULL DEFAULT 'inference',
    access              TEXT NOT NULL DEFAULT '{}',
    rpm_limit           BIGINT,
    tpm_limit           BIGINT,
    max_concurrent      BIGINT,
    created_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS api_keys_hash_idx ON api_keys(hash);
CREATE INDEX IF NOT EXISTS api_keys_owner_idx ON api_keys(owner_user_id);

CREATE TABLE IF NOT EXISTS external_keys (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    provider            TEXT NOT NULL,
    ciphertext          BYTEA NOT NULL,
    key_prefix          TEXT NOT NULL,
    key_suffix          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ,
    UNIQUE(user_id, provider)
);

CREATE TABLE IF NOT EXISTS teams (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    access              TEXT NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    deleted_at          TIMESTAMPTZ,
    created_by          TEXT
);

CREATE TABLE IF NOT EXISTS team_memberships (
    id                  TEXT PRIMARY KEY,
    team_id             TEXT NOT NULL,
    user_id             TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    UNIQUE(team_id, user_id)
);

CREATE TABLE IF NOT EXISTS request_telemetry (
    id                  TEXT PRIMARY KEY,
    request_id          TEXT NOT NULL,
    trace_id            TEXT,
    api_key_id          TEXT,
    user_id             TEXT,
    team_id             TEXT,
    surface             TEXT NOT NULL,
    requested_model     TEXT NOT NULL,
    decision_model      TEXT NOT NULL,
    decision_provider   TEXT NOT NULL,
    input_tokens        BIGINT NOT NULL,
    output_tokens       BIGINT NOT NULL,
    cache_read_tokens   BIGINT NOT NULL,
    cache_write_tokens  BIGINT NOT NULL,
    cost_micros         BIGINT NOT NULL,
    status              INTEGER NOT NULL,
    is_error            BOOLEAN NOT NULL,
    latency_ms          BIGINT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS telemetry_created_idx
    ON request_telemetry(created_at);
CREATE INDEX IF NOT EXISTS telemetry_api_key_idx
    ON request_telemetry(api_key_id, created_at);

CREATE TABLE IF NOT EXISTS spend_rollup (
    subject_type        TEXT NOT NULL,
    subject_id          TEXT NOT NULL,
    period              TEXT NOT NULL,
    period_start        TIMESTAMPTZ NOT NULL,
    spend_micros        BIGINT NOT NULL DEFAULT 0,
    request_count       BIGINT NOT NULL DEFAULT 0,
    input_tokens        BIGINT NOT NULL DEFAULT 0,
    output_tokens       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (subject_type, subject_id, period, period_start)
);

CREATE TABLE IF NOT EXISTS budgets (
    id                  TEXT PRIMARY KEY,
    subject_type        TEXT NOT NULL,
    subject_id          TEXT NOT NULL,
    period              TEXT NOT NULL,
    hard_limit_micros   BIGINT NOT NULL,
    soft_limit_micros   BIGINT,
    action              TEXT NOT NULL,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    deleted_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS budgets_subject_idx
    ON budgets(subject_type, subject_id);

CREATE TABLE IF NOT EXISTS rate_limit_counters (
    scope               TEXT NOT NULL,
    dimension           TEXT NOT NULL,
    window_start        TIMESTAMPTZ NOT NULL,
    count               BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, dimension, window_start)
);

CREATE TABLE IF NOT EXISTS deployments (
    id                  TEXT PRIMARY KEY,
    model_name          TEXT NOT NULL,
    provider            TEXT NOT NULL,
    upstream_model      TEXT NOT NULL,
    api_base            TEXT,
    api_key             TEXT,
    upstream_format     TEXT NOT NULL,
    weight              INTEGER NOT NULL DEFAULT 1,
    pricing             TEXT,
    health_check        TEXT NOT NULL DEFAULT 'none',
    health_path         TEXT,
    natural_key         TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    deleted_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS deployments_model_idx
    ON deployments(model_name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS deployments_natural_key_uq
    ON deployments(natural_key) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS sessions (
    token               TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
"#;
