-- SQLite baseline. ids/timestamps as TEXT, money as INTEGER, blobs as BLOB.
--
-- Identity model: users own keys; users group into teams. There is no tenancy
-- ("installation") layer, so no installation_id column appears.
--
-- Models are a first-class entity: `models` holds the identity, `deployments`
-- are the concrete upstreams behind it (1:N — that is the load-balancing
-- feature). Everything internal references models.id, so a model can be renamed
-- with a single UPDATE. `models.name` is the public name clients request on the
-- wire; it is a unique label, not the identity.

CREATE TABLE users (
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
CREATE UNIQUE INDEX users_username_uq ON users(username) WHERE deleted_at IS NULL;

CREATE TABLE api_keys (
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
CREATE UNIQUE INDEX api_keys_hash_idx ON api_keys(hash);
CREATE INDEX api_keys_owner_idx ON api_keys(owner_user_id);

CREATE TABLE external_keys (
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

CREATE TABLE teams (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    access              TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT,
    created_by          TEXT
);

CREATE TABLE team_memberships (
    id                  TEXT PRIMARY KEY,
    team_id             TEXT NOT NULL,
    user_id             TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    UNIQUE(team_id, user_id)
);

-- requested_model / decision_model are the names AS THEY WERE at the time, not
-- references. They are historical facts; a later rename must not rewrite them.
CREATE TABLE request_telemetry (
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
CREATE INDEX telemetry_created_idx ON request_telemetry(created_at);
CREATE INDEX telemetry_api_key_idx ON request_telemetry(api_key_id, created_at);

CREATE TABLE spend_rollup (
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

CREATE TABLE budgets (
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
CREATE INDEX budgets_subject_idx ON budgets(subject_type, subject_id);

CREATE TABLE rate_limit_counters (
    scope               TEXT NOT NULL,
    dimension           TEXT NOT NULL,
    window_start        TEXT NOT NULL,
    count               INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, dimension, window_start)
);

-- The model entity. `name` is the public name clients send on the wire, unique
-- across live models. Models are not soft-deleted: a model is "live" when it
-- has at least one live deployment, which preserves the pre-normalization
-- behaviour where a model existed only as long as something backed it.
CREATE TABLE models (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE UNIQUE INDEX models_name_uq ON models(name);

-- A provider: one upstream endpoint, its credentials, and the deployments served
-- through it. Credentials live here rather than on each deployment because they
-- describe the *endpoint* — two models behind one OpenAI account are one key,
-- not two copies of it. `extra` is the same story: the Cloudflare Access flag
-- and literal headers are edge concerns of the endpoint.
--
-- `upstream_format` deliberately is NOT here: one endpoint can serve several
-- (OpenAI serves openai_chat and openai_embed from the same base), so the wire
-- format belongs to the deployment.
CREATE TABLE providers (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    -- NULL means "the wire format's default base".
    api_base            TEXT,
    api_key             TEXT,
    extra               TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE UNIQUE INDEX providers_name_uq ON providers(name);

-- One binding of a model to a provider, in a given wire format. Several
-- deployments of one model are the load-balancing fan-out.
CREATE TABLE deployments (
    id                  TEXT PRIMARY KEY,
    model_id            TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    -- CASCADE reaps tombstoned deployments when a provider is removed.
    -- Deleting a provider that still has *live* deployments is refused in the
    -- store (`delete_provider`), which is the check that carries meaning here:
    -- deployments are soft-deleted, so RESTRICT would also trip on tombstones
    -- and a provider could never be removed once it had ever been used.
    provider_id         TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    upstream_model      TEXT NOT NULL,
    upstream_format     TEXT NOT NULL,
    weight              INTEGER NOT NULL DEFAULT 1,
    pricing             TEXT,
    health_check        TEXT NOT NULL DEFAULT 'none',
    health_path         TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT
);
CREATE INDEX deployments_model_idx ON deployments(model_id) WHERE deleted_at IS NULL;
CREATE INDEX deployments_provider_idx ON deployments(provider_id) WHERE deleted_at IS NULL;

-- A deployment's identity, and the idempotency key for `gateway import`. Keyed
-- on ids rather than names, so renaming a model or a provider cannot make an
-- import re-insert the deployment under its old name. Every column is NOT NULL,
-- so this needs no COALESCE.
CREATE UNIQUE INDEX deployments_identity_uq
    ON deployments(model_id, provider_id, upstream_model)
    WHERE deleted_at IS NULL;

CREATE TABLE sessions (
    token               TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

-- alias -> model id. Renaming a model auto-inserts a row here for the old name,
-- so clients that hardcoded it keep resolving.
CREATE TABLE model_aliases (
    alias               TEXT PRIMARY KEY,
    model_id            TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    created_at          TEXT NOT NULL
);
CREATE INDEX model_aliases_model_idx ON model_aliases(model_id);
