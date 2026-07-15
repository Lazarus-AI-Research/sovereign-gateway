# SovereignGateway — identity model v2 (the refactor in progress)

`yb-core` has been refactored and is FROZEN + compiling. Cascade the rest to match it.
Read `crates/yb-core/src/{model,principal,store,spend,rbac}.rs` for the exact frozen API.

## The model
- **No installations / no tenancy layer.** Delete every `installation`/`Installation`
  reference. There is no `installations` table, no `installation_id` column anywhere.
- **`User` IS the login account** (table `users`): `{id, username UNIQUE, password_hash
  (argon2), role, rpm_limit/tpm_limit/max_concurrent, created_at, last_login_at, deleted_at}`.
  The old separate `accounts` table and email-based `users` are gone — merged into this.
- **Roles are only `admin` and `member`** (no viewer). `Role::{Member(default), Admin}`.
  `"user"` parses to `Member`.
- **Keys belong to a user**: `ApiKey.owner_user_id: Id` (required), `team_id: Option<Id>`,
  no `installation_id`. A member creates/revokes their OWN keys; an admin creates keys for
  any user and sees all keys.
- **Teams** (table `teams`, no installation): `{id, name, access: AccessPolicy, ...}`.
  Membership many-to-many via `team_memberships {id, team_id, user_id, created_at}`.
- **KeyAuth = `{user: User, api_key: ApiKey}`** (verify_api_key returns the key + its owner).
- **Principal = `{user_id, username, role, expires_at}`** (the console session; `is_admin()`).
- **Spend/budgets** attach to subject = `key | user | team` (SubjectType has NO Installation).
  `RollupDelta`/`Budget` have NO `installation_id`. `period`: day|week|month|`total`.
- **Telemetry**: no `installation_id`; has `api_key_id, user_id, team_id`.
- **Dropped**: the credit-ledger/billing methods (`get_balance`/`debit_credit`) and
  `spend_tables_exist` — remove from impls. `external_keys` keyed by `user_id` now.
- Deployments and rate-limit counters are unchanged.

## Store trait — implement EXACTLY `crates/yb-core/src/store.rs`
users (create/get/get_by_username/list/set_password/set_role/set_limits/mark_login/delete/
count_users/count_admins); api keys (create/verify→KeyAuth/get/list/list_for_user/mark_used/
delete/update_access/update_limits); external keys by user; teams + memberships (incl.
list_team_members); telemetry; spend/budgets by subject (+ list_all_budgets); rate counter;
deployments.

## Schema (both dialects, `crates/yb-store/src/schema.rs`)
Drop `installations`, `accounts`, `credit_*`, `billing_overrides`. New/changed:
- `users(id, username, password_hash, role, rpm_limit, tpm_limit, max_concurrent, created_at,
  last_login_at, deleted_at)` + unique index on username where deleted_at is null.
- `api_keys(id, owner_user_id, team_id, hash, key_prefix, key_suffix, name, access(json),
  rpm_limit, tpm_limit, max_concurrent, created_at, last_used_at, deleted_at)`.
- `teams(id, name, access(json), created_at, updated_at, deleted_at, created_by)`.
- `team_memberships(id, team_id, user_id, created_at)` unique (team_id,user_id).
- `external_keys(id, user_id, provider, ciphertext, key_prefix, key_suffix, created_at, last_used_at)`.
- `request_telemetry(... api_key_id, user_id, team_id, surface, ... no installation_id)`.
- `spend_rollup(subject_type, subject_id, period, period_start, spend_micros, request_count,
  input_tokens, output_tokens)` PK(subject_type,subject_id,period,period_start).
- `budgets(id, subject_type, subject_id, period, hard_limit_micros, soft_limit_micros, action,
  enabled, created_at, updated_at, deleted_at)`.
- `deployments`, `rate_limit_counters` unchanged.
Keep `CREATE TABLE IF NOT EXISTS` (idempotent). It's fine to leave dropped tables' DDL absent.

## Server (`yb-server`)
- Admin API drops all `/installations` routes. `/admin/v1/users` = the login users CRUD
  (create {username,password,role}, list, set role, set password, delete; last-admin guard).
- `/admin/v1/auth/{login,logout,me}`: login by `{username,password}` (argon2 verify) → cookie
  session (Principal). `me` → `{username, role}`.
- `/admin/v1/keys`: admin lists ALL keys and creates a key for any `owner_user_id`; a member
  lists/creates/revokes only their OWN keys (owner = the session user). `/keys/:id/access`,
  `/keys/:id` delete (owner or admin).
- `/admin/v1/teams` (no installation): list/create/delete, `/teams/:id/access`,
  `/teams/:id/members` (add {user_id}, list, remove).
- `/admin/v1/budgets` (subject_type+subject_id), `/admin/v1/spend`. No installation query params.
- `run_inference`: `verify_api_key` → KeyAuth{user, api_key}; effective access = key.access ∪
  team.access (if team_id); RequestCtx carries user_id/team_id + access; rate-limit + budget by
  key/user/team. Drop installation everywhere.
- **SPA fallback**: in selfhosted, add an axum `fallback` that serves the admin `index.html`
  (so `preact-router` history paths like `/teams` work on deep-link/refresh). API routes
  (`/v1/*`, `/v1beta/*`, `/admin/*`, `/health`, `/ui/*`, `/`) still match first.

## Frontend (`yb-server/frontend/src/main.tsx`, bundled by rolldown build.rs)
- Use **`preact-router`** (history API, clean paths — NOT hash). VENDOR it:
  download `preact-router` ESM into `frontend/src/vendor/preact-router.mjs` and rewrite its
  `from "preact"` import to `./preact.mjs`. Routes: `/` (redirect to /models or /keys),
  `/models`, `/keys`, `/teams`, `/users`, `/budgets`, `/spend`. Use `<Router>`, `<Route>`,
  `route()` for nav; a top nav with `<a href>`/Link.
- Identity UX: login by username/password (cookie). A **member** sees: Models (read), my Keys
  (create/revoke own), my Spend. An **admin** additionally sees: Users (manage login users),
  Teams, Budgets, all Keys (with owner-user picker), Spend (all). No Installations tab.
- Keep system light/dark (prefers-color-scheme) already in index.html.

## Bin (`yb-bin`)
- `setup [--user --password]` creates/resets an ADMIN user (create_user, argon2). `serve`
  auto-creates admin/admin on first run if `count_users()==0`. AppState drops admin_password
  (already done). Remove any installation references.

## Gates
Every crate compiles (`cargo build`) and tests pass (`cargo test`). `scripts/smoke_sqlite.sh`
updated: no installations; serve auto-creates admin/admin; login → cookie; issue a key (admin,
for the admin user or a created member); exercise 4 surfaces; assert telemetry + parquet shard.
README + `gateway.example.toml` updated (no installation mentions).
