//! The self-hosted admin API (`/admin/v1/*`).
//!
//! Mounted by [`crate::build_router`] only under
//! [`DeploymentMode::Selfhosted`](yb_core::config::DeploymentMode::Selfhosted).
//! Every route except login requires an authenticated [`Principal`] — a logged-in
//! [`User`] resolved from an opaque session-cookie token looked up in the
//! `sessions` table — and is gated by role
//! ([`yb_core::rbac::authorize`]) or by resource ownership.
//!
//! This module never depends on a concrete `Store`: it issues keys by generating
//! a token and its hex-SHA-256 inline (see [`create_key`]) and building an
//! [`ApiKey`] for [`Store::create_api_key`](yb_core::Store::create_api_key).

// The admin guard helpers (`authz`/own-or-admin) return `Result<(), Response>` by
// design: a failed check *is* the HTTP response to send. The `Response` Err
// payload is intentionally large, so silence the size lint for this module.
#![allow(clippy::result_large_err)]

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use yb_core::config::AuthProvider;
use yb_core::model::{AccessPolicy, ApiKey, KeyScope, Role, Session, Team, TeamMembership, User};
use yb_core::principal::Principal as CorePrincipal;
use yb_core::rbac::{authorize, Action};
use yb_core::spend::{Budget, SubjectType};
use yb_core::{new_id, now, Error};

use crate::error_response;
use crate::sso::SsoUser;
use crate::state::AppState;

/// The session cookie name.
const SESSION_COOKIE: &str = "yb_session";

/// Default session lifetime: 7 days.
const SESSION_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// Build the admin sub-router (state applied by the parent router).
pub fn router() -> Router<AppState> {
    Router::new()
        // auth (login/logout/me) — login is the only unauthenticated route
        .route("/auth/config", get(auth_config))
        .route("/auth/login", post(auth_login))
        .route("/auth/sso/start", post(auth_sso_start))
        .route("/auth/sso/code", post(auth_sso_code))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/me", get(auth_me))
        .route("/auth/password", put(change_my_password))
        // login users (admin-managed CRUD; replaces the old /accounts surface)
        .route("/users", get(list_users).post(create_user))
        .route("/users/invite", post(invite_user))
        .route("/users/:id", delete(delete_user))
        .route("/users/:id/role", put(set_user_role))
        .route("/users/:id/password", put(set_user_password))
        // models (the entity: a public name, its aliases, its deployments)
        .route("/models", get(list_models).post(create_model))
        .route("/models/:id/name", put(rename_model))
        // deployments (one model's upstream fan-out)
        .route("/deployments", get(list_deployments).post(create_deployment))
        .route("/deployments/health", get(health_all_models))
        .route("/deployments/:id", delete(delete_deployment))
        .route("/deployments/:id/health", post(health_one_model))
        // model aliases (extra public name -> model)
        .route("/aliases", get(list_aliases).post(create_alias))
        .route("/aliases/:alias", delete(delete_alias))
        // keys (owned by users; admin sees all)
        .route("/keys", get(list_keys).post(create_key))
        .route("/keys/:id", delete(delete_key))
        .route("/keys/:id/access", put(key_access))
        // teams
        .route("/teams", get(list_teams).post(create_team))
        .route("/teams/:id", delete(delete_team))
        .route("/teams/:id/access", put(team_access))
        .route("/teams/:id/members", post(add_member).get(list_members))
        .route("/teams/:id/members/:user_id", delete(remove_member))
        // budgets
        .route("/budgets", get(list_budgets).put(put_budget))
        .route("/budgets/:id", delete(delete_budget))
        // typeahead completion for the console's pill editors
        .route("/complete", get(complete))
        // spend
        .route("/spend", get(spend))
}

// ---- principal extraction ------------------------------------------------

/// An authenticated console caller — a [`User`] resolved from its session
/// cookie. Wrapped locally (the inner type is foreign) so the extractor and
/// authorization helpers can hang methods off it.
#[derive(Clone)]
pub struct Principal(pub CorePrincipal);

impl Principal {
    fn role(&self) -> Role {
        self.0.role
    }
    fn is_admin(&self) -> bool {
        self.0.is_admin()
    }
    fn user_id(&self) -> &str {
        &self.0.user_id
    }
}

#[axum::async_trait]
impl FromRequestParts<AppState> for Principal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let unauthorized = || error_response(&Error::Unauthorized("sign in required".into()));

        // Machine auth: an admin-scope virtual key in `Authorization: Bearer` —
        // the control-plane path. The key acts as its owner user; the role is
        // read fresh so demotions apply immediately.
        if let Some(bearer) = bearer_of(&parts.headers) {
            let auth = match state.store.verify_api_key(&crate::hex_sha256(&bearer)).await {
                Ok(Some(a)) => a,
                Ok(None) => return Err(unauthorized()),
                Err(e) => return Err(error_response(&e)),
            };
            if !auth.api_key.has_scope(KeyScope::Admin) {
                return Err(error_response(&Error::Forbidden(
                    "this key is not admin-scoped".into(),
                )));
            }
            let _ = state.store.mark_api_key_used(&auth.api_key.id).await;
            return Ok(Principal(CorePrincipal {
                user_id: auth.user.id,
                username: auth.user.username,
                role: auth.user.role,
                expires_at: now() + chrono::Duration::seconds(SESSION_TTL_SECS),
            }));
        }

        // Local session cookie (`yb_session`): host-only, backed by our own
        // session store (local password login + the sso code/link flow).
        if let Some(token) = session_cookie(&parts.headers) {
            if let Ok(Some(session)) = state.store.get_session(&token).await {
                if let Ok(Some(user)) = state.store.get_user(&session.user_id).await {
                    return Ok(Principal(CorePrincipal {
                        user_id: user.id,
                        username: user.username,
                        role: user.role,
                        expires_at: session.expires_at,
                    }));
                }
            }
        }

        // Unified cross-app cookie (`lzr_session`): a session minted by the IdP
        // and shared across *.lzrlab.dev. Validate it by introspecting against
        // the IdP, then map the identity to a local user (roles stay ours, read
        // fresh each request).
        if let Some(sso) = &state.sso {
            let name = state
                .auth
                .sso
                .as_ref()
                .and_then(|c| c.session_cookie.clone())
                .unwrap_or_else(|| "lzr_session".to_string());
            if let Some(token) = cookie_value(&parts.headers, &name) {
                if let Ok(sso_user) = sso.introspect(&token).await {
                    return match upsert_sso_user(state, &sso_user).await {
                        Ok(user) => Ok(Principal(CorePrincipal {
                            user_id: user.id,
                            username: user.username,
                            role: user.role,
                            expires_at: now() + chrono::Duration::seconds(SESSION_TTL_SECS),
                        })),
                        Err(e) => Err(error_response(&e)),
                    };
                }
            }
        }

        Err(unauthorized())
    }
}

/// Extract a bearer token from the `Authorization` header, if present.
fn bearer_of(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("authorization")?.to_str().ok()?;
    let lower = v.to_ascii_lowercase();
    let stripped = lower.strip_prefix("bearer ")?;
    Some(v[v.len() - stripped.len()..].trim().to_string())
}

/// Extract the `yb_session` value from the `Cookie` header, if present.
fn session_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, SESSION_COOKIE)
}

/// Extract a named cookie's value from the `Cookie` header, if present.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get("cookie")?.to_str().ok()?;
    let prefix = format!("{name}=");
    for part in cookies.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix(&prefix) {
            return Some(val.to_string());
        }
    }
    None
}

// ---- authorization helpers -----------------------------------------------

/// Authorize `principal` for `action`, returning a 403 response on failure.
fn authz(principal: &Principal, action: Action) -> Result<(), Response> {
    authorize(principal.role(), action).map_err(|e| error_response(&e))
}

/// Wrap a store result as a JSON response.
fn respond<T: Serialize>(r: yb_core::Result<T>) -> Response {
    match r {
        Ok(v) => Json(v).into_response(),
        Err(e) => error_response(&e),
    }
}

/// Wrap a unit store result as `{"ok": true}`.
fn respond_unit(r: yb_core::Result<()>) -> Response {
    match r {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => error_response(&e),
    }
}

// ---- query / body DTOs ---------------------------------------------------

/// `GET /complete` query: which vocabulary to complete, the (optional) prefix
/// typed so far, and how many suggestions to return.
#[derive(Deserialize)]
struct CompleteQuery {
    kind: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct SubjectQuery {
    subject_type: String,
    subject_id: String,
}

#[derive(Deserialize)]
struct CreateKeyBody {
    #[serde(default)]
    name: Option<String>,
    /// Required for admins issuing on behalf of a user; ignored for members
    /// (their own id is always used).
    #[serde(default)]
    owner_user_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    /// The key's grant set: a JSON array of any of `inference`, `admin`.
    /// Defaults to `["inference"]`. Admin scope authenticates to this
    /// management API as the owning user — only admins may mint a key holding
    /// it.
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    access: AccessPolicy,
    #[serde(default)]
    rpm_limit: Option<i64>,
    #[serde(default)]
    tpm_limit: Option<i64>,
    #[serde(default)]
    max_concurrent: Option<i64>,
}

#[derive(Deserialize)]
struct AccessBody {
    access: AccessPolicy,
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct CreateUserBody {
    username: String,
    password: String,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Deserialize)]
struct RoleBody {
    role: String,
}

#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

/// Self-service password change: the caller proves they know their current
/// password before setting a new one.
#[derive(Deserialize)]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct CreateTeamBody {
    name: String,
    #[serde(default)]
    access: AccessPolicy,
}

#[derive(Deserialize)]
struct MemberBody {
    user_id: String,
}

// ---- auth (login / logout / me) ------------------------------------------

fn set_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL_SECS}")
}

fn clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// `POST /auth/login` — unauthenticated; verify a user's password, create a
/// session row, and hand back its opaque token as a cookie.
async fn auth_login(State(state): State<AppState>, Json(body): Json<LoginBody>) -> Response {
    if !state.auth.has(AuthProvider::Local) {
        return error_response(&Error::Forbidden(
            "local password login is disabled on this server".into(),
        ));
    }
    let user = match state.store.get_user_by_username(&body.username).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_response(&Error::Unauthorized("invalid credentials".into())),
        Err(e) => return error_response(&e),
    };
    if !state.hasher.verify(&body.password, &user.password_hash) {
        return error_response(&Error::Unauthorized("invalid credentials".into()));
    }
    mint_session_response(&state, &user).await
}

/// Mint a fresh session for `user`, persist it, and return the `{username, role}`
/// body with a `Set-Cookie`. Shared by every login provider (local + sso) so the
/// cookie/session semantics are identical regardless of how the user proved who
/// they are.
async fn mint_session_response(state: &AppState, user: &User) -> Response {
    // Best-effort last-login bookkeeping; never fails the login.
    let _ = state.store.mark_user_login(&user.id).await;

    // 128 bits of opaque entropy as the cookie token; only its row maps to a user.
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let session = Session {
        token: token.clone(),
        user_id: user.id.clone(),
        created_at: now(),
        expires_at: now() + chrono::Duration::seconds(SESSION_TTL_SECS),
    };
    if let Err(e) = state.store.create_session(&session).await {
        return error_response(&e);
    }
    let mut resp = Json(json!({
        "username": user.username,
        "role": user.role.as_str(),
    }))
    .into_response();
    if let Ok(val) = set_cookie(&token).parse() {
        resp.headers_mut().insert("set-cookie", val);
    }
    resp
}

/// Append the unified cross-app `lzr_session` cookie to `resp` when the IdP
/// issued a shared session token and a cookie domain is configured. This is what
/// makes one login on any `*.lzrlab.dev` app authenticate the others: the cookie
/// is `Domain`-scoped to the parent domain, and every app validates it by
/// introspecting against the IdP. No domain configured ⇒ SSO off (no-op).
fn append_shared_cookie(resp: &mut Response, state: &AppState, sso_user: &SsoUser) {
    let (Some(token), Some(cfg)) = (sso_user.session.as_deref(), state.auth.sso.as_ref()) else {
        return;
    };
    let Some(domain) = cfg.session_cookie_domain.as_deref().filter(|d| !d.is_empty()) else {
        return;
    };
    let name = cfg.session_cookie.clone().unwrap_or_else(|| "lzr_session".to_string());
    let cookie = format!(
        "{name}={token}; Domain={domain}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={SESSION_TTL_SECS}"
    );
    if let Ok(val) = cookie.parse() {
        resp.headers_mut().append("set-cookie", val);
    }
}

/// `GET /auth/config` — public: which login providers the SPA should render,
/// plus the Turnstile sitekey (when configured) so the sso login can show the
/// bot-check widget.
async fn auth_config(State(state): State<AppState>) -> Response {
    let providers: Vec<&str> = state.auth.providers.iter().map(|p| p.as_str()).collect();
    let turnstile_sitekey = state
        .auth
        .sso
        .as_ref()
        .and_then(|s| s.turnstile_sitekey.clone())
        .filter(|k| !k.is_empty());
    Json(json!({ "providers": providers, "turnstile_sitekey": turnstile_sitekey })).into_response()
}

#[derive(Deserialize)]
struct SsoStartBody {
    email: String,
    /// Cloudflare Turnstile token from the login widget (when enabled).
    #[serde(default)]
    turnstile_token: Option<String>,
}

/// `POST /auth/sso/start` — ask the IdP to email a sign-in code + link. Always
/// `{ok:true}` for a reachable IdP (no account enumeration); the IdP's dev
/// passthrough (code/link) is surfaced when present, for headless testing.
async fn auth_sso_start(State(state): State<AppState>, Json(body): Json<SsoStartBody>) -> Response {
    let Some(sso) = sso_or_disabled(&state) else {
        return error_response(&Error::Forbidden("sso login is not enabled".into()));
    };
    match sso.start(&body.email, body.turnstile_token.as_deref()).await {
        Ok(out) => {
            let mut resp = json!({ "ok": true });
            if let Some(code) = out.dev_code {
                resp["dev_code"] = json!(code);
            }
            if let Some(link) = out.dev_link {
                resp["dev_link"] = json!(link);
            }
            Json(resp).into_response()
        }
        Err(e) => error_response(&e),
    }
}

#[derive(Deserialize)]
struct SsoCodeBody {
    email: String,
    code: String,
}

/// `POST /auth/sso/code` — complete an sso login with the typed 6-digit code.
/// On success, map the IdP identity to a local user and mint a session.
async fn auth_sso_code(State(state): State<AppState>, Json(body): Json<SsoCodeBody>) -> Response {
    let Some(sso) = sso_or_disabled(&state) else {
        return error_response(&Error::Forbidden("sso login is not enabled".into()));
    };
    let sso_user = match sso.code(&body.email, &body.code).await {
        Ok(u) => u,
        Err(e) => return error_response(&e),
    };
    match upsert_sso_user(&state, &sso_user).await {
        Ok(user) => {
            let mut resp = mint_session_response(&state, &user).await;
            append_shared_cookie(&mut resp, &state, &sso_user);
            resp
        }
        Err(e) => error_response(&e),
    }
}

#[derive(Deserialize)]
pub struct SsoVerifyQuery {
    lt: String,
}

/// `GET /auth/verify?lt=…` — complete an sso login from the emailed magic link,
/// then 302 into the SPA with the session cookie set. Mounted at the top level
/// (not under `/admin/v1`) because the IdP emails the fixed path
/// `{callback_base}/auth/verify`.
pub async fn auth_sso_verify(
    State(state): State<AppState>,
    Query(q): Query<SsoVerifyQuery>,
) -> Response {
    let Some(sso) = sso_or_disabled(&state) else {
        return error_response(&Error::Forbidden("sso login is not enabled".into()));
    };
    let sso_user = match sso.verify(&q.lt).await {
        Ok(u) => u,
        Err(e) => return error_response(&e),
    };
    let user = match upsert_sso_user(&state, &sso_user).await {
        Ok(u) => u,
        Err(e) => return error_response(&e),
    };
    // Reuse the shared minting to get a Set-Cookie, then convert to a redirect
    // into the SPA root (the cookie header is preserved).
    let mut resp = mint_session_response(&state, &user).await;
    append_shared_cookie(&mut resp, &state, &sso_user);
    if resp.status().is_success() {
        *resp.status_mut() = axum::http::StatusCode::SEE_OTHER;
        if let Ok(loc) = "/".parse() {
            resp.headers_mut().insert("location", loc);
        }
    }
    resp
}

/// The configured [`SsoClient`], or `None` when the `sso` provider isn't both
/// enabled and configured.
fn sso_or_disabled(state: &AppState) -> Option<std::sync::Arc<crate::sso::SsoClient>> {
    if !state.auth.has(AuthProvider::Sso) {
        return None;
    }
    state.sso.clone()
}

/// Resolve the local [`User`] behind an IdP identity, auto-provisioning on first
/// sight. The user is keyed by `username == email`; a newly created row gets a
/// **sentinel, non-verifying** password hash (so an sso-only user can never also
/// pass local password login).
///
/// **Authorization is the gateway's, not the IdP's**: the IdP only proves the
/// email. A new account is always created as `Member`; grant admin explicitly in
/// the gateway — `gateway set-role <email> admin` (CLI, writes the DB) or the
/// console (`/admin/v1/users/:id/role`). Existing users keep their gateway role.
async fn upsert_sso_user(state: &AppState, sso_user: &SsoUser) -> Result<User, Error> {
    let email = sso_user.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(Error::Unauthorized("sso returned no email".into()));
    }
    // Existing users keep whatever role the gateway has for them.
    if let Some(user) = state.store.get_user_by_username(&email).await? {
        return Ok(user);
    }
    let user = User {
        id: new_id(),
        username: email,
        // Sentinel: Argon2 verification never matches a non-PHC string, so this
        // account cannot be used with the local password path.
        password_hash: "!sso".to_string(),
        role: Role::Member,
        rpm_limit: None,
        tpm_limit: None,
        max_concurrent: None,
        created_at: now(),
        last_login_at: None,
        deleted_at: None,
    };
    state.store.create_user(&user).await?;
    Ok(user)
}

/// `POST /auth/logout` — delete the session row and clear the cookie.
async fn auth_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = session_cookie(&headers) {
        let _ = state.store.delete_session(&token).await;
    }
    // Global logout: invalidate the shared IdP session (so every *.lzrlab.dev app
    // drops), and clear the domain-scoped cookie.
    let shared = state
        .auth
        .sso
        .as_ref()
        .and_then(|c| c.session_cookie_domain.as_deref().filter(|d| !d.is_empty()).map(|d| (c, d)));
    let mut cleared_shared: Option<String> = None;
    if let Some((cfg, domain)) = shared {
        let name = cfg.session_cookie.clone().unwrap_or_else(|| "lzr_session".to_string());
        if let Some(token) = cookie_value(&headers, &name) {
            if let Some(sso) = &state.sso {
                let _ = sso.logout(&token).await;
            }
        }
        cleared_shared = Some(format!(
            "{name}=; Domain={domain}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        ));
    }
    let mut resp = Json(json!({ "ok": true })).into_response();
    if let Ok(val) = clear_cookie().parse() {
        resp.headers_mut().insert("set-cookie", val);
    }
    if let Some(c) = cleared_shared {
        if let Ok(val) = c.parse() {
            resp.headers_mut().append("set-cookie", val);
        }
    }
    resp
}

/// `GET /auth/me` — the signed-in user.
async fn auth_me(principal: Principal) -> Response {
    Json(json!({
        "username": principal.0.username,
        "role": principal.0.role.as_str(),
    }))
    .into_response()
}

/// `PUT /auth/password` — the signed-in user changes their own password. Requires
/// the current password (any authenticated user; no admin role needed).
async fn change_my_password(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    let user = match state.store.get_user(principal.user_id()).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_response(&Error::Unauthorized("sign in required".into())),
        Err(e) => return error_response(&e),
    };
    if !state.hasher.verify(&body.current_password, &user.password_hash) {
        return error_response(&Error::Unauthorized("current password is incorrect".into()));
    }
    if body.new_password.is_empty() {
        return error_response(&Error::BadRequest("new password must not be empty".into()));
    }
    let hash = match state.hasher.hash(&body.new_password) {
        Ok(h) => h,
        Err(e) => return error_response(&e),
    };
    respond_unit(state.store.set_user_password(&user.id, &hash).await)
}

// ---- login users (admin-managed CRUD) ------------------------------------

/// `GET /users` — list login users (admin only).
async fn list_users(principal: Principal, State(state): State<AppState>) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    match state.store.list_users().await {
        Ok(users) => Json(
            users
                .into_iter()
                .map(|u| {
                    json!({
                        "id": u.id,
                        "username": u.username,
                        "role": u.role.as_str(),
                        "created_at": u.created_at,
                        "last_login_at": u.last_login_at,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => error_response(&e),
    }
}

/// `POST /users` — create a **local** password login user (admin only). Only
/// meaningful when the `local` provider is enabled; on an SSO-only server a
/// password user could never sign in, so use `POST /users/invite` instead.
async fn create_user(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    if !state.auth.has(AuthProvider::Local) {
        return error_response(&Error::BadRequest(
            "local password login is disabled; invite the user instead (POST /users/invite)".into(),
        ));
    }
    let role = match Role::parse(body.role.as_deref().unwrap_or("member")) {
        Ok(r) => r,
        Err(e) => return error_response(&e),
    };
    let hash = match state.hasher.hash(&body.password) {
        Ok(h) => h,
        Err(e) => return error_response(&e),
    };
    let user = User {
        id: new_id(),
        username: body.username,
        password_hash: hash,
        role,
        rpm_limit: None,
        tpm_limit: None,
        max_concurrent: None,
        created_at: now(),
        last_login_at: None,
        deleted_at: None,
    };
    match state.store.create_user(&user).await {
        Ok(()) => Json(json!({ "id": user.id, "username": user.username, "role": role.as_str() }))
            .into_response(),
        Err(e) => error_response(&e),
    }
}

#[derive(Deserialize)]
struct InviteUserBody {
    email: String,
    #[serde(default)]
    role: Option<String>,
}

/// `POST /users/invite` — invite a user to sign in via the IdP (admin only).
/// Provisions them in the IdP (so the login email works) and creates the local
/// account keyed by email with the chosen role and a non-verifying password
/// (SSO-login only). Idempotent: an existing local user just has its role set.
/// This is the SSO-native replacement for password user creation.
async fn invite_user(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<InviteUserBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    let Some(sso) = sso_or_disabled(&state) else {
        return error_response(&Error::BadRequest(
            "invite requires the sso provider to be enabled".into(),
        ));
    };
    let role = match Role::parse(body.role.as_deref().unwrap_or("member")) {
        Ok(r) => r,
        Err(e) => return error_response(&e),
    };
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return error_response(&Error::BadRequest("a valid email is required".into()));
    }
    // 1. Provision in the IdP so the email-code login works for them.
    if let Err(e) = sso.invite(&email, None).await {
        return error_response(&e);
    }
    // 2. Create/settle the local account with the chosen role.
    let result = match state.store.get_user_by_username(&email).await {
        Ok(Some(u)) => state.store.set_user_role(&u.id, role).await,
        Ok(None) => {
            let user = User {
                id: new_id(),
                username: email.clone(),
                password_hash: "!sso".to_string(),
                role,
                rpm_limit: None,
                tpm_limit: None,
                max_concurrent: None,
                created_at: now(),
                last_login_at: None,
                deleted_at: None,
            };
            state.store.create_user(&user).await
        }
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => Json(json!({ "username": email, "role": role.as_str() })).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `PUT /users/:id/role` — change a user's role (admin only, last-admin guarded).
async fn set_user_role(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<RoleBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    let role = match Role::parse(&body.role) {
        Ok(r) => r,
        Err(e) => return error_response(&e),
    };
    if let Err(r) = guard_last_admin(&state, &id, role != Role::Admin).await {
        return r;
    }
    respond_unit(state.store.set_user_role(&id, role).await)
}

/// `PUT /users/:id/password` — reset a user's password (admin only).
async fn set_user_password(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<PasswordBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    let hash = match state.hasher.hash(&body.password) {
        Ok(h) => h,
        Err(e) => return error_response(&e),
    };
    respond_unit(state.store.set_user_password(&id, &hash).await)
}

/// `DELETE /users/:id` — delete a login user (admin only, last-admin guarded).
async fn delete_user(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    if let Err(r) = guard_last_admin(&state, &id, true).await {
        return r;
    }
    respond_unit(state.store.delete_user(&id).await)
}

/// Refuse an operation that would remove/demote the last admin user.
/// `losing_admin` is true when the target would no longer be an admin afterward.
async fn guard_last_admin(state: &AppState, id: &str, losing_admin: bool) -> Result<(), Response> {
    if !losing_admin {
        return Ok(());
    }
    let target = match state.store.get_user(id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(error_response(&Error::NotFound("user".into()))),
        Err(e) => return Err(error_response(&e)),
    };
    if target.role == Role::Admin {
        let admins = state.store.count_admins().await.unwrap_or(0);
        if admins <= 1 {
            return Err(error_response(&Error::Forbidden(
                "cannot remove the last admin user".into(),
            )));
        }
    }
    Ok(())
}

// ---- models (the live deployment list) -----------------------------------

/// Request body to create a deployment via `POST /models`.
#[derive(Debug, Deserialize)]
struct CreateModelBody {
    model_name: String,
    provider: String,
    upstream_model: String,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    /// The upstream wire format — the deployment's only "adapter shape"
    /// (a chat dialect like `openai_chat`, or an embeddings dialect like
    /// `cohere_embed`).
    upstream_format: yb_core::UpstreamFormat,
    #[serde(default)]
    weight: Option<u32>,
    #[serde(default)]
    pricing: Option<yb_core::catalog::ModelPrice>,
    /// Health-check method for this backend (independent of upstream_format):
    /// none | http_ok | models_list | probe.
    #[serde(default)]
    health_check: yb_core::HealthCheck,
    /// URL for http_ok checks (absolute, or relative to api_base's origin).
    #[serde(default)]
    health_path: Option<String>,
    /// Open-ended per-deployment extras, e.g.
    /// `{"cloudflare_access": true, "headers": {"X-Tenant": "acme"}}`. The
    /// Cloudflare service token itself is file-owned
    /// (`[upstream.cloudflare_access]`) and cannot be set, read, or overridden
    /// through this API — only the flag selecting it can.
    #[serde(default)]
    extra: yb_core::Extra,
}

/// `GET /deployments` — list the live deployments (member+).
async fn list_deployments(principal: Principal, State(state): State<AppState>) -> Response {
    if let Err(r) = authz(&principal, Action::ReadCatalog) {
        return r;
    }
    respond(state.store.list_deployments().await)
}

/// `GET /models` — list the model entities, each with its aliases and the
/// number of deployments backing it (member+).
///
/// The console groups its table by model, so the fan-out is counted here rather
/// than inferred client-side from the deployment list.
async fn list_models(principal: Principal, State(state): State<AppState>) -> Response {
    if let Err(r) = authz(&principal, Action::ReadCatalog) {
        return r;
    }
    let models = match state.store.list_models().await {
        Ok(m) => m,
        Err(e) => return error_response(&e),
    };
    let deployments = match state.store.list_deployments().await {
        Ok(d) => d,
        Err(e) => return error_response(&e),
    };
    let aliases = match state.store.list_aliases().await {
        Ok(a) => a,
        Err(e) => return error_response(&e),
    };
    let out: Vec<_> = models
        .into_iter()
        .map(|m| {
            let mut names: Vec<&str> = aliases
                .iter()
                .filter(|a| a.model_id == m.id)
                .map(|a| a.alias.as_str())
                .collect();
            names.sort_unstable();
            json!({
                "id": m.id,
                "name": m.name,
                "aliases": names,
                "deployment_count": deployments.iter().filter(|d| d.model_id == m.id).count(),
                "created_at": m.created_at,
                "updated_at": m.updated_at,
            })
        })
        .collect();
    respond(Ok(out))
}

/// Validate a public model name or an alias.
///
/// Deliberately permissive about punctuation — real upstream ids look like
/// `meta-llama/Llama-3-70B` — but rejects the shapes that break a URL path or a
/// JSON round-trip.
fn validate_public_name(s: &str) -> std::result::Result<String, Response> {
    let t = s.trim();
    if t.is_empty() {
        return Err(error_response(&Error::BadRequest("name is required".into())));
    }
    if t.chars().count() > 200 {
        return Err(error_response(&Error::BadRequest(
            "name must be 200 characters or fewer".into(),
        )));
    }
    if t.chars().any(|c| c.is_ascii_control()) {
        return Err(error_response(&Error::BadRequest(
            "name must not contain control characters".into(),
        )));
    }
    Ok(t.to_string())
}

#[derive(Deserialize)]
struct RenameModelBody {
    name: String,
}

/// `PUT /models/:id/name` — rename a model, leaving its previous name behind as
/// an alias so clients mid-flight keep resolving (admin only).
///
/// The alias is not optional. Renaming is a one-click inline edit in the
/// console, and a rename without it is a silent outage for every client still
/// naming the old model.
async fn rename_model(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<RenameModelBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::EditConfig) {
        return r;
    }
    let name = match validate_public_name(&body.name) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let rec = match state.store.rename_model(&id, &name).await {
        Ok(r) => r,
        Err(e) => return error_response(&e),
    };
    if let Err(e) = state.reload_models().await {
        return error_response(&e);
    }
    respond(Ok(rec))
}

#[derive(Deserialize)]
struct CreateModelEntityBody {
    name: String,
}

/// `POST /models` — create a model by name, with no deployments yet (admin only).
///
/// A model with no deployments is deliberately allowed: it is visible in the
/// console and completable in the policy editor, but absent from the router
/// snapshot and from `GET /v1/models`, so it cannot be routed to. That is what
/// lets an operator pre-authorize (or pre-deny) a model before standing up the
/// upstream that serves it.
async fn create_model(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<CreateModelEntityBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::EditConfig) {
        return r;
    }
    let name = match validate_public_name(&body.name) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let rec = match state.store.ensure_model(&name).await {
        Ok(r) => r,
        Err(e) => return error_response(&e),
    };
    if let Err(e) = state.reload_models().await {
        return error_response(&e);
    }
    respond(Ok(rec))
}

/// `POST /deployments` — add a deployment and hot-reload the router (admin only).
///
/// The body names its model; the store resolves that to a model row, creating
/// one if the name is new.
async fn create_deployment(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<CreateModelBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::EditConfig) {
        return r;
    }
    let model_name = match validate_public_name(&body.model_name) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let dep = yb_core::NewDeployment {
        model_name,
        provider: body.provider,
        upstream_model: body.upstream_model,
        api_base: body.api_base,
        api_key: body.api_key,
        upstream_format: body.upstream_format,
        weight: body.weight.unwrap_or(1),
        pricing: body.pricing,
        health_check: body.health_check,
        health_path: body.health_path,
        extra: body.extra.clone(),
    };
    let created = match state.store.create_deployment(&dep).await {
        Ok(d) => d,
        Err(e) => return error_response(&e),
    };
    if let Err(e) = state.reload_models().await {
        return error_response(&e);
    }
    respond(Ok(created))
}

/// `DELETE /deployments/:id` — soft-delete a deployment and hot-reload (admin only).
async fn delete_deployment(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = authz(&principal, Action::EditConfig) {
        return r;
    }
    if let Err(e) = state.store.delete_deployment(&id).await {
        return error_response(&e);
    }
    if let Err(e) = state.reload_models().await {
        return error_response(&e);
    }
    respond(Ok(json!({ "deleted": id })))
}

// ---- backend health checks ------------------------------------------------

/// `GET /models/health` — run every deployment's configured health check
/// (concurrently) and report per-deployment results.
async fn health_all_models(principal: Principal, State(state): State<AppState>) -> Response {
    if let Err(r) = authz(&principal, Action::ReadCatalog) {
        return r;
    }
    let deps = match state.store.list_deployments().await {
        Ok(d) => d,
        Err(e) => return error_response(&e),
    };
    let reports = state.gateway.check_deployments(&deps).await;
    Json(reports).into_response()
}

/// `POST /models/:id/health` — run one deployment's configured health check now.
async fn health_one_model(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ReadCatalog) {
        return r;
    }
    let dep = match state.store.get_deployment(&id).await {
        Ok(Some(d)) => d,
        Ok(None) => return error_response(&Error::NotFound("deployment".into())),
        Err(e) => return error_response(&e),
    };
    Json(state.gateway.check_deployment(&dep).await).into_response()
}

// ---- model aliases -------------------------------------------------------

#[derive(Deserialize)]
struct CreateAliasBody {
    alias: String,
    target: String,
}

/// `GET /aliases` — list model aliases (member+, same visibility as models).
async fn list_aliases(principal: Principal, State(state): State<AppState>) -> Response {
    if let Err(r) = authz(&principal, Action::ReadCatalog) {
        return r;
    }
    respond(state.store.list_aliases().await)
}

/// `POST /aliases` — add/replace an alias and hot-reload the router (admin only).
async fn create_alias(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<CreateAliasBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::EditConfig) {
        return r;
    }
    if body.alias.is_empty() || body.target.is_empty() {
        return error_response(&Error::BadRequest("alias and target are required".into()));
    }
    if body.alias == body.target {
        return error_response(&Error::BadRequest("an alias cannot point to itself".into()));
    }
    let alias_name = match validate_public_name(&body.alias) {
        Ok(n) => n,
        Err(r) => return r,
    };
    // `target` is a name — this is a hand-authored edge — so resolve it. An
    // alias to a model that does not exist used to be accepted and then simply
    // never resolved; it is a 404 now.
    let target = match state.store.get_model_by_name(&body.target).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return error_response(&Error::NotFound(format!("model \"{}\"", body.target)))
        }
        Err(e) => return error_response(&e),
    };
    // A name is either a model's or an alias's, never both — otherwise the
    // alias is silently shadowed by the model of the same name.
    match state.store.get_model_by_name(&alias_name).await {
        Ok(Some(_)) => {
            return error_response(&Error::Conflict(format!(
                "\"{alias_name}\" is already a model name"
            )))
        }
        Ok(None) => {}
        Err(e) => return error_response(&e),
    }
    let alias = match state.store.upsert_alias(&alias_name, &target.id).await {
        Ok(a) => a,
        Err(e) => return error_response(&e),
    };
    if let Err(e) = state.reload_models().await {
        return error_response(&e);
    }
    respond(Ok(alias))
}

/// `DELETE /aliases/:alias` — remove an alias and hot-reload (admin only).
async fn delete_alias(
    principal: Principal,
    State(state): State<AppState>,
    Path(alias): Path<String>,
) -> Response {
    if let Err(r) = authz(&principal, Action::EditConfig) {
        return r;
    }
    if let Err(e) = state.store.delete_alias(&alias).await {
        return error_response(&e);
    }
    if let Err(e) = state.reload_models().await {
        return error_response(&e);
    }
    respond(Ok(json!({ "deleted": alias })))
}

// ---- typeahead completion ------------------------------------------------

/// How many of a model's aliases a suggestion names before summarizing the rest.
const ALIAS_HINT_MAX: usize = 3;

/// One typeahead suggestion. `value` is what the console stores (a model name,
/// a provider name, a user id); `label` is what it shows; `hint` is secondary
/// context that helps disambiguate but is never stored.
#[derive(Serialize)]
struct Suggestion {
    value: String,
    label: String,
    hint: String,
}

/// Rank `hay` against an already-lowercased `needle`: exact, prefix, substring,
/// or no match. An empty needle matches everything at the lowest rank, so an
/// unfiltered dropdown still opens with the alphabetical head of the list.
fn rank(hay: &str, needle: &str) -> Option<u8> {
    if needle.is_empty() {
        return Some(3);
    }
    let h = hay.to_lowercase();
    if h == needle {
        Some(0)
    } else if h.starts_with(needle) {
        Some(1)
    } else if h.contains(needle) {
        Some(2)
    } else {
        None
    }
}

/// `GET /complete?kind=…&q=…&limit=…` — suggest values that actually exist.
///
/// Backs the console's pill editors (access policies, team membership) so an
/// operator picks a real model, provider, or user rather than typing a string
/// that silently matches nothing. Matching is case-insensitive and ranked
/// exact → prefix → substring, then alphabetical; an empty `q` returns the head
/// of the list so clicking the field is enough to browse.
///
/// For `model` the suggested `value` is the model **id** while the `label` is
/// its name, because that is what an [`AccessPolicy`] stores. Holding the id is
/// what keeps a rule matching after a rename; a name would silently stop
/// matching. Aliases still appear, as a hint on their model's row, and are
/// matchable — they are a legitimate way to *find* a model — but are never the
/// value, since a policy is checked after aliases resolve.
///
/// Authorization tracks what each list already discloses: `model` and
/// `provider` restate `GET /deployments`, which any member may read, while
/// `user` exposes the account list and keeps the `ManageMembers` bar.
async fn complete(
    principal: Principal,
    State(state): State<AppState>,
    Query(q): Query<CompleteQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let needle = q.q.trim().to_lowercase();
    let mut hits: Vec<(u8, Suggestion)> = Vec::new();

    match q.kind.as_str() {
        "model" | "provider" => {
            if let Err(r) = authz(&principal, Action::ReadCatalog) {
                return r;
            }
            let deps = match state.store.list_deployments().await {
                Ok(d) => d,
                Err(e) => return error_response(&e),
            };
            if q.kind == "provider" {
                // Distinct providers, hinted with how many deployments back them.
                let mut counts: BTreeMap<String, usize> = BTreeMap::new();
                for d in &deps {
                    *counts.entry(d.provider.clone()).or_default() += 1;
                }
                for (provider, n) in counts {
                    if let Some(r) = rank(&provider, &needle) {
                        let hint = format!("{n} deployment{}", if n == 1 { "" } else { "s" });
                        hits.push((
                            r,
                            Suggestion {
                                label: provider.clone(),
                                value: provider,
                                hint,
                            },
                        ));
                    }
                }
            } else {
                let aliases = state.store.list_aliases().await.unwrap_or_default();
                let models = match state.store.list_models().await {
                    Ok(m) => m,
                    Err(e) => return error_response(&e),
                };
                // Keyed by model id, because that is what a policy stores. Built
                // from the model list rather than the deployments, so a model
                // with no deployments yet is still completable — which is how an
                // operator pre-authorizes one.
                let mut by_model: BTreeMap<String, (String, BTreeSet<String>, Vec<String>)> =
                    BTreeMap::new();
                for m in &models {
                    by_model
                        .entry(m.id.clone())
                        .or_insert_with(|| (m.name.clone(), BTreeSet::new(), Vec::new()));
                }
                for d in &deps {
                    if let Some(e) = by_model.get_mut(&d.model_id) {
                        e.1.insert(d.provider.clone());
                    }
                }
                for a in &aliases {
                    if let Some(e) = by_model.get_mut(&a.model_id) {
                        e.2.push(a.alias.clone());
                    }
                }
                for (model_id, (model, providers, mut names)) in by_model {
                    // An alias is a legitimate way to *find* a model, so match on
                    // it too — but the value stays the model id.
                    let r = rank(&model, &needle).or_else(|| {
                        names.iter().filter_map(|a| rank(a, &needle)).min()
                    });
                    let Some(r) = r else { continue };
                    names.sort();
                    let mut hint = providers.into_iter().collect::<Vec<_>>().join(", ");
                    if !names.is_empty() {
                        // A popular model can carry dozens of aliases; a dropdown
                        // row has space for a reminder, not the whole list.
                        let shown = names.len().min(ALIAS_HINT_MAX);
                        hint.push_str(" · aka ");
                        hint.push_str(&names[..shown].join(", "));
                        if names.len() > shown {
                            hint.push_str(&format!(" +{} more", names.len() - shown));
                        }
                    }
                    hits.push((
                        r,
                        Suggestion {
                            label: model,
                            value: model_id,
                            hint,
                        },
                    ));
                }
            }
        }
        "user" => {
            if let Err(r) = authz(&principal, Action::ManageMembers) {
                return r;
            }
            let users = match state.store.list_users().await {
                Ok(u) => u,
                Err(e) => return error_response(&e),
            };
            for u in users {
                if let Some(r) = rank(&u.username, &needle) {
                    hits.push((
                        r,
                        Suggestion {
                            value: u.id,
                            label: u.username,
                            hint: u.role.as_str().to_string(),
                        },
                    ));
                }
            }
        }
        other => {
            return error_response(&Error::BadRequest(format!(
                "unknown completion kind {other:?} (expected model, provider, or user)"
            )))
        }
    }

    hits.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.label.cmp(&b.1.label)));
    hits.truncate(limit);
    Json(hits.into_iter().map(|(_, s)| s).collect::<Vec<_>>()).into_response()
}

// ---- keys ----------------------------------------------------------------

/// `GET /keys` — admins see every key; members see only their own.
async fn list_keys(principal: Principal, State(state): State<AppState>) -> Response {
    let r = if principal.is_admin() {
        state.store.list_api_keys().await
    } else {
        state.store.list_api_keys_for_user(principal.user_id()).await
    };
    respond(r)
}

/// `POST /keys` — admins issue for any `owner_user_id` (defaulting to themselves);
/// members always issue for themselves.
async fn create_key(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<CreateKeyBody>,
) -> Response {
    let owner = if principal.is_admin() {
        body.owner_user_id
            .clone()
            .unwrap_or_else(|| principal.user_id().to_string())
    } else {
        // Members may only own their own keys; any supplied owner is ignored.
        principal.user_id().to_string()
    };
    // The grant set is a JSON array; default to inference-only. parse_set
    // validates + dedupes each name.
    let raw = body.scopes.as_ref().map(|l| l.join(" ")).unwrap_or_else(|| "inference".into());
    let scopes = match KeyScope::parse_set(&raw) {
        Ok(v) => v,
        Err(e) => return error_response(&e),
    };
    if scopes.contains(&KeyScope::Admin) && !principal.is_admin() {
        return error_response(&Error::Forbidden(
            "only admins may create admin-scope keys".into(),
        ));
    }

    // Generate a `yb_` token inline (64 hex chars of entropy), and persist only
    // its hex-SHA-256. The plaintext token is returned exactly once.
    let entropy = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let token = format!("yb_{entropy}");
    let key_prefix = format!("yb_{}", &entropy[..8]);
    let key_suffix = entropy[entropy.len() - 4..].to_string();

    let api_key = ApiKey {
        id: new_id(),
        owner_user_id: owner,
        team_id: body.team_id,
        hash: crate::hex_sha256(&token),
        key_prefix,
        key_suffix,
        name: body.name,
        scopes,
        access: body.access,
        rpm_limit: body.rpm_limit,
        tpm_limit: body.tpm_limit,
        max_concurrent: body.max_concurrent,
        created_at: now(),
        last_used_at: None,
        deleted_at: None,
    };

    if let Err(e) = state.store.create_api_key(&api_key).await {
        return error_response(&e);
    }
    // Surface the plaintext token alongside the safe key metadata, once.
    Json(json!({ "token": token, "key": api_key })).into_response()
}

/// Load the key at `id` and ensure the caller owns it (or is an admin).
async fn own_key_or_admin(
    state: &AppState,
    principal: &Principal,
    id: &str,
) -> Result<ApiKey, Response> {
    let key = match state.store.get_api_key(id).await {
        Ok(Some(k)) => k,
        Ok(None) => return Err(error_response(&Error::NotFound("key".into()))),
        Err(e) => return Err(error_response(&e)),
    };
    if !principal.is_admin() && key.owner_user_id != principal.user_id() {
        return Err(error_response(&Error::Forbidden(
            "not your key".into(),
        )));
    }
    Ok(key)
}

/// `DELETE /keys/:id` — revoke a key (owner or admin).
async fn delete_key(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = own_key_or_admin(&state, &principal, &id).await {
        return r;
    }
    respond_unit(state.store.delete_api_key(&id).await)
}

/// `PUT /keys/:id/access` — edit a key's access policy (owner or admin).
async fn key_access(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AccessBody>,
) -> Response {
    if let Err(r) = own_key_or_admin(&state, &principal, &id).await {
        return r;
    }
    respond_unit(state.store.update_api_key_access(&id, &body.access).await)
}

// ---- teams ---------------------------------------------------------------

async fn list_teams(principal: Principal, State(state): State<AppState>) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    respond(state.store.list_teams().await)
}

async fn create_team(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<CreateTeamBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    let team = Team {
        id: new_id(),
        name: body.name,
        access: body.access,
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
        created_by: Some(principal.0.username.clone()),
    };
    match state.store.create_team(&team).await {
        Ok(()) => Json(team).into_response(),
        Err(e) => error_response(&e),
    }
}

async fn delete_team(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    respond_unit(state.store.delete_team(&id).await)
}

async fn team_access(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AccessBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    respond_unit(state.store.update_team_access(&id, &body.access).await)
}

async fn add_member(
    principal: Principal,
    State(state): State<AppState>,
    Path(team_id): Path<String>,
    Json(body): Json<MemberBody>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    let membership = TeamMembership {
        id: new_id(),
        team_id,
        user_id: body.user_id,
        created_at: now(),
    };
    match state.store.upsert_membership(&membership).await {
        Ok(()) => Json(membership).into_response(),
        Err(e) => error_response(&e),
    }
}

async fn list_members(
    principal: Principal,
    State(state): State<AppState>,
    Path(team_id): Path<String>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    respond(state.store.list_team_members(&team_id).await)
}

async fn remove_member(
    principal: Principal,
    State(state): State<AppState>,
    Path((team_id, user_id)): Path<(String, String)>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ManageMembers) {
        return r;
    }
    respond_unit(state.store.delete_membership(&team_id, &user_id).await)
}

// ---- budgets -------------------------------------------------------------

async fn list_budgets(
    principal: Principal,
    State(state): State<AppState>,
    Query(q): Query<SubjectQuery>,
) -> Response {
    if let Err(r) = authz(&principal, Action::ViewSpend) {
        return r;
    }
    let subject_type = match SubjectType::parse(&q.subject_type) {
        Ok(s) => s,
        Err(e) => return error_response(&e),
    };
    respond(state.store.list_budgets(subject_type, &q.subject_id).await)
}

async fn put_budget(
    principal: Principal,
    State(state): State<AppState>,
    Json(budget): Json<Budget>,
) -> Response {
    if let Err(r) = authz(&principal, Action::EditConfig) {
        return r;
    }
    respond_unit(state.store.upsert_budget(&budget).await)
}

async fn delete_budget(
    principal: Principal,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = authz(&principal, Action::EditConfig) {
        return r;
    }
    respond_unit(state.store.delete_budget(&id).await)
}

// ---- spend ---------------------------------------------------------------

async fn spend(principal: Principal, State(state): State<AppState>) -> Response {
    if let Err(r) = authz(&principal, Action::ViewSpend) {
        return r;
    }
    respond(state.store.spend_rows().await)
}
