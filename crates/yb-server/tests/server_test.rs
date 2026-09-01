//! HTTP surface tests for `yb-server`.
//!
//! Builds a real router over a temp-file [`SqliteStore`] and a [`MockClient`]-
//! backed [`Gateway`], then drives it with `tower`'s `oneshot` to assert the
//! three load-bearing behaviours: health is open, unauthenticated inference is
//! rejected, and an authenticated request is translated and served.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use yb_core::config::{DeploymentConfig, DeploymentMode, ModelConfig, Strategy};
use yb_core::crypto::NoopEncryptor;
use yb_core::model::{AccessPolicy, Role, User};
use yb_core::ratelimit::Limiter;
use yb_core::store::LimitColumns;
use yb_core::{new_id, now, NullLogger, Store, WireFormat};

use yb_gateway::{DeploymentRouter, Gateway};
use yb_providers::{MockClient, UpstreamClient};
use yb_server::{build_router, AppState};
use yb_store::{issue_api_key, Argon2Hasher, SqliteStore};

/// A canned OpenAI chat completion the mock upstream replays for `gpt-4o`.
fn upstream_completion() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello there!"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap()
}

/// Build an [`AppState`] over a fresh temp SQLite db, returning it plus the
/// plaintext virtual-key token issued for the seeded user.
async fn setup() -> (AppState, String) {
    let path = std::env::temp_dir().join(format!("yb-server-{}.db", new_id()));
    let store = Arc::new(SqliteStore::connect(path.to_str().unwrap()).await.unwrap());
    store.migrate().await.unwrap();

    let user = User {
        id: new_id(),
        username: "alice".into(),
        password_hash: "x".into(),
        role: Role::Member,
        rpm_limit: None,
        tpm_limit: None,
        max_concurrent: None,
        created_at: now(),
        last_login_at: None,
        deleted_at: None,
    };
    store.create_user(&user).await.unwrap();

    let issued = issue_api_key(
        store.as_ref(),
        &user.id,
        Some("test-key".into()),
        None,
        Default::default(),
        AccessPolicy::default(),
        LimitColumns::default(),
    )
    .await
    .unwrap();

    let models = vec![ModelConfig {
        model_name: "my-model".into(),
        aliases: vec![],
        deployments: vec![DeploymentConfig {
            provider: "openai".into(),
            upstream_model: "gpt-4o".into(),
            api_base: None,
            api_key: None,
            upstream_format: WireFormat::OpenaiChat.into(),
            weight: 1,
            pricing: None,
            health_check: Default::default(),
            health_path: None,
            extra: Default::default(),
        }],
    }];

    let client: Arc<dyn UpstreamClient> = Arc::new(MockClient::json(upstream_completion()));
    let router = Arc::new(DeploymentRouter::from_models(
        models,
        HashMap::new(),
        HashMap::new(),
        Strategy::Simple,
    ));
    let gateway = Arc::new(Gateway::new(
        client,
        router.clone(),
        store.clone(),
        Arc::new(NullLogger),
    ));

    let state = AppState {
        store: store.clone(),
        gateway,
        router,
        limiter: Arc::new(Limiter::new(Duration::from_secs(60))),
        encryptor: Arc::new(NoopEncryptor),
        hasher: Arc::new(Argon2Hasher::new()),
        observer: Arc::new(yb_core::NullObserver),
        mode: DeploymentMode::Selfhosted,
        auth: Arc::new(yb_core::config::AuthConfig::default()),
        sso: None,
        budgets_enabled: false,
        ratelimit_enabled: false,
    };

    (state, issued.token)
}

#[tokio::test]
async fn health_is_open() {
    let (state, _token) = setup().await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["status"], "ok");
}

#[tokio::test]
async fn unauthenticated_inference_is_rejected() {
    let (state, _token) = setup().await;
    let app = build_router(state);

    let body = json!({
        "model": "my-model",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn authenticated_anthropic_happy_path() {
    let (state, token) = setup().await;
    let app = build_router(state);

    let body = json!({
        "model": "my-model",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    // The OpenAI upstream completion is re-encoded onto the Anthropic surface.
    assert_eq!(v["type"], "message");
    assert_eq!(v["role"], "assistant");
    assert_eq!(v["content"][0]["type"], "text");
    assert_eq!(v["content"][0]["text"], "Hello there!");
    assert_eq!(v["usage"]["input_tokens"], 10);
    assert_eq!(v["usage"]["output_tokens"], 5);
}

#[tokio::test]
async fn x_gateway_key_header_authenticates() {
    let (state, token) = setup().await;
    let app = build_router(state);

    let body = json!({
        "model": "my-model",
        "messages": [{"role": "user", "content": "hi"}]
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-gateway-key", token)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Pluggable admin auth: the `sso` provider (direct code flow) against a mock IdP
// ---------------------------------------------------------------------------

/// Spawn a minimal mock identity provider on an ephemeral port. It speaks the
/// relying-party contract the gateway's `SsoClient` calls: `/api/login/start`
/// returns a dev code, and `/api/login/code` accepts `123456` for
/// `admin@example.com` (returning `{user, role}`) and rejects everything else.
/// Returns the base URL.
async fn mock_idp() -> String {
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::Value as J;

    async fn start(Json(b): Json<J>) -> Json<J> {
        // Echo any turnstile_token back as dev_code so a test can assert the
        // gateway forwarded it; otherwise the fixed dev code.
        let dev = b
            .get("turnstile_token")
            .and_then(|t| t.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("123456");
        Json(json!({ "ok": true, "dev_code": dev }))
    }
    async fn code(Json(b): Json<J>) -> axum::response::Response {
        use axum::response::IntoResponse;
        let email = b.get("email").and_then(|e| e.as_str()).unwrap_or("");
        let code = b.get("code").and_then(|c| c.as_str()).unwrap_or("");
        if email == "admin@example.com" && code == "123456" {
            Json(json!({
                "user": { "id": "u1", "email": "admin@example.com", "name": "Admin" },
                "role": "whatever-the-idp-says",
                "session": "SHARED-SESSION-TOKEN"
            }))
            .into_response()
        } else {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_code" }))).into_response()
        }
    }
    // Unified-session introspection: the one shared token resolves to the identity.
    async fn introspect(Json(b): Json<J>) -> axum::response::Response {
        use axum::response::IntoResponse;
        let session = b.get("session").and_then(|s| s.as_str()).unwrap_or("");
        if session == "SHARED-SESSION-TOKEN" {
            Json(json!({ "user": { "id": "u1", "email": "admin@example.com", "name": "Admin" }, "role": "x" }))
                .into_response()
        } else {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_session" }))).into_response()
        }
    }

    let app = Router::new()
        .route("/api/login/start", post(start))
        .route("/api/login/code", post(code))
        .route("/api/session/introspect", post(introspect))
        .route("/api/users/invite", post(|| async { Json(json!({ "ok": true })) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Build an [`AppState`] with a chosen set of auth providers, optionally wired to
/// a mock IdP base URL. No models/keys needed for auth tests.
async fn setup_auth(providers: Vec<yb_core::config::AuthProvider>, sso_base: Option<String>) -> AppState {
    setup_auth_ts(providers, sso_base, None).await
}

/// As [`setup_auth`], with an optional Turnstile sitekey on the sso config.
async fn setup_auth_ts(
    providers: Vec<yb_core::config::AuthProvider>,
    sso_base: Option<String>,
    turnstile_sitekey: Option<&str>,
) -> AppState {
    use yb_core::config::{AuthConfig, SsoAuthConfig};

    let path = std::env::temp_dir().join(format!("yb-auth-{}.db", new_id()));
    let store = Arc::new(SqliteStore::connect(path.to_str().unwrap()).await.unwrap());
    store.migrate().await.unwrap();

    let sso_cfg = sso_base.as_ref().map(|base| SsoAuthConfig {
        base_url: base.clone(),
        client_id: "gateway".into(),
        client_secret: "s3cret".into(),
        callback_base: "https://gateway.test".into(),
        turnstile_sitekey: turnstile_sitekey.map(str::to_string),
        session_cookie: Some("lzr_session".into()),
        session_cookie_domain: Some("lzrlab.dev".into()),
    });
    let auth = Arc::new(AuthConfig {
        providers,
        sso: sso_cfg.clone(),
        saml: None,
    });
    let sso = sso_cfg
        .as_ref()
        .and_then(yb_server::sso::SsoClient::from_config)
        .map(Arc::new);

    let router = Arc::new(DeploymentRouter::from_models(
        vec![],
        HashMap::new(),
        HashMap::new(),
        Strategy::Simple,
    ));
    let client: Arc<dyn UpstreamClient> = Arc::new(MockClient::json(upstream_completion()));
    let gateway = Arc::new(Gateway::new(client, router.clone(), store.clone(), Arc::new(NullLogger)));

    AppState {
        store,
        gateway,
        router,
        limiter: Arc::new(Limiter::new(Duration::from_secs(60))),
        encryptor: Arc::new(NoopEncryptor),
        hasher: Arc::new(Argon2Hasher::new()),
        observer: Arc::new(yb_core::NullObserver),
        mode: DeploymentMode::Selfhosted,
        auth,
        sso,
        budgets_enabled: false,
        ratelimit_enabled: false,
    }
}

async fn post_json(app: &axum::Router, uri: &str, body: Value) -> axum::http::Response<axum::body::Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn sso_code_login_provisions_user_and_sets_cookie() {
    use yb_core::config::AuthProvider::{Local, Sso};
    let idp = mock_idp().await;
    let state = setup_auth(vec![Local, Sso], Some(idp)).await;
    let store = state.store.clone();
    let app = build_router(state);

    // config advertises both providers
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/admin/v1/auth/config").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(v["providers"], json!(["local", "sso"]));

    // start → dev code passthrough
    let resp = post_json(&app, "/admin/v1/auth/sso/start", json!({"email":"admin@example.com"})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(v["dev_code"], "123456");

    // code → session cookie + auto-provisioned user. Role is the gateway's, not the
    // IdP's: a brand-new sso user is a Member (the IdP said "whatever-the-idp-says").
    let resp = post_json(&app, "/admin/v1/auth/sso/code", json!({"email":"admin@example.com","code":"123456"})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("set-cookie").unwrap().to_str().unwrap().contains("yb_session="));
    let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(v["role"], "member");

    // the user now exists locally, keyed by email, with a non-verifying password
    let u = store.get_user_by_username("admin@example.com").await.unwrap().unwrap();
    assert_eq!(u.role, Role::Member);
    assert_eq!(u.password_hash, "!sso");
}

#[tokio::test]
async fn preset_role_persists_across_first_sso_login() {
    use yb_core::config::AuthProvider::{Local, Sso};
    let idp = mock_idp().await;
    let state = setup_auth(vec![Local, Sso], Some(idp)).await;
    let store = state.store.clone();

    // Pre-provision the user as admin BEFORE they ever log in (what the
    // `gateway set-role` CLI does): a row with a non-verifying password.
    store
        .create_user(&User {
            id: new_id(),
            username: "admin@example.com".into(),
            password_hash: "!sso".into(),
            role: Role::Admin,
            rpm_limit: None,
            tpm_limit: None,
            max_concurrent: None,
            created_at: now(),
            last_login_at: None,
            deleted_at: None,
        })
        .await
        .unwrap();

    let app = build_router(state);
    let resp = post_json(&app, "/admin/v1/auth/sso/code", json!({"email":"admin@example.com","code":"123456"})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    // The pre-set admin role is preserved — sso login does not downgrade it.
    assert_eq!(v["role"], "admin");
    assert_eq!(store.get_user_by_username("admin@example.com").await.unwrap().unwrap().role, Role::Admin);
}

#[tokio::test]
async fn sso_wrong_code_is_401() {
    use yb_core::config::AuthProvider::{Local, Sso};
    let idp = mock_idp().await;
    let state = setup_auth(vec![Local, Sso], Some(idp)).await;
    let app = build_router(state);
    let resp = post_json(&app, "/admin/v1/auth/sso/code", json!({"email":"admin@example.com","code":"000000"})).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sso_routes_403_when_provider_disabled() {
    use yb_core::config::AuthProvider::Local;
    let state = setup_auth(vec![Local], None).await; // sso not enabled
    let app = build_router(state);
    let resp = post_json(&app, "/admin/v1/auth/sso/start", json!({"email":"x@example.com"})).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn local_login_403_when_local_disabled() {
    use yb_core::config::AuthProvider::Sso;
    let idp = mock_idp().await;
    let state = setup_auth(vec![Sso], Some(idp)).await; // local not enabled
    let app = build_router(state);
    let resp = post_json(&app, "/admin/v1/auth/login", json!({"username":"admin","password":"admin"})).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn turnstile_sitekey_exposed_and_token_forwarded() {
    use yb_core::config::AuthProvider::Sso;
    let idp = mock_idp().await;
    let state = setup_auth_ts(vec![Sso], Some(idp), Some("SITEKEY-123")).await;
    let app = build_router(state);

    // /auth/config exposes the sitekey so the SPA can render the widget.
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/admin/v1/auth/config").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(v["providers"], json!(["sso"]));
    assert_eq!(v["turnstile_sitekey"], "SITEKEY-123");

    // The gateway forwards the turnstile_token to the IdP (mock echoes it as dev_code).
    let resp = post_json(&app, "/admin/v1/auth/sso/start",
        json!({"email":"admin@example.com","turnstile_token":"TS-TOKEN-XYZ"})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(v["dev_code"], "TS-TOKEN-XYZ");
}

#[tokio::test]
async fn sso_login_sets_shared_cookie_and_it_authenticates() {
    use yb_core::config::AuthProvider::Sso;
    let idp = mock_idp().await;
    let state = setup_auth(vec![Sso], Some(idp)).await;
    let app = build_router(state);

    // Log in via the code flow → response sets BOTH yb_session and the unified
    // lzr_session (Domain=lzrlab.dev) from the IdP-issued token.
    let resp = post_json(&app, "/admin/v1/auth/sso/code", json!({"email":"admin@example.com","code":"123456"})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let shared = cookies.iter().find(|c| c.starts_with("lzr_session=")).expect("shared cookie set");
    assert!(shared.contains("lzr_session=SHARED-SESSION-TOKEN"));
    assert!(shared.contains("Domain=lzrlab.dev"), "{shared}");

    // A fresh request carrying ONLY the unified cookie (no yb_session) is
    // authenticated via introspection → provisions the local user.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/v1/auth/me")
                .header("cookie", "lzr_session=SHARED-SESSION-TOKEN")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(v["username"], "admin@example.com");

    // A bogus unified cookie does not authenticate.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/v1/auth/me")
                .header("cookie", "lzr_session=NOPE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invite_provisions_local_user_with_role_and_password_create_is_blocked() {
    use yb_core::config::AuthProvider::Sso;
    let idp = mock_idp().await;
    let state = setup_auth(vec![Sso], Some(idp)).await;
    let store = state.store.clone();
    // Seed a local admin + session so we can call the admin API with a cookie.
    let admin = User {
        id: new_id(), username: "boss".into(), password_hash: "!sso".into(),
        role: Role::Admin, rpm_limit: None, tpm_limit: None, max_concurrent: None,
        created_at: now(), last_login_at: None, deleted_at: None,
    };
    store.create_user(&admin).await.unwrap();
    let sess = yb_core::model::Session { token: "adm".into(), user_id: admin.id.clone(), created_at: now(), expires_at: now() + chrono::Duration::hours(1) };
    store.create_session(&sess).await.unwrap();
    let app = build_router(state);
    let c = "cookie: yb_session=adm";

    // Invite creates a local user (email as username, sentinel pw, admin role).
    let resp = app.clone().oneshot(Request::builder().method("POST").uri("/admin/v1/users/invite")
        .header("content-type", "application/json").header("cookie", &c[8..])
        .body(Body::from(serde_json::to_vec(&json!({"email":"NewGuy@lazarus.enterprises","role":"admin"})).unwrap())).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let u = store.get_user_by_username("newguy@lazarus.enterprises").await.unwrap().expect("provisioned");
    assert_eq!(u.role, Role::Admin);
    assert_eq!(u.password_hash, "!sso");

    // Password create is blocked when local is disabled.
    let resp = app.oneshot(Request::builder().method("POST").uri("/admin/v1/users")
        .header("content-type", "application/json").header("cookie", &c[8..])
        .body(Body::from(serde_json::to_vec(&json!({"username":"x","password":"y","role":"member"})).unwrap())).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
// ---------------------------------------------------------------------------
// Typeahead completion (`GET /complete`) behind the console's pill editors
// ---------------------------------------------------------------------------

/// Seed a deployment row so `/complete?kind=model` has something to find.
async fn seed_dep(store: &dyn Store, model_name: &str, provider: &str) {
    let dep = yb_core::NewDeployment {
        model_name: model_name.into(),
        provider_name: provider.into(),
        upstream_model: model_name.into(),
        upstream_format: WireFormat::OpenaiChat.into(),
        weight: 1,
        pricing: None,
        health_check: Default::default(),
        health_path: None,
    };
    store.create_deployment(&dep).await.unwrap();
}

/// The model id behind a public name, for tests that must speak ids (an access
/// policy) while reading like they speak names.
async fn model_id(store: &dyn Store, name: &str) -> String {
    store.get_model_by_name(name).await.unwrap().expect("model exists").id
}

/// The provider id behind a provider name, for the same reason.
async fn provider_id(store: &dyn Store, name: &str) -> String {
    store.get_provider_by_name(name).await.unwrap().expect("provider exists").id
}

/// Log `user_id` in by minting a session row directly, returning the cookie
/// header value — cheaper than driving the password login for an authz test.
async fn session_cookie(store: &dyn Store, user_id: &str) -> String {
    let token = new_id();
    store
        .create_session(&yb_core::model::Session {
            token: token.clone(),
            user_id: user_id.to_string(),
            created_at: now(),
            expires_at: now() + chrono::Duration::seconds(3600),
        })
        .await
        .unwrap();
    format!("yb_session={token}")
}

async fn get_json(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn complete_suggests_models_and_providers_that_exist() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "gpt-4o", "azure").await;
    seed_dep(store.as_ref(), "claude-sonnet", "anthropic").await;
    // Four aliases, one more than a hint names before it summarizes the rest.
    let sonnet_id = model_id(store.as_ref(), "claude-sonnet").await;
    for alias in ["smart", "sonnet", "default", "big"] {
        store.upsert_alias(alias, &sonnet_id).await.unwrap();
    }

    // The seeded user is a plain member — reading the catalog is enough.
    let user = store.list_users().await.unwrap().pop().unwrap();
    let cookie = session_cookie(store.as_ref(), &user.id).await;
    let app = build_router(state);

    // Empty query: everything, alphabetical, deduped across deployments. Note
    // `my-model` is absent — `setup` puts it in the in-memory router only, and
    // completion answers from the persisted deployment list, which is what an
    // access policy is actually evaluated against.
    let (status, v) = get_json(&app, "/admin/v1/complete?kind=model", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    // `value` is the model id now (that is what a policy stores); the name is
    // the label.
    let names: Vec<&str> = v.as_array().unwrap().iter().map(|s| s["label"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["claude-sonnet", "gpt-4o"]);
    // Both providers of gpt-4o show up as a hint; the alias annotates its target.
    let hint = |name: &str| -> String {
        v.as_array()
            .unwrap()
            .iter()
            .find(|s| s["label"] == name)
            .unwrap()["hint"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(hint("gpt-4o"), "azure, openai");
    assert_eq!(
        hint("claude-sonnet"),
        "anthropic \u{b7} aka big, default, smart +1 more"
    );

    // Prefix filtering is case-insensitive.
    let gpt_id = model_id(store.as_ref(), "gpt-4o").await;
    let (_, v) = get_json(&app, "/admin/v1/complete?kind=model&q=GPT", &cookie).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["label"], "gpt-4o");
    assert_eq!(v[0]["value"], gpt_id);

    // An alias finds its model, but the suggested value is the model id — an
    // access policy is matched against the model, never the alias, and holding
    // the id is what keeps that rule matching after a rename.
    let (_, v) = get_json(&app, "/admin/v1/complete?kind=model&q=smart", &cookie).await;
    assert_eq!(v[0]["label"], "claude-sonnet");
    assert_eq!(v[0]["value"], sonnet_id);

    // Providers are distinct, with a deployment count as the hint. As with
    // models, the value is the id a policy stores and the label is the name.
    let (_, v) = get_json(&app, "/admin/v1/complete?kind=provider", &cookie).await;
    let provs: Vec<&str> = v.as_array().unwrap().iter().map(|s| s["label"].as_str().unwrap()).collect();
    assert_eq!(provs, vec!["anthropic", "azure", "openai"]);
    assert_eq!(v[0]["value"], provider_id(store.as_ref(), "anthropic").await);
    assert_eq!(v[0]["hint"], "1 deployment");

    // Completing the user list is member-forbidden: it discloses the accounts.
    let (status, _) = get_json(&app, "/admin/v1/complete?kind=user", &cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An unknown vocabulary is a request error, not an empty list.
    let (status, v) = get_json(&app, "/admin/v1/complete?kind=nope", &cookie).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(v["error"]["message"].as_str().unwrap().contains("nope"));
}

#[tokio::test]
async fn complete_requires_a_session() {
    let (state, _token) = setup().await;
    let app = build_router(state);
    let (status, _) = get_json(&app, "/admin/v1/complete?kind=model", "yb_session=bogus").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Model discovery (`GET /v1/models` and its per-shape siblings)
// ---------------------------------------------------------------------------

/// Issue a key for the seeded user under `access`, returning its plaintext token.
async fn key_with(store: &dyn Store, access: AccessPolicy, team_id: Option<String>) -> String {
    let user = store.list_users().await.unwrap().pop().unwrap();
    issue_api_key(
        store,
        &user.id,
        Some("scoped".into()),
        team_id,
        Default::default(),
        access,
        LimitColumns::default(),
    )
    .await
    .unwrap()
    .token
}

/// `PUT uri` with `body`, authenticated by a session cookie.
async fn put_json(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
    body: Value,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// `POST uri` with `body`, authenticated by a session cookie.
async fn post_json_as(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
    body: Value,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A session cookie for a freshly created admin, for the mutation endpoints.
async fn admin_cookie(store: &dyn Store) -> String {
    let admin = User {
        id: new_id(),
        username: format!("admin-{}", new_id()),
        password_hash: "x".into(),
        role: Role::Admin,
        rpm_limit: None,
        tpm_limit: None,
        max_concurrent: None,
        created_at: now(),
        last_login_at: None,
        deleted_at: None,
    };
    store.create_user(&admin).await.unwrap();
    session_cookie(store, &admin.id).await
}

/// The headline behaviour: renaming leaves the old name working.
///
/// A rename that simply dropped the old name would be a silent outage for every
/// client that hardcoded it, so the store inserts the old name as an alias in
/// the same transaction. This asserts it end to end, through the router.
#[tokio::test]
async fn rename_keeps_the_old_name_routable() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    state.reload_models().await.unwrap();
    let id = model_id(store.as_ref(), "gpt-4o").await;
    let cookie = admin_cookie(store.as_ref()).await;
    let app = build_router(state.clone());

    let (status, body) = put_json(
        &app,
        &format!("/admin/v1/models/{id}/name"),
        &cookie,
        json!({ "name": "gpt-4o-2024" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["name"], "gpt-4o-2024");
    assert_eq!(body["id"], id, "rename must not change the model's identity");

    // Discovery shows only the new name...
    let (_, v) = get_json(&app, "/admin/v1/models", &cookie).await;
    let names: Vec<&str> = v.as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["gpt-4o-2024"]);

    // ...while the old one survives as an alias, pointing at the same model.
    let aliases = store.list_aliases().await.unwrap();
    assert_eq!(aliases.len(), 1);
    assert_eq!(aliases[0].alias, "gpt-4o");
    assert_eq!(aliases[0].target, "gpt-4o-2024");

    // And the router resolves both, with no restart.
    let snap_resolves = |name: &str| {
        use yb_core::Router as _;
        let mut rq = yb_core::RouteRequest::default();
        rq.requested_model = name.to_string();
        state.router.resolve(&rq).is_ok()
    };
    assert!(snap_resolves("gpt-4o-2024"), "the new name must route");
    assert!(snap_resolves("gpt-4o"), "the old name must still route via the alias");
}

/// The security regression this whole normalization exists for.
///
/// Under the old name-based policy this test fails: `denied_models: ["gpt-4o"]`
/// silently stops matching the instant the model is renamed, so the key gains
/// access to a model it was explicitly forbidden — no error, no log line.
/// Holding the id makes the deny survive.
#[tokio::test]
async fn a_deny_survives_a_rename() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "claude-sonnet", "anthropic").await;
    state.reload_models().await.unwrap();

    let denied_id = model_id(store.as_ref(), "gpt-4o").await;
    let token = key_with(
        store.as_ref(),
        AccessPolicy {
            denied_model_ids: vec![denied_id.clone()],
            ..Default::default()
        },
        None,
    )
    .await;
    let cookie = admin_cookie(store.as_ref()).await;
    let app = build_router(state.clone());

    // Denied before the rename.
    let (_, v) = get_as(&app, "/v1/models", &token).await;
    let listed = |v: &Value| -> Vec<String> {
        v["data"].as_array().unwrap().iter()
            .map(|m| m["id"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(listed(&v), vec!["claude-sonnet".to_string()]);

    let (status, _) = put_json(
        &app,
        &format!("/admin/v1/models/{denied_id}/name"),
        &cookie,
        json!({ "name": "gpt-4o-renamed" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Still denied after it — under both its new and its old name.
    let (_, v) = get_as(&app, "/v1/models", &token).await;
    assert_eq!(
        listed(&v),
        vec!["claude-sonnet".to_string()],
        "a renamed model must stay denied — this is the bug ids exist to prevent"
    );
}

/// Bulk create is the counterpart to discovery: selecting twenty models should
/// be one request and one router reload, not twenty of each.
#[tokio::test]
async fn bulk_deployments_create_and_are_idempotent() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    let cookie = admin_cookie(store.as_ref()).await;
    let app = build_router(state.clone());

    let body = json!({
        "provider": "local-vllm",
        "upstream_format": "openai_chat",
        "models": [
            { "upstream_model": "gpt-4o",      "model_name": "gpt-4o" },
            // An upstream id may answer to a different public name.
            { "upstream_model": "gpt-4o-mini", "model_name": "fast" },
        ]
    });
    let (status, v) = post_json_as(&app, "/admin/v1/deployments/bulk", &cookie, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{v:?}");
    assert_eq!(v["created"], 2);
    assert_eq!(v["skipped"], 0);

    // The provider was created on demand, and both models exist.
    assert!(store.get_provider_by_name("local-vllm").await.unwrap().is_some());
    assert!(store.get_model_by_name("fast").await.unwrap().is_some());
    let deps = store.list_deployments().await.unwrap();
    assert_eq!(deps.len(), 2);
    let fast = deps.iter().find(|d| d.model_name == "fast").unwrap();
    assert_eq!(fast.upstream_model, "gpt-4o-mini");

    // Re-running is a no-op rather than a duplicate — the same identity index
    // that makes `gateway import` idempotent.
    let (status, v) = post_json_as(&app, "/admin/v1/deployments/bulk", &cookie, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["created"], 0);
    assert_eq!(v["skipped"], 2);
    assert_eq!(store.list_deployments().await.unwrap().len(), 2);

    // And the router picked them up without a restart.
    let (_, v) = get_json(&app, "/admin/v1/models", &cookie).await;
    let names: Vec<&str> = v.as_array().unwrap().iter()
        .map(|m| m["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["fast", "gpt-4o"]);
}

/// Discovery is an admin action against a real endpoint, so the failure modes
/// that do not need an upstream are worth pinning.
#[tokio::test]
async fn discovery_rejects_unknown_providers_and_non_admins() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    let id = provider_id(store.as_ref(), "openai").await;
    let cookie = admin_cookie(store.as_ref()).await;
    let app = build_router(state);

    let (status, _) = post_json_as(&app, "/admin/v1/providers/nope/discover", &cookie,
                                   json!({ "upstream_format": "openai_chat" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Voyage publishes no model list; discovery must say so rather than
    // inventing a URL that 404s.
    let (status, v) = post_json_as(&app, &format!("/admin/v1/providers/{id}/discover"), &cookie,
                                   json!({ "upstream_format": "voyage_embed" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(v["error"]["message"].as_str().unwrap().contains("no model-listing endpoint"));

    let member = store.list_users().await.unwrap().into_iter()
        .find(|u| u.role == Role::Member).expect("seeded member");
    let member_cookie = session_cookie(store.as_ref(), &member.id).await;
    let (status, _) = post_json_as(&app, &format!("/admin/v1/providers/{id}/discover"),
                                   &member_cookie, json!({ "upstream_format": "openai_chat" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The provider half of the same guarantee.
///
/// A provider used to be a bare string on the deployment row, so a policy that
/// denied `anthropic` stopped matching the moment the provider was renamed —
/// the identical silent-grant as models had. Providers are entities now, and
/// the deny is by id.
#[tokio::test]
async fn a_provider_deny_survives_a_provider_rename() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "claude-sonnet", "anthropic").await;
    state.reload_models().await.unwrap();

    let denied = provider_id(store.as_ref(), "anthropic").await;
    let token = key_with(
        store.as_ref(),
        AccessPolicy { denied_provider_ids: vec![denied.clone()], ..Default::default() },
        None,
    )
    .await;
    let cookie = admin_cookie(store.as_ref()).await;
    let app = build_router(state.clone());

    let listed = |v: &Value| -> Vec<String> {
        v["data"].as_array().unwrap().iter()
            .map(|m| m["id"].as_str().unwrap().to_string()).collect()
    };
    let (_, v) = get_as(&app, "/v1/models", &token).await;
    assert_eq!(listed(&v), vec!["gpt-4o".to_string()], "denied before the rename");

    let (status, _) = put_json(
        &app,
        &format!("/admin/v1/providers/{denied}"),
        &cookie,
        json!({ "name": "anthropic-prod" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, v) = get_as(&app, "/v1/models", &token).await;
    assert_eq!(
        listed(&v),
        vec!["gpt-4o".to_string()],
        "a renamed provider must stay denied"
    );
}

/// One endpoint, one credential — configured once and read by every deployment
/// served through it.
#[tokio::test]
async fn deployments_read_their_providers_endpoint() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "text-embedding-3-small", "openai").await;
    let id = provider_id(store.as_ref(), "openai").await;
    let cookie = admin_cookie(store.as_ref()).await;
    let app = build_router(state);

    let (status, body) = put_json(
        &app,
        &format!("/admin/v1/providers/{id}"),
        &cookie,
        json!({ "name": "openai", "api_base": "https://api.example/v1", "api_key": "sk-shared" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    // The credential is never disclosed, only whether one is set.
    assert_eq!(body["has_api_key"], true);
    assert!(body.get("api_key").is_none(), "a key must never be read back out");

    let deps = store.list_deployments().await.unwrap();
    assert_eq!(deps.len(), 2);
    for d in &deps {
        assert_eq!(d.api_base.as_deref(), Some("https://api.example/v1"));
        assert_eq!(d.api_key.as_deref(), Some("sk-shared"));
    }

    // A second edit that omits the key keeps it, rather than blanking it.
    let (status, _) = put_json(&app, &format!("/admin/v1/providers/{id}"), &cookie,
                               json!({ "name": "openai", "api_base": "https://api.example/v1" })).await;
    assert_eq!(status, StatusCode::OK);
    let deps = store.list_deployments().await.unwrap();
    assert_eq!(deps[0].api_key.as_deref(), Some("sk-shared"));
}

#[tokio::test]
async fn rename_rejects_bad_input_and_non_admins() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "claude-sonnet", "anthropic").await;
    let id = model_id(store.as_ref(), "gpt-4o").await;
    let cookie = admin_cookie(store.as_ref()).await;
    let app = build_router(state);

    // A name another model already holds.
    let (status, _) = put_json(&app, &format!("/admin/v1/models/{id}/name"), &cookie,
                               json!({ "name": "claude-sonnet" })).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Blank, and whitespace-only, are both rejected.
    for bad in ["", "   "] {
        let (status, _) = put_json(&app, &format!("/admin/v1/models/{id}/name"), &cookie,
                                   json!({ "name": bad })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "name {bad:?} should be rejected");
    }

    // An unknown model.
    let (status, _) = put_json(&app, "/admin/v1/models/nope/name", &cookie,
                               json!({ "name": "whatever" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A plain member may read the catalog but not rename.
    let member = store.list_users().await.unwrap().into_iter()
        .find(|u| u.role == Role::Member).expect("seeded member");
    let member_cookie = session_cookie(store.as_ref(), &member.id).await;
    let (status, _) = put_json(&app, &format!("/admin/v1/models/{id}/name"), &member_cookie,
                               json!({ "name": "member-rename" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Nothing above changed the name.
    assert_eq!(model_id(store.as_ref(), "gpt-4o").await, id);
}

/// `GET uri` bearing `token`, returning the status and parsed body.
async fn get_as(app: &axum::Router, uri: &str, token: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// The `id`s in an OpenAI-shaped model list.
fn openai_ids(v: &Value) -> Vec<String> {
    v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn model_discovery_lists_only_what_the_key_may_call() {
    let (state, token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "claude-sonnet", "anthropic").await;

    // A key restricted to one model, and one with no restrictions at all.
    let scoped = key_with(
        store.as_ref(),
        AccessPolicy {
            allowed_model_ids: vec![model_id(store.as_ref(), "gpt-4o").await],
            ..Default::default()
        },
        None,
    )
    .await;
    let app = build_router(state);

    let (status, v) = get_as(&app, "/v1/models", &scoped).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(openai_ids(&v), vec!["gpt-4o"]);

    // The unrestricted key still sees the whole catalog — filtering is a
    // policy consequence, not a blanket narrowing.
    let (_, v) = get_as(&app, "/v1/models", &token).await;
    let all = openai_ids(&v);
    assert!(all.contains(&"claude-sonnet".to_string()), "{all:?}");
    assert!(all.contains(&"gpt-4o".to_string()), "{all:?}");

    // Every shape answers with the same set, in its own JSON.
    let (_, v) = get_as(&app, "/anthropic/v1/models", &scoped).await;
    let ids: Vec<&str> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["gpt-4o"]);

    let (_, v) = get_as(&app, "/v1beta/models", &scoped).await;
    let names: Vec<&str> = v["models"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["baseModelId"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["gpt-4o"]);
}

#[tokio::test]
async fn a_model_whose_only_provider_is_denied_is_not_listed() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "claude-sonnet", "anthropic").await;

    // The model itself is permitted; its sole provider is not. Listing it
    // would advertise a model whose every call dies at "no eligible provider".
    let token = key_with(
        store.as_ref(),
        AccessPolicy {
            denied_provider_ids: vec![provider_id(store.as_ref(), "anthropic").await],
            ..Default::default()
        },
        None,
    )
    .await;
    let app = build_router(state);

    let (_, v) = get_as(&app, "/v1/models", &token).await;
    let ids = openai_ids(&v);
    assert!(ids.contains(&"gpt-4o".to_string()));
    assert!(!ids.contains(&"claude-sonnet".to_string()), "{ids:?}");
}

#[tokio::test]
async fn discovery_applies_the_team_policy_too() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "claude-sonnet", "anthropic").await;

    // The key grants everything; its team is the ceiling. A catalog built from
    // the key alone would advertise the two models the team forbids.
    let team = yb_core::model::Team {
        id: new_id(),
        name: "locked".into(),
        access: AccessPolicy {
            allowed_model_ids: vec![model_id(store.as_ref(), "claude-sonnet").await],
            ..Default::default()
        },
        created_at: now(),
        updated_at: now(),
        deleted_at: None,
        created_by: None,
    };
    store.create_team(&team).await.unwrap();
    let token = key_with(store.as_ref(), AccessPolicy::default(), Some(team.id.clone())).await;
    let app = build_router(state);

    let (_, v) = get_as(&app, "/v1/models", &token).await;
    assert_eq!(openai_ids(&v), vec!["claude-sonnet"]);
}

#[tokio::test]
async fn a_hidden_model_cannot_be_confirmed_by_fetching_it_directly() {
    let (state, _token) = setup().await;
    let store = state.store.clone();
    seed_dep(store.as_ref(), "gpt-4o", "openai").await;
    seed_dep(store.as_ref(), "claude-sonnet", "anthropic").await;
    let token = key_with(
        store.as_ref(),
        AccessPolicy {
            allowed_model_ids: vec![model_id(store.as_ref(), "gpt-4o").await],
            ..Default::default()
        },
        None,
    )
    .await;
    let app = build_router(state);

    let (status, _) = get_as(&app, "/v1beta/models/gpt-4o", &token).await;
    assert_eq!(status, StatusCode::OK);
    // Omitting it from the list but serving it here would leak the catalog one
    // guess at a time.
    let (status, _) = get_as(&app, "/v1beta/models/claude-sonnet", &token).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn model_discovery_needs_a_credential() {
    let (state, _token) = setup().await;
    let app = build_router(state);

    // Entitlement is undefined without a caller, so an anonymous list is not
    // "everything" — it is rejected, like inference.
    for uri in ["/v1/models", "/anthropic/v1/models", "/v1beta/models"] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }

    let (status, _) = get_as(&app, "/v1/models", "not-a-real-key").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
