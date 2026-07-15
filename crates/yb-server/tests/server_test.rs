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
