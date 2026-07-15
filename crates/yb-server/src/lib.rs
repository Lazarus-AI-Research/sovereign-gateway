//! # yb-server
//!
//! The HTTP surface for the gateway: an [`axum`] router that exposes the four
//! inference dialects (Anthropic Messages, OpenAI Chat Completions, OpenAI
//! Responses, and Google Gemini) plus health/model discovery, and — under
//! `Selfhosted` mode — a JSON admin API for keys, users, teams, budgets,
//! rate-limits and spend.
//!
//! The crate owns only transport concerns: extracting the bearer credential,
//! verifying it against the [`Store`](yb_core::Store), enforcing rate limits and
//! budgets, then handing the raw request body to the
//! [`Gateway`](yb_gateway::Gateway) and re-encoding its result onto the wire. All
//! routing, wire translation, and upstream I/O live further inward; this layer
//! never speaks a concrete backend (no `yb-store`, no `reqwest`).
//!
//! Build the router from an [`AppState`] with [`build_router`].

pub mod admin;
pub mod sso;
pub mod state;
pub mod ui;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use sha2::{Digest, Sha256};

use yb_core::config::DeploymentMode;
use yb_core::principal::KeyAuth;
use yb_core::ratelimit::Limits;
use yb_core::spend::{BudgetAction, SubjectType};
use yb_core::{EmbedFormat, UpstreamFormat, new_id, now, Error, WireFormat};
use yb_gateway::{GatewayResponse, RequestCtx};

pub use state::AppState;

/// Build the full application router for `state`.
///
/// Each of the four surfaces is reachable two ways:
/// - **canonical** bare paths (`/v1/messages`, `/v1/chat/completions`,
///   `/v1/responses`, `/v1beta/...`) so a vendor SDK pointed at the base URL
///   works drop-in, and
/// - an **explicit per-shape prefix** (`/anthropic/...`, `/openai/...`,
///   `/gemini/...`) that namespaces a provider's whole surface and removes the
///   one ambiguity in the bare layout: `GET /v1/models` is shared by OpenAI and
///   Anthropic with different JSON shapes, so the prefix lets a client ask for
///   the shape it expects.
///
/// The admin surface (`/admin/v1/*`) mounts only under
/// [`DeploymentMode::Selfhosted`].
pub fn build_router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        // --- canonical (drop-in) paths --------------------------------------
        .route("/v1/messages", post(anthropic_messages))
        .route("/v1/chat/completions", post(openai_chat))
        .route("/v1/responses", post(openai_responses))
        .route("/v1/embeddings", post(openai_embeddings))
        .route("/v1/multimodalembeddings", post(voyage_embeddings))
        .route("/v2/embed", post(cohere_embed))
        // Gemini: GET lists models, POST does inference (one wildcard, two
        // methods — avoids a static-vs-catch-all route conflict).
        .route("/v1beta/*path", get(gemini_models).post(gemini))
        // Shared discovery path defaults to the OpenAI shape.
        .route("/v1/models", get(models_openai))
        // --- explicit per-shape prefixes ------------------------------------
        .route("/anthropic/v1/messages", post(anthropic_messages))
        .route("/anthropic/v1/models", get(models_anthropic))
        .route("/openai/v1/chat/completions", post(openai_chat))
        .route("/openai/v1/responses", post(openai_responses))
        .route("/openai/v1/embeddings", post(openai_embeddings))
        .route("/voyage/v1/multimodalembeddings", post(voyage_embeddings))
        .route("/cohere/v2/embed", post(cohere_embed))
        .route("/openai/v1/models", get(models_openai))
        .route("/gemini/v1beta/*path", get(gemini_models).post(gemini));

    if state.mode == DeploymentMode::Selfhosted {
        router = router
            .route("/", get(ui::index))
            .route("/ui/app.js", get(ui::app_js))
            // The IdP emails its magic link as `{callback_base}/auth/verify?lt=…`
            // (a fixed suffix), so the sso link handler is served here at the top
            // level — not only under /admin/v1. The typed-code flow is separate
            // (POST /admin/v1/auth/sso/code).
            .route("/auth/verify", get(admin::auth_sso_verify))
            .nest("/admin/v1", admin::router())
            // SPA fallback: serve the admin shell for any unmatched **non-API**
            // GET so `preact-router` history paths (e.g. `/teams`) resolve on a
            // deep-link or refresh. Unmatched API paths still return 404 JSON.
            .fallback(spa_fallback);
    }

    router.with_state(state)
}

/// Fallback: 404 (JSON) for unmatched API paths, otherwise the SPA shell so
/// client-side routes work on deep-link/refresh.
async fn spa_fallback(uri: axum::http::Uri) -> Response {
    let p = uri.path();
    let is_api = p.starts_with("/admin")
        || p.starts_with("/v1")
        || p.starts_with("/v1beta")
        || p.starts_with("/v2")
        || p.starts_with("/ui")
        || p == "/health";
    if is_api {
        error_response(&Error::NotFound(format!("no route for {p}")))
    } else {
        ui::index().await
    }
}

// ---- liveness / discovery ------------------------------------------------

/// Liveness probe. Always 200.
async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// `GET /metrics` — Prometheus text exposition of the observability aggregates.
/// 404 when telemetry (or its prometheus view) is disabled.
async fn metrics(State(state): State<AppState>) -> Response {
    match state.observer.prometheus() {
        Some(text) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            text,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The distinct public model names currently configured (from the DB
/// deployments), in stable order. Discovery endpoints render these per shape.
async fn model_names(state: &AppState) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut names = Vec::new();
    if let Ok(deployments) = state.store.list_deployments().await {
        for d in deployments {
            if seen.insert(d.model_name.clone()) {
                names.push(d.model_name);
            }
        }
    }
    names
}

/// `GET /v1/models` and `/openai/v1/models` — OpenAI-shaped model list.
async fn models_openai(State(state): State<AppState>) -> Json<serde_json::Value> {
    let data: Vec<_> = model_names(&state)
        .await
        .into_iter()
        .map(|id| json!({ "id": id, "object": "model", "created": 0, "owned_by": "gateway" }))
        .collect();
    Json(json!({ "object": "list", "data": data }))
}

/// `GET /anthropic/v1/models` — Anthropic-shaped model list.
async fn models_anthropic(State(state): State<AppState>) -> Json<serde_json::Value> {
    let ids = model_names(&state).await;
    let data: Vec<_> = ids
        .iter()
        .map(|id| json!({ "type": "model", "id": id, "display_name": id, "created_at": "1970-01-01T00:00:00Z" }))
        .collect();
    Json(json!({
        "data": data,
        "has_more": false,
        "first_id": ids.first(),
        "last_id": ids.last(),
    }))
}

/// `GET /v1beta/models` and `/gemini/v1beta/models` — Gemini-shaped model list.
async fn models_gemini(state: &AppState) -> serde_json::Value {
    let models: Vec<_> = model_names(state)
        .await
        .into_iter()
        .map(|id| {
            json!({
                "name": format!("models/{id}"),
                "baseModelId": id,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
            })
        })
        .collect();
    json!({ "models": models })
}

/// `GET /v1beta/*path` — Gemini discovery. Handles `models` (list); any other
/// GET shape is reported as not-found.
async fn gemini_models(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    let p = path.trim_end_matches('/');
    if p == "models" || p == "v1beta/models" {
        return Json(models_gemini(&state).await).into_response();
    }
    // A single-model GET (`models/<id>`) — return that model if configured.
    if let Some(id) = p.strip_prefix("models/") {
        if !id.contains(':') && model_names(&state).await.iter().any(|m| m == id) {
            return Json(json!({
                "name": format!("models/{id}"),
                "baseModelId": id,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
            }))
            .into_response();
        }
    }
    error_response(&Error::NotFound(format!("Gemini discovery path /v1beta/{path}")))
}

// ---- inference handlers --------------------------------------------------

/// `POST /v1/messages` — Anthropic Messages.
async fn anthropic_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    run_inference(state, WireFormat::Anthropic.into(), headers, body).await
}

/// `POST /v1/chat/completions` — OpenAI Chat Completions.
async fn openai_chat(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    run_inference(state, WireFormat::OpenaiChat.into(), headers, body).await
}

/// `POST /v1/responses` — OpenAI Responses.
async fn openai_responses(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    run_inference(state, WireFormat::OpenaiResponses.into(), headers, body).await
}

/// `POST /v1/embeddings` — OpenAI-dialect embeddings (also the shape vLLM,
/// TEI, LiteLLM, Jina, and Voyage's text endpoint speak).
async fn openai_embeddings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    run_inference(state, EmbedFormat::OpenaiEmbed.into(), headers, body).await
}

/// `POST /v2/embed` — Cohere-dialect embeddings.
async fn cohere_embed(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    run_inference(state, EmbedFormat::CohereEmbed.into(), headers, body).await
}

/// `POST /v1/multimodalembeddings` — Voyage-dialect multimodal embeddings.
async fn voyage_embeddings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    run_inference(state, EmbedFormat::VoyageEmbed.into(), headers, body).await
}

/// `POST /v1beta/*path` — Gemini. The public model id and the action
/// (`generateContent` vs `streamGenerateContent`) travel in the URL, not the
/// body, so we lift the model into the JSON body before handing it to the
/// gateway (which parses the body to discover the requested model).
async fn gemini(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: Bytes,
) -> Response {
    let Some((model, action)) = parse_gemini_path(&path) else {
        return error_response(&Error::BadRequest(format!(
            "unrecognized Gemini path: /v1beta/{path}"
        )));
    };

    // Inject the URL-borne model id and the action's intent into the body so
    // the parser can surface both for routing and response shaping — `stream`
    // for chat, `batch` for embeddings (mirroring the chat model/stream
    // injection).
    let mut value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return error_response(&Error::BadRequest(format!("invalid JSON body: {e}"))),
    };
    let Some(obj) = value.as_object_mut() else {
        return error_response(&Error::BadRequest("body is not a JSON object".into()));
    };
    obj.insert("model".to_string(), json!(model));
    let surface: UpstreamFormat = match action.as_str() {
        "embedContent" | "batchEmbedContents" => {
            obj.insert("batch".to_string(), json!(action == "batchEmbedContents"));
            EmbedFormat::GeminiEmbed.into()
        }
        _ => {
            obj.insert("stream".to_string(), json!(action == "streamGenerateContent"));
            WireFormat::Gemini.into()
        }
    };
    let rewritten = match serde_json::to_vec(&value) {
        Ok(b) => Bytes::from(b),
        Err(e) => return error_response(&Error::Internal(e.to_string())),
    };

    run_inference(state, surface, headers, rewritten).await
}

/// Split a Gemini sub-path of the form `models/<model>:<action>` into its model
/// id and action. Returns `None` if the shape is unrecognized.
fn parse_gemini_path(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("models/").unwrap_or(path);
    let (model, action) = rest.split_once(':')?;
    if model.is_empty() || action.is_empty() {
        return None;
    }
    Some((model.to_string(), action.to_string()))
}

/// The shared inference pipeline: authenticate the bearer, enforce rate limits
/// and budgets, then drive the [`Gateway`](yb_gateway::Gateway) and re-encode
/// its response onto the client connection. `surface` is the client dialect —
/// a chat wire format or an embeddings format; the admission pipeline is
/// identical, only the gateway entry point differs.
async fn run_inference(
    state: AppState,
    surface: UpstreamFormat,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. Authenticate the virtual key.
    let Some(token) = bearer_token(&headers) else {
        return error_response(&Error::Unauthorized("missing bearer credential".into()));
    };
    let keyauth = match state.store.verify_api_key(&hex_sha256(&token)).await {
        Ok(Some(k)) => k,
        Ok(None) => return error_response(&Error::Unauthorized("invalid api key".into())),
        Err(e) => return error_response(&e),
    };
    // A key must carry the `inference` scope to run inference. (A key may hold
    // both `inference` and `admin`; one holding only `admin` is rejected here.)
    if !keyauth.api_key.has_scope(yb_core::KeyScope::Inference) {
        return error_response(&Error::Forbidden(
            "this key lacks the inference scope".into(),
        ));
    }

    // 2. Rate limiting (preflight RPM + concurrency + TPM exhaustion).
    let limits = resolve_limits(&keyauth);
    let scope = keyauth.api_key.id.clone();
    // Held for the duration of this handler; releases the concurrency slot on drop.
    let _guard = if state.ratelimit_enabled {
        let at = now();
        let (decision, guard) = state.limiter.check(&scope, limits, at);
        if !decision.allowed {
            return error_response(&Error::RateLimited {
                retry_after: decision.retry_after,
                reason: decision.reason.to_string(),
            });
        }
        let (exhausted, retry) = state.limiter.tpm_exhausted(&scope, limits, at);
        if exhausted {
            return error_response(&Error::RateLimited {
                retry_after: retry,
                reason: "tpm".to_string(),
            });
        }
        Some(guard)
    } else {
        None
    };

    // 3. Budget enforcement (hard, blocking budgets only).
    if state.budgets_enabled {
        if let Err(e) = enforce_budgets(&state, &keyauth).await {
            return error_response(&e);
        }
    }

    // 4. Build the request context and orchestrate.
    let request_id = header_str(&headers, "x-request-id").unwrap_or_else(new_id);
    let trace_id = header_str(&headers, "x-trace-id")
        .or_else(|| header_str(&headers, "traceparent"));

    // Effective model/provider access = the key's grant merged with its team's
    // (deny wins; allow-lists are ceilings). This grants access "by team".
    let mut access = keyauth.api_key.access.clone();
    if let Some(team_id) = &keyauth.api_key.team_id {
        if let Ok(Some(team)) = state.store.get_team(team_id).await {
            access = access.merge(&team.access);
        }
    }

    let ctx = RequestCtx {
        api_key: Some(keyauth.api_key.clone()),
        user_id: Some(keyauth.api_key.owner_user_id.clone()),
        team_id: keyauth.api_key.team_id.clone(),
        request_id,
        trace_id,
        excluded_models: Default::default(),
        excluded_providers: Default::default(),
        access,
    };

    // Best-effort last-used bookkeeping; never fails the request.
    let _ = state.store.mark_api_key_used(&keyauth.api_key.id).await;

    let result = match surface {
        UpstreamFormat::Chat(f) => state.gateway.handle(f, &body, ctx).await,
        UpstreamFormat::Embed(f) => state.gateway.handle_embed(f, &body, ctx).await,
    };
    match result {
        Ok(resp) => gateway_response_into_axum(resp),
        Err(e) => error_response(&e),
    }
}

/// Resolve effective per-request limits: the key's own limits take precedence,
/// falling back to its owner user's, and finally to "unlimited" (0).
fn resolve_limits(auth: &KeyAuth) -> Limits {
    let k = &auth.api_key;
    let u = &auth.user;
    Limits {
        rpm: k.rpm_limit.or(u.rpm_limit).unwrap_or(0),
        tpm: k.tpm_limit.or(u.tpm_limit).unwrap_or(0),
        max_concurrent: k.max_concurrent.or(u.max_concurrent).unwrap_or(0),
    }
}

/// Reject the request with 402 if any enabled, blocking budget for the key, its
/// owner user, or its owning team has met or exceeded its hard limit for the
/// current period. Budgets with period `total` cap lifetime spend (no time
/// window).
async fn enforce_budgets(state: &AppState, auth: &KeyAuth) -> yb_core::Result<()> {
    // Gather budgets for every subject this turn attributes spend to.
    let mut budgets = state
        .store
        .list_budgets(SubjectType::Key, &auth.api_key.id)
        .await?;
    budgets.extend(
        state
            .store
            .list_budgets(SubjectType::User, &auth.api_key.owner_user_id)
            .await?,
    );
    if let Some(team_id) = &auth.api_key.team_id {
        budgets.extend(state.store.list_budgets(SubjectType::Team, team_id).await?);
    }

    let at = now();
    for b in budgets {
        if !b.enabled || b.action != BudgetAction::Block {
            continue;
        }
        let period_start = b.period.bucket_start(at);
        let spent = state
            .store
            .period_spend(b.subject_type, &b.subject_id, b.period, period_start)
            .await?;
        if spent >= b.hard_limit_micros {
            return Err(Error::BudgetExceeded(format!(
                "{} budget for {} exhausted ({} / {} micros)",
                b.period.as_str(),
                b.subject_type.as_str(),
                spent,
                b.hard_limit_micros
            )));
        }
    }
    Ok(())
}

// ---- credential + header helpers -----------------------------------------

/// Extract the virtual-key credential from `Authorization: Bearer <token>`, the
/// Anthropic-style `x-api-key` header, or `x-gateway-key` (in that order). The
/// `x-api-key` form lets native Anthropic clients (and SDKs like rust-genai)
/// point at this surface unchanged.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = header_str(headers, "authorization") {
        let lower = v.to_ascii_lowercase();
        if let Some(stripped) = lower.strip_prefix("bearer ") {
            // Slice the original (preserve case) at the same offset.
            return Some(v[v.len() - stripped.len()..].trim().to_string());
        }
    }
    if let Some(v) = header_str(headers, "x-api-key") {
        return Some(v.trim().to_string());
    }
    header_str(headers, "x-gateway-key").map(|s| s.trim().to_string())
}

/// Read a header as an owned `String`, if present and valid UTF-8.
fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Hex-encoded SHA-256 of a token — the lookup key for `Store::verify_api_key`.
pub(crate) fn hex_sha256(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    to_hex(&hasher.finalize())
}

/// Lowercase hex encoding with no separators.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}


// ---- response mapping ----------------------------------------------------

/// Convert a [`GatewayResponse`] into an axum [`Response`], preserving status
/// and headers and streaming the body when the gateway streamed it.
fn gateway_response_into_axum(resp: GatewayResponse) -> Response {
    match resp {
        GatewayResponse::Full {
            status,
            headers,
            body,
        } => build_response(status, headers, Body::from(body)),
        GatewayResponse::Stream {
            status,
            headers,
            stream,
        } => build_response(status, headers, Body::from_stream(stream)),
    }
}

/// Assemble a response from a numeric status, header pairs, and a body.
fn build_response(status: u16, headers: Vec<(String, String)>, body: Body) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Render a domain [`Error`] as the JSON envelope `{"error":{"code","message"}}`
/// with the contractual HTTP status, attaching `Retry-After` for rate limits.
pub(crate) fn error_response(err: &Error) -> Response {
    let status =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = (
        status,
        Json(json!({
            "error": {
                "code": err.code(),
                "message": err.to_string(),
            }
        })),
    )
        .into_response();

    if let Error::RateLimited { retry_after, .. } = err {
        let secs = retry_after.as_secs().max(1);
        if let Ok(val) = secs.to_string().parse() {
            resp.headers_mut().insert("retry-after", val);
        }
    }
    resp
}
