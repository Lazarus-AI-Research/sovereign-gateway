//! [`Gateway`]: the request-orchestration service.
//!
//! A `Gateway` ties together the four adapter contracts — an
//! [`UpstreamClient`], a [`Router`], a [`Store`], and a [`RequestLogger`] — and
//! exposes a single entry point, [`Gateway::handle`], that takes a raw inbound
//! request on some client [`WireFormat`] (the *surface*) and drives it through:
//!
//! 1. **parse** the body into the IR ([`wire::parse_request`]),
//! 2. **route** it to an ordered candidate list (applying the caller's access
//!    policy + context exclusions, then [`Router::resolve`]),
//! 3. **dispatch with fallback**: for each candidate, emit the request in the
//!    candidate's upstream format, call the upstream, and fail over on a
//!    retryable / model-not-found status — but never once response bytes have
//!    been committed,
//! 4. **translate** the upstream response (buffered or SSE stream) back into the
//!    surface format, and
//! 5. **record** telemetry, a spend rollup, and a request-log record.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures::{stream, StreamExt};

use yb_core::catalog::{builtin_price, ModelPrice};
use yb_core::spend::{Period, RollupDelta, SubjectType};
use yb_core::{
    new_id, now, AccessPolicy, ApiKey, Deployment, Error, NullObserver, Observer,
    RequestLogRecord, RequestLogger, Result, RouteRequest, Router, Store, TelemetryRecord,
    Timestamp, WireFormat,
};
use yb_providers::{
    auth_headers, build_url, is_model_not_found, is_retryable, ByteStream, ResponseBody,
    UpstreamClient, UpstreamRequest,
};
use yb_wire::{ChatRequest, ContentBlock, EmitOptions, StreamEvent, Usage};

use crate::wire;

/// Records turns that never reach a committed upstream response, so failed and
/// abandoned dispatches still show up in telemetry/observability:
/// - explicit failures (`fail`): routing errors, every-candidate-failed;
/// - cancellation (`Drop` while armed): the client disconnected during
///   dispatch — recorded as **499** (client closed request).
///
/// Disarmed once a committed response takes over (RecordCtx handles it, or the
/// stream's own guards do).
pub(crate) struct TurnGuard {
    store: Arc<dyn Store>,
    observer: Arc<dyn Observer>,
    api_key_id: Option<String>,
    user_id: Option<String>,
    team_id: Option<String>,
    trace_id: Option<String>,
    request_id: String,
    surface: String,
    requested_model: String,
    started: Instant,
    created_at: Timestamp,
    armed: bool,
}

impl TurnGuard {
    fn record(&self, status: u16) -> TelemetryRecord {
        TelemetryRecord {
            id: new_id(),
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            api_key_id: self.api_key_id.clone(),
            user_id: self.user_id.clone(),
            team_id: self.team_id.clone(),
            surface: self.surface.clone(),
            requested_model: self.requested_model.clone(),
            decision_model: self.requested_model.clone(),
            decision_provider: "none".to_string(),
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            cost_micros: 0,
            status: status as i32,
            is_error: true,
            latency_ms: self.started.elapsed().as_millis() as i64,
            created_at: self.created_at,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Record an uncommitted failure with the error's HTTP status, then disarm.
    pub(crate) async fn fail(&mut self, status: u16) {
        self.armed = false;
        let rec = self.record(status);
        self.observer.turn(&rec);
        if let Err(e) = self.store.insert_telemetry(&rec).await {
            tracing::warn!(error = %e, "gateway: insert_telemetry (failed turn) failed");
        }
    }
}

impl Drop for TurnGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Client abandoned the request mid-dispatch; hand the record to the
        // runtime (Drop cannot await).
        let rec = self.record(499);
        self.observer.turn(&rec);
        let store = self.store.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = store.insert_telemetry(&rec).await {
                    tracing::warn!(error = %e, "gateway: insert_telemetry (abandoned turn) failed");
                }
            });
        }
    }
}

/// Per-request context resolved by the server's auth/middleware layers before
/// the gateway runs. Carries the authenticated identity (the key and its owner
/// user/team) and the access exclusions already distilled from the key/team
/// policy.
#[derive(Debug, Clone, Default)]
pub struct RequestCtx {
    /// The virtual key the request authenticated with, if any.
    pub api_key: Option<ApiKey>,
    /// The owning user of the authenticating key, if any.
    pub user_id: Option<String>,
    /// The owning team of the authenticating key, if any.
    pub team_id: Option<String>,
    /// Correlation id for this request (also used as the telemetry/log key).
    pub request_id: String,
    /// Optional distributed-trace id.
    pub trace_id: Option<String>,
    /// Public model names excluded for this caller (denylist).
    pub excluded_models: BTreeSet<String>,
    /// Provider attribution names excluded for this caller (denylist).
    pub excluded_providers: BTreeSet<String>,
    /// The effective model/provider access grant for this caller — the key's
    /// policy merged with its team's. Deny wins, allow-lists are ceilings.
    pub access: AccessPolicy,
}

impl RequestCtx {
    /// A minimal context with a fresh request id and no key-level restrictions.
    /// Useful for tests and trusted internal calls.
    pub fn new() -> Self {
        RequestCtx {
            request_id: new_id(),
            ..Default::default()
        }
    }
}

/// The client-facing result of [`Gateway::handle`].
pub enum GatewayResponse {
    /// A fully buffered response (non-streaming completions).
    Full {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// A streamed response: client-native SSE bytes as they are translated.
    Stream {
        status: u16,
        headers: Vec<(String, String)>,
        stream: ByteStream,
    },
}

impl std::fmt::Debug for GatewayResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayResponse::Full { status, body, .. } => f
                .debug_struct("Full")
                .field("status", status)
                .field("body_len", &body.len())
                .finish(),
            GatewayResponse::Stream { status, .. } => {
                f.debug_struct("Stream").field("status", status).finish()
            }
        }
    }
}

impl GatewayResponse {
    /// The HTTP status of either variant.
    pub fn status(&self) -> u16 {
        match self {
            GatewayResponse::Full { status, .. } | GatewayResponse::Stream { status, .. } => *status,
        }
    }
}

/// The orchestration service. Cheap to clone-by-`Arc`; all collaborators are
/// trait objects so the concrete backends never leak into the gateway.
pub struct Gateway {
    pub(crate) client: Arc<dyn UpstreamClient>,
    pub(crate) router: Arc<dyn Router>,
    pub(crate) store: Arc<dyn Store>,
    pub(crate) logger: Arc<dyn RequestLogger>,
    pub(crate) observer: Arc<dyn Observer>,
}

impl Gateway {
    /// Construct a gateway from its four collaborators (no observability export).
    pub fn new(
        client: Arc<dyn UpstreamClient>,
        router: Arc<dyn Router>,
        store: Arc<dyn Store>,
        logger: Arc<dyn RequestLogger>,
    ) -> Self {
        Self::with_observer(client, router, store, logger, Arc::new(NullObserver))
    }

    /// Construct a gateway with an observability sink receiving one call per
    /// served turn.
    pub fn with_observer(
        client: Arc<dyn UpstreamClient>,
        router: Arc<dyn Router>,
        store: Arc<dyn Store>,
        logger: Arc<dyn RequestLogger>,
        observer: Arc<dyn Observer>,
    ) -> Self {
        Gateway {
            client,
            router,
            store,
            logger,
            observer,
        }
    }

    /// Orchestrate one inbound request and produce a translated response.
    ///
    /// `surface` is the client's wire format (it governs both how `body` is
    /// parsed and how the upstream response is re-encoded). Failover stops as
    /// soon as an upstream commits response bytes (a 2xx, or any non-retryable
    /// status).
    pub async fn handle(
        &self,
        surface: WireFormat,
        body: &[u8],
        ctx: RequestCtx,
    ) -> Result<GatewayResponse> {
        let started = Instant::now();
        let created_at = now();

        // 1. Parse the inbound body into the IR.
        let chat = wire::parse_request(surface, body)?;

        // Anything past this point is an attempted turn: the guard makes sure it
        // is recorded even when no upstream response ever commits (routing
        // failure, every candidate failing, or the client hanging up).
        let mut guard = self.turn_guard(&ctx, surface.as_str(), &chat.model, started, created_at);

        // 2. Route: build the RouteRequest from policy, then resolve + apply the
        //    access ceilings the router does not model (allow-lists).
        let route = self.build_route_request(&chat, &ctx);
        let decision = match self.router.resolve(&route) {
            Ok(d) => d,
            Err(e) => {
                guard.fail(e.http_status()).await;
                return Err(e);
            }
        };
        let candidates = self.filter_access(decision.candidates, &ctx);
        if candidates.is_empty() {
            let e = Error::NoEligibleProvider(chat.model.clone());
            guard.fail(e.http_status()).await;
            return Err(e);
        }

        let stream_requested = chat.stream;
        let mut last_err: Option<Error> = None;
        let mut saw_embed_only = true;

        // 3. Dispatch with fallback. We ALWAYS call the upstream in streaming
        //    mode, regardless of what the client asked for: it lets us fail over
        //    while buffering, and gives one uniform path that the translator can
        //    either stream through or aggregate into a single response body.
        for deployment in candidates {
            // Chat requests only dispatch to chat-format deployments; embedding
            // deployments are a different universe (see Gateway::handle_embed).
            let upstream_fmt = match deployment.upstream_format {
                yb_core::UpstreamFormat::Chat(f) => f,
                yb_core::UpstreamFormat::Embed(_) => continue,
            };
            saw_embed_only = false;
            let opts = EmitOptions {
                target_model: deployment.upstream_model.clone(),
                force_reasoning_effort: None,
                stream: true,
            };
            let (up_body, mut headers) = match wire::emit_request(upstream_fmt, &chat, &opts) {
                Ok(v) => v,
                Err(e) => {
                    guard.fail(e.http_status()).await;
                    return Err(e);
                }
            };
            // The upstream credential is the deployment's literal `api_key`.
            let api_key = deployment.api_key.clone().unwrap_or_default();
            headers.extend(auth_headers(upstream_fmt, &api_key));
            let url = build_url(
                upstream_fmt,
                deployment.api_base.as_deref(),
                &deployment.upstream_model,
                true,
            );

            let ureq = UpstreamRequest {
                url,
                method: Default::default(),
                headers,
                body: up_body,
                stream: true,
            };

            let resp = match self.client.send(ureq).await {
                Ok(r) => r,
                // Transport-level failure: try the next candidate.
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let status = resp.status;
            if !(200..300).contains(&status) {
                // Read the upstream error body (draining the stream if the error
                // came back as SSE) so the real provider message is surfaced.
                let message = read_body_message(resp.body).await;
                if is_retryable(status) || is_model_not_found(status) {
                    last_err = Some(Error::Upstream {
                        provider: deployment.provider.clone(),
                        status,
                        message,
                    });
                    continue;
                }
                // Non-retryable upstream error: committed. Record an error turn
                // and surface it.
                guard.disarm();
                let rctx = self.record_ctx(
                    &ctx, surface.as_str(), &chat.model, &deployment,
                    body.to_vec(), started, created_at,
                );
                rctx.finish(Usage::default(), status, true, Vec::new(), 0).await;
                return Err(Error::Upstream {
                    provider: deployment.provider.clone(),
                    status,
                    message,
                });
            }

            // 4 + 5. Success. The upstream was always asked to stream, so it
            //    normally hands back a `Stream`; a `Full` body means the provider
            //    ignored streaming (or it's a mock). Either way we adapt to what
            //    the *client* requested:
            //      client non-stream + upstream stream  → aggregate → one body
            //      client non-stream + upstream full    → re-encode body
            //      client stream     + upstream stream  → translate SSE through
            //      client stream     + upstream full    → expand body → one SSE
            guard.disarm();
            let rctx = self.record_ctx(
                &ctx, surface.as_str(), &chat.model, &deployment,
                body.to_vec(), started, created_at,
            );
            // The Responses response object echoes the request's prompt-cache
            // fields; when the upstream doesn't echo them, fill from the request.
            let cache_echo = (chat.prompt_cache_key.clone(), chat.prompt_cache_retention.clone());
            return match (stream_requested, resp.body) {
                (false, ResponseBody::Stream(up)) => {
                    aggregate_stream(up, upstream_fmt, surface, rctx, status, cache_echo).await
                }
                (false, ResponseBody::Full(bytes)) => {
                    let mut resp = wire::parse_response(upstream_fmt, &bytes)?;
                    apply_cache_echo(&mut resp, cache_echo);
                    emit_full(surface, resp, rctx, status).await
                }
                (true, ResponseBody::Stream(up)) => {
                    let stream =
                        translate_stream(up, upstream_fmt, surface, rctx, status, cache_echo);
                    Ok(GatewayResponse::Stream {
                        status,
                        headers: sse_headers(),
                        stream,
                    })
                }
                (true, ResponseBody::Full(bytes)) => {
                    let mut resp = wire::parse_response(upstream_fmt, &bytes)?;
                    apply_cache_echo(&mut resp, cache_echo);
                    full_to_stream(resp, surface, rctx, status).await
                }
            };
        }

        // All candidates exhausted without a committed response.
        let e = if saw_embed_only {
            Error::BadRequest(format!(
                "model {} is an embeddings model; use an embeddings endpoint",
                chat.model
            ))
        } else {
            last_err.unwrap_or_else(|| Error::NoEligibleProvider(chat.model.clone()))
        };
        guard.fail(e.http_status()).await;
        Err(e)
    }

    /// Arm a [`TurnGuard`] for an attempted turn (chat or embed surface).
    pub(crate) fn turn_guard(
        &self,
        ctx: &RequestCtx,
        surface: &str,
        requested_model: &str,
        started: Instant,
        created_at: Timestamp,
    ) -> TurnGuard {
        TurnGuard {
            store: self.store.clone(),
            observer: self.observer.clone(),
            api_key_id: ctx.api_key.as_ref().map(|k| k.id.clone()),
            user_id: ctx.user_id.clone(),
            team_id: ctx.team_id.clone(),
            trace_id: ctx.trace_id.clone(),
            request_id: ctx.request_id.clone(),
            surface: surface.to_string(),
            requested_model: requested_model.to_string(),
            started,
            created_at,
            armed: true,
        }
    }

    /// Distill the caller's policy into a [`RouteRequest`]: union the context
    /// denylists with the effective access grant ([`RequestCtx::access`], = key
    /// ∪ team), and lift its provider allow-list into the `enabled_providers`
    /// ceiling.
    fn build_route_request(&self, chat: &ChatRequest, ctx: &RequestCtx) -> RouteRequest {
        let mut excluded_models: BTreeSet<String> = ctx.excluded_models.clone();
        excluded_models.extend(ctx.access.denied_models.iter().cloned());

        let mut denied_providers: BTreeSet<String> = ctx.excluded_providers.clone();
        denied_providers.extend(ctx.access.denied_providers.iter().cloned());

        let enabled_providers = if ctx.access.allowed_providers.is_empty() {
            None
        } else {
            Some(ctx.access.allowed_providers.iter().cloned().collect())
        };

        RouteRequest {
            requested_model: chat.model.clone(),
            estimated_input_tokens: estimate_tokens(chat),
            has_tools: !chat.tools.is_empty(),
            has_images: chat
                .messages
                .iter()
                .flat_map(|m| &m.content)
                .any(|c| matches!(c, ContentBlock::Image { .. })),
            excluded_models,
            enabled_providers,
            denied_providers,
            preferred_models: Vec::new(),
        }
    }

    /// Apply the access ceilings the router does not model: the effective grant's
    /// `allowed_models` / `allowed_providers` allow-lists, plus a belt-and-braces
    /// re-check of the context denylists.
    pub(crate) fn filter_access(&self, candidates: Vec<Deployment>, ctx: &RequestCtx) -> Vec<Deployment> {
        candidates
            .into_iter()
            .filter(|d| {
                if !ctx.access.permits_model(&d.model_name)
                    || !ctx.access.permits_provider(&d.provider)
                {
                    return false;
                }
                !ctx.excluded_models.contains(&d.model_name)
                    && !ctx.excluded_providers.contains(&d.provider)
            })
            .collect()
    }

    /// Assemble the owned telemetry/logging context for one served turn.
    /// `surface` is the telemetry label of the client dialect (chat or embed).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_ctx(
        &self,
        ctx: &RequestCtx,
        surface: &str,
        requested_model: &str,
        deployment: &Deployment,
        request_body: Vec<u8>,
        started: Instant,
        created_at: Timestamp,
    ) -> RecordCtx {
        RecordCtx {
            store: self.store.clone(),
            logger: self.logger.clone(),
            observer: self.observer.clone(),
            api_key_id: ctx.api_key.as_ref().map(|k| k.id.clone()),
            user_id: ctx.user_id.clone(),
            team_id: ctx.team_id.clone(),
            trace_id: ctx.trace_id.clone(),
            request_id: ctx.request_id.clone(),
            surface: surface.to_string(),
            requested_model: requested_model.to_string(),
            deployment: deployment.clone(),
            request_body,
            start: started,
            created_at,
        }
    }
}

/// A crude input-size estimate (≈ 4 chars/token over all message text) used only
/// as routing signal; never billed.
fn estimate_tokens(chat: &ChatRequest) -> u32 {
    let mut chars = 0usize;
    for block in chat.system.iter().flatten().chain(chat.messages.iter().flat_map(|m| &m.content)) {
        if let ContentBlock::Text { text } = block {
            chars += text.len();
        }
    }
    (chars / 4).min(u32::MAX as usize) as u32
}

/// Read an upstream error body into a short message, draining the stream when
/// the error arrived as SSE. Capped so a misbehaving upstream can't flood logs.
pub(crate) async fn read_body_message(body: ResponseBody) -> String {
    let bytes = match body {
        ResponseBody::Full(bytes) => bytes,
        ResponseBody::Stream(mut s) => {
            let mut buf = Vec::new();
            while let Some(item) = s.next().await {
                match item {
                    Ok(b) => buf.extend_from_slice(&b),
                    Err(_) => break,
                }
                if buf.len() >= 64 * 1024 {
                    break;
                }
            }
            buf
        }
    };
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "upstream error (no body)".to_string()
    } else {
        trimmed.chars().take(2000).collect()
    }
}

/// Owned data needed to write telemetry, a spend rollup, and a reqlog record
/// once a turn's token usage is known.
#[derive(Clone)]
pub(crate) struct RecordCtx {
    store: Arc<dyn Store>,
    logger: Arc<dyn RequestLogger>,
    observer: Arc<dyn Observer>,
    api_key_id: Option<String>,
    user_id: Option<String>,
    team_id: Option<String>,
    trace_id: Option<String>,
    request_id: String,
    surface: String,
    requested_model: String,
    deployment: Deployment,
    request_body: Vec<u8>,
    start: Instant,
    created_at: Timestamp,
}

impl RecordCtx {
    /// Price the turn (deployment pricing → built-in catalog → free), then write
    /// the telemetry row, upsert the spend rollups (key/user/team), and emit the
    /// request-log record. Storage failures are logged, not propagated: they
    /// must never fail an otherwise-successful inference.
    pub(crate) async fn finish(
        &self,
        usage: Usage,
        status: u16,
        is_error: bool,
        response_body: Vec<u8>,
        response_bytes: i64,
    ) {
        let price = self
            .deployment
            .pricing
            .or_else(|| builtin_price(&self.deployment.upstream_model))
            .or_else(|| builtin_price(&self.deployment.model_name))
            .unwrap_or_else(|| ModelPrice::new(0.0, 0.0));

        // A successful turn that reports no tokens is billed at zero and is
        // invisible to spend tracking. That is always an upstream or translation
        // fault, never a real result, so say so loudly rather than quietly
        // writing a zero row — this is how a whole provider silently stops
        // billing (an OpenAI-compatible stream omits usage entirely unless
        // `stream_options.include_usage` is set, for instance).
        if !is_error && (200..300).contains(&status) && usage.is_empty() {
            tracing::warn!(
                provider = %self.deployment.provider,
                model = %self.deployment.model_name,
                upstream_model = %self.deployment.upstream_model,
                request_id = %self.request_id,
                "upstream reported no token usage; this turn is recorded as unbilled"
            );
        }

        let input = usage.input_tokens as i64;
        let output = usage.output_tokens as i64;
        let cache_read = usage.cache_read_tokens as i64;
        let cache_write = usage.cache_write_tokens as i64;
        let cost = price.cost_micros(input, output, cache_read, cache_write);
        let latency_ms = self.start.elapsed().as_millis() as i64;

        let telemetry = TelemetryRecord {
            id: new_id(),
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            api_key_id: self.api_key_id.clone(),
            user_id: self.user_id.clone(),
            team_id: self.team_id.clone(),
            surface: self.surface.clone(),
            requested_model: self.requested_model.clone(),
            decision_model: self.deployment.model_name.clone(),
            decision_provider: self.deployment.provider.clone(),
            input_tokens: input,
            output_tokens: output,
            cache_read_tokens: cache_read,
            cache_write_tokens: cache_write,
            cost_micros: cost,
            status: status as i32,
            is_error,
            latency_ms,
            created_at: self.created_at,
        };
        // Observability export (non-blocking aggregate/enqueue).
        self.observer.turn(&telemetry);
        if let Err(e) = self.store.insert_telemetry(&telemetry).await {
            tracing::warn!(error = %e, "gateway: insert_telemetry failed");
        }

        // Spend rollup, attributed for the current day to every subject this
        // turn belongs to: the api key, its owner user, and its owning team
        // (when present). This is what powers per-key/user/team accounting and
        // budgets.
        let period = Period::Day;
        let period_start = period.bucket_start(self.created_at);
        let mut subjects: Vec<(SubjectType, String)> = Vec::new();
        if let Some(id) = &self.api_key_id {
            subjects.push((SubjectType::Key, id.clone()));
        }
        if let Some(id) = &self.user_id {
            subjects.push((SubjectType::User, id.clone()));
        }
        if let Some(id) = &self.team_id {
            subjects.push((SubjectType::Team, id.clone()));
        }
        for (subject_type, subject_id) in subjects {
            let delta = RollupDelta {
                subject_type,
                subject_id,
                period,
                period_start,
                spend_micros: cost,
                request_count: 1,
                input_tokens: input,
                output_tokens: output,
            };
            if let Err(e) = self.store.upsert_rollup(&delta).await {
                tracing::warn!(error = %e, subject = ?subject_type, "gateway: upsert_rollup failed");
            }
        }

        // Request/response capture (non-blocking sink).
        self.logger.log(RequestLogRecord {
            ts: self.created_at,
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            installation_id: String::new(),
            surface: self.surface.clone(),
            requested_model: self.requested_model.clone(),
            decision_model: self.deployment.model_name.clone(),
            decision_provider: self.deployment.provider.clone(),
            upstream_status: status as i32,
            is_error,
            request_bytes: self.request_body.len() as i64,
            response_bytes,
            response_truncated: false,
            request_body: self.request_body.clone(),
            response_body,
        });
    }
}

/// Field-wise max merge of a usage delta into the running total. Works whether a
/// format reports usage incrementally or cumulatively.
fn merge_usage(acc: &mut Usage, u: &Usage) {
    acc.merge(u);
}

/// Maximum silence between upstream stream chunks before the turn is treated as
/// a transport failure (recorded, and the client stream ends) instead of
/// hanging forever on a stalled upstream.
const UPSTREAM_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// `upstream.next()` with the idle guard applied: a stall becomes a transport
/// error item.
async fn next_or_stall(
    upstream: &mut ByteStream,
) -> Option<std::result::Result<Bytes, Error>> {
    match tokio::time::timeout(UPSTREAM_IDLE_TIMEOUT, upstream.next()).await {
        Ok(item) => item,
        Err(_) => Some(Err(Error::Upstream {
            provider: "upstream".into(),
            status: 504,
            message: format!(
                "stream stalled: no data for {}s",
                UPSTREAM_IDLE_TIMEOUT.as_secs()
            ),
        })),
    }
}

/// Fill the response's prompt-cache echo from the request when the upstream did
/// not echo it itself (an upstream echo wins).
fn apply_cache_echo(
    resp: &mut yb_wire::ChatResponse,
    (key, retention): (Option<String>, Option<String>),
) {
    if resp.prompt_cache_key.is_none() {
        resp.prompt_cache_key = key;
    }
    if resp.prompt_cache_retention.is_none() {
        resp.prompt_cache_retention = retention;
    }
}

/// Headers for a buffered (non-stream) client response.
fn json_headers(surface: WireFormat) -> Vec<(String, String)> {
    vec![(
        "content-type".to_string(),
        wire::full_content_type(surface).to_string(),
    )]
}

/// Headers for a streamed (SSE) client response.
fn sse_headers() -> Vec<(String, String)> {
    vec![
        ("content-type".to_string(), "text/event-stream".to_string()),
        ("cache-control".to_string(), "no-cache".to_string()),
    ]
}

/// Emit a finished [`ChatResponse`] as a buffered client body, record the turn,
/// and return it.
async fn emit_full(
    surface: WireFormat,
    resp: yb_wire::ChatResponse,
    rctx: RecordCtx,
    status: u16,
) -> Result<GatewayResponse> {
    let client_bytes = wire::emit_response(surface, &resp)?;
    let resp_len = client_bytes.len() as i64;
    // The reqlog captures the IR (normalized ChatResponse JSON), not the
    // client-native bytes: one uniform schema across all surfaces.
    let ir_json = serde_json::to_vec(&resp).unwrap_or_default();
    rctx.finish(resp.usage, status, false, ir_json, resp_len).await;
    Ok(GatewayResponse::Full {
        status,
        headers: json_headers(surface),
        body: client_bytes,
    })
}

/// Consume an upstream SSE stream fully, fold it into one [`ChatResponse`] with
/// [`yb_wire::Aggregator`], then emit it as a buffered client body. This is the
/// path for a non-streaming client served (as always) by a streaming upstream.
async fn aggregate_stream(
    mut upstream: ByteStream,
    upstream_fmt: WireFormat,
    surface: WireFormat,
    rctx: RecordCtx,
    status: u16,
    cache_echo: (Option<String>, Option<String>),
) -> Result<GatewayResponse> {
    let mut decoder = wire::Decoder::new(upstream_fmt);
    let mut agg = yb_wire::Aggregator::new();
    let mut buf: Vec<u8> = Vec::new();

    while let Some(item) = next_or_stall(&mut upstream).await {
        match item {
            Ok(chunk) => {
                buf.extend_from_slice(&chunk);
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    let text = String::from_utf8_lossy(&line);
                    let line = text.trim_end_matches(['\r', '\n']);
                    agg.push_all(&decoder.decode_line(line));
                }
            }
            Err(e) => {
                // Upstream broke mid-stream after committing 2xx; we cannot fail
                // over now. Record an error turn and surface the transport error.
                rctx.finish(yb_wire::Usage::default(), status, true, Vec::new(), 0)
                    .await;
                return Err(e);
            }
        }
    }
    // Flush any trailing partial line.
    if !buf.is_empty() {
        let text = String::from_utf8_lossy(&buf);
        let line = text.trim_end_matches(['\r', '\n']);
        agg.push_all(&decoder.decode_line(line));
    }

    let mut resp = agg.into_response(rctx.request_id.clone());
    apply_cache_echo(&mut resp, cache_echo);
    emit_full(surface, resp, rctx, status).await
}

/// Expand a buffered upstream [`ChatResponse`] into a single client SSE payload,
/// for the rare case of a streaming client served by a non-streaming upstream.
async fn full_to_stream(
    resp: yb_wire::ChatResponse,
    surface: WireFormat,
    rctx: RecordCtx,
    status: u16,
) -> Result<GatewayResponse> {
    let events = yb_wire::events_from_response(&resp);
    let mut encoder = wire::Encoder::new(surface);
    let bytes = encoder.encode(&events);
    let n = bytes.len() as i64;
    let ir_json = serde_json::to_vec(&resp).unwrap_or_default();
    rctx.finish(resp.usage, status, false, ir_json, n).await;
    let s = stream::once(async move { Ok(Bytes::from(bytes)) });
    Ok(GatewayResponse::Stream {
        status,
        headers: sse_headers(),
        stream: Box::pin(s),
    })
}

/// Mutable state threaded through the streaming-translation `unfold`.
struct StreamState {
    upstream: ByteStream,
    /// Bytes received but not yet split into complete lines.
    buf: Vec<u8>,
    decoder: wire::Decoder,
    encoder: wire::Encoder,
    usage: Usage,
    /// Folds every decoded event into a [`ChatResponse`] so the reqlog can
    /// capture the turn as normalized IR even on the streaming path.
    agg: yb_wire::Aggregator,
    response_bytes: i64,
    status: u16,
    rctx: RecordCtx,
    /// Set once the upstream stream ends (or errors).
    done: bool,
    /// Set once telemetry has been recorded (exactly once).
    recorded: bool,
}

impl StreamState {
    /// Serialize the aggregated IR response for the reqlog capture.
    fn ir_json(&mut self) -> Vec<u8> {
        let agg = std::mem::take(&mut self.agg);
        let resp = agg.into_response(self.rctx.request_id.clone());
        serde_json::to_vec(&resp).unwrap_or_default()
    }
}

impl Drop for StreamState {
    /// The client can abandon a streaming response at any moment (timeout,
    /// disconnect), which drops this future mid-`await` — none of the in-stream
    /// record paths run. Catch that here: file the partial turn as **499**
    /// (client closed request, per the nginx convention) via a spawned task,
    /// since `finish` is async and `Drop` is not.
    fn drop(&mut self) {
        if self.recorded {
            return;
        }
        let agg = std::mem::take(&mut self.agg);
        let resp = agg.into_response(self.rctx.request_id.clone());
        let ir = serde_json::to_vec(&resp).unwrap_or_default();
        let rctx = self.rctx.clone();
        let usage = self.usage;
        let bytes = self.response_bytes;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                rctx.finish(usage, 499, true, ir, bytes).await;
            });
        }
    }
}

/// Build the client-facing translated SSE stream.
///
/// Upstream bytes are buffered and split on `\n`; each line is decoded into IR
/// [`StreamEvent`]s, which are re-encoded into the surface's native SSE dialect
/// and yielded. Token usage is accumulated as it streams; when the upstream
/// ends, telemetry / rollup / reqlog are written exactly once.
fn translate_stream(
    upstream: ByteStream,
    upstream_fmt: WireFormat,
    surface: WireFormat,
    rctx: RecordCtx,
    status: u16,
    cache_echo: (Option<String>, Option<String>),
) -> ByteStream {
    let mut encoder = wire::Encoder::new(surface);
    encoder.set_prompt_cache(cache_echo.0, cache_echo.1);
    let init = StreamState {
        upstream,
        buf: Vec::new(),
        decoder: wire::Decoder::new(upstream_fmt),
        encoder,
        usage: Usage::default(),
        agg: yb_wire::Aggregator::new(),
        response_bytes: 0,
        status,
        rctx,
        done: false,
        recorded: false,
    };

    let s = stream::unfold(init, |mut st| async move {
        loop {
            if st.done {
                if !st.recorded {
                    let ir = st.ir_json();
                    st.rctx
                        .finish(st.usage, st.status, false, ir, st.response_bytes)
                        .await;
                    // Read by StreamState::drop (suppresses the 499 fallback),
                    // which the unused-assignment lint cannot see.
                    #[allow(unused_assignments)]
                    {
                        st.recorded = true;
                    }
                }
                return None;
            }

            match next_or_stall(&mut st.upstream).await {
                Some(Ok(chunk)) => {
                    st.buf.extend_from_slice(&chunk);
                    let mut events = Vec::new();
                    while let Some(pos) = st.buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = st.buf.drain(..=pos).collect();
                        let text = String::from_utf8_lossy(&line);
                        let line = text.trim_end_matches(['\r', '\n']);
                        let evs = st.decoder.decode_line(line);
                        for ev in &evs {
                            if let StreamEvent::UsageDelta { usage } = ev {
                                merge_usage(&mut st.usage, usage);
                            }
                        }
                        st.agg.push_all(&evs);
                        events.extend(evs);
                    }
                    if events.is_empty() {
                        continue; // need more bytes before we have output
                    }
                    let bytes = st.encoder.encode(&events);
                    if bytes.is_empty() {
                        continue;
                    }
                    st.response_bytes += bytes.len() as i64;
                    return Some((Ok(Bytes::from(bytes)), st));
                }
                Some(Err(e)) => {
                    // Bytes already committed; surface the transport error and
                    // stop. Record NOW (as an error turn): once we yield Err the
                    // body is torn down and this future may never be polled
                    // again, so the done-poll safety net would not run.
                    st.done = true;
                    let ir = st.ir_json();
                    st.rctx
                        .finish(st.usage, st.status, true, ir, st.response_bytes)
                        .await;
                    st.recorded = true;
                    return Some((Err(e), st));
                }
                None => {
                    // Flush any trailing partial line, then record and finish.
                    let mut events = Vec::new();
                    if !st.buf.is_empty() {
                        let line = std::mem::take(&mut st.buf);
                        let text = String::from_utf8_lossy(&line);
                        let line = text.trim_end_matches(['\r', '\n']);
                        let evs = st.decoder.decode_line(line);
                        for ev in &evs {
                            if let StreamEvent::UsageDelta { usage } = ev {
                                merge_usage(&mut st.usage, usage);
                            }
                        }
                        st.agg.push_all(&evs);
                        events.extend(evs);
                    }
                    st.done = true;
                    let bytes = if events.is_empty() {
                        Bytes::new()
                    } else {
                        let b = st.encoder.encode(&events);
                        st.response_bytes += b.len() as i64;
                        Bytes::from(b)
                    };
                    let ir = st.ir_json();
                    st.rctx
                        .finish(st.usage, st.status, false, ir, st.response_bytes)
                        .await;
                    st.recorded = true;
                    return Some((Ok(bytes), st));
                }
            }
        }
    });

    Box::pin(s)
}
