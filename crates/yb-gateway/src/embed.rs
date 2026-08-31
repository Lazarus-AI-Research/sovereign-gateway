//! [`Gateway::handle_embed`]: the embeddings counterpart of `handle`.
//!
//! Embeddings share the gateway's routing (aliases, access policy, failover)
//! and recording (TurnGuard, RecordCtx → telemetry/spend/reqlog/observer)
//! machinery, but the dispatch itself is far simpler than chat: the upstream is
//! always called **buffered** (`stream: false` — embeddings never stream), and
//! every candidate is retry-safe until a 2xx commits.
//!
//! Observability parity with chat: every embed turn — success, upstream error,
//! routing failure, or client abandonment — flows through the same
//! [`yb_core::Observer`], so it lands in the metrics registry (labels:
//! `surface = "openai_embed" | …`, model, provider, status) and is exported as
//! a per-turn OTLP event + span with full-cardinality attributes.

use yb_core::{EmbedFormat, Error, Result, RouteRequest, UpstreamFormat};
use yb_providers::{
    build_embed_url, embed_auth_headers, is_model_not_found, is_retryable, ResponseBody,
    UpstreamRequest,
};
use yb_wire::{EmbedEmitOptions, EmbedPart, EmbedRequest, Usage};

use crate::service::{read_body_message, Gateway, GatewayResponse, RequestCtx};
use crate::wire;

impl Gateway {
    /// Orchestrate one inbound embeddings request and produce a translated,
    /// buffered response. `surface` is the client's embeddings dialect.
    pub async fn handle_embed(
        &self,
        surface: EmbedFormat,
        body: &[u8],
        ctx: RequestCtx,
    ) -> Result<GatewayResponse> {
        let started = std::time::Instant::now();
        let created_at = yb_core::now();

        // 1. Parse the inbound body into the embed IR (rejects empty inputs and
        //    token arrays with a 400).
        let req = wire::parse_embed_request(surface, body)?;

        // Anything past this point is an attempted turn — same guarantees as
        // chat: failures and abandonment are recorded, not silently dropped.
        let mut guard =
            self.turn_guard(&ctx, surface.as_str(), &req.model, started, created_at);

        // 2. Route through the same resolver (aliases + access policy apply).
        let route = build_embed_route_request(&req, &ctx);
        let decision = match self.router.resolve(&route) {
            Ok(d) => d,
            Err(e) => {
                guard.fail(e.http_status()).await;
                return Err(e);
            }
        };
        let candidates = self.filter_access(decision.candidates, &ctx);
        if candidates.is_empty() {
            let e = Error::NoEligibleProvider(req.model.clone());
            guard.fail(e.http_status()).await;
            return Err(e);
        }

        let mut last_err: Option<Error> = None;
        let mut saw_chat_only = true;

        // 3. Dispatch with fallback — buffered, and always retry-safe (nothing
        //    commits until a 2xx body is in hand).
        for deployment in candidates {
            // Embedding requests only dispatch to embedding-format deployments.
            let upstream_fmt = match deployment.upstream_format {
                UpstreamFormat::Embed(f) => f,
                UpstreamFormat::Chat(_) => continue,
            };
            saw_chat_only = false;

            let opts = EmbedEmitOptions::new(deployment.upstream_model.clone());
            let (up_body, mut headers) = match wire::emit_embed_request(upstream_fmt, &req, &opts)
            {
                Ok(v) => v,
                Err(e) => {
                    guard.fail(e.http_status()).await;
                    return Err(e);
                }
            };
            let api_key = deployment.api_key.clone().unwrap_or_default();
            headers.extend(embed_auth_headers(upstream_fmt, &api_key));
            yb_providers::append_headers(
                &mut headers,
                self.extra_headers(&deployment.extra, &deployment.model_name),
            );
            let url = build_embed_url(
                upstream_fmt,
                deployment.api_base.as_deref(),
                &deployment.upstream_model,
            );

            let ureq = UpstreamRequest {
                url,
                method: Default::default(),
                headers,
                body: up_body,
                stream: false,
            };
            let resp = match self.client.send(ureq).await {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let status = resp.status;
            if !(200..300).contains(&status) {
                let message = read_body_message(resp.body).await;
                if is_retryable(status) || is_model_not_found(status) {
                    last_err = Some(Error::Upstream {
                        provider: deployment.provider.clone(),
                        status,
                        message,
                    });
                    continue;
                }
                // Non-retryable: committed error turn.
                guard.disarm();
                let rctx = self.record_ctx(
                    &ctx, surface.as_str(), &req.model, &deployment,
                    body.to_vec(), started, created_at,
                );
                rctx.finish(Usage::default(), status, true, Vec::new(), 0).await;
                return Err(Error::Upstream {
                    provider: deployment.provider.clone(),
                    status,
                    message,
                });
            }

            // 4. Success: buffer (a mock may still hand back a stream), parse,
            //    re-emit on the client surface, and record.
            let bytes = match resp.body {
                ResponseBody::Full(b) => b,
                ResponseBody::Stream(_) => {
                    // stream:false upstream requests are buffered by the HTTP
                    // client; a streamed body here can only come from a mock.
                    read_body_message(resp.body).await.into_bytes()
                }
            };
            let parsed = wire::parse_embed_response(upstream_fmt, &bytes)?;
            let client_body = wire::emit_embed_response(surface, &parsed, &req)?;

            guard.disarm();
            let rctx = self.record_ctx(
                &ctx, surface.as_str(), &req.model, &deployment,
                body.to_vec(), started, created_at,
            );
            let usage = Usage {
                input_tokens: parsed.usage.input_tokens,
                ..Default::default()
            };
            // The reqlog captures the normalized IR response, like chat does.
            let ir_json = serde_json::to_vec(&parsed).unwrap_or_default();
            let n = client_body.len() as i64;
            rctx.finish(usage, status, false, ir_json, n).await;

            return Ok(GatewayResponse::Full {
                status,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: client_body,
            });
        }

        // All candidates exhausted without a committed response.
        let e = if saw_chat_only {
            Error::BadRequest(format!(
                "model {} resolves only to chat deployments; use a chat endpoint",
                req.model
            ))
        } else {
            last_err.unwrap_or_else(|| Error::NoEligibleProvider(req.model.clone()))
        };
        guard.fail(e.http_status()).await;
        Err(e)
    }
}

/// Distill the caller's policy into a [`RouteRequest`] for an embeddings turn —
/// same policy math as chat, with embed-appropriate signals.
fn build_embed_route_request(req: &EmbedRequest, ctx: &RequestCtx) -> RouteRequest {
    let mut excluded_models = ctx.excluded_models.clone();
    excluded_models.extend(ctx.access.denied_models.iter().cloned());

    let mut denied_providers = ctx.excluded_providers.clone();
    denied_providers.extend(ctx.access.denied_providers.iter().cloned());

    let enabled_providers = if ctx.access.allowed_providers.is_empty() {
        None
    } else {
        Some(ctx.access.allowed_providers.iter().cloned().collect())
    };

    let chars: usize = req
        .inputs
        .iter()
        .flat_map(|i| &i.parts)
        .map(|p| match p {
            EmbedPart::Text { text } => text.len(),
            EmbedPart::Image { .. } => 0,
        })
        .sum();

    RouteRequest {
        requested_model: req.model.clone(),
        estimated_input_tokens: (chars / 4).min(u32::MAX as usize) as u32,
        has_tools: false,
        has_images: req.inputs.iter().any(|i| i.has_image()),
        excluded_models,
        enabled_providers,
        denied_providers,
        preferred_models: Vec::new(),
    }
}
