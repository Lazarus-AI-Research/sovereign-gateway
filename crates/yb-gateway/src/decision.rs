//! [`Gateway::handle_decision`]: SystemOne (`POST /v1/systemone`, `jev`) and
//! OpenAI / LiteLLM Decisions (`POST /v1/decisions`, `decisions`), routed and
//! metered like every other turn.
//!
//! Both surfaces share an identical request body (arbitrary `state` — string,
//! Chat Completions `messages`, Responses `input`, or `{ system, messages }` —
//! plus structured `questions` with `noul` / `enum` / `scale` / `rank` / `subset`
//! types, optional `thinking_budget`, `prompt_cache_key`, etc.) and execute in a
//! single buffered forward pass (`max_tokens = 0`, no SSE).
//!
//! When the chosen deployment serves the caller's exact decision shape natively,
//! the request and response bytes are relayed verbatim (with only the top-level
//! `"model"` spliced to `deployment.upstream_model`). When the deployment serves
//! the sibling decision shape (`jev` vs `decisions`), the response envelope is
//! translated losslessly via [`yb_wire::translate_decision_response`].

use yb_core::{DecisionFormat, Deployment, Error, Result, RouteRequest};
use yb_providers::{
    build_decision_url, decision_auth_headers, is_model_not_found, is_retryable, ResponseBody,
    UpstreamRequest,
};
use yb_wire::{DecisionMeta, Usage};

use crate::service::{read_body_message, waited_ms, Gateway, GatewayResponse, RequestCtx};
use crate::wire::wire_err;

impl Gateway {
    /// Orchestrate one inbound decision / SystemOne request and produce a
    /// buffered response in the caller's `surface` envelope.
    pub async fn handle_decision(
        &self,
        surface: DecisionFormat,
        body: &[u8],
        ctx: RequestCtx,
    ) -> Result<GatewayResponse> {
        let started = std::time::Instant::now();
        let created_at = yb_core::now();

        // 1. Validate request structure (`model`, `state`, non-empty `questions`,
        //    `stream != true`) without re-serializing or mutating client JSON.
        let meta = yb_wire::parse_decision_request(body).map_err(wire_err)?;

        let mut guard = self.turn_guard(&ctx, surface.as_str(), &meta.model, started, created_at);

        // 2. Resolve model / alias + access policy, preferring deployments that
        //    serve the caller's exact decision shape natively within each model.
        let route = build_decision_route_request(&meta, &ctx);
        let decision = match self.router.resolve(&route) {
            Ok(d) => d,
            Err(e) => {
                guard.fail(e.http_status()).await;
                return Err(e);
            }
        };
        let candidates =
            prefer_native_decision(self.filter_access(decision.candidates, &ctx), surface);
        if candidates.is_empty() {
            let e = Error::NoEligibleProvider(meta.model.clone());
            guard.fail(e.http_status()).await;
            return Err(e);
        }

        let mut last_err: Option<Error> = None;
        let mut saw_non_decision_only = true;

        // 3. Dispatch buffered with failover (single forward pass, stateless).
        for deployment in candidates {
            let Some((target_fmt, target_base, _relay)) = deployment.decision_target(surface)
            else {
                continue;
            };
            let target_base = target_base.map(str::to_string);
            saw_non_decision_only = false;

            let model_json = match serde_json::to_vec(&deployment.upstream_model) {
                Ok(m) => m,
                Err(e) => {
                    let e = Error::Internal(e.to_string());
                    guard.fail(e.http_status()).await;
                    return Err(e);
                }
            };
            let up_body = match crate::relay::set_top_level(body, "model", &model_json) {
                Ok(b) => b,
                Err(e) => {
                    guard.fail(e.http_status()).await;
                    return Err(e);
                }
            };

            let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
            let api_key = deployment.api_key.as_deref().unwrap_or_default();
            headers.extend(decision_auth_headers(api_key));
            yb_providers::append_headers(
                &mut headers,
                self.extra_headers(&deployment.extra, &deployment.model_name),
            );
            let url = build_decision_url(target_fmt, target_base.as_deref());

            let ureq = UpstreamRequest {
                url,
                method: Default::default(),
                headers,
                body: up_body,
                stream: false,
            };

            let resp = match self.client.send(ureq.clone()).await {
                Ok(r) => r,
                Err(Error::ConnectionLost(_)) => match self.client.send(ureq).await {
                    Ok(r) => r,
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                },
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
                guard.disarm();
                let rctx = self.record_ctx(
                    &ctx,
                    surface.as_str(),
                    &meta.model,
                    &deployment,
                    body.to_vec(),
                    started,
                    created_at,
                );
                rctx.finish(Usage::default(), status, true, Vec::new(), 0)
                    .await;
                return Err(Error::Upstream {
                    provider: deployment.provider.clone(),
                    status,
                    message,
                });
            }

            // 4. Buffer response, extract usage + cache hits, translate envelope
            //    if cross-shape (`jev` <-> `decisions`), and record.
            let resp_headers = resp.headers;
            let bytes = match resp.body {
                ResponseBody::Full(b) => b,
                ResponseBody::Stream(_) => read_body_message(resp.body).await.into_bytes(),
            };
            let usage = yb_wire::parse_decision_usage(&bytes).unwrap_or_default();
            let client_body = match yb_wire::translate_decision_response(
                target_fmt == DecisionFormat::Jev,
                surface == DecisionFormat::Jev,
                &bytes,
            ) {
                Ok(b) => b,
                Err(e) => {
                    let e = wire_err(e);
                    guard.fail(e.http_status()).await;
                    return Err(e);
                }
            };

            guard.disarm();
            let mut rctx = self.record_ctx(
                &ctx,
                surface.as_str(),
                &meta.model,
                &deployment,
                body.to_vec(),
                started,
                created_at,
            );
            rctx.waited_ms = waited_ms(&resp_headers);
            let n = client_body.len() as i64;
            rctx.finish(usage, status, false, client_body.clone(), n)
                .await;

            let content_type = resp_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "application/json".to_string());
            return Ok(GatewayResponse::Full {
                status,
                headers: vec![("content-type".to_string(), content_type)],
                body: client_body,
            });
        }

        let e = if saw_non_decision_only {
            Error::BadRequest(format!(
                "model {} does not serve decision/systemone endpoints",
                meta.model
            ))
        } else {
            last_err.unwrap_or_else(|| Error::NoEligibleProvider(meta.model.clone()))
        };
        guard.fail(e.http_status()).await;
        Err(e)
    }
}

/// Order candidates within each `model_id` group so deployments serving the
/// caller's exact decision shape natively precede cross-shape (`jev` <-> `decisions`)
/// deployments, preserving router order otherwise.
fn prefer_native_decision(candidates: Vec<Deployment>, surface: DecisionFormat) -> Vec<Deployment> {
    let mut models: Vec<String> = Vec::new();
    let mut keyed: Vec<(usize, bool, usize, Deployment)> = candidates
        .into_iter()
        .enumerate()
        .map(|(i, d)| {
            let group = match models.iter().position(|m| m == &d.model_id) {
                Some(g) => g,
                None => {
                    models.push(d.model_id.clone());
                    models.len() - 1
                }
            };
            let cross_shape = !matches!(d.decision_target(surface), Some((_, _, true)));
            (group, cross_shape, i, d)
        })
        .collect();
    keyed.sort_by_key(|(g, cross, i, _)| (*g, *cross, *i));
    keyed.into_iter().map(|(_, _, _, d)| d).collect()
}

fn build_decision_route_request(meta: &DecisionMeta, ctx: &RequestCtx) -> RouteRequest {
    let mut excluded_model_ids = ctx.excluded_model_ids.clone();
    excluded_model_ids.extend(ctx.access.denied_model_ids.iter().cloned());

    let mut denied_provider_ids = ctx.excluded_provider_ids.clone();
    denied_provider_ids.extend(ctx.access.denied_provider_ids.iter().cloned());

    let enabled_provider_ids = if ctx.access.allowed_provider_ids.is_empty() {
        None
    } else {
        Some(ctx.access.allowed_provider_ids.iter().cloned().collect())
    };

    RouteRequest {
        requested_model: meta.model.clone(),
        estimated_input_tokens: (meta.estimated_chars / 4).min(u32::MAX as usize) as u32,
        has_tools: false,
        has_images: meta.has_images,
        excluded_model_ids,
        enabled_provider_ids,
        denied_provider_ids,
        preferred_models: Vec::new(),
    }
}
