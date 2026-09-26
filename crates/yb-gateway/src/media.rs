//! [`Gateway::handle_media`]: OpenAI image generation, speech and
//! transcription, routed and recorded like every other turn.
//!
//! These are forwarded rather than translated: the body goes upstream as the
//! client sent it, naming the deployment's model, and the upstream's answer
//! (an image as JSON, speech as audio bytes, a transcript as JSON) comes back
//! with its own content type. A turn records no tokens, only that it happened.

use yb_core::{Error, MediaFormat, Result, RouteRequest, UpstreamFormat};
use yb_providers::{
    build_media_url, is_model_not_found, is_retryable, media_auth_headers, HttpMethod,
    ResponseBody, UpstreamRequest,
};
use yb_wire::{route_media_request, video_model, Usage};

use crate::service::{read_body_message, Gateway, GatewayResponse, RequestCtx};
use crate::wire::wire_err;

impl Gateway {
    /// Orchestrate one inbound media request. `content_type` is the client's,
    /// and is forwarded with the body.
    pub async fn handle_media(
        &self,
        surface: MediaFormat,
        body: &[u8],
        content_type: &str,
        ctx: RequestCtx,
    ) -> Result<GatewayResponse> {
        let started = std::time::Instant::now();
        let created_at = yb_core::now();
        let request = route_media_request(body, content_type).map_err(wire_err)?;
        let mut guard =
            self.turn_guard(&ctx, surface.as_str(), &request.model, started, created_at);

        let route = build_media_route_request(&request.model, &ctx);
        let decision = match self.router.resolve(&route) {
            Ok(d) => d,
            Err(e) => {
                guard.fail(e.http_status()).await;
                return Err(e);
            }
        };
        let candidates = self.filter_access(decision.candidates, &ctx);
        if candidates.is_empty() {
            let e = Error::NoEligibleProvider(request.model.clone());
            guard.fail(e.http_status()).await;
            return Err(e);
        }

        let mut last_err: Option<Error> = None;
        let mut saw_other_kind_only = true;
        for deployment in candidates {
            // A media request goes only to a deployment that serves the same
            // endpoint: a speech model cannot answer a transcription.
            if deployment.upstream_format != UpstreamFormat::Media(surface) {
                continue;
            }
            saw_other_kind_only = false;

            let upstream_body = match request.upstream_body(body, &deployment.upstream_model) {
                Ok(b) => b,
                Err(e) => {
                    let e = wire_err(e);
                    guard.fail(e.http_status()).await;
                    return Err(e);
                }
            };
            let mut headers = vec![("content-type".to_string(), content_type.to_string())];
            headers.extend(media_auth_headers(
                deployment.api_key.as_deref().unwrap_or_default(),
            ));
            yb_providers::append_headers(
                &mut headers,
                self.extra_headers(&deployment.extra, &deployment.model_name),
            );
            let upstream = UpstreamRequest {
                url: build_media_url(surface, deployment.api_base.as_deref()),
                method: Default::default(),
                headers,
                body: upstream_body,
                stream: false,
            };
            let response = match self.client.send(upstream).await {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let status = response.status;
            let response_type = response
                .header("content-type")
                .unwrap_or("application/octet-stream")
                .to_string();
            if !(200..300).contains(&status) {
                let message = read_body_message(response.body).await;
                if is_retryable(status) || is_model_not_found(status) {
                    last_err = Some(Error::Upstream {
                        provider: deployment.provider.clone(),
                        status,
                        message,
                    });
                    continue;
                }
                guard.disarm();
                let record = self.record_ctx(
                    &ctx,
                    surface.as_str(),
                    &request.model,
                    &deployment,
                    body.to_vec(),
                    started,
                    created_at,
                );
                let mut record = record;
                record.reports_usage = false;
                record
                    .finish(Usage::default(), status, true, Vec::new(), 0)
                    .await;
                return Err(Error::Upstream {
                    provider: deployment.provider.clone(),
                    status,
                    message,
                });
            }

            let bytes = match response.body {
                ResponseBody::Full(b) => b,
                ResponseBody::Stream(_) => read_body_message(response.body).await.into_bytes(),
            };
            guard.disarm();
            let mut record = self.record_ctx(
                &ctx,
                surface.as_str(),
                &request.model,
                &deployment,
                body.to_vec(),
                started,
                created_at,
            );
            record.reports_usage = false;
            // Audio is not worth keeping in the request log; JSON answers are.
            let logged = if response_type.starts_with("application/json") {
                bytes.clone()
            } else {
                Vec::new()
            };
            record
                .finish(Usage::default(), status, false, logged, bytes.len() as i64)
                .await;
            return Ok(GatewayResponse::Full {
                status,
                headers: vec![("content-type".to_string(), response_type)],
                body: bytes,
            });
        }

        let e = if saw_other_kind_only {
            Error::BadRequest(format!(
                "model {} does not serve {}",
                request.model,
                surface.path()
            ))
        } else {
            last_err.unwrap_or_else(|| Error::NoEligibleProvider(request.model.clone()))
        };
        guard.fail(e.http_status()).await;
        Err(e)
    }
}

/// What a request about a video already made asks: how it is going, its
/// file, or that it be cancelled and forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoLookup {
    Status,
    Content,
    Delete,
}

impl Gateway {
    /// Forward a request about a video to the deployment that made it, which
    /// the video's id names by its upstream model. A model served by several
    /// deployments is asked of each in turn until one knows the video; one
    /// that cannot be reached is passed over, and its error returned when no
    /// other knew the video, since it may be the one that made it. Only making
    /// a video is a turn: asking after it every few seconds would fill the
    /// request log with polls.
    pub async fn handle_video(
        &self,
        id: &str,
        lookup: VideoLookup,
        ctx: RequestCtx,
    ) -> Result<GatewayResponse> {
        let no_such_video = || Error::NotFound("no such video".into());
        let model = video_model(id).map_err(|_| no_such_video())?;
        let serving = self
            .router
            .serving(MediaFormat::OpenaiVideos.into(), &model);
        let mut answer = None;
        let mut unreachable = None;
        for deployment in self.filter_access(serving, &ctx) {
            let response = match self.ask_about_video(&deployment, id, lookup).await {
                Ok(response) => response,
                Err(e) => {
                    unreachable = Some(e);
                    continue;
                }
            };
            let GatewayResponse::Full { status, .. } = &response else {
                return Ok(response);
            };
            if *status != 404 {
                return Ok(response);
            }
            answer = Some(response);
        }
        match (unreachable, answer) {
            (Some(e), _) => Err(e),
            (None, Some(response)) => Ok(response),
            (None, None) => Err(no_such_video()),
        }
    }

    async fn ask_about_video(
        &self,
        deployment: &yb_core::Deployment,
        id: &str,
        lookup: VideoLookup,
    ) -> Result<GatewayResponse> {
        let mut url = format!(
            "{}/{id}",
            build_media_url(MediaFormat::OpenaiVideos, deployment.api_base.as_deref())
        );
        if lookup == VideoLookup::Content {
            url.push_str("/content");
        }
        let mut headers = media_auth_headers(deployment.api_key.as_deref().unwrap_or_default());
        yb_providers::append_headers(
            &mut headers,
            self.extra_headers(&deployment.extra, &deployment.model_name),
        );
        let upstream = UpstreamRequest {
            url,
            method: if lookup == VideoLookup::Delete {
                HttpMethod::Delete
            } else {
                HttpMethod::Get
            },
            headers,
            body: Vec::new(),
            stream: false,
        };
        let response = self.client.send(upstream).await?;
        let status = response.status;
        let response_type = response
            .header("content-type")
            .unwrap_or("application/octet-stream")
            .to_string();
        // A request that is not streamed is answered in full, a video's bytes
        // included.
        let ResponseBody::Full(body) = response.body else {
            return Err(Error::Upstream {
                provider: deployment.provider.clone(),
                status: 502,
                message: "the engine streamed a video lookup".into(),
            });
        };
        Ok(GatewayResponse::Full {
            status,
            headers: vec![("content-type".to_string(), response_type)],
            body,
        })
    }
}

/// The caller's policy as a [`RouteRequest`] for a media turn.
fn build_media_route_request(model: &str, ctx: &RequestCtx) -> RouteRequest {
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
        requested_model: model.to_string(),
        estimated_input_tokens: 0,
        has_tools: false,
        has_images: false,
        excluded_model_ids,
        enabled_provider_ids,
        denied_provider_ids,
        preferred_models: Vec::new(),
    }
}
