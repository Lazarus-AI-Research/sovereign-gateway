//! Backend health checks.
//!
//! Every deployment can carry a [`HealthCheck`] method chosen **independently**
//! of its wire format: `http_ok` (GET a status URL — vLLM `/health`, TEI
//! `/health`, a load balancer's `/`), `models_list` (GET the backend's model
//! listing with the deployment's own auth), or `probe` (a minimal real request
//! in the deployment's dialect — 1-token chat turn or a tiny embedding).
//! Checks run on demand from the admin API; they are never in the request path.

use std::time::{Duration, Instant};

use serde::Serialize;
use yb_core::{DeploymentRecord, EmbedFormat, HealthCheck, UpstreamFormat, WireFormat};
use yb_providers::{
    auth_headers, build_embed_url, build_url, embed_auth_headers, HttpMethod, UpstreamRequest,
};
use yb_wire::{EmbedEmitOptions, EmbedInput, EmbedRequest, EmitOptions};

use crate::service::{read_body_message, Gateway};
use crate::wire;

/// How long a single health check may take end to end.
const CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// The outcome of one deployment health check.
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub deployment_id: String,
    pub model_name: String,
    pub provider: String,
    pub upstream_format: &'static str,
    /// The configured check method that ran.
    pub check: &'static str,
    pub healthy: bool,
    /// The upstream HTTP status, when a request was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Gateway {
    /// Run the configured health check for one deployment.
    pub async fn check_deployment(&self, dep: &DeploymentRecord) -> HealthReport {
        let started = Instant::now();
        let mut report = HealthReport {
            deployment_id: dep.id.clone(),
            model_name: dep.model_name.clone(),
            provider: dep.provider.clone(),
            upstream_format: dep.upstream_format.as_str(),
            check: dep.health_check.as_str(),
            healthy: false,
            status: None,
            latency_ms: 0,
            detail: None,
        };

        let extra = self.extra_headers(&dep.extra, &dep.model_name);
        let request = match build_check_request(dep, extra) {
            Ok(Some(r)) => r,
            Ok(None) => {
                // No check configured: report as healthy-by-assumption.
                report.healthy = true;
                report.detail = Some("no health check configured".into());
                return report;
            }
            Err(detail) => {
                report.detail = Some(detail);
                return report;
            }
        };

        match tokio::time::timeout(CHECK_TIMEOUT, self.client.send(request)).await {
            Ok(Ok(resp)) => {
                report.status = Some(resp.status);
                report.healthy = (200..300).contains(&resp.status);
                if !report.healthy {
                    let msg = read_body_message(resp.body).await;
                    report.detail = Some(msg.chars().take(300).collect());
                }
            }
            Ok(Err(e)) => report.detail = Some(format!("transport: {e}")),
            Err(_) => {
                report.detail =
                    Some(format!("timed out after {}s", CHECK_TIMEOUT.as_secs()))
            }
        }
        report.latency_ms = started.elapsed().as_millis() as u64;
        report
    }

    /// Run the configured health check for every live deployment, concurrently.
    pub async fn check_deployments(&self, deps: &[DeploymentRecord]) -> Vec<HealthReport> {
        futures::future::join_all(deps.iter().map(|d| self.check_deployment(d))).await
    }
}

/// Build the request a deployment's check performs, or `Ok(None)` when no check
/// is configured. `Err` carries a configuration problem (reported unhealthy).
fn build_check_request(
    dep: &DeploymentRecord,
    extra: Vec<(String, String)>,
) -> std::result::Result<Option<UpstreamRequest>, String> {
    let api_key = dep.api_key.clone().unwrap_or_default();
    let mut auth = match dep.upstream_format {
        UpstreamFormat::Chat(f) => auth_headers(f, &api_key),
        UpstreamFormat::Embed(f) => embed_auth_headers(f, &api_key),
    };
    // Edge headers (e.g. Cloudflare Access) apply to every check method — a
    // backend behind Zero Trust 403s the probe otherwise.
    yb_providers::append_headers(&mut auth, extra);

    match dep.health_check {
        HealthCheck::None => Ok(None),

        HealthCheck::HttpOk => {
            let url = match dep.health_path.as_deref() {
                Some(p) if p.starts_with("http://") || p.starts_with("https://") => p.to_string(),
                other => {
                    let base = dep
                        .api_base
                        .as_deref()
                        .ok_or_else(|| "http_ok needs api_base or an absolute health_path".to_string())?;
                    format!("{}{}", origin_of(base), other.unwrap_or("/"))
                }
            };
            Ok(Some(UpstreamRequest {
                url,
                method: HttpMethod::Get,
                headers: auth,
                body: Vec::new(),
                stream: false,
            }))
        }

        HealthCheck::ModelsList => {
            let url = models_list_url(dep)?;
            Ok(Some(UpstreamRequest {
                url,
                method: HttpMethod::Get,
                headers: auth,
                body: Vec::new(),
                stream: false,
            }))
        }

        HealthCheck::Probe => {
            let (url, body, mut headers) = match dep.upstream_format {
                UpstreamFormat::Chat(f) => {
                    let req = probe_chat_request(&dep.upstream_model);
                    let (body, headers) = wire::emit_request(
                        f,
                        &req,
                        &EmitOptions::new(dep.upstream_model.clone()),
                    )
                    .map_err(|e| format!("probe emit: {e}"))?;
                    let url = build_url(f, dep.api_base.as_deref(), &dep.upstream_model, false);
                    (url, body, headers)
                }
                UpstreamFormat::Embed(f) => {
                    let req = probe_embed_request(&dep.upstream_model);
                    let (body, headers) = wire::emit_embed_request(
                        f,
                        &req,
                        &EmbedEmitOptions::new(dep.upstream_model.clone()),
                    )
                    .map_err(|e| format!("probe emit: {e}"))?;
                    let url = build_embed_url(f, dep.api_base.as_deref(), &dep.upstream_model);
                    (url, body, headers)
                }
            };
            headers.extend(auth);
            Ok(Some(UpstreamRequest {
                url,
                method: HttpMethod::Post,
                headers,
                body,
                stream: false,
            }))
        }
    }
}

/// A minimal 1-token chat turn for `probe` checks on chat deployments.
fn probe_chat_request(model: &str) -> yb_wire::ChatRequest {
    let mut req = yb_wire::ChatRequest {
        model: model.to_string(),
        max_tokens: Some(1),
        ..Default::default()
    };
    req.messages.push(yb_wire::Message::new(
        yb_wire::Role::User,
        vec![yb_wire::ContentBlock::text("ping")],
    ));
    req
}

/// A minimal single-text embedding for `probe` checks on embed deployments.
fn probe_embed_request(model: &str) -> EmbedRequest {
    EmbedRequest {
        model: model.to_string(),
        inputs: vec![EmbedInput::text("ping")],
        input_type: None,
        output_dimensions: None,
        truncate: None,
        encoding_format: None,
        cohere_embedding_types: None,
        gemini_batch: false,
    }
}

/// The model-listing URL for a backend family, with the same version-dedup join
/// semantics as request URLs.
///
/// Takes the format and base rather than a whole deployment, because provider
/// model-discovery calls it before any deployment exists.
pub fn models_list_url_for(
    fmt: UpstreamFormat,
    api_base: Option<&str>,
) -> std::result::Result<String, String> {
    let (default_base, version, endpoint) = match fmt {
        UpstreamFormat::Chat(WireFormat::Anthropic) => ("https://api.anthropic.com", "v1", "models"),
        UpstreamFormat::Chat(WireFormat::OpenaiChat | WireFormat::OpenaiResponses)
        | UpstreamFormat::Embed(EmbedFormat::OpenaiEmbed) => {
            ("https://api.openai.com", "v1", "models")
        }
        UpstreamFormat::Chat(WireFormat::Gemini) | UpstreamFormat::Embed(EmbedFormat::GeminiEmbed) => {
            ("https://generativelanguage.googleapis.com", "v1beta", "models")
        }
        UpstreamFormat::Embed(EmbedFormat::CohereEmbed) => ("https://api.cohere.com", "v1", "models"),
        UpstreamFormat::Embed(EmbedFormat::OllamaEmbed) => ("http://localhost:11434", "api", "tags"),
        UpstreamFormat::Embed(EmbedFormat::VoyageEmbed) => {
            return Err(
                "voyage has no model-listing endpoint; use http_ok or probe".to_string()
            )
        }
    };
    let base = api_base.unwrap_or(default_base);
    let base = base.strip_suffix('/').unwrap_or(base);
    Ok(if base == version || base.ends_with(&format!("/{version}")) {
        format!("{base}/{endpoint}")
    } else {
        format!("{base}/{version}/{endpoint}")
    })
}

/// Back-compat shim for the health path, which has a deployment in hand.
fn models_list_url(dep: &DeploymentRecord) -> std::result::Result<String, String> {
    models_list_url_for(dep.upstream_format, dep.api_base.as_deref())
}

/// The `scheme://host[:port]` origin of a URL (path stripped).
fn origin_of(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(slash) = rest.find('/') {
            return url[..scheme_end + 3 + slash].to_string();
        }
    }
    url.strip_suffix('/').unwrap_or(url).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use yb_core::EmbedFormat;

    fn dep(fmt: UpstreamFormat, base: Option<&str>, check: HealthCheck, path: Option<&str>) -> DeploymentRecord {
        DeploymentRecord {
            id: "d1".into(),
            model_id: "m1".into(),
            provider_id: "p1".into(),
            model_name: "m".into(),
            provider: "p".into(),
            upstream_model: "um".into(),
            api_base: base.map(str::to_string),
            api_key: Some("k".into()),
            upstream_format: fmt,
            weight: 1,
            pricing: None,
            health_check: check,
            health_path: path.map(str::to_string),
            extra: Default::default(),
            created_at: yb_core::now(),
            updated_at: yb_core::now(),
            deleted_at: None,
        }
    }

    #[test]
    fn http_ok_joins_origin() {
        let d = dep(
            WireFormat::OpenaiChat.into(),
            Some("http://host:8000/v1"),
            HealthCheck::HttpOk,
            Some("/health"),
        );
        let r = build_check_request(&d, Vec::new()).unwrap().unwrap();
        assert_eq!(r.url, "http://host:8000/health");
        assert_eq!(r.method, HttpMethod::Get);
    }

    #[test]
    fn models_list_urls_per_family() {
        let d = dep(WireFormat::OpenaiChat.into(), Some("http://host:8000/v1"), HealthCheck::ModelsList, None);
        assert_eq!(build_check_request(&d, Vec::new()).unwrap().unwrap().url, "http://host:8000/v1/models");
        let d = dep(EmbedFormat::OllamaEmbed.into(), Some("http://host:11434"), HealthCheck::ModelsList, None);
        assert_eq!(build_check_request(&d, Vec::new()).unwrap().unwrap().url, "http://host:11434/api/tags");
        let d = dep(EmbedFormat::VoyageEmbed.into(), None, HealthCheck::ModelsList, None);
        assert!(build_check_request(&d, Vec::new()).is_err());
    }

    #[test]
    fn probe_builds_dialect_request() {
        let d = dep(WireFormat::Anthropic.into(), None, HealthCheck::Probe, None);
        let r = build_check_request(&d, Vec::new()).unwrap().unwrap();
        assert_eq!(r.url, "https://api.anthropic.com/v1/messages");
        assert_eq!(r.method, HttpMethod::Post);
        assert!(!r.body.is_empty());
        let d = dep(EmbedFormat::CohereEmbed.into(), None, HealthCheck::Probe, None);
        let r = build_check_request(&d, Vec::new()).unwrap().unwrap();
        assert_eq!(r.url, "https://api.cohere.com/v2/embed");
    }

    /// Edge headers must be present on every check shape, and must not displace
    /// the deployment's own upstream auth.
    #[test]
    fn extra_headers_reach_every_check_method() {
        let cf = vec![
            ("cf-access-client-id".to_string(), "cid".to_string()),
            ("cf-access-client-secret".to_string(), "sec".to_string()),
        ];
        let has_cf = |r: &UpstreamRequest| {
            r.headers.iter().any(|(k, v)| k == "cf-access-client-id" && v == "cid")
                && r.headers.iter().any(|(k, _)| k == "cf-access-client-secret")
        };

        let d = dep(WireFormat::OpenaiChat.into(), Some("http://h:8000/v1"), HealthCheck::HttpOk, Some("/health"));
        let r = build_check_request(&d, cf.clone()).unwrap().unwrap();
        assert!(has_cf(&r));
        assert!(r.headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer k"));

        let d = dep(WireFormat::OpenaiChat.into(), Some("http://h:8000/v1"), HealthCheck::ModelsList, None);
        assert!(has_cf(&build_check_request(&d, cf.clone()).unwrap().unwrap()));

        let d = dep(WireFormat::OpenaiChat.into(), Some("http://h:8000/v1"), HealthCheck::Probe, None);
        assert!(has_cf(&build_check_request(&d, cf).unwrap().unwrap()));
    }

    #[test]
    fn none_means_no_request() {
        let d = dep(WireFormat::OpenaiChat.into(), None, HealthCheck::None, None);
        assert!(build_check_request(&d, Vec::new()).unwrap().is_none());
    }
}

/// Parse a model-listing response into upstream model ids.
///
/// Each family answers in its own shape, so this mirrors [`models_list_url_for`]:
/// OpenAI-compatible and Anthropic return `{"data":[{"id":…}]}`; Gemini and
/// Cohere return `{"models":[{"name":…}]}`; Ollama returns `{"models":[{"name":…}]}`
/// from `/api/tags`. Gemini prefixes ids with `models/`, which is stripped so the
/// value matches what a request would send.
pub fn parse_models_list(fmt: UpstreamFormat, body: &[u8]) -> std::result::Result<Vec<String>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("upstream returned invalid JSON: {e}"))?;
    let mut out = Vec::new();
    let (key, field) = match fmt {
        UpstreamFormat::Chat(WireFormat::Gemini) | UpstreamFormat::Embed(EmbedFormat::GeminiEmbed) => {
            ("models", "name")
        }
        UpstreamFormat::Embed(EmbedFormat::CohereEmbed | EmbedFormat::OllamaEmbed) => {
            ("models", "name")
        }
        _ => ("data", "id"),
    };
    let Some(items) = v.get(key).and_then(|d| d.as_array()) else {
        return Err(format!("upstream response has no `{key}` array"));
    };
    for item in items {
        if let Some(id) = item.get(field).and_then(|s| s.as_str()) {
            // Gemini reports `models/gemini-1.5-pro`; requests send the bare id.
            out.push(id.strip_prefix("models/").unwrap_or(id).to_string());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use yb_core::routing::{EmbedFormat, WireFormat};

    #[test]
    fn parses_each_family_response_shape() {
        // OpenAI-compatible and Anthropic: {"data":[{"id":…}]}
        let openai = br#"{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"}]}"#;
        assert_eq!(
            parse_models_list(WireFormat::OpenaiChat.into(), openai).unwrap(),
            vec!["gpt-4o", "gpt-4o-mini"]
        );
        let anthropic = br#"{"data":[{"id":"claude-sonnet-4"}]}"#;
        assert_eq!(
            parse_models_list(WireFormat::Anthropic.into(), anthropic).unwrap(),
            vec!["claude-sonnet-4"]
        );

        // Gemini: {"models":[{"name":"models/…"}]} — the prefix is stripped so
        // the value matches what a request actually sends.
        let gemini = br#"{"models":[{"name":"models/gemini-2.0-flash"}]}"#;
        assert_eq!(
            parse_models_list(WireFormat::Gemini.into(), gemini).unwrap(),
            vec!["gemini-2.0-flash"]
        );

        // Ollama's /api/tags.
        let ollama = br#"{"models":[{"name":"llama3"},{"name":"nomic-embed-text"}]}"#;
        assert_eq!(
            parse_models_list(EmbedFormat::OllamaEmbed.into(), ollama).unwrap(),
            vec!["llama3", "nomic-embed-text"]
        );
    }

    #[test]
    fn results_are_sorted_and_deduped() {
        let body = br#"{"data":[{"id":"b"},{"id":"a"},{"id":"b"}]}"#;
        assert_eq!(
            parse_models_list(WireFormat::OpenaiChat.into(), body).unwrap(),
            vec!["a", "b"]
        );
    }

    /// A wrong-shaped or non-JSON body is a clear error, not an empty list —
    /// "the endpoint serves nothing" and "we could not read the reply" must not
    /// look the same in the console.
    #[test]
    fn a_bad_body_is_an_error_not_an_empty_list() {
        assert!(parse_models_list(WireFormat::OpenaiChat.into(), b"not json").is_err());
        let wrong_shape = br#"{"models":[{"name":"x"}]}"#;
        assert!(parse_models_list(WireFormat::OpenaiChat.into(), wrong_shape).is_err());
    }

    /// Voyage has no listing endpoint, so discovery must say so rather than
    /// inventing a URL that 404s.
    #[test]
    fn voyage_has_no_listing_endpoint() {
        let err = models_list_url_for(EmbedFormat::VoyageEmbed.into(), None).unwrap_err();
        assert!(err.contains("no model-listing endpoint"), "{err}");
    }

    #[test]
    fn listing_url_joins_without_duplicating_the_version() {
        assert_eq!(
            models_list_url_for(WireFormat::OpenaiChat.into(), Some("http://host:8000/v1")).unwrap(),
            "http://host:8000/v1/models"
        );
        assert_eq!(
            models_list_url_for(WireFormat::OpenaiChat.into(), Some("http://host:8000")).unwrap(),
            "http://host:8000/v1/models"
        );
        assert_eq!(
            models_list_url_for(WireFormat::OpenaiChat.into(), None).unwrap(),
            "https://api.openai.com/v1/models"
        );
    }
}
