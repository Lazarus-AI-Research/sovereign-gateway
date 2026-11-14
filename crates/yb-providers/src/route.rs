//! URL and auth-header construction per [`WireFormat`], plus HTTP status
//! classifiers used to drive failover.
//!
//! This module is the only place in the crate with vendor-specific knowledge,
//! and even that is purely mechanical (endpoint paths, auth header names). All
//! payload shaping happens in `yb-wire`.

use yb_core::{DecisionFormat, EmbedFormat, WireFormat};

/// Default API bases per vendor (without a version segment — `build_url` adds it).
const ANTHROPIC_BASE: &str = "https://api.anthropic.com";
const OPENAI_BASE: &str = "https://api.openai.com";
const GEMINI_BASE: &str = "https://generativelanguage.googleapis.com";
const COHERE_BASE: &str = "https://api.cohere.com";
const VOYAGE_BASE: &str = "https://api.voyageai.com";
const OLLAMA_BASE: &str = "http://localhost:11434";

/// The `anthropic-version` value we pin for the Messages API.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Joins `endpoint` below `base`, inserting `default_version` (e.g. `"v1"`,
/// `"v1beta"`, `"v2"`, `"api"`) only when `base`'s URL path does not already
/// end in `default_version` or an explicit version segment (`/v<digits>[alpha|beta]`).
///
/// Inspecting the URL *path* (after `scheme://host`) ensures hostnames like
/// `http://v2:8000` still receive `/v1/...`, while custom versioned bases like
/// `https://api.z.ai/api/paas/v4` join directly to `.../v4/chat/completions`
/// rather than `.../v4/v1/chat/completions`.
pub fn join_versioned_endpoint(base: &str, default_version: &str, endpoint: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = match base.find("://") {
        Some(idx) => match base[idx + 3..].find('/') {
            Some(slash) => &base[idx + 3 + slash + 1..],
            None => "",
        },
        None => base.strip_prefix('/').unwrap_or(base),
    };
    let last_seg = path.rsplit('/').next().unwrap_or("");
    if last_seg == default_version || is_explicit_version_segment(last_seg) {
        format!("{base}/{endpoint}")
    } else {
        format!("{base}/{default_version}/{endpoint}")
    }
}

fn is_explicit_version_segment(seg: &str) -> bool {
    let Some(rest) = seg.strip_prefix('v') else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return false;
    }
    matches!(&rest[digits..], "" | "alpha" | "beta")
}

/// Builds the upstream request URL for a deployment, keyed on the **upstream
/// wire format** (so an OpenAI *Responses* deployment targets `/responses`, not
/// `/chat/completions`).
///
/// A configured `api_base` is the model's own base URL. It may or may not
/// already include a version segment (`/v1`, `/v1beta`, `/v4`, …) — both styles
/// are supported via [`join_versioned_endpoint`].
///
/// `stream` only changes the URL for Gemini (a distinct `:streamGenerateContent`
/// action with `alt=sse`); Anthropic and OpenAI carry the stream toggle in the
/// body and the Responses API streams from the same `/responses` path.
pub fn build_url(
    fmt: WireFormat,
    api_base: Option<&str>,
    upstream_model: &str,
    stream: bool,
) -> String {
    let (default_base, version, endpoint) = match fmt {
        WireFormat::Anthropic => (ANTHROPIC_BASE, "v1", "messages".to_string()),
        WireFormat::OpenaiChat => (OPENAI_BASE, "v1", "chat/completions".to_string()),
        WireFormat::OpenaiResponses => (OPENAI_BASE, "v1", "responses".to_string()),
        WireFormat::Gemini => {
            let action = if stream {
                format!("{upstream_model}:streamGenerateContent?alt=sse")
            } else {
                format!("{upstream_model}:generateContent")
            };
            (GEMINI_BASE, "v1beta", format!("models/{action}"))
        }
    };

    join_versioned_endpoint(api_base.unwrap_or(default_base), version, &endpoint)
}

/// Builds the upstream request URL for an **embeddings** deployment. Embeddings
/// never stream, so there is no stream toggle. Version-segment dedup works the
/// same as [`build_url`].
pub fn build_embed_url(fmt: EmbedFormat, api_base: Option<&str>, upstream_model: &str) -> String {
    let (default_base, version, endpoint) = match fmt {
        EmbedFormat::OpenaiEmbed => (OPENAI_BASE, "v1", "embeddings".to_string()),
        EmbedFormat::GeminiEmbed => (
            GEMINI_BASE,
            "v1beta",
            format!("models/{upstream_model}:batchEmbedContents"),
        ),
        EmbedFormat::CohereEmbed => (COHERE_BASE, "v2", "embed".to_string()),
        EmbedFormat::VoyageEmbed => (VOYAGE_BASE, "v1", "multimodalembeddings".to_string()),
        EmbedFormat::OllamaEmbed => (OLLAMA_BASE, "api", "embed".to_string()),
    };

    join_versioned_endpoint(api_base.unwrap_or(default_base), version, &endpoint)
}

/// Builds the upstream request URL for a **decision / SystemOne** deployment
/// (`POST /v1/systemone` for `jev`, `POST /v1/decisions` for `decisions`).
pub fn build_decision_url(fmt: DecisionFormat, api_base: Option<&str>) -> String {
    join_versioned_endpoint(api_base.unwrap_or(OPENAI_BASE), "v1", fmt.path())
}

/// The URL of an OpenAI media endpoint below a deployment's base, with the same
/// `/v1` handling as the other OpenAI-compatible URLs.
pub fn build_media_url(fmt: yb_core::MediaFormat, api_base: Option<&str>) -> String {
    join_versioned_endpoint(api_base.unwrap_or(OPENAI_BASE), "v1", fmt.path())
}

/// The prefix that makes a stored upstream key a reference to an environment
/// variable rather than the secret itself.
pub const ENVIRONMENT_REFERENCE: &str = "env:";

/// The upstream secret a stored key stands for: `env:NAME` reads `NAME` from
/// the gateway's environment, so an operator can hand a secret to the
/// process without writing it into the database; anything else is the secret
/// itself. An unset variable is an empty key, which the upstream refuses.
pub fn upstream_secret(api_key: &str) -> String {
    match api_key.strip_prefix(ENVIRONMENT_REFERENCE) {
        Some(name) => std::env::var(name).unwrap_or_else(|_| {
            tracing::warn!(
                variable = name,
                "an upstream key names an unset environment variable"
            );
            String::new()
        }),
        None => api_key.to_string(),
    }
}

/// Builds the vendor-specific authentication headers for a wire format.
///
/// - Anthropic: `x-api-key` plus the required `anthropic-version` pin.
/// - OpenAI (chat or responses): `Authorization: Bearer <key>`.
/// - Gemini: `x-goog-api-key`.
///
/// `Content-Type` and any payload headers are the emitter's responsibility, not
/// this function's.
pub fn auth_headers(fmt: WireFormat, api_key: &str) -> Vec<(String, String)> {
    let api_key = &upstream_secret(api_key);
    match fmt {
        WireFormat::Anthropic => vec![
            ("x-api-key".to_string(), api_key.to_string()),
            (
                "anthropic-version".to_string(),
                ANTHROPIC_VERSION.to_string(),
            ),
        ],
        WireFormat::OpenaiChat | WireFormat::OpenaiResponses => {
            vec![("authorization".to_string(), format!("Bearer {api_key}"))]
        }
        WireFormat::Gemini => {
            vec![("x-goog-api-key".to_string(), api_key.to_string())]
        }
    }
}

/// Builds the vendor-specific authentication headers for an embeddings format.
///
/// - Gemini: `x-goog-api-key`.
/// - OpenAI / Cohere / Voyage: `Authorization: Bearer <key>`.
/// - Ollama: bare Ollama has no auth — the Bearer header is sent only when a
///   key is configured (e.g. for a proxy in front).
pub fn embed_auth_headers(fmt: EmbedFormat, api_key: &str) -> Vec<(String, String)> {
    let api_key = &upstream_secret(api_key);
    match fmt {
        EmbedFormat::GeminiEmbed => {
            vec![("x-goog-api-key".to_string(), api_key.to_string())]
        }
        EmbedFormat::OllamaEmbed if api_key.is_empty() => vec![],
        _ => vec![("authorization".to_string(), format!("Bearer {api_key}"))],
    }
}

/// The authentication header for SystemOne (`jev`) and Decisions endpoints:
/// `Authorization: Bearer <key>` when a key is configured.
pub fn decision_auth_headers(api_key: &str) -> Vec<(String, String)> {
    let secret = upstream_secret(api_key);
    if secret.is_empty() {
        Vec::new()
    } else {
        vec![("authorization".to_string(), format!("Bearer {secret}"))]
    }
}

/// The authentication header for OpenAI's image, speech and transcription
/// endpoints: `Authorization: Bearer <key>`.
pub fn media_auth_headers(api_key: &str) -> Vec<(String, String)> {
    vec![(
        "authorization".to_string(),
        format!("Bearer {}", upstream_secret(api_key)),
    )]
}

/// The Cloudflare Access service-token header pair.
///
/// Cloudflare Zero Trust fronts an origin and rejects unauthenticated traffic at
/// the edge with a `403`. A *service token* — a client id and secret issued by
/// Cloudflare — is presented in these two headers so machine-to-machine calls
/// satisfy the application policy.
///
/// This is edge auth and is **orthogonal** to the deployment's own upstream
/// credential: both are sent, and the origin still applies its own auth (a vLLM
/// server behind Access still wants its `Authorization: Bearer …`).
pub fn cloudflare_access_headers(client_id: &str, client_secret: &str) -> Vec<(String, String)> {
    vec![
        ("cf-access-client-id".to_string(), client_id.to_string()),
        (
            "cf-access-client-secret".to_string(),
            client_secret.to_string(),
        ),
    ]
}

/// Append `extra` to `headers`, skipping any header whose name is already
/// present (compared case-insensitively).
///
/// The skip is the point: extras are attacker-adjacent in a way auth is not —
/// they come from a database row an admin can edit, while the wire-format auth
/// headers and the Cloudflare service token come from the deployment's own
/// credential and from `gateway.toml`. Appending blindly would let a row inject
/// a second `authorization` (ambiguous to the origin) or a forged
/// `cf-access-client-id`. First writer wins, so callers should push in order of
/// decreasing authority: wire auth, then the file-owned service token, then the
/// deployment's literal headers.
pub fn append_headers(headers: &mut Vec<(String, String)>, extra: Vec<(String, String)>) {
    for (name, value) in extra {
        let dup = headers
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(&name));
        if !dup {
            headers.push((name, value));
        }
    }
}

/// Whether an upstream HTTP `status` is worth retrying on the next candidate.
///
/// Covers transient server-side and back-pressure conditions: any 5xx, plus
/// `408 Request Timeout` and `429 Too Many Requests`.
pub fn is_retryable(status: u16) -> bool {
    status >= 500 || status == 408 || status == 429
}

/// Whether an upstream HTTP `status` indicates the requested model is unknown to
/// this deployment (`404 Not Found`), which should trigger failover to the next
/// candidate rather than a hard error.
pub fn is_model_not_found(status: u16) -> bool {
    status == 404
}

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn joins_versioned_and_unversioned_bases_cleanly() {
        assert_eq!(
            build_url(
                WireFormat::OpenaiChat,
                Some("https://api.z.ai/api/paas/v4"),
                "glm-5",
                false
            ),
            "https://api.z.ai/api/paas/v4/chat/completions"
        );
        assert_eq!(
            build_url(
                WireFormat::Anthropic,
                Some("https://api.z.ai/api/anthropic"),
                "glm-5",
                false
            ),
            "https://api.z.ai/api/anthropic/v1/messages"
        );
        assert_eq!(
            build_url(WireFormat::OpenaiChat, Some("http://v2:8000"), "m", false),
            "http://v2:8000/v1/chat/completions"
        );
        assert_eq!(
            build_decision_url(DecisionFormat::Jev, Some("https://cluster.example/v1/")),
            "https://cluster.example/v1/systemone"
        );
        assert_eq!(
            build_decision_url(DecisionFormat::Decisions, Some("https://cluster.example")),
            "https://cluster.example/v1/decisions"
        );
    }
}
