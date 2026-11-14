//! Routing: the LiteLLM-style model→deployment contract (no ML).

use crate::catalog::ModelPrice;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The wire protocol a **chat** surface or upstream speaks. Chat and embedding
/// formats are disjoint types — there is no translation between them — so this
/// enum never carries an embedding dialect (see [`EmbedFormat`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireFormat {
    Anthropic,
    OpenaiChat,
    OpenaiResponses,
    Gemini,
}

impl WireFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            WireFormat::Anthropic => "anthropic",
            WireFormat::OpenaiChat => "openai_chat",
            WireFormat::OpenaiResponses => "openai_responses",
            WireFormat::Gemini => "gemini",
        }
    }

    /// Every chat shape, in the order the console lists them.
    pub const ALL: [WireFormat; 4] = [
        WireFormat::Anthropic,
        WireFormat::OpenaiChat,
        WireFormat::OpenaiResponses,
        WireFormat::Gemini,
    ];

    /// Parse a shape name (`anthropic`, `openai_chat`, …).
    pub fn parse(s: &str) -> Option<WireFormat> {
        WireFormat::ALL.into_iter().find(|f| f.as_str() == s)
    }
}

/// One API shape a provider serves natively, with the base URL it is served
/// under when that differs from the provider's `api_base` (for example, a
/// provider serving `/v1/messages` at `.../api/anthropic` and
/// `/v1/chat/completions` at `.../api/paas/v4`).
///
/// A request whose shape the chosen deployment serves natively is relayed as
/// the client sent it — only the model id and credentials change — rather than
/// translated through an IR; translation within a family (chat, embeddings, or
/// decision) is the fallback for shapes the deployment does not serve directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderShape {
    pub format: UpstreamFormat,
    /// `None` (or blank): falls back to the provider's `api_base`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,
}

/// The wire protocol an **embeddings** surface or upstream speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbedFormat {
    /// OpenAI `POST /v1/embeddings` — also vLLM, TEI, LiteLLM, Jina (incl. its
    /// multimodal `[{text}|{image}]` inputs), Voyage's text endpoint, etc.
    OpenaiEmbed,
    /// Gemini `:embedContent` / `:batchEmbedContents`.
    GeminiEmbed,
    /// Cohere `POST /v2/embed` (text, image, and multimodal `inputs`).
    CohereEmbed,
    /// Voyage `POST /v1/multimodalembeddings` (interleaved text+image).
    VoyageEmbed,
    /// Ollama `POST /api/embed` (upstream only; no inbound surface).
    OllamaEmbed,
}

impl EmbedFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            EmbedFormat::OpenaiEmbed => "openai_embed",
            EmbedFormat::GeminiEmbed => "gemini_embed",
            EmbedFormat::CohereEmbed => "cohere_embed",
            EmbedFormat::VoyageEmbed => "voyage_embed",
            EmbedFormat::OllamaEmbed => "ollama_embed",
        }
    }

    pub const ALL: [EmbedFormat; 5] = [
        EmbedFormat::OpenaiEmbed,
        EmbedFormat::GeminiEmbed,
        EmbedFormat::CohereEmbed,
        EmbedFormat::VoyageEmbed,
        EmbedFormat::OllamaEmbed,
    ];
}

/// The wire protocol a **decision / SystemOne** surface or upstream speaks:
/// single-forward-pass structured logit probing (`max_tokens = 0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionFormat {
    /// SystemOne (`POST /v1/systemone`, `"object": "systemone"`).
    Jev,
    /// OpenAI / LiteLLM Decisions (`POST /v1/decisions`, `"object": "decision"`).
    Decisions,
}

impl DecisionFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            DecisionFormat::Jev => "jev",
            DecisionFormat::Decisions => "decisions",
        }
    }

    /// Endpoint path segment below `/v1`.
    pub fn path(self) -> &'static str {
        match self {
            DecisionFormat::Jev => "systemone",
            DecisionFormat::Decisions => "decisions",
        }
    }

    /// The sibling decision surface, for lossless envelope translation when an
    /// upstream serves one decision shape and the client called the other.
    pub fn other(self) -> Self {
        match self {
            DecisionFormat::Jev => DecisionFormat::Decisions,
            DecisionFormat::Decisions => DecisionFormat::Jev,
        }
    }

    pub const ALL: [DecisionFormat; 2] = [DecisionFormat::Jev, DecisionFormat::Decisions];
}

/// The protocol a **media** surface or upstream speaks: OpenAI's image
/// generation, speech, transcription and video endpoints. Nothing is
/// translated: the gateway reads the model to route and forwards the request
/// as it came.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaFormat {
    /// `POST /v1/images/generations`, JSON in and out.
    OpenaiImages,
    /// `POST /v1/audio/speech`, JSON in, audio bytes out.
    OpenaiSpeech,
    /// `POST /v1/audio/transcriptions`, multipart form in, JSON out.
    OpenaiTranscription,
    /// `POST /v1/videos`, JSON in and out: a video is made as a job, asked
    /// after, fetched and deleted by its id under the same path.
    OpenaiVideos,
}

impl MediaFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            MediaFormat::OpenaiImages => "openai_images",
            MediaFormat::OpenaiSpeech => "openai_speech",
            MediaFormat::OpenaiTranscription => "openai_transcription",
            MediaFormat::OpenaiVideos => "openai_videos",
        }
    }

    /// The endpoint below an OpenAI-compatible `/v1` base.
    pub fn path(self) -> &'static str {
        match self {
            MediaFormat::OpenaiImages => "images/generations",
            MediaFormat::OpenaiSpeech => "audio/speech",
            MediaFormat::OpenaiTranscription => "audio/transcriptions",
            MediaFormat::OpenaiVideos => "videos",
        }
    }
}

/// What a provider or deployment speaks upstream: chat, embeddings, decision,
/// or media. Untagged serde over disjoint snake_case string sets, so config,
/// DB, and admin JSON carry flat strings (`"openai_chat"`, `"openai_embed"`,
/// `"jev"`, `"decisions"`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpstreamFormat {
    Chat(WireFormat),
    Embed(EmbedFormat),
    Decision(DecisionFormat),
    Media(MediaFormat),
}

impl UpstreamFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            UpstreamFormat::Chat(f) => f.as_str(),
            UpstreamFormat::Embed(f) => f.as_str(),
            UpstreamFormat::Decision(f) => f.as_str(),
            UpstreamFormat::Media(f) => f.as_str(),
        }
    }
}

impl From<MediaFormat> for UpstreamFormat {
    fn from(f: MediaFormat) -> Self {
        UpstreamFormat::Media(f)
    }
}

impl From<WireFormat> for UpstreamFormat {
    fn from(f: WireFormat) -> Self {
        UpstreamFormat::Chat(f)
    }
}

impl From<EmbedFormat> for UpstreamFormat {
    fn from(f: EmbedFormat) -> Self {
        UpstreamFormat::Embed(f)
    }
}

impl From<DecisionFormat> for UpstreamFormat {
    fn from(f: DecisionFormat) -> Self {
        UpstreamFormat::Decision(f)
    }
}

/// Choose a deterministic primary `upstream_format` from a list of enabled
/// shapes when a caller omits `upstream_format` (preferring `openai_chat`, then
/// the first chat shape, then the first shape).
pub fn default_upstream_format(shapes: &[UpstreamFormat]) -> Option<UpstreamFormat> {
    if shapes.contains(&UpstreamFormat::Chat(WireFormat::OpenaiChat)) {
        return Some(UpstreamFormat::Chat(WireFormat::OpenaiChat));
    }
    if let Some(&chat) = shapes.iter().find(|f| matches!(f, UpstreamFormat::Chat(_))) {
        return Some(chat);
    }
    shapes.first().copied()
}

/// How to health-check a deployment's backend. Chosen **independently** of the
/// wire format: the same OpenAI-compat deployment might use `http_ok` against
/// vLLM's `/health`, `models_list` against a SaaS `/v1/models`, or a real
/// 1-token `probe` — whatever the operator trusts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheck {
    /// No health check configured (the default).
    #[default]
    None,
    /// GET a URL and require a 2xx. Uses `health_path` — absolute, or relative
    /// to the origin of `api_base` (e.g. `/health` on a vLLM host).
    HttpOk,
    /// GET the backend's model-listing endpoint with the deployment's auth.
    ModelsList,
    /// Send a minimal real request in the deployment's wire format
    /// (1-token chat turn, or a tiny embedding).
    Probe,
}

impl HealthCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthCheck::None => "none",
            HealthCheck::HttpOk => "http_ok",
            HealthCheck::ModelsList => "models_list",
            HealthCheck::Probe => "probe",
        }
    }
}

/// Open-ended per-deployment extras: a `string → value` JSON object stored on
/// the deployment row, so new knobs are additive and need no migration.
///
/// Three keys are understood today:
///
/// - `cloudflare_access` (bool) — present the Cloudflare Access service token so
///   the request passes a Zero Trust edge policy. The flag only selects *which*
///   credential to send; the credential itself lives in `gateway.toml`
///   (`[upstream.cloudflare_access]`), is immutable at runtime, and is never
///   stored here, returned by the admin API, or editable in the UI.
/// - `headers` (string map) — literal request headers to add.
/// - `vision` (bool) — the models this provider serves take images as input;
///   model discovery says so, so a caller can pick a vision model without
///   trying one.
///
/// Any other key is preserved verbatim, so a value written by a newer build
/// survives a round-trip through an older one.
///
/// ```toml
/// extra = { cloudflare_access = true, headers = { "X-Tenant" = "acme" } }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Extra {
    /// Send the `CF-Access-Client-Id` / `CF-Access-Client-Secret` service-token
    /// pair from `[upstream.cloudflare_access]`.
    pub cloudflare_access: bool,
    /// Literal headers to add to every upstream call for this deployment. These
    /// are applied *last* and never displace auth (see `append_headers`).
    pub headers: BTreeMap<String, String>,
    /// The models this provider serves take images as input.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub vision: bool,
    /// Keys this build does not interpret, kept so they round-trip intact.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

impl Extra {
    /// Whether nothing is set — the common case, stored as `{}`.
    pub fn is_empty(&self) -> bool {
        !self.cloudflare_access && self.headers.is_empty() && self.rest.is_empty()
    }
}

/// A public model: the entity a client names, an alias points at, and an access
/// policy references.
///
/// One model has N deployments (the load-balancing fan-out) and N aliases. The
/// `name` is the public string clients send on the wire and is mutable — see
/// `Store::rename_model`. `id` is what every other row stores, so a rename is a
/// single `UPDATE` and can never silently break a policy or an alias.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRecord {
    pub id: crate::ids::Id,
    pub name: String,
    pub created_at: crate::ids::Timestamp,
    pub updated_at: crate::ids::Timestamp,
}

/// The last health-check result recorded for a deployment.
///
/// Cached so the console can colour a status bubble on load without calling
/// every upstream — an on-demand check is an explicit click, not a page render.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthRecord {
    pub deployment_id: crate::ids::Id,
    pub healthy: bool,
    /// Which check produced this (`probe`, `http_ok`, …), so the console can
    /// say what was actually measured rather than implying a live call.
    pub check_kind: String,
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub detail: Option<String>,
    pub checked_at: crate::ids::Timestamp,
}

/// A provider: one upstream endpoint, its credentials, and the deployments
/// served through it.
///
/// `api_base` and `api_key` live here rather than on each deployment because
/// they describe the *endpoint*, not the binding — two models behind one OpenAI
/// account are one base and one key, not two copies of each. `extra` is the
/// same story: the Cloudflare Access flag and literal headers are edge concerns
/// of the endpoint.
///
/// `upstream_format` deliberately does **not** live here: one endpoint can
/// serve several wire formats (OpenAI serves `openai_chat` and `openai_embed`
/// from the same base), so the format belongs to the deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRecord {
    pub id: crate::ids::Id,
    pub name: String,
    pub api_base: Option<String>,
    /// The upstream credential. Never serialized back out.
    #[serde(default, skip_serializing)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub extra: Extra,
    /// The API shapes this endpoint serves natively (see [`ProviderShape`]),
    /// across chat, embeddings, decision/SystemOne, and media. Empty: legacy
    /// mode where each deployment serves its own `upstream_format`.
    #[serde(default)]
    pub shapes: Vec<ProviderShape>,
    pub created_at: crate::ids::Timestamp,
    pub updated_at: crate::ids::Timestamp,
}

impl ProviderRecord {
    /// Resolved `api_base` for `fmt` on this provider: the shape's own
    /// non-blank `api_base` if declared, otherwise the provider's `api_base`.
    pub fn base_for(&self, fmt: UpstreamFormat) -> Option<&str> {
        self.shapes
            .iter()
            .find(|s| s.format == fmt)
            .and_then(|s| s.api_base.as_deref().filter(|b| !b.trim().is_empty()))
            .or(self.api_base.as_deref())
    }
}

/// Resolve the effective `(format, api_base)` pairs served by a deployment.
///
/// - When `provider_shapes` is non-empty, it defines the ceiling of shapes the
///   provider supports (and each shape's `api_base`). `deployment_shapes = None`
///   inherits all of them; `Some(filter)` narrows to the subset in `filter`.
/// - When `provider_shapes` is empty (legacy provider with no checkboxes set),
///   `deployment_shapes = None` falls back to `[(upstream_format, api_base)]`.
pub fn resolve_effective_shapes<'a>(
    provider_shapes: &'a [ProviderShape],
    deployment_shapes: Option<&'a [UpstreamFormat]>,
    upstream_format: UpstreamFormat,
    api_base: Option<&'a str>,
) -> Vec<(UpstreamFormat, Option<&'a str>)> {
    let shape_base = |ps: &'a ProviderShape| -> Option<&'a str> {
        ps.api_base
            .as_deref()
            .filter(|b| !b.trim().is_empty())
            .or(api_base)
    };
    if !provider_shapes.is_empty() {
        match deployment_shapes {
            Some(filter) => provider_shapes
                .iter()
                .filter(|ps| filter.contains(&ps.format))
                .map(|ps| (ps.format, shape_base(ps)))
                .collect(),
            None => {
                if matches!(
                    upstream_format,
                    UpstreamFormat::Embed(_) | UpstreamFormat::Media(_)
                ) && !provider_shapes.iter().any(|ps| {
                    std::mem::discriminant(&ps.format) == std::mem::discriminant(&upstream_format)
                }) {
                    return vec![(upstream_format, api_base)];
                }
                provider_shapes
                    .iter()
                    .map(|ps| (ps.format, shape_base(ps)))
                    .collect()
            }
        }
    } else {
        match deployment_shapes {
            Some(filter) => filter.iter().map(|&f| (f, api_base)).collect(),
            None => vec![(upstream_format, api_base)],
        }
    }
}

/// The fields a caller supplies to create a deployment.
///
/// The model is **named**, not id'd: every producer of a new deployment — the
/// admin API body, the import file, a test — speaks the human name, and the
/// store resolves it to a model row (creating one if the name is new). Kept
/// distinct from [`DeploymentRecord`] so a write can never carry a `model_id`
/// and a `model_name` that disagree.
#[derive(Debug, Clone)]
pub struct NewDeployment {
    pub model_name: String,
    /// The provider is named, not id'd, for the same reason the model is: every
    /// producer speaks the human name and the store resolves it. `api_base`,
    /// `api_key` and `extra` are not here — they belong to the provider.
    pub provider_name: String,
    pub upstream_model: String,
    pub upstream_format: UpstreamFormat,
    /// Optional per-deployment shape subset (`None` = inherit all provider shapes).
    pub shapes: Option<Vec<UpstreamFormat>>,
    pub weight: u32,
    pub pricing: Option<ModelPrice>,
    pub health_check: HealthCheck,
    pub health_path: Option<String>,
}

/// One concrete upstream binding for a public model name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    /// The model this deployment backs. Stable across renames — everything
    /// internal (access policy, alias targets, dedupe) keys on this.
    pub model_id: crate::ids::Id,
    /// Public model name clients request (e.g. `gpt-4o`). Joined from
    /// `models.name`, so it follows a rename with no write here.
    pub model_name: String,
    /// The provider this deployment is served through. Stable across renames.
    pub provider_id: crate::ids::Id,
    /// The provider's current name (e.g. `openai`), joined at read time.
    pub provider: String,
    /// Model id sent upstream (may differ from `model_name`).
    pub upstream_model: String,
    pub api_base: Option<String>,
    /// The upstream provider api key, stored on the deployment. Never serialized
    /// back out (kept out of admin API responses).
    #[serde(default, skip_serializing)]
    pub api_key: Option<String>,
    /// Primary / fallback upstream format.
    pub upstream_format: UpstreamFormat,
    pub weight: u32,
    pub pricing: Option<ModelPrice>,
    /// How to health-check this backend (independent of `upstream_format`).
    #[serde(default)]
    pub health_check: HealthCheck,
    /// URL for `http_ok` checks: absolute, or relative to `api_base`'s origin.
    #[serde(default)]
    pub health_path: Option<String>,
    /// Open-ended per-deployment extras (see [`Extra`]).
    #[serde(default)]
    pub extra: Extra,
    /// Optional per-deployment shape filter (`None` = inherit all of
    /// `provider_shapes`).
    #[serde(default)]
    pub shapes: Option<Vec<UpstreamFormat>>,
    /// The provider's natively served API shapes, joined at read time.
    #[serde(default)]
    pub provider_shapes: Vec<ProviderShape>,
}

impl Deployment {
    /// Effective `(format, api_base)` pairs served by this deployment.
    pub fn effective_shapes(&self) -> Vec<(UpstreamFormat, Option<&str>)> {
        resolve_effective_shapes(
            &self.provider_shapes,
            self.shapes.as_deref(),
            self.upstream_format,
            self.api_base.as_deref(),
        )
    }

    /// The base URL to relay a `fmt`-shaped request to unchanged, if this
    /// deployment serves `fmt` natively.
    pub fn native_base(&self, fmt: impl Into<UpstreamFormat>) -> Option<Option<&str>> {
        let target = fmt.into();
        self.effective_shapes()
            .into_iter()
            .find(|(f, _)| *f == target)
            .map(|(_, b)| b)
    }

    /// Resolve how this deployment handles an inbound chat `surface`:
    /// `(target_wire_format, resolved_api_base, is_same_shape_relay)`.
    /// Returns `None` if this deployment serves no chat shapes at all.
    pub fn chat_target(&self, surface: WireFormat) -> Option<(WireFormat, Option<&str>, bool)> {
        let eff = self.effective_shapes();
        if let Some((_, base)) = eff
            .iter()
            .find(|(f, _)| *f == UpstreamFormat::Chat(surface))
        {
            return Some((surface, *base, true));
        }
        let chats: Vec<(WireFormat, Option<&str>)> = eff
            .into_iter()
            .filter_map(|(f, b)| match f {
                UpstreamFormat::Chat(w) => Some((w, b)),
                _ => None,
            })
            .collect();
        if chats.is_empty() {
            return None;
        }
        if let UpstreamFormat::Chat(own) = self.upstream_format {
            if let Some(&(_, base)) = chats.iter().find(|(w, _)| *w == own) {
                return Some((own, base, false));
            }
        }
        if let Some(&(_, base)) = chats.iter().find(|(w, _)| *w == WireFormat::OpenaiChat) {
            return Some((WireFormat::OpenaiChat, base, false));
        }
        let (w, base) = chats[0];
        Some((w, base, false))
    }

    /// Resolve how this deployment handles an inbound embedding `surface`:
    /// `(target_embed_format, resolved_api_base, is_same_shape)`.
    pub fn embed_target(&self, surface: EmbedFormat) -> Option<(EmbedFormat, Option<&str>, bool)> {
        let eff = self.effective_shapes();
        if let Some((_, base)) = eff
            .iter()
            .find(|(f, _)| *f == UpstreamFormat::Embed(surface))
        {
            return Some((surface, *base, true));
        }
        let embeds: Vec<(EmbedFormat, Option<&str>)> = eff
            .into_iter()
            .filter_map(|(f, b)| match f {
                UpstreamFormat::Embed(e) => Some((e, b)),
                _ => None,
            })
            .collect();
        if embeds.is_empty() {
            return None;
        }
        if let UpstreamFormat::Embed(own) = self.upstream_format {
            if let Some(&(_, base)) = embeds.iter().find(|(e, _)| *e == own) {
                return Some((own, base, false));
            }
        }
        let (e, base) = embeds[0];
        Some((e, base, false))
    }

    /// Resolve how this deployment handles an inbound decision `surface`:
    /// `(target_decision_format, resolved_api_base, is_same_shape_relay)`.
    pub fn decision_target(
        &self,
        surface: DecisionFormat,
    ) -> Option<(DecisionFormat, Option<&str>, bool)> {
        let eff = self.effective_shapes();
        if let Some((_, base)) = eff
            .iter()
            .find(|(f, _)| *f == UpstreamFormat::Decision(surface))
        {
            return Some((surface, *base, true));
        }
        let other = surface.other();
        if let Some((_, base)) = eff
            .iter()
            .find(|(f, _)| *f == UpstreamFormat::Decision(other))
        {
            return Some((other, *base, false));
        }
        None
    }
}

/// A persisted deployment row: the live model list lives in the database, so a
/// deployment carries an id and lifecycle timestamps. Convert with
/// [`DeploymentRecord::to_deployment`] for routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub id: crate::ids::Id,
    /// The model this deployment backs.
    pub model_id: crate::ids::Id,
    /// The model's current public name, joined from `models.name` at read time
    /// rather than stored here — which is what lets a rename be one `UPDATE`.
    pub model_name: String,
    /// The provider this deployment is served through.
    pub provider_id: crate::ids::Id,
    /// The provider's current name, joined from `providers.name` at read time.
    pub provider: String,
    pub upstream_model: String,
    pub api_base: Option<String>,
    /// The upstream provider api key. Never serialized back out (kept out of
    /// admin API responses).
    #[serde(default, skip_serializing)]
    pub api_key: Option<String>,
    pub upstream_format: UpstreamFormat,
    pub weight: u32,
    pub pricing: Option<ModelPrice>,
    #[serde(default)]
    pub health_check: HealthCheck,
    #[serde(default)]
    pub health_path: Option<String>,
    /// Open-ended per-deployment extras (see [`Extra`]).
    #[serde(default)]
    pub extra: Extra,
    /// Optional per-deployment shape subset (`None` = inherit all of
    /// `provider_shapes`).
    #[serde(default)]
    pub shapes: Option<Vec<UpstreamFormat>>,
    /// The provider's natively served API shapes, joined at read time.
    #[serde(default)]
    pub provider_shapes: Vec<ProviderShape>,
    pub created_at: crate::ids::Timestamp,
    pub updated_at: crate::ids::Timestamp,
    pub deleted_at: Option<crate::ids::Timestamp>,
}

impl DeploymentRecord {
    /// Effective `(format, api_base)` pairs served by this deployment record.
    pub fn effective_shapes(&self) -> Vec<(UpstreamFormat, Option<&str>)> {
        resolve_effective_shapes(
            &self.provider_shapes,
            self.shapes.as_deref(),
            self.upstream_format,
            self.api_base.as_deref(),
        )
    }

    /// Project the storage row onto the routing-time [`Deployment`] value.
    pub fn to_deployment(&self) -> Deployment {
        Deployment {
            model_id: self.model_id.clone(),
            model_name: self.model_name.clone(),
            provider_id: self.provider_id.clone(),
            provider: self.provider.clone(),
            upstream_model: self.upstream_model.clone(),
            api_base: self.api_base.clone(),
            api_key: self.api_key.clone(),
            upstream_format: self.upstream_format,
            weight: self.weight,
            pricing: self.pricing,
            health_check: self.health_check,
            health_path: self.health_path.clone(),
            extra: self.extra.clone(),
            shapes: self.shapes.clone(),
            provider_shapes: self.provider_shapes.clone(),
        }
    }
}

/// The pure-value description of an inbound turn used to resolve deployments.
#[derive(Debug, Clone, Default)]
pub struct RouteRequest {
    pub requested_model: String,
    pub estimated_input_tokens: u32,
    pub has_tools: bool,
    pub has_images: bool,
    /// Model ids excluded by installation/key/team policy. Ids, not names, so
    /// that renaming a model cannot silently stop a deny from matching.
    pub excluded_model_ids: BTreeSet<String>,
    /// If `Some`, only these provider **ids** are enabled (allowlist ceiling).
    pub enabled_provider_ids: Option<BTreeSet<String>>,
    /// Provider **ids** explicitly denied.
    pub denied_provider_ids: BTreeSet<String>,
    /// Preferred public model names in rank order (best first).
    pub preferred_models: Vec<String>,
}

/// The output of resolution: an ordered list of deployments to try
/// (primary first, then fallbacks), already filtered by access policy.
#[derive(Debug, Clone)]
pub struct Decision {
    pub candidates: Vec<Deployment>,
    pub reason: String,
}

/// The routing contract. A `Router` turns a request into an ordered candidate
/// list. It must return `NoEligibleProvider` (not an empty success) when policy
/// filters out everything.
pub trait Router: Send + Sync {
    fn resolve(&self, req: &RouteRequest) -> Result<Decision>;

    /// Every deployment that speaks `format` to an upstream model of this
    /// name, whatever public model it serves: how a request about work a
    /// deployment already did finds it again. None where the router cannot
    /// say.
    fn serving(&self, _format: UpstreamFormat, _upstream_model: &str) -> Vec<Deployment> {
        Vec::new()
    }
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    fn mk_dep(
        own: UpstreamFormat,
        api_base: Option<&str>,
        provider_shapes: Vec<ProviderShape>,
        shapes: Option<Vec<UpstreamFormat>>,
    ) -> Deployment {
        Deployment {
            model_id: "m1".into(),
            model_name: "m".into(),
            provider_id: "p1".into(),
            provider: "p".into(),
            upstream_model: "um".into(),
            api_base: api_base.map(str::to_string),
            api_key: None,
            upstream_format: own,
            weight: 1,
            pricing: None,
            health_check: HealthCheck::None,
            health_path: None,
            extra: Extra::default(),
            shapes,
            provider_shapes,
        }
    }

    #[test]
    fn provider_shapes_are_inherited_by_default_and_narrowed_per_deployment() {
        let base = Some("https://h/v1");
        // Legacy provider with no shapes declared: only the deployment's own format.
        let legacy = mk_dep(WireFormat::OpenaiChat.into(), base, Vec::new(), None);
        assert_eq!(legacy.native_base(WireFormat::OpenaiChat), Some(base));
        assert_eq!(legacy.native_base(WireFormat::Anthropic), None);
        assert_eq!(legacy.decision_target(DecisionFormat::Jev), None);

        // Provider declaring chat + embed + jev across distinct bases.
        let p_shapes = vec![
            ProviderShape {
                format: WireFormat::Anthropic.into(),
                api_base: Some("https://h/anthropic".into()),
            },
            ProviderShape {
                format: WireFormat::OpenaiChat.into(),
                api_base: Some("  ".into()),
            },
            ProviderShape {
                format: EmbedFormat::OpenaiEmbed.into(),
                api_base: Some("https://h/embed/v1".into()),
            },
            ProviderShape {
                format: DecisionFormat::Jev.into(),
                api_base: None,
            },
        ];

        // Deployment with shapes = None inherits all provider shapes.
        let inherited = mk_dep(WireFormat::OpenaiChat.into(), base, p_shapes.clone(), None);
        assert_eq!(
            inherited.chat_target(WireFormat::Anthropic),
            Some((WireFormat::Anthropic, Some("https://h/anthropic"), true))
        );
        // Blank per-shape base falls back to provider's api_base.
        assert_eq!(
            inherited.chat_target(WireFormat::OpenaiChat),
            Some((WireFormat::OpenaiChat, base, true))
        );
        // Unchecked chat shape translates to preferred enabled chat shape.
        assert_eq!(
            inherited.chat_target(WireFormat::Gemini),
            Some((WireFormat::OpenaiChat, base, false))
        );
        // Decision target relays Jev natively and translates Decisions -> Jev.
        assert_eq!(
            inherited.decision_target(DecisionFormat::Jev),
            Some((DecisionFormat::Jev, base, true))
        );
        assert_eq!(
            inherited.decision_target(DecisionFormat::Decisions),
            Some((DecisionFormat::Jev, base, false))
        );
        assert_eq!(
            inherited.embed_target(EmbedFormat::OpenaiEmbed),
            Some((EmbedFormat::OpenaiEmbed, Some("https://h/embed/v1"), true))
        );

        // Narrowed embed-only deployment on the same provider serves neither chat nor jev.
        let embed_only = mk_dep(
            EmbedFormat::OpenaiEmbed.into(),
            base,
            p_shapes,
            Some(vec![EmbedFormat::OpenaiEmbed.into()]),
        );
        assert_eq!(embed_only.chat_target(WireFormat::OpenaiChat), None);
        assert_eq!(embed_only.decision_target(DecisionFormat::Jev), None);
        assert_eq!(
            embed_only.embed_target(EmbedFormat::OpenaiEmbed),
            Some((EmbedFormat::OpenaiEmbed, Some("https://h/embed/v1"), true))
        );
    }

    #[test]
    fn shapes_serialize_as_flat_format_names() {
        let shapes = [
            ProviderShape {
                format: WireFormat::OpenaiChat.into(),
                api_base: None,
            },
            ProviderShape {
                format: EmbedFormat::OpenaiEmbed.into(),
                api_base: Some("https://e/v1".into()),
            },
            ProviderShape {
                format: DecisionFormat::Jev.into(),
                api_base: None,
            },
            ProviderShape {
                format: DecisionFormat::Decisions.into(),
                api_base: None,
            },
        ];
        let json = serde_json::to_string(&shapes).unwrap();
        assert_eq!(
            json,
            r#"[{"format":"openai_chat"},{"format":"openai_embed","api_base":"https://e/v1"},{"format":"jev"},{"format":"decisions"}]"#
        );
        let back: Vec<ProviderShape> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_slice(), &shapes);
        assert_eq!(
            WireFormat::parse("openai_responses"),
            Some(WireFormat::OpenaiResponses)
        );
        assert_eq!(WireFormat::parse("openai_embed"), None);
    }
}
