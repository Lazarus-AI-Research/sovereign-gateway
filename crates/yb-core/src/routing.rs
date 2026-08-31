//! Routing: the LiteLLM-style model→deployment contract (no ML).

use crate::catalog::ModelPrice;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The wire protocol a **chat** surface or upstream speaks. Chat and embedding
/// formats are disjoint types — there is no translation between them — so this
/// enum never carries an embedding dialect (see [`EmbedFormat`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
}

/// The wire protocol an **embeddings** surface or upstream speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
}

/// What a deployment speaks upstream: a chat dialect or an embeddings dialect.
/// Untagged serde over two disjoint snake_case string sets, so config/DB/admin
/// carry flat strings (`"openai_chat"`, `"cohere_embed"`, …) with no migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpstreamFormat {
    Chat(WireFormat),
    Embed(EmbedFormat),
}

impl UpstreamFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            UpstreamFormat::Chat(f) => f.as_str(),
            UpstreamFormat::Embed(f) => f.as_str(),
        }
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
/// Two keys are understood today:
///
/// - `cloudflare_access` (bool) — present the Cloudflare Access service token so
///   the request passes a Zero Trust edge policy. The flag only selects *which*
///   credential to send; the credential itself lives in `gateway.toml`
///   (`[upstream.cloudflare_access]`), is immutable at runtime, and is never
///   stored here, returned by the admin API, or editable in the UI.
/// - `headers` (string map) — literal request headers to add.
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
    pub created_at: crate::ids::Timestamp,
    pub updated_at: crate::ids::Timestamp,
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
    /// The upstream wire format — the sole "adapter shape" for a deployment.
    /// Picks the endpoint path, request/response translation, and auth scheme.
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
    pub created_at: crate::ids::Timestamp,
    pub updated_at: crate::ids::Timestamp,
    pub deleted_at: Option<crate::ids::Timestamp>,
}

impl DeploymentRecord {
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
}
