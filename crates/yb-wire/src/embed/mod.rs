//! Embeddings translation: a small IR plus parse/emit for the embedding wire
//! dialects. Deliberately separate from the chat IR — chat and embeddings are
//! disjoint universes with no translation between them, and embeddings never
//! stream (no SSE machinery here).
//!
//! Formats: [`openai`] (`/v1/embeddings`, the dominant dialect incl. Jina-style
//! multimodal inputs), [`gemini`] (`:embedContent`/`:batchEmbedContents`),
//! [`cohere`] (`/v2/embed`), [`voyage`] (`/v1/multimodalembeddings`,
//! interleaved text+image), and [`ollama`] (`/api/embed`, upstream-only).

pub mod cohere;
pub mod gemini;
pub mod ollama;
pub mod openai;
pub mod voyage;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Result, WireError};

/// One typed unit of embedding input content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmbedPart {
    Text {
        text: String,
    },
    Image {
        /// e.g. `image/png`; `None` when unknown.
        media_type: Option<String>,
        /// Raw base64 payload (no `data:` prefix).
        data: Option<String>,
        /// http(s) URL; mutually exclusive with `data`.
        url: Option<String>,
    },
}

/// One embedding-producing unit: a list of parts. Multimodal formats allow
/// mixed text+image per vector; text-only formats require exactly one Text part.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbedInput {
    pub parts: Vec<EmbedPart>,
}

impl EmbedInput {
    pub fn text(s: impl Into<String>) -> Self {
        EmbedInput { parts: vec![EmbedPart::Text { text: s.into() }] }
    }

    /// The single text of an all-text input, or `None` if it has images or
    /// more than one part.
    pub fn as_single_text(&self) -> Option<&str> {
        match self.parts.as_slice() {
            [EmbedPart::Text { text }] => Some(text),
            _ => None,
        }
    }

    pub fn has_image(&self) -> bool {
        self.parts.iter().any(|p| matches!(p, EmbedPart::Image { .. }))
    }
}

/// How the client asked for vectors to be encoded in its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodingFormat {
    Float,
    Base64,
}

/// A normalized embeddings request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbedRequest {
    pub model: String,
    pub inputs: Vec<EmbedInput>,
    /// Normalized task hint: `query` | `document` | `classification` |
    /// `clustering`. Unmappable vendor values are dropped at emit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_dimensions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncate: Option<bool>,
    // ---- client-echo fields: they shape the *client* response only and are
    // ---- never blindly forwarded upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding_format: Option<EncodingFormat>,
    /// Cohere `embedding_types` the client asked for (validated ⊆ {float, base64}).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohere_embedding_types: Option<Vec<String>>,
    /// The client used Gemini's `:batchEmbedContents` (vs single `:embedContent`).
    #[serde(default)]
    pub gemini_batch: bool,
}

/// Usage attribution for an embeddings turn (input-only; embeddings have no
/// output tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EmbedUsage {
    /// Billed input tokens (text + image tokens where the vendor folds them in).
    pub input_tokens: u32,
    /// Informational image accounting (Cohere image tokens / Voyage pixels).
    pub image_units: u32,
}

/// A normalized embeddings response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbedResponse {
    pub model: String,
    pub embeddings: Vec<Vec<f32>>,
    pub usage: EmbedUsage,
}

/// Options controlling how an [`EmbedRequest`] is emitted upstream.
#[derive(Debug, Clone, Default)]
pub struct EmbedEmitOptions {
    /// The upstream model id to put on the wire (the deployment's `upstream_model`).
    pub target_model: String,
}

impl EmbedEmitOptions {
    pub fn new(target_model: impl Into<String>) -> Self {
        EmbedEmitOptions { target_model: target_model.into() }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Encode a float vector as base64 of little-endian f32 bytes — the convention
/// OpenAI and Cohere use for `base64` embedding encodings.
pub fn f32s_to_base64(v: &[f32]) -> String {
    let mut bytes = Vec::with_capacity(v.len() * 4);
    for f in v {
        bytes.extend_from_slice(&f.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode a base64 string of little-endian f32 bytes into a float vector.
pub fn base64_to_f32s(s: &str) -> Result<Vec<f32>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| WireError::InvalidRequest(format!("bad base64 embedding: {e}")))?;
    if !bytes.len().is_multiple_of(4) {
        return Err(WireError::InvalidRequest(
            "base64 embedding length is not a multiple of 4 bytes".into(),
        ));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

/// Render an image part as a `data:` URI (required by Cohere/Voyage inline
/// forms). URL-only images cannot be inlined — the gateway never fetches
/// remote content.
pub(crate) fn image_to_data_uri(media_type: Option<&str>, data: Option<&str>) -> Result<String> {
    match data {
        Some(d) => Ok(crate::common::build_data_url(media_type, d)),
        None => Err(WireError::InvalidRequest(
            "this upstream requires inline base64 images; URL images are not fetched by the gateway"
                .into(),
        )),
    }
}

/// Normalized task hint → Gemini `taskType`.
pub(crate) fn input_type_to_gemini(t: &str) -> Option<&'static str> {
    match t {
        "query" => Some("RETRIEVAL_QUERY"),
        "document" => Some("RETRIEVAL_DOCUMENT"),
        "classification" => Some("CLASSIFICATION"),
        "clustering" => Some("CLUSTERING"),
        _ => None,
    }
}

/// Gemini `taskType` → normalized task hint (case-insensitive).
pub(crate) fn gemini_to_input_type(t: &str) -> Option<&'static str> {
    match t.to_ascii_uppercase().as_str() {
        "RETRIEVAL_QUERY" | "QUESTION_ANSWERING" => Some("query"),
        "RETRIEVAL_DOCUMENT" | "FACT_VERIFICATION" => Some("document"),
        "CLASSIFICATION" => Some("classification"),
        "CLUSTERING" => Some("clustering"),
        _ => None,
    }
}

/// Normalized task hint → Cohere `input_type`. Cohere v3+ requires the field,
/// so `None` maps to `search_document`.
pub(crate) fn input_type_to_cohere(t: Option<&str>) -> &'static str {
    match t {
        Some("query") => "search_query",
        Some("classification") => "classification",
        Some("clustering") => "clustering",
        _ => "search_document",
    }
}

/// Cohere `input_type` → normalized task hint.
pub(crate) fn cohere_to_input_type(t: &str) -> Option<&'static str> {
    match t {
        "search_query" => Some("query"),
        "search_document" => Some("document"),
        "classification" => Some("classification"),
        "clustering" => Some("clustering"),
        _ => None, // e.g. "image" — images speak for themselves
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f32_base64_roundtrip() {
        let v = vec![0.0f32, 1.5, -2.25, 3.4e38];
        let b = f32s_to_base64(&v);
        assert_eq!(base64_to_f32s(&b).unwrap(), v);
    }

    #[test]
    fn bad_base64_rejected() {
        assert!(base64_to_f32s("!!!").is_err());
        // 3 bytes -> not a multiple of 4
        let b = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]);
        assert!(base64_to_f32s(&b).is_err());
    }

    #[test]
    fn input_type_tables() {
        assert_eq!(input_type_to_gemini("query"), Some("RETRIEVAL_QUERY"));
        assert_eq!(gemini_to_input_type("retrieval_document"), Some("document"));
        assert_eq!(input_type_to_cohere(None), "search_document");
        assert_eq!(input_type_to_cohere(Some("query")), "search_query");
        assert_eq!(cohere_to_input_type("search_query"), Some("query"));
        assert_eq!(cohere_to_input_type("image"), None);
    }

    #[test]
    fn url_image_cannot_inline() {
        assert!(image_to_data_uri(Some("image/png"), None).is_err());
        assert_eq!(
            image_to_data_uri(Some("image/png"), Some("QUJD")).unwrap(),
            "data:image/png;base64,QUJD"
        );
    }
}
