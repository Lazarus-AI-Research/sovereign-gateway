//! # yb-wire
//!
//! A hand-rolled, provider-agnostic intermediate representation (IR) for LLM
//! chat requests, responses, and streams — plus parse/emit adapters for the
//! four wire formats the gateway speaks:
//!
//! - [`anthropic`] — the Anthropic Messages API (`/v1/messages`)
//! - [`openai_chat`] — OpenAI Chat Completions (`/v1/chat/completions`)
//! - [`openai_responses`] — OpenAI Responses (`/v1/responses`)
//! - [`gemini`] — Google Gemini `generateContent`
//!
//! Each format module exposes the same surface:
//! `parse_request`, `emit_request`, `parse_response`, `emit_response`, and the
//! streaming pair `decode_sse` / `encode_sse` with a small per-format state.
//!
//! The crate depends only on `serde`, `serde_json`, and `thiserror`; it does
//! **not** depend on `yb-core`. At the gateway boundary a [`WireError`] is
//! mapped onto `yb_core::Error::Wire`.

pub mod anthropic;
pub mod embed;
mod aggregate;
mod common;
pub mod error;
pub mod gemini;
pub mod ir;
pub mod openai_chat;
pub mod openai_responses;

pub use aggregate::{events_from_response, Aggregator};
pub use error::{Result, WireError};
pub use embed::{
    EmbedEmitOptions, EmbedInput, EmbedPart, EmbedRequest, EmbedResponse, EmbedUsage,
    EncodingFormat,
};
pub use ir::{
    ChatRequest, ChatResponse, ContentBlock, Message, Reasoning, Role, StopReason, StreamEvent,
    Tool, ToolChoice, Usage,
};

/// An emitted upstream request: the serialized body plus the format-specific
/// headers (`content-type`, `anthropic-version`, …) the caller should send.
pub type EmittedRequest = (Vec<u8>, Vec<(String, String)>);

/// Options controlling how a [`ChatRequest`] is emitted to an upstream format.
#[derive(Debug, Clone, Default)]
pub struct EmitOptions {
    /// The upstream model id to put on the wire (the deployment's `upstream_model`).
    pub target_model: String,
    /// When set, overrides any reasoning effort on the request.
    pub force_reasoning_effort: Option<String>,
    /// Whether the upstream call should stream.
    pub stream: bool,
}

impl EmitOptions {
    /// Construct emit options for a target model with no overrides.
    pub fn new(target_model: impl Into<String>) -> Self {
        EmitOptions {
            target_model: target_model.into(),
            force_reasoning_effort: None,
            stream: false,
        }
    }
}
