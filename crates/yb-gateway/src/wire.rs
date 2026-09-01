//! Per-[`WireFormat`] dispatch over the `yb-wire` translators.
//!
//! `yb-wire` exposes one module per wire format, each with an identical surface
//! (`parse_request`, `emit_request`, `parse_response`, `emit_response`, and the
//! streaming `decode_sse` / `encode_sse` pair) but with *distinct*, format-specific
//! `SseState` / `EmitState` types. This module is the single place that turns a
//! runtime [`WireFormat`] value into the right concrete call, and it maps the
//! standalone [`yb_wire::WireError`] onto [`yb_core::Error::Wire`] at the boundary.

use yb_core::{EmbedFormat, Error, Result, WireFormat};
use yb_wire::{
    anthropic, embed, gemini, openai_chat, openai_responses, ChatRequest, ChatResponse,
    EmbedEmitOptions, EmbedRequest, EmbedResponse, EmitOptions, EmittedRequest, StreamEvent,
};

/// Map a `yb-wire` error into the domain error type.
fn wire_err(e: yb_wire::WireError) -> Error {
    Error::Wire(e.to_string())
}

/// Parse an inbound client body (in `fmt`) into the IR.
pub fn parse_request(fmt: WireFormat, body: &[u8]) -> Result<ChatRequest> {
    match fmt {
        WireFormat::Anthropic => anthropic::parse_request(body),
        WireFormat::OpenaiChat => openai_chat::parse_request(body),
        WireFormat::OpenaiResponses => openai_responses::parse_request(body),
        WireFormat::Gemini => gemini::parse_request(body),
    }
    .map_err(wire_err)
}

/// Emit an IR request as an upstream body (+ headers) in `fmt`.
pub fn emit_request(fmt: WireFormat, req: &ChatRequest, opts: &EmitOptions) -> Result<EmittedRequest> {
    match fmt {
        WireFormat::Anthropic => anthropic::emit_request(req, opts),
        WireFormat::OpenaiChat => openai_chat::emit_request(req, opts),
        WireFormat::OpenaiResponses => openai_responses::emit_request(req, opts),
        WireFormat::Gemini => gemini::emit_request(req, opts),
    }
    .map_err(wire_err)
}

/// Parse an upstream response body (in `fmt`) into the IR.
pub fn parse_response(fmt: WireFormat, body: &[u8]) -> Result<ChatResponse> {
    match fmt {
        WireFormat::Anthropic => anthropic::parse_response(body),
        WireFormat::OpenaiChat => openai_chat::parse_response(body),
        WireFormat::OpenaiResponses => openai_responses::parse_response(body),
        WireFormat::Gemini => gemini::parse_response(body),
    }
    .map_err(wire_err)
}

/// Emit an IR response as a client-native body in `fmt`.
pub fn emit_response(fmt: WireFormat, resp: &ChatResponse) -> Result<Vec<u8>> {
    match fmt {
        WireFormat::Anthropic => anthropic::emit_response(resp),
        WireFormat::OpenaiChat => openai_chat::emit_response(resp),
        WireFormat::OpenaiResponses => openai_responses::emit_response(resp),
        WireFormat::Gemini => gemini::emit_response(resp),
    }
    .map_err(wire_err)
}

/// The client-facing `content-type` for a buffered (non-stream) response.
pub fn full_content_type(_fmt: WireFormat) -> &'static str {
    // All four surfaces return a JSON object for a buffered completion.
    "application/json"
}

// ---------------------------------------------------------------------------
// Embeddings dispatch — a disjoint universe from chat: separate IR, separate
// per-format modules, no SSE. Typed on [`EmbedFormat`], so a chat format can
// never reach these (and vice versa) by construction.
// ---------------------------------------------------------------------------

/// Parse an inbound embeddings body (in `fmt`) into the embed IR.
pub fn parse_embed_request(fmt: EmbedFormat, body: &[u8]) -> Result<EmbedRequest> {
    match fmt {
        EmbedFormat::OpenaiEmbed => embed::openai::parse_request(body),
        EmbedFormat::GeminiEmbed => embed::gemini::parse_request(body),
        EmbedFormat::CohereEmbed => embed::cohere::parse_request(body),
        EmbedFormat::VoyageEmbed => embed::voyage::parse_request(body),
        EmbedFormat::OllamaEmbed => embed::ollama::parse_request(body),
    }
    .map_err(wire_err)
}

/// Emit an embed IR request as an upstream body (+ headers) in `fmt`.
pub fn emit_embed_request(
    fmt: EmbedFormat,
    req: &EmbedRequest,
    opts: &EmbedEmitOptions,
) -> Result<EmittedRequest> {
    match fmt {
        EmbedFormat::OpenaiEmbed => embed::openai::emit_request(req, opts),
        EmbedFormat::GeminiEmbed => embed::gemini::emit_request(req, opts),
        EmbedFormat::CohereEmbed => embed::cohere::emit_request(req, opts),
        EmbedFormat::VoyageEmbed => embed::voyage::emit_request(req, opts),
        EmbedFormat::OllamaEmbed => embed::ollama::emit_request(req, opts),
    }
    .map_err(wire_err)
}

/// Parse an upstream embeddings response body (in `fmt`) into the embed IR.
pub fn parse_embed_response(fmt: EmbedFormat, body: &[u8]) -> Result<EmbedResponse> {
    match fmt {
        EmbedFormat::OpenaiEmbed => embed::openai::parse_response(body),
        EmbedFormat::GeminiEmbed => embed::gemini::parse_response(body),
        EmbedFormat::CohereEmbed => embed::cohere::parse_response(body),
        EmbedFormat::VoyageEmbed => embed::voyage::parse_response(body),
        EmbedFormat::OllamaEmbed => embed::ollama::parse_response(body),
    }
    .map_err(wire_err)
}

/// Emit an embed IR response as a client-native body in `fmt`. `req` supplies
/// the client-echo fields (encoding_format, embedding_types, gemini_batch).
pub fn emit_embed_response(
    fmt: EmbedFormat,
    resp: &EmbedResponse,
    req: &EmbedRequest,
) -> Result<Vec<u8>> {
    match fmt {
        EmbedFormat::OpenaiEmbed => embed::openai::emit_response(resp, req),
        EmbedFormat::GeminiEmbed => embed::gemini::emit_response(resp, req),
        EmbedFormat::CohereEmbed => embed::cohere::emit_response(resp, req),
        EmbedFormat::VoyageEmbed => embed::voyage::emit_response(resp, req),
        EmbedFormat::OllamaEmbed => embed::ollama::emit_response(resp, req),
    }
    .map_err(wire_err)
}

/// A stateful SSE decoder bound to a single upstream wire format.
///
/// Wraps the format-specific `SseState` so the gateway can drive line-by-line
/// decoding without naming the concrete type.
pub enum Decoder {
    Anthropic(anthropic::SseState),
    OpenaiChat(openai_chat::SseState),
    OpenaiResponses(openai_responses::SseState),
    Gemini(gemini::SseState),
}

impl Decoder {
    /// A fresh decoder for `fmt`.
    pub fn new(fmt: WireFormat) -> Self {
        match fmt {
            WireFormat::Anthropic => Decoder::Anthropic(Default::default()),
            WireFormat::OpenaiChat => Decoder::OpenaiChat(Default::default()),
            WireFormat::OpenaiResponses => Decoder::OpenaiResponses(Default::default()),
            WireFormat::Gemini => Decoder::Gemini(Default::default()),
        }
    }

    /// Decode one SSE line into zero or more IR stream events.
    pub fn decode_line(&mut self, line: &str) -> Vec<StreamEvent> {
        match self {
            Decoder::Anthropic(s) => anthropic::decode_sse(line, s),
            Decoder::OpenaiChat(s) => openai_chat::decode_sse(line, s),
            Decoder::OpenaiResponses(s) => openai_responses::decode_sse(line, s),
            Decoder::Gemini(s) => gemini::decode_sse(line, s),
        }
    }
}

/// A stateful SSE encoder bound to a single client wire format.
pub enum Encoder {
    Anthropic(anthropic::EmitState),
    OpenaiChat(openai_chat::EmitState),
    OpenaiResponses(openai_responses::EmitState),
    Gemini(gemini::EmitState),
}

impl Encoder {
    /// A fresh encoder for `fmt`.
    pub fn new(fmt: WireFormat) -> Self {
        match fmt {
            WireFormat::Anthropic => Encoder::Anthropic(Default::default()),
            WireFormat::OpenaiChat => Encoder::OpenaiChat(Default::default()),
            WireFormat::OpenaiResponses => Encoder::OpenaiResponses(Default::default()),
            WireFormat::Gemini => Encoder::Gemini(Default::default()),
        }
    }

    /// Encode IR stream events into client-native SSE bytes.
    pub fn encode(&mut self, events: &[StreamEvent]) -> Vec<u8> {
        match self {
            Encoder::Anthropic(s) => anthropic::encode_sse(events, s),
            Encoder::OpenaiChat(s) => openai_chat::encode_sse(events, s),
            Encoder::OpenaiResponses(s) => openai_responses::encode_sse(events, s),
            Encoder::Gemini(s) => gemini::encode_sse(events, s),
        }
    }

    /// Relay token usage on this stream, as `stream_options.include_usage`
    /// requests. A no-op on every surface but OpenAI Chat, which is the only
    /// one that makes usage opt-in.
    pub fn set_include_usage(&mut self, on: bool) {
        if let Encoder::OpenaiChat(s) = self {
            s.set_include_usage(on);
        }
    }

    /// Bytes still owed when the upstream stream ends.
    ///
    /// The OpenAI Chat surface holds `[DONE]` back while it waits for the
    /// trailing usage chunk; if the upstream hangs up without sending one, this
    /// closes the client's stream rather than leaving it unterminated. A no-op
    /// on every other surface.
    pub fn finish(&mut self) -> Vec<u8> {
        match self {
            Encoder::OpenaiChat(s) => s.finish(),
            _ => Vec::new(),
        }
    }

    /// Seed the prompt-cache echo carried on the Responses surface's response
    /// envelopes; a no-op on every other surface.
    pub fn set_prompt_cache(&mut self, key: Option<String>, retention: Option<String>) {
        if let Encoder::OpenaiResponses(s) = self {
            s.set_prompt_cache(key, retention);
        }
    }
}
