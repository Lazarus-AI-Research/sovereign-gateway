//! Lossless translation to and from QE's Chat Completions dialect.
//!
//! QE serves Anthropic Messages, OpenAI Chat Completions and OpenAI Responses
//! natively, and normalizes all three into one internal request whose
//! messages are chat-format; its Chat input, with QE's extensions
//! (`chat_template_kwargs`, string or integer `reasoning_effort`,
//! `thinking_token_budget`, `reasoning_content` on assistant turns, cache
//! breakpoints, custom tools, `top_k`, …), is effectively that internal
//! representation. So a request in another shape can be written as the QE
//! Chat request that QE prepares into exactly what its native parser for
//! that shape would have prepared ([`request`]), and QE's Chat answer read
//! back into the event sequence QE's native encoder for that shape would have
//! written from ([`reply`]).
//!
//! Unlike the cross-provider IR, nothing here guesses: effort levels,
//! budgets, key order, text joining and tool shapes are QE's own rules,
//! ported. The few things QE's Chat surface cannot carry are refused or
//! reported (see the PR description and [`request::Gaps`]).

pub mod reply;
pub mod request;

pub use reply::{
    anthropic_message, assistant_message, collect_chat, input_items, AnthropicStream, ChatEvents,
    Collected, Ev, ResponsesCtx, ResponsesStream, SamplingDefaults,
};
pub use request::{
    anthropic_to_chat, encode_reasoning, responses_to_chat, Gaps, NoItems, ResponseItems,
    ResponsesChat,
};
