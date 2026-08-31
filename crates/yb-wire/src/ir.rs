//! The provider-agnostic intermediate representation (IR) for chat turns.
//!
//! Every wire format (`anthropic`, `openai_chat`, `openai_responses`, `gemini`)
//! parses into these types and emits from them. The IR is deliberately close to
//! the Anthropic Messages shape (typed content blocks, explicit tool_use /
//! tool_result), because that is the richest common denominator: it can carry
//! interleaved text, images, reasoning, tool calls, and tool results in order.
//!
//! The IR is `serde`-serializable with sensible attributes so it can be logged
//! or snapshotted, but it is **not** a wire format itself — the per-format
//! modules do the real mapping by hand.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A normalized chat-completion request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChatRequest {
    /// The requested public model name (overridden on emit via `EmitOptions`).
    pub model: String,
    /// The conversation turns in order. System content lives in [`Self::system`].
    pub messages: Vec<Message>,
    /// System prompt as one or more content blocks (usually a single `Text`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<Vec<ContentBlock>>,
    /// Tool / function definitions available to the model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Tool>,
    /// How the model may use the tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Stop sequences.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    pub stream: bool,
    /// Extended-thinking / reasoning controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<Reasoning>,
    /// Provider metadata (e.g. Anthropic `metadata.user_id`).
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub metadata: Map<String, Value>,
    /// Anthropic context-management directives (context editing). Anthropic-only:
    /// a named, modeled slot so an Anthropic→Anthropic route preserves it, while
    /// emitters for other formats simply ignore it — it has no equivalent there
    /// and so can never leak cross-format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_management: Option<Value>,
    /// Anthropic output configuration. Anthropic-only (see `context_management`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_config: Option<Value>,
    /// OpenAI prompt-cache affinity key (`prompt_cache_key`), present on both the
    /// Responses and Chat Completions shapes. Round-trips on those two surfaces;
    /// no equivalent elsewhere, so other emitters ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache_key: Option<String>,
    /// OpenAI `prompt_cache_retention`. Always emitted alongside a cache key
    /// (defaulting to `"24h"` when the client didn't send one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache_retention: Option<String>,
}

/// A single conversational turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

impl Message {
    /// Construct a message from a role and its content blocks.
    pub fn new(role: Role, content: Vec<ContentBlock>) -> Self {
        Message { role, content }
    }

    /// Concatenate the text of all [`ContentBlock::Text`] blocks.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for block in &self.content {
            if let ContentBlock::Text { text } = block {
                out.push_str(text);
            }
        }
        out
    }
}

/// Who authored a turn. `Tool` carries tool results back to the model; in the
/// Anthropic mapping these are folded into `User` turns, but other formats keep
/// them distinct, so the IR models the role explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    /// OpenAI's `developer` role. Distinct from `system` because it may appear
    /// mid-conversation (system is expected only at the front), and some backends
    /// enforce that — so collapsing it to `system` breaks them.
    Developer,
    User,
    Assistant,
    Tool,
}

/// A typed unit of message content. Ordering within a message is significant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Plain text.
    Text { text: String },
    /// An image, either inline base64 (`data` + `media_type`) or by `url`.
    Image {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    /// A tool/function call emitted by the assistant.
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    /// The result of running a tool, sent back to the model.
    ToolResult {
        tool_use_id: String,
        /// Result payload as content blocks (commonly a single `Text`).
        content: Vec<ContentBlock>,
        #[serde(default)]
        is_error: bool,
    },
    /// Extended-thinking / reasoning text from the assistant.
    Thinking { text: String },
}

impl ContentBlock {
    /// Shorthand for a text block.
    pub fn text(s: impl Into<String>) -> Self {
        ContentBlock::Text { text: s.into() }
    }
}

/// A tool the model may call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the tool's arguments.
    pub input_schema: Value,
}

/// How the model may use tools on a given turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolChoice {
    /// Model decides whether to call a tool.
    Auto,
    /// Model must not call a tool.
    None,
    /// Model must call some tool.
    Required,
    /// Model must call the named tool.
    Tool(String),
}

/// Extended-thinking / reasoning controls. `effort` is the OpenAI-style knob
/// (`low`/`medium`/`high`); `budget_tokens` is the Anthropic-style token budget.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Reasoning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u32>,
}

/// A normalized chat-completion response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatResponse {
    pub id: String,
    pub model: String,
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
    pub usage: Usage,
    /// OpenAI prompt-cache fields, echoed on the Responses **response object**
    /// (they are request parameters that the API reflects back). Captured from
    /// an upstream echo when present; the gateway fills them from the request
    /// when the upstream does not echo. Only the Responses emitter writes them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache_retention: Option<String>,
}

/// Why the model stopped generating.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StopReason {
    /// Natural end of the assistant turn.
    #[default]
    EndTurn,
    /// Hit the output token cap.
    MaxTokens,
    /// Emitted a stop sequence.
    StopSequence,
    /// Stopped to call a tool.
    ToolUse,
    /// Any provider-specific reason we don't model.
    Other(String),
}

impl StopReason {
    /// The canonical lowercase string for this reason.
    pub fn as_str(&self) -> &str {
        match self {
            StopReason::EndTurn => "end_turn",
            StopReason::MaxTokens => "max_tokens",
            StopReason::StopSequence => "stop_sequence",
            StopReason::ToolUse => "tool_use",
            StopReason::Other(s) => s.as_str(),
        }
    }

    /// Parse from the canonical IR string.
    pub fn from_canonical(s: &str) -> StopReason {
        match s {
            "end_turn" => StopReason::EndTurn,
            "max_tokens" => StopReason::MaxTokens,
            "stop_sequence" => StopReason::StopSequence,
            "tool_use" => StopReason::ToolUse,
            other => StopReason::Other(other.to_string()),
        }
    }
}

impl Serialize for StopReason {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for StopReason {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(StopReason::from_canonical(&s))
    }
}

/// Token accounting. All counts are in tokens; cache fields are zero when the
/// provider does not report prompt caching.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub input_tokens: u32,
    #[serde(default)]
    pub output_tokens: u32,
    #[serde(default)]
    pub cache_read_tokens: u32,
    #[serde(default)]
    pub cache_write_tokens: u32,
}

impl Usage {
    /// Fold another report into this one, keeping the larger count per field.
    ///
    /// Upstreams report usage in different rhythms: Anthropic sends input once
    /// and output cumulatively, Gemini repeats a growing total on every chunk,
    /// and an OpenAI stream sends one final tally — but several also emit
    /// interim events carrying a null or zeroed usage object. Taking the
    /// maximum makes every one of those orders converge on the true total, and
    /// makes a stray zero incapable of erasing a real count.
    pub fn merge(&mut self, other: &Usage) {
        self.input_tokens = self.input_tokens.max(other.input_tokens);
        self.output_tokens = self.output_tokens.max(other.output_tokens);
        self.cache_read_tokens = self.cache_read_tokens.max(other.cache_read_tokens);
        self.cache_write_tokens = self.cache_write_tokens.max(other.cache_write_tokens);
    }

    /// Whether any token was reported at all.
    ///
    /// A 200 with nothing here means the turn is unbilled and invisible to spend
    /// tracking, which is worth surfacing rather than silently recording zero.
    pub fn is_empty(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.cache_read_tokens == 0
            && self.cache_write_tokens == 0
    }
}

/// A single normalized streaming event. Translators decode upstream SSE into a
/// sequence of these and re-encode them into the client's native SSE dialect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    /// Stream opened; carries the responding model id.
    MessageStart { model: String },
    /// Incremental assistant text.
    TextDelta { text: String },
    /// Incremental reasoning text.
    ThinkingDelta { text: String },
    /// A tool call has begun.
    ToolUseStart { id: String, name: String },
    /// Incremental JSON for the in-progress tool call's arguments.
    ToolUseDelta { partial_json: String },
    /// Updated token usage.
    UsageDelta { usage: Usage },
    /// Stream finished with a stop reason.
    Done { stop_reason: StopReason },
}

#[cfg(test)]
mod usage_tests {
    use super::Usage;

    #[test]
    fn merging_keeps_the_largest_report_per_field() {
        let mut u = Usage::default();
        assert!(u.is_empty());

        // Anthropic's rhythm: input once, output growing.
        u.merge(&Usage { input_tokens: 41, output_tokens: 0, ..Default::default() });
        u.merge(&Usage { input_tokens: 41, output_tokens: 30, ..Default::default() });
        assert_eq!((u.input_tokens, u.output_tokens), (41, 30));
        assert!(!u.is_empty());

        // A trailing zeroed report must not erase a real count — this is the
        // failure that silently zeroes a turn's bill.
        u.merge(&Usage::default());
        assert_eq!((u.input_tokens, u.output_tokens), (41, 30));

        // Cache fields fold the same way.
        u.merge(&Usage { cache_read_tokens: 7, ..Default::default() });
        u.merge(&Usage { cache_read_tokens: 0, cache_write_tokens: 3, ..Default::default() });
        assert_eq!((u.cache_read_tokens, u.cache_write_tokens), (7, 3));
    }
}
