//! The Anthropic Messages API wire format (`POST /v1/messages`).
//!
//! This format is the closest to the IR — typed content blocks, explicit
//! `tool_use` / `tool_result`, and a separate `system` field — so the mapping
//! here is mostly mechanical.

use crate::common::*;
use crate::error::{Result, WireError};
use crate::ir::*;
use crate::{EmitOptions, EmittedRequest};
use serde_json::{json, Map, Value};

/// The Anthropic API version header value we emit.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

// ===========================================================================
// Request
// ===========================================================================

/// Parse an Anthropic Messages request body into the IR.
pub fn parse_request(bytes: &[u8]) -> Result<ChatRequest> {
    let v: Value = serde_json::from_slice(bytes)?;
    v.as_object()
        .ok_or_else(|| WireError::InvalidRequest("body is not a JSON object".into()))?;

    let mut req = ChatRequest {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        stream: opt_bool(&v, "stream"),
        max_tokens: opt_u32(&v, "max_tokens"),
        temperature: opt_f32(&v, "temperature"),
        top_p: opt_f32(&v, "top_p"),
        stop: str_vec(v.get("stop_sequences")),
        ..Default::default()
    };

    if let Some(sys) = v.get("system") {
        req.system = Some(parse_content(sys)?);
    }

    if let Some(msgs) = opt_arr(&v, "messages") {
        for m in msgs {
            let content = m
                .get("content")
                .map(parse_content)
                .transpose()?
                .unwrap_or_default();
            let role = match opt_str(m, "role") {
                Some("user") => Role::User,
                Some("assistant") => Role::Assistant,
                // Some clients place a system turn inside `messages` (in addition
                // to, or instead of, the top-level `system`). Fold it into the
                // system prompt so every emitter treats it uniformly.
                Some("system") => {
                    req.system.get_or_insert_with(Vec::new).extend(content);
                    continue;
                }
                Some(other) => {
                    return Err(WireError::invalid("messages[].role", format!("unknown {other}")))
                }
                None => return Err(WireError::missing("messages[].role")),
            };
            req.messages.push(Message::new(role, content));
        }
    }

    if let Some(tools) = opt_arr(&v, "tools") {
        for t in tools {
            req.tools.push(Tool {
                name: req_str(t, "name")?.to_string(),
                description: opt_str(t, "description").map(str::to_string),
                input_schema: t.get("input_schema").cloned().unwrap_or(Value::Null),
            });
        }
    }

    if let Some(tc) = v.get("tool_choice") {
        req.tool_choice = Some(parse_tool_choice(tc)?);
    }

    if let Some(th) = v.get("thinking") {
        if opt_str(th, "type") != Some("disabled") {
            req.reasoning = Some(Reasoning {
                effort: None,
                budget_tokens: opt_u32(th, "budget_tokens"),
            });
        }
    }

    if let Some(md) = v.get("metadata").and_then(Value::as_object) {
        req.metadata = md.clone();
    }

    // Anthropic-only features: modeled as named IR fields (not a catch-all), so
    // an Anthropic→Anthropic route preserves them and no other emitter sees them.
    req.context_management = v.get("context_management").cloned();
    req.output_config = v.get("output_config").cloned();

    Ok(req)
}

/// Emit an IR request as an Anthropic Messages request body plus headers.
pub fn emit_request(req: &ChatRequest, opts: &EmitOptions) -> Result<EmittedRequest> {
    let mut body = Map::new();

    let model = if opts.target_model.is_empty() {
        req.model.clone()
    } else {
        opts.target_model.clone()
    };
    body.insert("model".into(), json!(model));
    // Anthropic requires max_tokens; fall back to a safe default.
    body.insert("max_tokens".into(), json!(req.max_tokens.unwrap_or(4096)));

    // Includes inline System/Developer messages, which `emit_message` skips —
    // without this they reach neither `system` nor `messages`.
    let system = req.effective_system();
    if !system.is_empty() {
        body.insert("system".into(), emit_system(&system));
    }

    let messages: Vec<Value> = req.messages.iter().filter_map(emit_message).collect();
    body.insert("messages".into(), Value::Array(messages));

    if !req.tools.is_empty() {
        let tools: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                let mut o = Map::new();
                o.insert("name".into(), json!(t.name));
                insert_opt(&mut o, "description", t.description.clone());
                o.insert("input_schema".into(), t.input_schema.clone());
                Value::Object(o)
            })
            .collect();
        body.insert("tools".into(), Value::Array(tools));
    }

    if let Some(tc) = &req.tool_choice {
        body.insert("tool_choice".into(), emit_tool_choice(tc));
    }

    insert_opt(&mut body, "temperature", req.temperature);
    insert_opt(&mut body, "top_p", req.top_p);
    if !req.stop.is_empty() {
        body.insert("stop_sequences".into(), json!(req.stop));
    }
    if opts.stream {
        body.insert("stream".into(), json!(true));
    }

    let effort = opts
        .force_reasoning_effort
        .clone()
        .or_else(|| req.reasoning.as_ref().and_then(|r| r.effort.clone()));
    if let Some(budget) = req.reasoning.as_ref().and_then(|r| r.budget_tokens).or_else(|| {
        // Map an OpenAI-style effort onto an approximate Anthropic budget.
        effort.as_deref().map(effort_to_budget)
    }) {
        body.insert("thinking".into(), json!({"type": "enabled", "budget_tokens": budget}));
    }

    if !req.metadata.is_empty() {
        body.insert("metadata".into(), Value::Object(req.metadata.clone()));
    }
    // Anthropic-only features round-trip on the Anthropic surface.
    if let Some(cm) = &req.context_management {
        body.insert("context_management".into(), cm.clone());
    }
    if let Some(oc) = &req.output_config {
        body.insert("output_config".into(), oc.clone());
    }

    let bytes = serde_json::to_vec(&Value::Object(body))?;
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()),
    ];
    Ok((bytes, headers))
}

fn effort_to_budget(effort: &str) -> u32 {
    match effort {
        "low" => 1024,
        "high" => 8192,
        _ => 4096,
    }
}

// ===========================================================================
// Response
// ===========================================================================

/// Parse an Anthropic Messages response body into the IR.
pub fn parse_response(bytes: &[u8]) -> Result<ChatResponse> {
    let v: Value = serde_json::from_slice(bytes)?;
    let content = v
        .get("content")
        .map(parse_content)
        .transpose()?
        .unwrap_or_default();
    Ok(ChatResponse {
        id: opt_str(&v, "id").unwrap_or_default().to_string(),
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        content,
        stop_reason: parse_stop_reason(opt_str(&v, "stop_reason")),
        usage: parse_usage(v.get("usage")),
        prompt_cache_key: None,
        prompt_cache_retention: None,
    })
}

/// Emit an IR response as an Anthropic Messages response body.
pub fn emit_response(resp: &ChatResponse) -> Result<Vec<u8>> {
    let content: Vec<Value> = resp.content.iter().map(emit_block).collect();
    let body = json!({
        "id": resp.id,
        "type": "message",
        "role": "assistant",
        "model": resp.model,
        "content": content,
        "stop_reason": stop_reason_str(&resp.stop_reason),
        "stop_sequence": Value::Null,
        "usage": emit_usage(&resp.usage),
    });
    Ok(serde_json::to_vec(&body)?)
}

fn emit_usage(u: &Usage) -> Value {
    json!({
        "input_tokens": u.input_tokens,
        "output_tokens": u.output_tokens,
        "cache_read_input_tokens": u.cache_read_tokens,
        "cache_creation_input_tokens": u.cache_write_tokens,
    })
}

fn parse_usage(v: Option<&Value>) -> Usage {
    let Some(v) = v else { return Usage::default() };
    Usage {
        input_tokens: opt_u32(v, "input_tokens").unwrap_or(0),
        output_tokens: opt_u32(v, "output_tokens").unwrap_or(0),
        cache_read_tokens: opt_u32(v, "cache_read_input_tokens").unwrap_or(0),
        cache_write_tokens: opt_u32(v, "cache_creation_input_tokens").unwrap_or(0),
    }
}

// ===========================================================================
// Shared content-block mapping
// ===========================================================================

/// Parse an Anthropic `content` value (string or array of blocks) into IR blocks.
fn parse_content(v: &Value) -> Result<Vec<ContentBlock>> {
    match v {
        Value::String(s) => Ok(vec![ContentBlock::text(s.clone())]),
        Value::Array(items) => items.iter().map(parse_block).collect(),
        Value::Null => Ok(vec![]),
        _ => Err(WireError::invalid("content", "expected string or array")),
    }
}

fn parse_block(b: &Value) -> Result<ContentBlock> {
    match opt_str(b, "type") {
        Some("text") => Ok(ContentBlock::text(opt_str(b, "text").unwrap_or_default())),
        Some("image") => {
            let src = b.get("source").unwrap_or(&Value::Null);
            match opt_str(src, "type") {
                Some("url") => Ok(ContentBlock::Image {
                    media_type: None,
                    data: None,
                    url: opt_str(src, "url").map(str::to_string),
                }),
                _ => Ok(ContentBlock::Image {
                    media_type: opt_str(src, "media_type").map(str::to_string),
                    data: opt_str(src, "data").map(str::to_string),
                    url: None,
                }),
            }
        }
        Some("tool_use") => Ok(ContentBlock::ToolUse {
            id: opt_str(b, "id").unwrap_or_default().to_string(),
            name: opt_str(b, "name").unwrap_or_default().to_string(),
            input: b.get("input").cloned().unwrap_or(json!({})),
        }),
        Some("tool_result") => Ok(ContentBlock::ToolResult {
            tool_use_id: opt_str(b, "tool_use_id").unwrap_or_default().to_string(),
            content: b.get("content").map(parse_content).transpose()?.unwrap_or_default(),
            is_error: opt_bool(b, "is_error"),
        }),
        Some("thinking") => Ok(ContentBlock::Thinking {
            text: opt_str(b, "thinking").unwrap_or_default().to_string(),
        }),
        Some(other) => Err(WireError::invalid("content[].type", format!("unknown {other}"))),
        None => Err(WireError::missing("content[].type")),
    }
}

fn emit_block(b: &ContentBlock) -> Value {
    match b {
        ContentBlock::Text { text } => json!({"type": "text", "text": text}),
        ContentBlock::Image { media_type, data, url } => {
            if let Some(url) = url {
                json!({"type": "image", "source": {"type": "url", "url": url}})
            } else {
                json!({"type": "image", "source": {
                    "type": "base64",
                    "media_type": media_type.clone().unwrap_or_else(|| "image/png".into()),
                    "data": data.clone().unwrap_or_default(),
                }})
            }
        }
        ContentBlock::ToolUse { id, name, input } => {
            json!({"type": "tool_use", "id": id, "name": name, "input": input})
        }
        ContentBlock::ToolResult { tool_use_id, content, is_error } => {
            let mut o = Map::new();
            o.insert("type".into(), json!("tool_result"));
            o.insert("tool_use_id".into(), json!(tool_use_id));
            o.insert("content".into(), emit_result_content(content));
            if *is_error {
                o.insert("is_error".into(), json!(true));
            }
            Value::Object(o)
        }
        ContentBlock::Thinking { text } => json!({"type": "thinking", "thinking": text}),
    }
}

/// Tool-result content renders as a plain string when it is all text, else as a
/// block array — matching how the Anthropic API accepts both shapes.
fn emit_result_content(content: &[ContentBlock]) -> Value {
    if content.iter().all(|b| matches!(b, ContentBlock::Text { .. })) {
        let mut s = String::new();
        for b in content {
            if let ContentBlock::Text { text } = b {
                s.push_str(text);
            }
        }
        json!(s)
    } else {
        Value::Array(content.iter().map(emit_block).collect())
    }
}

/// Emit one IR message as an Anthropic message object. `System` messages are
/// dropped here (system content travels in the top-level `system` field); a
/// `Tool` message becomes a `user` message carrying `tool_result` blocks.
fn emit_message(m: &Message) -> Option<Value> {
    let role = match m.role {
        Role::Assistant => "assistant",
        Role::User | Role::Tool => "user",
        Role::System | Role::Developer => return None,
    };
    let content = if m.content.len() == 1 {
        if let ContentBlock::Text { text } = &m.content[0] {
            json!(text)
        } else {
            json!([emit_block(&m.content[0])])
        }
    } else {
        Value::Array(m.content.iter().map(emit_block).collect())
    };
    Some(json!({"role": role, "content": content}))
}

fn emit_system(blocks: &[ContentBlock]) -> Value {
    if blocks.iter().all(|b| matches!(b, ContentBlock::Text { .. })) {
        let mut s = String::new();
        for b in blocks {
            if let ContentBlock::Text { text } = b {
                s.push_str(text);
            }
        }
        json!(s)
    } else {
        Value::Array(blocks.iter().map(emit_block).collect())
    }
}

fn parse_tool_choice(v: &Value) -> Result<ToolChoice> {
    match opt_str(v, "type") {
        Some("auto") => Ok(ToolChoice::Auto),
        Some("any") => Ok(ToolChoice::Required),
        Some("none") => Ok(ToolChoice::None),
        Some("tool") => Ok(ToolChoice::Tool(
            opt_str(v, "name").unwrap_or_default().to_string(),
        )),
        _ => Err(WireError::invalid("tool_choice.type", "unknown")),
    }
}

fn emit_tool_choice(tc: &ToolChoice) -> Value {
    match tc {
        ToolChoice::Auto => json!({"type": "auto"}),
        ToolChoice::None => json!({"type": "none"}),
        ToolChoice::Required => json!({"type": "any"}),
        ToolChoice::Tool(name) => json!({"type": "tool", "name": name}),
    }
}

fn parse_stop_reason(s: Option<&str>) -> StopReason {
    match s {
        Some("end_turn") => StopReason::EndTurn,
        Some("max_tokens") => StopReason::MaxTokens,
        Some("stop_sequence") => StopReason::StopSequence,
        Some("tool_use") => StopReason::ToolUse,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::EndTurn,
    }
}

/// The Anthropic stop-reason string for an IR [`StopReason`].
fn stop_reason_str(s: &StopReason) -> &str {
    match s {
        StopReason::EndTurn => "end_turn",
        StopReason::MaxTokens => "max_tokens",
        StopReason::StopSequence => "stop_sequence",
        StopReason::ToolUse => "tool_use",
        StopReason::Other(o) => o.as_str(),
    }
}

// ===========================================================================
// Streaming
// ===========================================================================

/// Decoder state for an Anthropic upstream SSE stream.
#[derive(Debug, Default)]
pub struct SseState {
    /// The stop reason carried on `message_delta`, surfaced on `message_stop`.
    stop_reason: Option<StopReason>,
}

/// Decode one line of an Anthropic SSE stream into IR events.
///
/// `event:` and blank lines are ignored; `data:` lines are parsed as JSON.
pub fn decode_sse(line: &str, state: &mut SseState) -> Vec<StreamEvent> {
    let Some(data) = sse_data(line) else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<Value>(data) else {
        return vec![];
    };
    match opt_str(&v, "type") {
        Some("message_start") => {
            let msg = v.get("message").unwrap_or(&Value::Null);
            let mut out = vec![StreamEvent::MessageStart {
                model: opt_str(msg, "model").unwrap_or_default().to_string(),
            }];
            if let Some(u) = msg.get("usage").filter(|u| !u.is_null()) {
                out.push(StreamEvent::UsageDelta { usage: parse_usage(Some(u)) });
            }
            out
        }
        Some("content_block_start") => {
            let block = v.get("content_block").unwrap_or(&Value::Null);
            if opt_str(block, "type") == Some("tool_use") {
                vec![StreamEvent::ToolUseStart {
                    id: opt_str(block, "id").unwrap_or_default().to_string(),
                    name: opt_str(block, "name").unwrap_or_default().to_string(),
                }]
            } else {
                vec![]
            }
        }
        Some("content_block_delta") => {
            let delta = v.get("delta").unwrap_or(&Value::Null);
            match opt_str(delta, "type") {
                Some("text_delta") => vec![StreamEvent::TextDelta {
                    text: opt_str(delta, "text").unwrap_or_default().to_string(),
                }],
                Some("thinking_delta") => vec![StreamEvent::ThinkingDelta {
                    text: opt_str(delta, "thinking").unwrap_or_default().to_string(),
                }],
                Some("input_json_delta") => vec![StreamEvent::ToolUseDelta {
                    partial_json: opt_str(delta, "partial_json").unwrap_or_default().to_string(),
                }],
                _ => vec![],
            }
        }
        Some("message_delta") => {
            let delta = v.get("delta").unwrap_or(&Value::Null);
            state.stop_reason = Some(parse_stop_reason(opt_str(delta, "stop_reason")));
            v.get("usage")
                .map(|u| vec![StreamEvent::UsageDelta { usage: parse_usage(Some(u)) }])
                .unwrap_or_default()
        }
        Some("message_stop") => vec![StreamEvent::Done {
            stop_reason: state.stop_reason.take().unwrap_or(StopReason::EndTurn),
        }],
        _ => vec![],
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BlockKind {
    Text,
    Thinking,
    Tool,
}

/// Encoder state for producing an Anthropic client SSE stream from IR events.
#[derive(Debug, Default)]
pub struct EmitState {
    started: bool,
    model: String,
    next_index: usize,
    open: Option<BlockKind>,
    usage: Usage,
}

/// Encode IR events into Anthropic-native client SSE bytes.
pub fn encode_sse(events: &[StreamEvent], state: &mut EmitState) -> Vec<u8> {
    let mut out = String::new();
    for ev in events {
        match ev {
            StreamEvent::MessageStart { model } => {
                state.model = model.clone();
                emit_message_start(&mut out, state);
            }
            StreamEvent::TextDelta { text } => {
                ensure_block(&mut out, state, BlockKind::Text);
                write_event(
                    &mut out,
                    "content_block_delta",
                    &json!({"type": "content_block_delta", "index": state.next_index,
                            "delta": {"type": "text_delta", "text": text}}),
                );
            }
            StreamEvent::ThinkingDelta { text } => {
                ensure_block(&mut out, state, BlockKind::Thinking);
                write_event(
                    &mut out,
                    "content_block_delta",
                    &json!({"type": "content_block_delta", "index": state.next_index,
                            "delta": {"type": "thinking_delta", "thinking": text}}),
                );
            }
            StreamEvent::ToolUseStart { id, name } => {
                ensure_started(&mut out, state);
                close_open(&mut out, state);
                write_event(
                    &mut out,
                    "content_block_start",
                    &json!({"type": "content_block_start", "index": state.next_index,
                            "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}}),
                );
                state.open = Some(BlockKind::Tool);
            }
            StreamEvent::ToolUseDelta { partial_json } => {
                ensure_block(&mut out, state, BlockKind::Tool);
                write_event(
                    &mut out,
                    "content_block_delta",
                    &json!({"type": "content_block_delta", "index": state.next_index,
                            "delta": {"type": "input_json_delta", "partial_json": partial_json}}),
                );
            }
            StreamEvent::UsageDelta { usage } => {
                // Anthropic reports input tokens once (on message_start) and
                // output tokens cumulatively, so the largest report per field is
                // the turn's total — see [`Usage::merge`].
                state.usage.merge(usage);
            }
            StreamEvent::Done { stop_reason } => {
                ensure_started(&mut out, state);
                close_open(&mut out, state);
                write_event(
                    &mut out,
                    "message_delta",
                    &json!({"type": "message_delta",
                            "delta": {"stop_reason": stop_reason_str(stop_reason), "stop_sequence": Value::Null},
                            "usage": {"output_tokens": state.usage.output_tokens}}),
                );
                write_event(&mut out, "message_stop", &json!({"type": "message_stop"}));
            }
        }
    }
    out.into_bytes()
}

fn emit_message_start(out: &mut String, state: &mut EmitState) {
    state.started = true;
    write_event(
        out,
        "message_start",
        &json!({"type": "message_start", "message": {
            "id": "msg_stream",
            "type": "message",
            "role": "assistant",
            "model": state.model,
            "content": [],
            "stop_reason": Value::Null,
            "stop_sequence": Value::Null,
            "usage": {"input_tokens": 0, "output_tokens": 0}
        }}),
    );
}

fn ensure_started(out: &mut String, state: &mut EmitState) {
    if !state.started {
        emit_message_start(out, state);
    }
}

/// Ensure a content block of `kind` is open at the current index, opening one
/// (and closing any mismatched open block) as needed.
fn ensure_block(out: &mut String, state: &mut EmitState, kind: BlockKind) {
    ensure_started(out, state);
    if state.open == Some(kind) {
        return;
    }
    close_open(out, state);
    let content_block = match kind {
        BlockKind::Text => json!({"type": "text", "text": ""}),
        BlockKind::Thinking => json!({"type": "thinking", "thinking": ""}),
        BlockKind::Tool => json!({"type": "tool_use", "id": "", "name": "", "input": {}}),
    };
    write_event(
        out,
        "content_block_start",
        &json!({"type": "content_block_start", "index": state.next_index, "content_block": content_block}),
    );
    state.open = Some(kind);
}

fn close_open(out: &mut String, state: &mut EmitState) {
    if state.open.take().is_some() {
        write_event(
            out,
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": state.next_index}),
        );
        state.next_index += 1;
    }
}

fn write_event(out: &mut String, name: &str, data: &Value) {
    out.push_str("event: ");
    out.push_str(name);
    out.push('\n');
    out.push_str("data: ");
    out.push_str(&data.to_string());
    out.push_str("\n\n");
}

/// Extract the JSON payload from an SSE `data:` line, or `None` for other lines.
pub(crate) fn sse_data(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("data:")?;
    Some(rest.strip_prefix(' ').unwrap_or(rest).trim_end())
}

#[cfg(test)]
mod extension_field_tests {
    use crate::EmitOptions;

    // An Anthropic body carrying Anthropic-only features plus a field we don't
    // model at all.
    fn anthropic_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "model": "claude-x",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}],
            "context_management": {"edits": [{"type": "clear"}]},
            "output_config": {"format": "json"},
            "some_future_field": {"a": 1}
        }))
        .unwrap()
    }

    #[test]
    fn anthropic_to_anthropic_preserves_named_features_but_drops_unmodeled() {
        let ir = super::parse_request(&anthropic_body()).unwrap();
        // Named, modeled features survive in the IR.
        assert!(ir.context_management.is_some());
        assert!(ir.output_config.is_some());

        let (bytes, _) = super::emit_request(&ir, &EmitOptions::default()).unwrap();
        let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(out.get("context_management").is_some(), "ant->ant keeps context_management");
        assert!(out.get("output_config").is_some(), "ant->ant keeps output_config");
        // The unmodeled field is gone — there is no `extra` escape hatch.
        assert!(out.get("some_future_field").is_none(), "unmodeled fields are dropped");
    }

    #[test]
    fn anthropic_to_responses_never_leaks_anthropic_features() {
        let ir = super::parse_request(&anthropic_body()).unwrap();
        let (bytes, _) = crate::openai_responses::emit_request(&ir, &EmitOptions::default()).unwrap();
        let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for k in ["context_management", "output_config", "some_future_field"] {
            assert!(out.get(k).is_none(), "Responses body must not carry Anthropic-only `{k}`");
        }
    }
}
