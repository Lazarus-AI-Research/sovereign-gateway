//! The OpenAI Responses API wire format (`POST /v1/responses`).
//!
//! Differences from chat completions: the system prompt is `instructions`; the
//! conversation is a flat `input` item list where assistant tool calls are
//! `function_call` items and tool results are `function_call_output` items;
//! content parts are tagged `input_text` / `output_text` / `input_image`; and
//! the output token cap is `max_output_tokens`.

use crate::common::*;
use crate::error::{Result, WireError};
use crate::ir::*;
use crate::{EmitOptions, EmittedRequest};
use serde_json::{json, Map, Value};

// ===========================================================================
// Request
// ===========================================================================

/// Parse an OpenAI Responses request body into the IR.
pub fn parse_request(bytes: &[u8]) -> Result<ChatRequest> {
    let v: Value = serde_json::from_slice(bytes)?;
    v.as_object()
        .ok_or_else(|| WireError::InvalidRequest("body is not a JSON object".into()))?;

    let mut req = ChatRequest {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        stream: opt_bool(&v, "stream"),
        max_tokens: opt_u32(&v, "max_output_tokens"),
        temperature: opt_f32(&v, "temperature"),
        top_p: opt_f32(&v, "top_p"),
        ..Default::default()
    };

    if let Some(instr) = opt_str(&v, "instructions") {
        req.system = Some(vec![ContentBlock::text(instr)]);
    }

    // Kept verbatim for a same-shape relay; see `ChatRequest::native_input`.
    if let Some(Value::Array(items)) = v.get("input") {
        req.native_input = Some(items.clone());
    }
    match v.get("input") {
        Some(Value::String(s)) => {
            req.messages
                .push(Message::new(Role::User, vec![ContentBlock::text(s.clone())]));
        }
        Some(Value::Array(items)) => {
            for item in items {
                parse_input_item(item, &mut req.messages)?;
            }
        }
        _ => {}
    }

    if let Some(tools) = opt_arr(&v, "tools") {
        for t in tools {
            if opt_str(t, "type") == Some("function") {
                req.tools.push(Tool {
                    name: req_str(t, "name")?.to_string(),
                    description: opt_str(t, "description").map(str::to_string),
                    input_schema: t.get("parameters").cloned().unwrap_or(json!({})),
                });
            }
        }
    }
    if let Some(tc) = v.get("tool_choice") {
        req.tool_choice = Some(parse_tool_choice(tc)?);
    }
    if let Some(r) = v.get("reasoning") {
        req.reasoning = Some(Reasoning {
            effort: opt_str(r, "effort").map(str::to_string),
            budget_tokens: None,
        });
    }
    req.prompt_cache_key = opt_str(&v, "prompt_cache_key").map(str::to_string);
    req.prompt_cache_retention = opt_str(&v, "prompt_cache_retention").map(str::to_string);

    Ok(req)
}

/// Fold one `input` item into the IR message list.
///
/// The Responses `input` array is an open vocabulary: beyond `message`,
/// `function_call` and `function_call_output`, clients emit tool items of their
/// own — Codex alone sends `custom_tool_call` for freeform tools and
/// `local_shell_call` for its shell, each with a matching `*_output`. Dropping
/// one of those loses half a tool exchange, and an assistant `tool_calls` with
/// no answering `tool` message is rejected outright by the upstream:
///
/// > an assistant message with 'tool_calls' must be followed by tool messages
/// > responding to each 'tool_call_id'
///
/// So unknown types are matched on **shape** rather than dropped: anything
/// carrying a `call_id` plus an `output` is a tool result, and anything
/// carrying a `call_id` plus a name is a tool call. Only items with no tool
/// linkage at all are ignored.
fn parse_input_item(item: &Value, messages: &mut Vec<Message>) -> Result<()> {
    match opt_str(item, "type") {
        Some("message") | None => {
            match opt_str(item, "role") {
                // A tool result can arrive as a message with role `tool`; its
                // id lives in `tool_call_id` (chat spelling) or `call_id`.
                Some("tool") => messages.push(tool_result_message(item, join_parts(item))),
                role => {
                    let role = match role {
                        Some("assistant") => Role::Assistant,
                        Some("system") => Role::System,
                        Some("developer") => Role::Developer,
                        _ => Role::User,
                    };
                    messages.push(Message::new(role, parse_content_parts(item.get("content"))));
                }
            }
        }
        // Every tool-call spelling: `function_call`, plus Codex's
        // `custom_tool_call` (freeform, args in `input`) and `local_shell_call`
        // (args in `action`).
        Some(t) if is_tool_call(t) => messages.push(tool_call_message(item)),
        // `mcp_call` is the one item carrying *both* halves of an exchange —
        // name and arguments alongside its output — and it is keyed on `id`
        // rather than `call_id`. Emit the pair, or the output is orphaned.
        Some("mcp_call") => {
            messages.push(tool_call_message(item));
            if item.get("output").is_some() {
                messages.push(tool_result_message(item, output_text(item.get("output"))));
            }
        }
        Some(t) if is_tool_output(t) => {
            messages.push(tool_result_message(item, output_text(item.get("output"))))
        }
        // Unknown type: fall back to shape, so a client's own tool vocabulary
        // still round-trips instead of silently losing an exchange.
        Some(_) if has_call_id(item) && item.get("output").is_some() => {
            messages.push(tool_result_message(item, output_text(item.get("output"))))
        }
        Some(_) if has_call_id(item) && opt_str(item, "name").is_some() => {
            messages.push(tool_call_message(item))
        }
        Some(_) => {}
    }
    Ok(())
}

fn is_tool_call(t: &str) -> bool {
    matches!(
        t,
        "function_call" | "custom_tool_call" | "local_shell_call" | "computer_call"
    )
}

fn is_tool_output(t: &str) -> bool {
    matches!(
        t,
        "function_call_output" | "custom_tool_call_output" | "local_shell_call_output"
    )
}

fn has_call_id(item: &Value) -> bool {
    opt_str(item, "call_id").is_some() || opt_str(item, "tool_call_id").is_some()
}

/// The id linking a call to its result, under any of its spellings.
fn call_id_of(item: &Value) -> String {
    opt_str(item, "call_id")
        .or_else(|| opt_str(item, "tool_call_id"))
        .or_else(|| opt_str(item, "id"))
        .unwrap_or_default()
        .to_string()
}

fn tool_call_message(item: &Value) -> Message {
    // `computer_call` names its tool only by its type, so fall back to that
    // rather than emitting a nameless call the upstream cannot dispatch.
    let name = opt_str(item, "name")
        .or_else(|| opt_str(item, "type"))
        .unwrap_or_default()
        .to_string();
    // Freeform tools carry their payload in `input`; `local_shell_call` in
    // `action`. Whichever is present, it becomes the call's arguments.
    let raw = opt_str(item, "arguments").or_else(|| opt_str(item, "input"));
    let input = match raw {
        Some(s) => parse_arguments(Some(s)),
        None => match item.get("action") {
            Some(a) => a.clone(),
            None => parse_arguments(None),
        },
    };
    Message::new(
        Role::Assistant,
        vec![ContentBlock::ToolUse { id: call_id_of(item), name, input }],
    )
}

fn tool_result_message(item: &Value, text: String) -> Message {
    Message::new(
        Role::Tool,
        vec![ContentBlock::ToolResult {
            tool_use_id: call_id_of(item),
            content: vec![ContentBlock::text(text)],
            is_error: false,
        }],
    )
}

/// Text of a `message`-shaped item, whose content may be a string or parts.
fn join_parts(item: &Value) -> String {
    match item.get("content") {
        Some(Value::String(s)) => s.clone(),
        other => other
            .map(|v| {
                parse_content_parts(Some(v))
                    .iter()
                    .filter_map(|b| match b {
                        ContentBlock::Text { text } => Some(text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default(),
    }
}

fn parse_content_parts(v: Option<&Value>) -> Vec<ContentBlock> {
    match v {
        Some(Value::String(s)) => vec![ContentBlock::text(s.clone())],
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| match opt_str(p, "type") {
                Some("input_text") | Some("output_text") | Some("text") => {
                    Some(ContentBlock::text(opt_str(p, "text").unwrap_or_default()))
                }
                Some("input_image") => {
                    let url = opt_str(p, "image_url").unwrap_or_default();
                    if let Some((media_type, data)) = parse_data_url(url) {
                        Some(ContentBlock::Image {
                            media_type: Some(media_type),
                            data: Some(data),
                            url: None,
                        })
                    } else {
                        Some(ContentBlock::Image {
                            media_type: None,
                            data: None,
                            url: Some(url.to_string()),
                        })
                    }
                }
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

/// Emit an IR request as an OpenAI Responses request body plus headers.
pub fn emit_request(req: &ChatRequest, opts: &EmitOptions) -> Result<EmittedRequest> {
    let mut body = Map::new();
    let model = if opts.target_model.is_empty() {
        req.model.clone()
    } else {
        opts.target_model.clone()
    };
    body.insert("model".into(), json!(model));
    // Some gateways require server-side storage off; default it false so a turn
    // is never persisted upstream.
    body.insert("store".into(), json!(false));

    if let Some(system) = &req.system {
        // The Responses `instructions` field is a single string.
        body.insert("instructions".into(), json!(join_text(system)));
    }

    // A Responses→Responses relay forwards the client's `input` untouched, so
    // provider-native items the IR cannot model — `reasoning` and its
    // `encrypted_content` above all — reach the upstream that understands
    // them. Rebuilding from `messages` would silently drop every one.
    // `instructions` is unaffected: it comes from the request's top-level
    // field, never from an input item, so there is nothing to duplicate.
    let input: Vec<Value> = match &req.native_input {
        Some(items) => items.clone(),
        None => {
            let mut out = Vec::new();
            for m in &req.messages {
                emit_input_items(m, &mut out)?;
            }
            out
        }
    };
    body.insert("input".into(), Value::Array(input));

    if !req.tools.is_empty() {
        let tools: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                let mut o = Map::new();
                o.insert("type".into(), json!("function"));
                o.insert("name".into(), json!(t.name));
                insert_opt(&mut o, "description", t.description.clone());
                o.insert("parameters".into(), t.input_schema.clone());
                Value::Object(o)
            })
            .collect();
        body.insert("tools".into(), Value::Array(tools));
    }
    if let Some(tc) = &req.tool_choice {
        body.insert("tool_choice".into(), emit_tool_choice(tc));
    }
    // NOTE: `max_output_tokens` is intentionally not emitted — some gateway
    // backends reject it as an unsupported parameter.
    insert_opt(&mut body, "temperature", req.temperature);
    insert_opt(&mut body, "top_p", req.top_p);
    if opts.stream {
        body.insert("stream".into(), json!(true));
    }
    let effort = opts
        .force_reasoning_effort
        .clone()
        .or_else(|| req.reasoning.as_ref().and_then(|r| r.effort.clone()));
    if let Some(effort) = effort {
        body.insert("reasoning".into(), json!({"effort": effort}));
    }
    // A cache key is always accompanied by a retention (default 24h).
    if let Some(key) = &req.prompt_cache_key {
        body.insert("prompt_cache_key".into(), json!(key));
        let retention = req.prompt_cache_retention.as_deref().unwrap_or("24h");
        body.insert("prompt_cache_retention".into(), json!(retention));
    }

    let bytes = serde_json::to_vec(&Value::Object(body))?;
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    Ok((bytes, headers))
}

fn emit_input_items(m: &Message, out: &mut Vec<Value>) -> Result<()> {
    match m.role {
        Role::System => {
            out.push(json!({"type": "message", "role": "system",
                "content": [{"type": "input_text", "text": m.text()}]}));
        }
        Role::Developer => {
            // Preserve `developer` verbatim: it may legally appear mid-conversation
            // (unlike `system`), and backends that convert Responses input to chat
            // reject a `system` message that is not first.
            out.push(json!({"type": "message", "role": "developer",
                "content": [{"type": "input_text", "text": m.text()}]}));
        }
        Role::User => {
            // Tool results inside a user turn become function_call_output items;
            // everything else becomes a user message.
            let mut parts: Vec<Value> = Vec::new();
            for b in &m.content {
                match b {
                    ContentBlock::ToolResult { tool_use_id, content, .. } => {
                        out.push(json!({"type": "function_call_output",
                            "call_id": tool_use_id, "output": join_text(content)}));
                    }
                    ContentBlock::Text { text } => {
                        parts.push(json!({"type": "input_text", "text": text}));
                    }
                    ContentBlock::Image { media_type, data, url } => {
                        let u = match (url, data) {
                            (Some(url), _) => url.clone(),
                            (None, Some(d)) => build_data_url(media_type.as_deref(), d),
                            _ => continue,
                        };
                        parts.push(json!({"type": "input_image", "image_url": u}));
                    }
                    _ => {}
                }
            }
            if !parts.is_empty() {
                out.push(json!({"type": "message", "role": "user", "content": parts}));
            }
        }
        Role::Tool => {
            for b in &m.content {
                if let ContentBlock::ToolResult { tool_use_id, content, .. } = b {
                    out.push(json!({"type": "function_call_output",
                        "call_id": tool_use_id, "output": join_text(content)}));
                }
            }
        }
        Role::Assistant => {
            let mut parts: Vec<Value> = Vec::new();
            for b in &m.content {
                match b {
                    ContentBlock::Text { text } => {
                        parts.push(json!({"type": "output_text", "text": text}));
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        // Flush any pending assistant text first so the message
                        // item precedes the function_call item, preserving order.
                        if !parts.is_empty() {
                            out.push(json!({"type": "message", "role": "assistant",
                                "content": std::mem::take(&mut parts)}));
                        }
                        out.push(json!({"type": "function_call", "call_id": id, "name": name,
                            "arguments": serde_json::to_string(input)?}));
                    }
                    _ => {}
                }
            }
            if !parts.is_empty() {
                out.push(json!({"type": "message", "role": "assistant", "content": parts}));
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Response
// ===========================================================================

/// Parse an OpenAI Responses response body into the IR.
pub fn parse_response(bytes: &[u8]) -> Result<ChatResponse> {
    let v: Value = serde_json::from_slice(bytes)?;
    let mut content: Vec<ContentBlock> = Vec::new();
    let mut saw_tool = false;
    if let Some(items) = opt_arr(&v, "output") {
        for item in items {
            match opt_str(item, "type") {
                Some("message") => {
                    content.extend(parse_content_parts(item.get("content")));
                }
                Some("function_call") => {
                    saw_tool = true;
                    content.push(ContentBlock::ToolUse {
                        id: opt_str(item, "call_id")
                            .or_else(|| opt_str(item, "id"))
                            .unwrap_or_default()
                            .to_string(),
                        name: opt_str(item, "name").unwrap_or_default().to_string(),
                        input: parse_arguments(opt_str(item, "arguments")),
                    });
                }
                Some("reasoning") => {
                    let text = item
                        .get("summary")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|s| opt_str(s, "text"))
                                .collect::<Vec<_>>()
                                .join("")
                        })
                        .unwrap_or_default();
                    if !text.is_empty() {
                        content.push(ContentBlock::Thinking { text });
                    }
                }
                _ => {}
            }
        }
    }

    let stop_reason = match opt_str(&v, "status") {
        Some("incomplete") => {
            let reason = v
                .get("incomplete_details")
                .and_then(|d| opt_str(d, "reason"));
            if reason == Some("max_output_tokens") {
                StopReason::MaxTokens
            } else {
                StopReason::Other(reason.unwrap_or("incomplete").to_string())
            }
        }
        _ if saw_tool => StopReason::ToolUse,
        _ => StopReason::EndTurn,
    };

    Ok(ChatResponse {
        id: opt_str(&v, "id").unwrap_or_default().to_string(),
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        content,
        stop_reason,
        usage: parse_usage(v.get("usage")),
        // The Responses response object echoes the request's cache fields.
        prompt_cache_key: opt_str(&v, "prompt_cache_key").map(str::to_string),
        prompt_cache_retention: opt_str(&v, "prompt_cache_retention").map(str::to_string),
    })
}

/// Emit an IR response as an OpenAI Responses response body.
pub fn emit_response(resp: &ChatResponse) -> Result<Vec<u8>> {
    let mut output: Vec<Value> = Vec::new();
    let mut text_parts: Vec<Value> = Vec::new();
    for b in &resp.content {
        match b {
            ContentBlock::Text { text } => {
                text_parts.push(json!({"type": "output_text", "text": text}));
            }
            ContentBlock::ToolUse { id, name, input } => {
                if !text_parts.is_empty() {
                    output.push(json!({"type": "message", "role": "assistant",
                        "content": std::mem::take(&mut text_parts)}));
                }
                output.push(json!({"type": "function_call", "call_id": id, "name": name,
                    "arguments": serde_json::to_string(input)?, "status": "completed"}));
            }
            _ => {}
        }
    }
    if !text_parts.is_empty() {
        output.push(json!({"type": "message", "role": "assistant", "content": text_parts}));
    }

    let u = &resp.usage;
    let mut body = json!({
        "id": resp.id,
        "object": "response",
        "model": resp.model,
        "status": "completed",
        "output": output,
        "usage": {
            "input_tokens": u.input_tokens,
            "output_tokens": u.output_tokens,
            "total_tokens": u.input_tokens + u.output_tokens,
            "input_tokens_details": {"cached_tokens": u.cache_read_tokens},
        },
    });
    // The Responses response object echoes the prompt-cache fields.
    if let (Some(obj), Some(key)) = (body.as_object_mut(), &resp.prompt_cache_key) {
        obj.insert("prompt_cache_key".into(), json!(key));
        let retention = resp.prompt_cache_retention.as_deref().unwrap_or("24h");
        obj.insert("prompt_cache_retention".into(), json!(retention));
    }
    Ok(serde_json::to_vec(&body)?)
}

fn parse_usage(v: Option<&Value>) -> Usage {
    let Some(v) = v else { return Usage::default() };
    let cache_read = v
        .get("input_tokens_details")
        .and_then(|d| opt_u32(d, "cached_tokens"))
        .unwrap_or(0);
    Usage {
        input_tokens: opt_u32(v, "input_tokens").unwrap_or(0),
        output_tokens: opt_u32(v, "output_tokens").unwrap_or(0),
        cache_read_tokens: cache_read,
        cache_write_tokens: 0,
    }
}

// ===========================================================================
// Shared helpers
// ===========================================================================

fn output_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| opt_str(p, "text"))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

fn parse_arguments(s: Option<&str>) -> Value {
    match s {
        Some(s) if !s.is_empty() => serde_json::from_str(s).unwrap_or_else(|_| json!(s)),
        _ => json!({}),
    }
}

fn join_text(blocks: &[ContentBlock]) -> String {
    let mut s = String::new();
    for b in blocks {
        if let ContentBlock::Text { text } = b {
            s.push_str(text);
        }
    }
    s
}

fn parse_tool_choice(v: &Value) -> Result<ToolChoice> {
    match v {
        Value::String(s) => match s.as_str() {
            "auto" => Ok(ToolChoice::Auto),
            "none" => Ok(ToolChoice::None),
            "required" => Ok(ToolChoice::Required),
            other => Err(WireError::invalid("tool_choice", format!("unknown {other}"))),
        },
        Value::Object(_) => Ok(ToolChoice::Tool(
            opt_str(v, "name").unwrap_or_default().to_string(),
        )),
        _ => Err(WireError::invalid("tool_choice", "expected string or object")),
    }
}

fn emit_tool_choice(tc: &ToolChoice) -> Value {
    match tc {
        ToolChoice::Auto => json!("auto"),
        ToolChoice::None => json!("none"),
        ToolChoice::Required => json!("required"),
        ToolChoice::Tool(name) => json!({"type": "function", "name": name}),
    }
}

// ===========================================================================
// Streaming
// ===========================================================================

/// Decoder state for an OpenAI Responses upstream SSE stream.
#[derive(Debug, Default)]
pub struct SseState {
    stop_reason: Option<StopReason>,
}

/// Decode one line of an OpenAI Responses SSE stream into IR events.
pub fn decode_sse(line: &str, state: &mut SseState) -> Vec<StreamEvent> {
    let Some(data) = crate::anthropic::sse_data(line) else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<Value>(data) else {
        return vec![];
    };
    match opt_str(&v, "type") {
        Some("response.created") => {
            let model = v
                .get("response")
                .and_then(|r| opt_str(r, "model"))
                .unwrap_or_default();
            vec![StreamEvent::MessageStart { model: model.to_string() }]
        }
        // `response.in_progress` repeats the created envelope — already handled.
        Some("response.in_progress") => vec![],
        Some("response.output_text.delta") => vec![StreamEvent::TextDelta {
            text: opt_str(&v, "delta").unwrap_or_default().to_string(),
        }],
        // vLLM streams `reasoning_text.delta`; OpenAI uses `reasoning_summary_text.delta`.
        Some("response.reasoning_text.delta") | Some("response.reasoning_summary_text.delta") => {
            vec![StreamEvent::ThinkingDelta {
                text: opt_str(&v, "delta").unwrap_or_default().to_string(),
            }]
        }
        Some("response.output_item.added") => {
            let item = v.get("item").unwrap_or(&Value::Null);
            if opt_str(item, "type") == Some("function_call") {
                state.stop_reason = Some(StopReason::ToolUse);
                vec![StreamEvent::ToolUseStart {
                    id: opt_str(item, "call_id").unwrap_or_default().to_string(),
                    name: opt_str(item, "name").unwrap_or_default().to_string(),
                }]
            } else {
                vec![]
            }
        }
        Some("response.function_call_arguments.delta") => vec![StreamEvent::ToolUseDelta {
            partial_json: opt_str(&v, "delta").unwrap_or_default().to_string(),
        }],
        Some("response.completed") | Some("response.incomplete") => {
            let mut out = Vec::new();
            // An interim `response.*` event can carry `"usage": null`; parsing
            // that would push an all-zero delta over a real one.
            if let Some(u) = v
                .get("response")
                .and_then(|r| r.get("usage"))
                .filter(|u| !u.is_null())
            {
                out.push(StreamEvent::UsageDelta { usage: parse_usage(Some(u)) });
            }
            out.push(StreamEvent::Done {
                stop_reason: state.stop_reason.take().unwrap_or(StopReason::EndTurn),
            });
            out
        }
        _ => vec![],
    }
}

/// Encoder state for producing an OpenAI Responses client SSE stream.
#[derive(Debug, Default)]
pub struct EmitState {
    model: String,
    seq: u64,
    usage: Option<Usage>,
    resp_id: String,
    /// Prompt-cache echo for the response envelopes (see [`ChatResponse`]);
    /// seeded from the client request by the gateway.
    prompt_cache_key: Option<String>,
    prompt_cache_retention: Option<String>,
    /// The next `output_index` to assign.
    next_index: u64,
    /// The currently-open output item, if any.
    open: Option<OpenItem>,
    /// Completed items, assembled into `response.completed`.
    done_items: Vec<Value>,
    /// `response.completed` held back until usage arrives.
    ///
    /// Unlike Chat Completions, the Responses API always reports usage on the
    /// terminal event — there is no `include_usage` to opt into. But an
    /// OpenAI-compatible *upstream* sends usage on a line after the one
    /// carrying `finish_reason`, so `Done` reaches this encoder first. Emitting
    /// `response.completed` there would publish `usage: null` and lose the
    /// counts, which is what a metering client reads.
    pending_completed: bool,
}

impl EmitState {
    /// Seed the prompt-cache echo carried on `response.created` / `.completed`.
    pub fn set_prompt_cache(&mut self, key: Option<String>, retention: Option<String>) {
        self.prompt_cache_key = key;
        self.prompt_cache_retention = retention;
    }
}

#[derive(Debug, Clone)]
enum OpenItem {
    Message { id: String, index: u64, text: String },
    Reasoning { id: String, index: u64, text: String },
    Tool { id: String, index: u64, call_id: String, name: String, args: String },
}

/// Encode IR events into OpenAI Responses client SSE bytes, emitting the full
/// item/part lifecycle (`output_item.added` → `content_part.added` → deltas →
/// `*.done`) that strict clients (e.g. codex) require — not just bare deltas.
pub fn encode_sse(events: &[StreamEvent], state: &mut EmitState) -> Vec<u8> {
    let mut out = String::new();
    for ev in events {
        match ev {
            StreamEvent::MessageStart { model } => {
                state.model = model.clone();
                if state.resp_id.is_empty() {
                    state.resp_id = "resp_stream".to_string();
                }
                let resp = state.response_obj("in_progress", json!([]));
                write_event(&mut out, state, "response.created",
                    json!({"type": "response.created", "response": resp.clone()}));
                write_event(&mut out, state, "response.in_progress",
                    json!({"type": "response.in_progress", "response": resp}));
            }
            StreamEvent::TextDelta { text } => {
                ensure_message(&mut out, state);
                let (id, index) = match state.open.as_mut() {
                    Some(OpenItem::Message { id, index, text: acc }) => {
                        acc.push_str(text);
                        (id.clone(), *index)
                    }
                    _ => continue,
                };
                write_event(&mut out, state, "response.output_text.delta", json!({
                    "type": "response.output_text.delta", "item_id": id,
                    "output_index": index, "content_index": 0, "delta": text, "logprobs": []}));
            }
            StreamEvent::ThinkingDelta { text } => {
                ensure_reasoning(&mut out, state);
                let (id, index) = match state.open.as_mut() {
                    Some(OpenItem::Reasoning { id, index, text: acc }) => {
                        acc.push_str(text);
                        (id.clone(), *index)
                    }
                    _ => continue,
                };
                write_event(&mut out, state, "response.reasoning_text.delta", json!({
                    "type": "response.reasoning_text.delta", "item_id": id,
                    "output_index": index, "content_index": 0, "delta": text}));
            }
            StreamEvent::ToolUseStart { id, name } => {
                close_open(&mut out, state);
                let index = state.next_index;
                state.next_index += 1;
                let item_id = format!("fc_{index}");
                write_event(&mut out, state, "response.output_item.added", json!({
                    "type": "response.output_item.added", "output_index": index,
                    "item": {"id": item_id, "type": "function_call", "call_id": id,
                             "name": name, "arguments": "", "status": "in_progress"}}));
                state.open = Some(OpenItem::Tool {
                    id: item_id, index, call_id: id.clone(), name: name.clone(), args: String::new(),
                });
            }
            StreamEvent::ToolUseDelta { partial_json } => {
                if let Some(OpenItem::Tool { id, index, args, .. }) = state.open.as_mut() {
                    args.push_str(partial_json);
                    let (id, index) = (id.clone(), *index);
                    write_event(&mut out, state, "response.function_call_arguments.delta", json!({
                        "type": "response.function_call_arguments.delta",
                        "item_id": id, "output_index": index, "delta": partial_json}));
                }
            }
            StreamEvent::UsageDelta { usage } => {
                state.usage.get_or_insert_default().merge(usage);
                // The usage `response.completed` was waiting on.
                if state.pending_completed {
                    state.pending_completed = false;
                    write_completed(&mut out, state);
                }
            }
            StreamEvent::Done { .. } => {
                // Close any open item now; only the terminal event waits.
                close_open(&mut out, state);
                if state.usage.is_some() {
                    write_completed(&mut out, state);
                } else {
                    state.pending_completed = true;
                }
            }
        }
    }
    out.into_bytes()
}

/// Write the terminal `response.completed` event.
fn write_completed(out: &mut String, state: &mut EmitState) {
    let resp = state.response_obj("completed", json!(state.done_items.clone()));
    write_event(out, state, "response.completed",
        json!({"type": "response.completed", "response": resp}));
}

impl EmitState {
    /// Close a stream that ended while still waiting for usage.
    ///
    /// Emits the deferred `response.completed` — with a null `usage`, which is
    /// the honest report when the upstream never sent any — so the client is
    /// never left without a terminal event.
    pub fn finish(&mut self) -> Vec<u8> {
        if !self.pending_completed {
            return Vec::new();
        }
        self.pending_completed = false;
        let mut out = String::new();
        write_completed(&mut out, self);
        out.into_bytes()
    }

    fn response_obj(&self, status: &str, output: Value) -> Value {
        let usage = self.usage.map(|u| json!({
            "input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
            "total_tokens": u.input_tokens + u.output_tokens})).unwrap_or(Value::Null);
        let mut resp = json!({"id": self.resp_id, "object": "response", "status": status,
               "model": self.model, "output": output, "usage": usage});
        if let (Some(obj), Some(key)) = (resp.as_object_mut(), &self.prompt_cache_key) {
            obj.insert("prompt_cache_key".into(), json!(key));
            let retention = self.prompt_cache_retention.as_deref().unwrap_or("24h");
            obj.insert("prompt_cache_retention".into(), json!(retention));
        }
        resp
    }
}

/// Open a message item (with its text content part) if one isn't already open.
fn ensure_message(out: &mut String, state: &mut EmitState) {
    if matches!(state.open, Some(OpenItem::Message { .. })) {
        return;
    }
    close_open(out, state);
    let index = state.next_index;
    state.next_index += 1;
    let id = format!("msg_{index}");
    write_event(out, state, "response.output_item.added", json!({
        "type": "response.output_item.added", "output_index": index,
        "item": {"id": id, "type": "message", "role": "assistant", "content": [], "status": "in_progress"}}));
    write_event(out, state, "response.content_part.added", json!({
        "type": "response.content_part.added", "item_id": id, "output_index": index,
        "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}}));
    state.open = Some(OpenItem::Message { id, index, text: String::new() });
}

/// Open a reasoning item (with its text part) if one isn't already open.
fn ensure_reasoning(out: &mut String, state: &mut EmitState) {
    if matches!(state.open, Some(OpenItem::Reasoning { .. })) {
        return;
    }
    close_open(out, state);
    let index = state.next_index;
    state.next_index += 1;
    let id = format!("rs_{index}");
    write_event(out, state, "response.output_item.added", json!({
        "type": "response.output_item.added", "output_index": index,
        "item": {"id": id, "type": "reasoning", "summary": [], "content": null, "status": "in_progress"}}));
    write_event(out, state, "response.reasoning_part.added", json!({
        "type": "response.reasoning_part.added", "item_id": id, "output_index": index,
        "content_index": 0, "part": {"type": "reasoning_text", "text": ""}}));
    state.open = Some(OpenItem::Reasoning { id, index, text: String::new() });
}

/// Close the currently-open item, emitting its `*.done` events and recording the
/// finished item for `response.completed`.
fn close_open(out: &mut String, state: &mut EmitState) {
    let Some(item) = state.open.take() else { return };
    match item {
        OpenItem::Message { id, index, text } => {
            write_event(out, state, "response.output_text.done", json!({
                "type": "response.output_text.done", "item_id": id, "output_index": index,
                "content_index": 0, "text": text, "logprobs": []}));
            write_event(out, state, "response.content_part.done", json!({
                "type": "response.content_part.done", "item_id": id, "output_index": index,
                "content_index": 0, "part": {"type": "output_text", "text": text, "annotations": []}}));
            let item = json!({"id": id, "type": "message", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}]});
            write_event(out, state, "response.output_item.done",
                json!({"type": "response.output_item.done", "output_index": index, "item": item.clone()}));
            state.done_items.push(item);
        }
        OpenItem::Reasoning { id, index, text } => {
            write_event(out, state, "response.reasoning_text.done", json!({
                "type": "response.reasoning_text.done", "item_id": id, "output_index": index,
                "content_index": 0, "text": text}));
            write_event(out, state, "response.reasoning_part.done", json!({
                "type": "response.reasoning_part.done", "item_id": id, "output_index": index,
                "content_index": 0, "part": {"type": "reasoning_text", "text": text}}));
            let item = json!({"id": id, "type": "reasoning", "summary": [], "status": "completed",
                "content": [{"type": "reasoning_text", "text": text}]});
            write_event(out, state, "response.output_item.done",
                json!({"type": "response.output_item.done", "output_index": index, "item": item.clone()}));
            state.done_items.push(item);
        }
        OpenItem::Tool { id, index, call_id, name, args } => {
            write_event(out, state, "response.function_call_arguments.done", json!({
                "type": "response.function_call_arguments.done", "item_id": id,
                "output_index": index, "arguments": args}));
            let item = json!({"id": id, "type": "function_call", "call_id": call_id,
                "name": name, "arguments": args, "status": "completed"});
            write_event(out, state, "response.output_item.done",
                json!({"type": "response.output_item.done", "output_index": index, "item": item.clone()}));
            state.done_items.push(item);
        }
    }
}

fn write_event(out: &mut String, state: &mut EmitState, name: &str, mut data: Value) {
    // The Responses API tags every SSE event with a monotonic sequence number.
    if let Some(obj) = data.as_object_mut() {
        obj.insert("sequence_number".into(), json!(state.seq));
    }
    state.seq += 1;
    out.push_str("event: ");
    out.push_str(name);
    out.push('\n');
    out.push_str("data: ");
    out.push_str(&data.to_string());
    out.push_str("\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::StopReason;

    fn encode_all(events: &[StreamEvent]) -> String {
        let mut st = EmitState::default();
        let mut out = encode_sse(events, &mut st);
        out.extend(st.finish());
        String::from_utf8(out).unwrap()
    }

    fn completed(sse: &str) -> Value {
        sse.lines()
            .filter(|l| l.starts_with("data:"))
            .map(|l| serde_json::from_str::<Value>(l[5..].trim()).unwrap())
            .find(|v| v["type"] == "response.completed")
            .expect("a response.completed event")
    }

    /// The Responses API always reports usage on its terminal event — there is
    /// no `include_usage` to opt into — but an OpenAI-compatible upstream sends
    /// usage on the line *after* the finish reason. `Done` therefore reaches
    /// the encoder first, and emitting `response.completed` there published
    /// `usage: null` and lost the counts a metering client reads.
    #[test]
    fn usage_arriving_after_done_still_lands_on_response_completed() {
        let sse = encode_all(&[
            StreamEvent::MessageStart { model: "k3".into() },
            StreamEvent::TextDelta { text: "ok".into() },
            StreamEvent::Done { stop_reason: StopReason::EndTurn },
            StreamEvent::UsageDelta {
                usage: Usage { input_tokens: 88, output_tokens: 35, ..Default::default() },
            },
        ]);
        let c = completed(&sse);
        assert_eq!(c["response"]["status"], "completed");
        assert_eq!(c["response"]["usage"]["input_tokens"], 88);
        assert_eq!(c["response"]["usage"]["output_tokens"], 35);
        assert_eq!(c["response"]["usage"]["total_tokens"], 123);
    }

    /// Usage that shares the terminal event (a Responses upstream) is emitted
    /// immediately, and the completed event is written exactly once.
    #[test]
    fn usage_before_done_emits_completed_once() {
        let sse = encode_all(&[
            StreamEvent::MessageStart { model: "k3".into() },
            StreamEvent::UsageDelta {
                usage: Usage { input_tokens: 1, output_tokens: 2, ..Default::default() },
            },
            StreamEvent::Done { stop_reason: StopReason::EndTurn },
        ]);
        assert_eq!(sse.matches("response.completed").count(), 2, "one event, named twice: {sse}");
        assert_eq!(completed(&sse)["response"]["usage"]["total_tokens"], 3);
    }

    /// An upstream that hangs up without ever sending usage must still leave
    /// the client with a terminal event — holding it back forever would strand
    /// the stream. A null `usage` is the honest report.
    #[test]
    fn a_stream_that_never_reports_usage_still_completes() {
        let sse = encode_all(&[
            StreamEvent::MessageStart { model: "k3".into() },
            StreamEvent::TextDelta { text: "ok".into() },
            StreamEvent::Done { stop_reason: StopReason::EndTurn },
        ]);
        let c = completed(&sse);
        assert_eq!(c["response"]["status"], "completed");
        assert_eq!(c["response"]["usage"], Value::Null);
    }
}

#[cfg(test)]
mod tool_pairing_tests {
    use super::*;
    use crate::EmitOptions;

    /// Translate a Responses `input` history into the chat body we'd send
    /// upstream, and report the role of each message.
    fn upstream_roles(input: Value) -> Vec<String> {
        let body = json!({"model": "m", "input": input, "stream": true});
        let req = parse_request(&serde_json::to_vec(&body).unwrap()).unwrap();
        let (bytes, _) =
            crate::openai_chat::emit_request(&req, &EmitOptions::new("k3".to_string())).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                let role = m["role"].as_str().unwrap().to_string();
                if m.get("tool_calls").is_some() {
                    format!("{role}+tool_calls")
                } else {
                    role
                }
            })
            .collect()
    }

    fn call_item(kind: &str, id: &str) -> Value {
        match kind {
            "custom_tool_call" => json!({"type": kind, "call_id": id, "name": "exec_command",
                                         "input": "echo hi"}),
            "local_shell_call" => json!({"type": kind, "call_id": id, "name": "exec_command",
                                         "action": {"command": ["echo", "hi"]}}),
            _ => json!({"type": kind, "call_id": id, "name": "exec_command", "arguments": "{}"}),
        }
    }

    /// Every tool-exchange spelling must yield an assistant `tool_calls`
    /// followed by an answering `tool` message.
    ///
    /// Without this, `custom_tool_call_output` (Codex freeform tools, e.g.
    /// `exec_command`) and `local_shell_call_output` fell through a catch-all
    /// and vanished, and a `role: "tool"` message was demoted to `user`. The
    /// upstream then rejected the whole turn:
    ///
    /// > The following tool_call_ids did not have response messages:
    /// > exec_command:0
    #[test]
    fn every_tool_exchange_spelling_pairs_call_with_result() {
        let id = "exec_command:0";
        let cases: Vec<(&str, Value, Value)> = vec![
            ("function_call", call_item("function_call", id),
             json!({"type": "function_call_output", "call_id": id, "output": "hi"})),
            ("custom_tool_call", call_item("custom_tool_call", id),
             json!({"type": "custom_tool_call_output", "call_id": id, "output": "hi"})),
            ("local_shell_call", call_item("local_shell_call", id),
             json!({"type": "local_shell_call_output", "call_id": id, "output": "hi"})),
            // A result delivered as a message with role `tool`.
            ("message role=tool", call_item("function_call", id),
             json!({"type": "message", "role": "tool", "tool_call_id": id, "content": "hi"})),
            // An unknown vocabulary, matched on shape alone.
            ("unknown_tool_call_output", call_item("function_call", id),
             json!({"type": "some_future_tool_output", "call_id": id, "output": "hi"})),
            // `computer_call` names its tool only by its type, and its args
            // live in `action`. Without both fallbacks the call was dropped
            // while its output survived — an orphan `tool` message, which an
            // upstream rejects just as surely as an unanswered call.
            ("computer_call",
             json!({"type": "computer_call", "call_id": id,
                    "action": {"type": "screenshot"}}),
             json!({"type": "computer_call_output", "call_id": id,
                    "output": {"type": "computer_screenshot"}})),
        ];
        for (label, call, result) in cases {
            let roles = upstream_roles(json!([call, result]));
            assert_eq!(
                roles,
                vec!["assistant+tool_calls".to_string(), "tool".to_string()],
                "{label}: a tool_calls message must be answered by a tool message, got {roles:?}"
            );
        }
    }

    /// The id must survive under every spelling, or the upstream cannot match
    /// the result to the call even when both messages are present.
    #[test]
    fn the_call_id_survives_translation() {
        let id = "exec_command:0";
        let body = json!({"model": "m", "stream": true, "input": [
            call_item("custom_tool_call", id),
            json!({"type": "custom_tool_call_output", "call_id": id, "output": "hi"}),
        ]});
        let req = parse_request(&serde_json::to_vec(&body).unwrap()).unwrap();
        let (bytes, _) =
            crate::openai_chat::emit_request(&req, &EmitOptions::new("k3".to_string())).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let msgs = v["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["tool_calls"][0]["id"], id);
        assert_eq!(msgs[0]["tool_calls"][0]["function"]["name"], "exec_command");
        assert_eq!(msgs[1]["tool_call_id"], id);
        assert_eq!(msgs[1]["content"], "hi");
    }

    /// `mcp_call` carries both halves of an exchange in one item, keyed on
    /// `id` rather than `call_id`, so it was dropped entirely.
    #[test]
    fn an_mcp_call_yields_both_halves() {
        let roles = upstream_roles(json!([
            {"type": "mcp_call", "id": "m:0", "name": "search",
             "arguments": "{}", "output": "found", "server_label": "s"}
        ]));
        assert_eq!(roles, vec!["assistant+tool_calls".to_string(), "tool".to_string()]);
    }

    /// A `developer` (or `system`) instruction sent inline in `input` must
    /// reach every upstream, including the ones that carry the system prompt
    /// out-of-band.
    ///
    /// Anthropic and Gemini build their system field from `req.system` alone,
    /// and their message mappers skip those roles — so an inline instruction
    /// reached neither, and vanished with no error at all. That is worse than
    /// the chat surface's `role 'developer' is not allowed`, which at least
    /// fails loudly.
    #[test]
    fn an_inline_developer_instruction_reaches_every_upstream() {
        let body = json!({"model":"m","stream":false,"input":[
            {"type":"message","role":"developer","content":"SENTINEL-INSTRUCTION"},
            {"type":"message","role":"user","content":"hi"}]});
        let req = parse_request(&serde_json::to_vec(&body).unwrap()).unwrap();
        let opts = EmitOptions::new("t");
        for (name, bytes) in [
            ("anthropic", crate::anthropic::emit_request(&req, &opts).unwrap().0),
            ("gemini", crate::gemini::emit_request(&req, &opts).unwrap().0),
            ("openai_chat", crate::openai_chat::emit_request(&req, &opts).unwrap().0),
            ("openai_responses", crate::openai_responses::emit_request(&req, &opts).unwrap().0),
        ] {
            let s = String::from_utf8(bytes).unwrap();
            assert!(
                s.contains("SENTINEL-INSTRUCTION"),
                "{name}: the developer instruction was dropped"
            );
        }
    }

    /// A Responses→Responses relay must forward provider-native items, not
    /// normalize them away.
    ///
    /// The IR has no home for `reasoning` (least of all its
    /// `encrypted_content`), `web_search_call`, `code_interpreter_call` or
    /// `item_reference`, so rebuilding the request from `messages` dropped
    /// every one — silently, and with real cost: a reasoning model expects its
    /// reasoning items echoed back.
    #[test]
    fn a_same_shape_relay_forwards_provider_native_items() {
        let input = json!([
            {"type":"message","role":"user","content":"hi"},
            {"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"ENCRYPTED-BLOB"},
            {"type":"web_search_call","id":"ws_1","status":"completed"},
            {"type":"code_interpreter_call","id":"ci_1","code":"1+1"},
            {"type":"item_reference","id":"ir_1"},
        ]);
        let body = json!({"model":"m","stream":false,"input":input.clone()});
        let req = parse_request(&serde_json::to_vec(&body).unwrap()).unwrap();
        let (out, _) = emit_request(&req, &EmitOptions::new("t")).unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["input"], input, "the client's input array must survive verbatim");
        // And `instructions` is not conjured from the inline items.
        assert!(v.get("instructions").is_none());
    }

    /// Top-level `instructions` still round-trips, and is not duplicated into
    /// the replayed `input`.
    #[test]
    fn top_level_instructions_survive_a_same_shape_relay() {
        let body = json!({"model":"m","stream":false,"instructions":"BE-TERSE",
                          "input":[{"type":"message","role":"user","content":"hi"}]});
        let req = parse_request(&serde_json::to_vec(&body).unwrap()).unwrap();
        let (out, _) = emit_request(&req, &EmitOptions::new("t")).unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["instructions"], "BE-TERSE");
        assert_eq!(v["input"].as_array().unwrap().len(), 1, "no duplicated instruction item");
    }

    /// Cross-shape translation still normalizes: a chat upstream cannot act on
    /// a `reasoning` item, so it must not be forwarded there.
    #[test]
    fn a_cross_shape_relay_still_normalizes() {
        let body = json!({"model":"m","stream":false,"input":[
            {"type":"message","role":"user","content":"hi"},
            {"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"ENCRYPTED-BLOB"}]});
        let req = parse_request(&serde_json::to_vec(&body).unwrap()).unwrap();
        let (out, _) =
            crate::openai_chat::emit_request(&req, &EmitOptions::new("t")).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("ENCRYPTED-BLOB"), "a chat upstream must not receive reasoning items");
        assert!(s.contains("\"role\":\"user\""));
    }

    /// An item with no tool linkage at all is still ignored — the shape
    /// fallback must not turn arbitrary metadata into a phantom tool message.
    #[test]
    fn items_without_tool_linkage_are_ignored() {
        let roles = upstream_roles(json!([
            {"type": "reasoning", "summary": []},
            {"type": "some_future_thing", "note": "no call_id here"},
            // id + name, but no tool exchange to relay — must not become a
            // phantom tool call, which is why the shape fallback keys on
            // `call_id` and never on a bare `id`.
            {"type": "mcp_approval_request", "id": "a:0", "name": "search"},
            {"type": "item_reference", "id": "r:0"},
            {"type": "message", "role": "user", "content": "hi"},
        ]));
        assert_eq!(roles, vec!["user".to_string()]);
    }
}



