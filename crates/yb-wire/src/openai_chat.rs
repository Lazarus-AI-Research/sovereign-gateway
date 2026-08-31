//! The OpenAI Chat Completions wire format (`POST /v1/chat/completions`).
//!
//! The main structural differences from the IR: the system prompt is the first
//! `system` message; tool results are standalone `tool` messages (not blocks
//! inside a user turn); and a tool call's arguments are a JSON *string* rather
//! than a JSON value. The emit path therefore splits IR tool-result blocks out
//! into their own messages.

use crate::common::*;
use crate::error::{Result, WireError};
use crate::ir::*;
use crate::{EmitOptions, EmittedRequest};
use serde_json::{json, Map, Value};

// ===========================================================================
// Request
// ===========================================================================

/// Parse an OpenAI Chat Completions request body into the IR.
pub fn parse_request(bytes: &[u8]) -> Result<ChatRequest> {
    let v: Value = serde_json::from_slice(bytes)?;
    v.as_object()
        .ok_or_else(|| WireError::InvalidRequest("body is not a JSON object".into()))?;

    let mut req = ChatRequest {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        stream: opt_bool(&v, "stream"),
        max_tokens: opt_u32(&v, "max_tokens").or_else(|| opt_u32(&v, "max_completion_tokens")),
        temperature: opt_f32(&v, "temperature"),
        top_p: opt_f32(&v, "top_p"),
        stop: parse_stop(v.get("stop")),
        ..Default::default()
    };

    let mut system: Vec<ContentBlock> = Vec::new();
    if let Some(msgs) = opt_arr(&v, "messages") {
        for m in msgs {
            match opt_str(m, "role") {
                Some("system") | Some("developer") => {
                    system.extend(parse_user_content(m.get("content")));
                }
                Some("user") => {
                    req.messages
                        .push(Message::new(Role::User, parse_user_content(m.get("content"))));
                }
                Some("assistant") => {
                    req.messages.push(Message::new(Role::Assistant, parse_assistant(m)?));
                }
                Some("tool") => {
                    let tool_use_id = opt_str(m, "tool_call_id").unwrap_or_default().to_string();
                    let content = parse_user_content(m.get("content"));
                    req.messages.push(Message::new(
                        Role::Tool,
                        vec![ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error: false,
                        }],
                    ));
                }
                Some(other) => {
                    return Err(WireError::invalid("messages[].role", format!("unknown {other}")))
                }
                None => return Err(WireError::missing("messages[].role")),
            }
        }
    }
    if !system.is_empty() {
        req.system = Some(system);
    }

    if let Some(tools) = opt_arr(&v, "tools") {
        for t in tools {
            let f = t.get("function").unwrap_or(t);
            req.tools.push(Tool {
                name: req_str(f, "name")?.to_string(),
                description: opt_str(f, "description").map(str::to_string),
                input_schema: f.get("parameters").cloned().unwrap_or(json!({})),
            });
        }
    }

    if let Some(tc) = v.get("tool_choice") {
        req.tool_choice = Some(parse_tool_choice(tc)?);
    }

    if let Some(effort) = opt_str(&v, "reasoning_effort") {
        req.reasoning = Some(Reasoning {
            effort: Some(effort.to_string()),
            budget_tokens: None,
        });
    }
    req.prompt_cache_key = opt_str(&v, "prompt_cache_key").map(str::to_string);
    req.prompt_cache_retention = opt_str(&v, "prompt_cache_retention").map(str::to_string);

    Ok(req)
}

/// Emit an IR request as an OpenAI Chat Completions request body plus headers.
pub fn emit_request(req: &ChatRequest, opts: &EmitOptions) -> Result<EmittedRequest> {
    let mut body = Map::new();
    let model = if opts.target_model.is_empty() {
        req.model.clone()
    } else {
        opts.target_model.clone()
    };
    body.insert("model".into(), json!(model));
    body.insert("messages".into(), Value::Array(emit_messages(req)?));

    if !req.tools.is_empty() {
        let tools: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                let mut f = Map::new();
                f.insert("name".into(), json!(t.name));
                insert_opt(&mut f, "description", t.description.clone());
                f.insert("parameters".into(), t.input_schema.clone());
                json!({"type": "function", "function": Value::Object(f)})
            })
            .collect();
        body.insert("tools".into(), Value::Array(tools));
    }
    if let Some(tc) = &req.tool_choice {
        body.insert("tool_choice".into(), emit_tool_choice(tc));
    }

    insert_opt(&mut body, "max_tokens", req.max_tokens);
    insert_opt(&mut body, "temperature", req.temperature);
    insert_opt(&mut body, "top_p", req.top_p);
    if !req.stop.is_empty() {
        body.insert("stop".into(), json!(req.stop));
    }
    if opts.stream {
        body.insert("stream".into(), json!(true));
        // An OpenAI-compatible server sends no usage at all in streaming mode
        // unless this is set — the token counts simply never arrive. The gateway
        // always streams upstream (it aggregates for non-streaming clients), so
        // without this every request through a Chat Completions upstream would
        // bill and report zero. Asking for usage costs nothing when the server
        // would have sent it anyway.
        body.insert("stream_options".into(), json!({"include_usage": true}));
    }

    let effort = opts
        .force_reasoning_effort
        .clone()
        .or_else(|| req.reasoning.as_ref().and_then(|r| r.effort.clone()));
    insert_opt(&mut body, "reasoning_effort", effort);

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

/// Expand IR messages into OpenAI messages, hoisting `system` and splitting
/// tool-result blocks into standalone `tool` messages.
fn emit_messages(req: &ChatRequest) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    if let Some(system) = &req.system {
        out.push(json!({"role": "system", "content": join_text(system)}));
    }
    for m in &req.messages {
        match m.role {
            Role::System => {
                out.push(json!({"role": "system", "content": m.text()}));
            }
            Role::Developer => {
                out.push(json!({"role": "developer", "content": m.text()}));
            }
            Role::Assistant => out.push(emit_assistant(m)?),
            Role::User | Role::Tool => {
                // Tool results become their own `tool` messages; anything else
                // stays in a `user` message (emitted after the tool results).
                let mut others: Vec<&ContentBlock> = Vec::new();
                for b in &m.content {
                    if let ContentBlock::ToolResult { tool_use_id, content, .. } = b {
                        out.push(json!({
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": join_text(content),
                        }));
                    } else {
                        others.push(b);
                    }
                }
                if !others.is_empty() {
                    out.push(json!({"role": "user", "content": emit_user_content(&others)}));
                }
            }
        }
    }
    Ok(out)
}

fn emit_assistant(m: &Message) -> Result<Value> {
    let mut text = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for b in &m.content {
        match b {
            ContentBlock::Text { text: t } => text.push_str(t),
            ContentBlock::ToolUse { id, name, input } => {
                tool_calls.push(json!({
                    "id": id,
                    "type": "function",
                    "function": {"name": name, "arguments": serde_json::to_string(input)?},
                }));
            }
            // Reasoning has no representation in chat completions; drop it.
            ContentBlock::Thinking { .. } => {}
            _ => {}
        }
    }
    let mut o = Map::new();
    o.insert("role".into(), json!("assistant"));
    if tool_calls.is_empty() {
        o.insert("content".into(), json!(text));
    } else {
        o.insert(
            "content".into(),
            if text.is_empty() { Value::Null } else { json!(text) },
        );
        o.insert("tool_calls".into(), Value::Array(tool_calls));
    }
    Ok(Value::Object(o))
}

/// Build OpenAI user `content`: a plain string when all-text, else a parts array.
fn emit_user_content(blocks: &[&ContentBlock]) -> Value {
    if blocks.iter().all(|b| matches!(b, ContentBlock::Text { .. })) {
        let mut s = String::new();
        for b in blocks {
            if let ContentBlock::Text { text } = b {
                s.push_str(text);
            }
        }
        return json!(s);
    }
    let parts: Vec<Value> = blocks
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text } => Some(json!({"type": "text", "text": text})),
            ContentBlock::Image { media_type, data, url } => {
                let u = match (url, data) {
                    (Some(url), _) => url.clone(),
                    (None, Some(data)) => build_data_url(media_type.as_deref(), data),
                    _ => return None,
                };
                Some(json!({"type": "image_url", "image_url": {"url": u}}))
            }
            _ => None,
        })
        .collect();
    Value::Array(parts)
}

// ===========================================================================
// Response
// ===========================================================================

/// Parse an OpenAI Chat Completions response body into the IR.
pub fn parse_response(bytes: &[u8]) -> Result<ChatResponse> {
    let v: Value = serde_json::from_slice(bytes)?;
    let choice = v
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| WireError::InvalidResponse("no choices".into()))?;
    let message = choice.get("message").unwrap_or(&Value::Null);

    let mut content: Vec<ContentBlock> = Vec::new();
    if let Some(text) = opt_str(message, "content") {
        if !text.is_empty() {
            content.push(ContentBlock::text(text));
        }
    }
    if let Some(calls) = opt_arr(message, "tool_calls") {
        for c in calls {
            let f = c.get("function").unwrap_or(&Value::Null);
            content.push(ContentBlock::ToolUse {
                id: opt_str(c, "id").unwrap_or_default().to_string(),
                name: opt_str(f, "name").unwrap_or_default().to_string(),
                input: parse_arguments(opt_str(f, "arguments")),
            });
        }
    }

    Ok(ChatResponse {
        id: opt_str(&v, "id").unwrap_or_default().to_string(),
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        content,
        stop_reason: finish_to_stop(opt_str(choice, "finish_reason")),
        usage: parse_usage(v.get("usage")),
        prompt_cache_key: None,
        prompt_cache_retention: None,
    })
}

/// Emit an IR response as an OpenAI Chat Completions response body.
pub fn emit_response(resp: &ChatResponse) -> Result<Vec<u8>> {
    let mut text = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for b in &resp.content {
        match b {
            ContentBlock::Text { text: t } => text.push_str(t),
            ContentBlock::ToolUse { id, name, input } => tool_calls.push(json!({
                "id": id,
                "type": "function",
                "function": {"name": name, "arguments": serde_json::to_string(input)?},
            })),
            _ => {}
        }
    }
    let mut message = Map::new();
    message.insert("role".into(), json!("assistant"));
    message.insert(
        "content".into(),
        if text.is_empty() && !tool_calls.is_empty() {
            Value::Null
        } else {
            json!(text)
        },
    );
    if !tool_calls.is_empty() {
        message.insert("tool_calls".into(), Value::Array(tool_calls));
    }

    let u = &resp.usage;
    let body = json!({
        "id": resp.id,
        "object": "chat.completion",
        "created": 0,
        "model": resp.model,
        "choices": [{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": stop_to_finish(&resp.stop_reason),
        }],
        "usage": {
            "prompt_tokens": u.input_tokens,
            "completion_tokens": u.output_tokens,
            "total_tokens": u.input_tokens + u.output_tokens,
        },
    });
    Ok(serde_json::to_vec(&body)?)
}

fn parse_usage(v: Option<&Value>) -> Usage {
    let Some(v) = v else { return Usage::default() };
    let cache_read = v
        .get("prompt_tokens_details")
        .and_then(|d| opt_u32(d, "cached_tokens"))
        .unwrap_or(0);
    Usage {
        input_tokens: opt_u32(v, "prompt_tokens").unwrap_or(0),
        output_tokens: opt_u32(v, "completion_tokens").unwrap_or(0),
        cache_read_tokens: cache_read,
        cache_write_tokens: 0,
    }
}

// ===========================================================================
// Shared mapping helpers
// ===========================================================================

fn parse_user_content(v: Option<&Value>) -> Vec<ContentBlock> {
    match v {
        Some(Value::String(s)) => vec![ContentBlock::text(s.clone())],
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| match opt_str(p, "type") {
                Some("text") | Some("input_text") => {
                    Some(ContentBlock::text(opt_str(p, "text").unwrap_or_default()))
                }
                Some("image_url") => {
                    let url = p
                        .get("image_url")
                        .and_then(|iu| opt_str(iu, "url"))
                        .unwrap_or_default();
                    Some(image_from_url(url))
                }
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn image_from_url(url: &str) -> ContentBlock {
    if let Some((media_type, data)) = parse_data_url(url) {
        ContentBlock::Image {
            media_type: Some(media_type),
            data: Some(data),
            url: None,
        }
    } else {
        ContentBlock::Image {
            media_type: None,
            data: None,
            url: Some(url.to_string()),
        }
    }
}

fn parse_assistant(m: &Value) -> Result<Vec<ContentBlock>> {
    let mut blocks = Vec::new();
    if let Some(text) = opt_str(m, "content") {
        if !text.is_empty() {
            blocks.push(ContentBlock::text(text));
        }
    }
    if let Some(calls) = opt_arr(m, "tool_calls") {
        for c in calls {
            let f = c.get("function").unwrap_or(&Value::Null);
            blocks.push(ContentBlock::ToolUse {
                id: opt_str(c, "id").unwrap_or_default().to_string(),
                name: opt_str(f, "name").unwrap_or_default().to_string(),
                input: parse_arguments(opt_str(f, "arguments")),
            });
        }
    }
    Ok(blocks)
}

/// Parse a tool-call `arguments` JSON *string* into a value (empty string -> {}).
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

fn parse_stop(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(_)) => str_vec(v),
        _ => vec![],
    }
}

fn parse_tool_choice(v: &Value) -> Result<ToolChoice> {
    match v {
        Value::String(s) => match s.as_str() {
            "auto" => Ok(ToolChoice::Auto),
            "none" => Ok(ToolChoice::None),
            "required" => Ok(ToolChoice::Required),
            other => Err(WireError::invalid("tool_choice", format!("unknown {other}"))),
        },
        Value::Object(_) => {
            let name = v
                .get("function")
                .and_then(|f| opt_str(f, "name"))
                .or_else(|| opt_str(v, "name"))
                .unwrap_or_default();
            Ok(ToolChoice::Tool(name.to_string()))
        }
        _ => Err(WireError::invalid("tool_choice", "expected string or object")),
    }
}

fn emit_tool_choice(tc: &ToolChoice) -> Value {
    match tc {
        ToolChoice::Auto => json!("auto"),
        ToolChoice::None => json!("none"),
        ToolChoice::Required => json!("required"),
        ToolChoice::Tool(name) => json!({"type": "function", "function": {"name": name}}),
    }
}

fn finish_to_stop(s: Option<&str>) -> StopReason {
    match s {
        Some("stop") => StopReason::EndTurn,
        Some("length") => StopReason::MaxTokens,
        Some("tool_calls") | Some("function_call") => StopReason::ToolUse,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::EndTurn,
    }
}

fn stop_to_finish(s: &StopReason) -> &str {
    match s {
        StopReason::EndTurn | StopReason::StopSequence => "stop",
        StopReason::MaxTokens => "length",
        StopReason::ToolUse => "tool_calls",
        StopReason::Other(o) => o.as_str(),
    }
}

// ===========================================================================
// Streaming
// ===========================================================================

/// Decoder state for an OpenAI Chat Completions upstream SSE stream.
#[derive(Debug, Default)]
pub struct SseState {
    started: bool,
}

/// Decode one line of an OpenAI chat SSE stream into IR events.
pub fn decode_sse(line: &str, state: &mut SseState) -> Vec<StreamEvent> {
    let Some(data) = crate::anthropic::sse_data(line) else {
        return vec![];
    };
    if data == "[DONE]" {
        return vec![];
    }
    let Ok(v) = serde_json::from_str::<Value>(data) else {
        return vec![];
    };

    let mut out = Vec::new();
    if !state.started {
        state.started = true;
        out.push(StreamEvent::MessageStart {
            model: opt_str(&v, "model").unwrap_or_default().to_string(),
        });
    }

    let choice = v
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|a| a.first());
    let mut finish: Option<StopReason> = None;
    if let Some(choice) = choice {
        let delta = choice.get("delta").unwrap_or(&Value::Null);
        if let Some(rc) = opt_str(delta, "reasoning_content") {
            if !rc.is_empty() {
                out.push(StreamEvent::ThinkingDelta { text: rc.to_string() });
            }
        }
        if let Some(text) = opt_str(delta, "content") {
            if !text.is_empty() {
                out.push(StreamEvent::TextDelta { text: text.to_string() });
            }
        }
        if let Some(calls) = opt_arr(delta, "tool_calls") {
            for c in calls {
                let f = c.get("function").unwrap_or(&Value::Null);
                if let Some(id) = opt_str(c, "id") {
                    if !id.is_empty() {
                        out.push(StreamEvent::ToolUseStart {
                            id: id.to_string(),
                            name: opt_str(f, "name").unwrap_or_default().to_string(),
                        });
                    }
                }
                if let Some(args) = opt_str(f, "arguments") {
                    if !args.is_empty() {
                        out.push(StreamEvent::ToolUseDelta { partial_json: args.to_string() });
                    }
                }
            }
        }
        finish = opt_str(choice, "finish_reason").map(|r| finish_to_stop(Some(r)));
    }
    // Usage (if present) must precede `Done` so re-encoders can fold it into
    // their terminal event.
    if let Some(u) = v.get("usage").filter(|u| !u.is_null()) {
        out.push(StreamEvent::UsageDelta { usage: parse_usage(Some(u)) });
    }
    if let Some(stop_reason) = finish {
        out.push(StreamEvent::Done { stop_reason });
    }
    out
}

/// Encoder state for producing an OpenAI chat client SSE stream from IR events.
#[derive(Debug)]
pub struct EmitState {
    started: bool,
    model: String,
    tool_index: i64,
    usage: Option<Usage>,
}

impl Default for EmitState {
    fn default() -> Self {
        EmitState {
            started: false,
            model: String::new(),
            tool_index: -1,
            usage: None,
        }
    }
}

/// Encode IR events into OpenAI-native client SSE bytes (`chat.completion.chunk`).
pub fn encode_sse(events: &[StreamEvent], state: &mut EmitState) -> Vec<u8> {
    let mut out = String::new();
    for ev in events {
        match ev {
            StreamEvent::MessageStart { model } => {
                state.model = model.clone();
                state.started = true;
                write_chunk(&mut out, state, json!({"role": "assistant"}), None);
            }
            StreamEvent::TextDelta { text } => {
                ensure_started(&mut out, state);
                write_chunk(&mut out, state, json!({"content": text}), None);
            }
            StreamEvent::ThinkingDelta { text } => {
                ensure_started(&mut out, state);
                write_chunk(&mut out, state, json!({"reasoning_content": text}), None);
            }
            StreamEvent::ToolUseStart { id, name } => {
                ensure_started(&mut out, state);
                state.tool_index += 1;
                write_chunk(
                    &mut out,
                    state,
                    json!({"tool_calls": [{
                        "index": state.tool_index,
                        "id": id,
                        "type": "function",
                        "function": {"name": name, "arguments": ""}
                    }]}),
                    None,
                );
            }
            StreamEvent::ToolUseDelta { partial_json } => {
                ensure_started(&mut out, state);
                let idx = state.tool_index.max(0);
                write_chunk(
                    &mut out,
                    state,
                    json!({"tool_calls": [{"index": idx, "function": {"arguments": partial_json}}]}),
                    None,
                );
            }
            StreamEvent::UsageDelta { usage } => {
                state.usage.get_or_insert_default().merge(usage);
            }
            StreamEvent::Done { stop_reason } => {
                ensure_started(&mut out, state);
                write_chunk(&mut out, state, json!({}), Some(stop_to_finish(stop_reason)));
                out.push_str("data: [DONE]\n\n");
            }
        }
    }
    out.into_bytes()
}

fn ensure_started(out: &mut String, state: &mut EmitState) {
    if !state.started {
        state.started = true;
        write_chunk(out, state, json!({"role": "assistant"}), None);
    }
}

fn write_chunk(out: &mut String, state: &EmitState, delta: Value, finish_reason: Option<&str>) {
    let chunk = json!({
        "id": "chatcmpl_stream",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": state.model,
        "choices": [{
            "index": 0,
            "delta": delta,
            "finish_reason": finish_reason.map(Value::from).unwrap_or(Value::Null),
        }],
    });
    out.push_str("data: ");
    out.push_str(&chunk.to_string());
    out.push_str("\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ChatRequest;

    fn emit(stream: bool) -> Value {
        let opts = EmitOptions { stream, ..EmitOptions::new("m") };
        let (body, _) = emit_request(&ChatRequest::default(), &opts).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn a_streaming_request_asks_for_usage() {
        // An OpenAI-compatible server reports no tokens at all in streaming mode
        // unless `stream_options.include_usage` is set. The gateway always
        // streams upstream, so omitting this silently zeroes every token count
        // and every cost derived from one.
        let v = emit(true);
        assert_eq!(v["stream"], json!(true));
        assert_eq!(v["stream_options"]["include_usage"], json!(true));

        // A non-streaming body must not carry the option: the field is only
        // meaningful alongside `stream`, and strict servers reject it without.
        let v = emit(false);
        assert!(v.get("stream").is_none());
        assert!(v.get("stream_options").is_none());
    }

    #[test]
    fn usage_survives_a_chunk_that_carries_no_choices() {
        // The usage chunk arrives last, after the chunk bearing `finish_reason`,
        // and carries an empty `choices` array. Parsing must not skip it.
        let line = r#"data: {"choices":[],"usage":{"prompt_tokens":41,"completion_tokens":30}}"#;
        let events = decode_sse(line, &mut SseState::default());
        let usage = events.iter().find_map(|e| match e {
            StreamEvent::UsageDelta { usage } => Some(*usage),
            _ => None,
        });
        let usage = usage.expect("a usage-only chunk yields a UsageDelta");
        assert_eq!(usage.input_tokens, 41);
        assert_eq!(usage.output_tokens, 30);
    }

    #[test]
    fn a_null_usage_field_yields_no_delta() {
        // Some servers put `"usage": null` on interim chunks. Parsing that as a
        // report would push an all-zero delta.
        let line = r#"data: {"choices":[],"usage":null}"#;
        let events = decode_sse(line, &mut SseState::default());
        assert!(!events
            .iter()
            .any(|e| matches!(e, StreamEvent::UsageDelta { .. })));
    }
}
