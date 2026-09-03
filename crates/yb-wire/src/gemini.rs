//! The Google Gemini `generateContent` wire format.
//!
//! Notable quirks: roles are `user` / `model` (no `system` or `tool` role —
//! the system prompt is `systemInstruction`, tool results are `functionResponse`
//! parts on a user turn); tool calls have no call-id, so we correlate by
//! function *name*; and generation knobs live under `generationConfig`.

use crate::common::*;
use crate::error::{Result, WireError};
use crate::ir::*;
use crate::{EmitOptions, EmittedRequest};
use serde_json::{json, Map, Value};

// ===========================================================================
// Request
// ===========================================================================

/// Parse a Gemini `generateContent` request body into the IR.
///
/// The model id usually travels in the URL, not the body, so `model` may be
/// empty after parsing — the gateway fills it from the route.
pub fn parse_request(bytes: &[u8]) -> Result<ChatRequest> {
    let v: Value = serde_json::from_slice(bytes)?;
    v.as_object()
        .ok_or_else(|| WireError::InvalidRequest("body is not a JSON object".into()))?;

    let mut req = ChatRequest {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        ..Default::default()
    };
    // Gemini conveys streaming intent in the URL action (`streamGenerateContent`
    // vs `generateContent`), not the body. The server lifts that into a synthetic
    // top-level `stream` bool (mirroring how it injects `model`).
    req.stream = v.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let sys = v.get("systemInstruction").or_else(|| v.get("system_instruction"));
    if let Some(sys) = sys {
        let blocks = parse_parts(sys.get("parts"));
        if !blocks.is_empty() {
            req.system = Some(blocks);
        }
    }

    if let Some(contents) = opt_arr(&v, "contents") {
        for c in contents {
            let blocks = parse_parts(c.get("parts"));
            let is_tool = blocks
                .iter()
                .all(|b| matches!(b, ContentBlock::ToolResult { .. }))
                && !blocks.is_empty();
            let role = match opt_str(c, "role") {
                Some("model") => Role::Assistant,
                _ if is_tool => Role::Tool,
                _ => Role::User,
            };
            req.messages.push(Message::new(role, blocks));
        }
    }

    if let Some(tools) = opt_arr(&v, "tools") {
        for t in tools {
            if let Some(decls) = opt_arr(t, "functionDeclarations") {
                for d in decls {
                    req.tools.push(Tool {
                        name: req_str(d, "name")?.to_string(),
                        description: opt_str(d, "description").map(str::to_string),
                        input_schema: d.get("parameters").cloned().unwrap_or(json!({})),
                    });
                }
            }
        }
    }

    if let Some(cfg) = v.get("toolConfig").and_then(|t| t.get("functionCallingConfig")) {
        req.tool_choice = Some(parse_tool_choice(cfg));
    }

    if let Some(g) = v.get("generationConfig") {
        req.max_tokens = opt_u32(g, "maxOutputTokens");
        req.temperature = opt_f32(g, "temperature");
        req.top_p = opt_f32(g, "topP");
        req.stop = str_vec(g.get("stopSequences"));
        if let Some(tc) = g.get("thinkingConfig") {
            req.reasoning = Some(Reasoning {
                effort: None,
                budget_tokens: opt_u32(tc, "thinkingBudget"),
            });
        }
    }

    Ok(req)
}

/// Emit an IR request as a Gemini `generateContent` request body plus headers.
pub fn emit_request(req: &ChatRequest, opts: &EmitOptions) -> Result<EmittedRequest> {
    let mut body = Map::new();

    // Gemini carries the model id in the URL, not the body; surface the target
    // model on the body only when explicitly provided so it is not lost.
    if !opts.target_model.is_empty() {
        body.insert("model".into(), json!(opts.target_model));
    }

    // Includes inline System/Developer messages, which `emit_content` skips —
    // without this they reach neither `systemInstruction` nor `contents`.
    let system = req.effective_system();
    if !system.is_empty() {
        body.insert(
            "systemInstruction".into(),
            json!({"parts": [{"text": join_text(&system)}]}),
        );
    }

    let contents: Vec<Value> = req.messages.iter().filter_map(emit_content).collect();
    body.insert("contents".into(), Value::Array(contents));

    if !req.tools.is_empty() {
        let decls: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                let mut o = Map::new();
                o.insert("name".into(), json!(t.name));
                insert_opt(&mut o, "description", t.description.clone());
                o.insert("parameters".into(), t.input_schema.clone());
                Value::Object(o)
            })
            .collect();
        body.insert("tools".into(), json!([{"functionDeclarations": decls}]));
    }

    if let Some(tc) = &req.tool_choice {
        body.insert("toolConfig".into(), emit_tool_choice(tc));
    }

    let mut g = Map::new();
    insert_opt(&mut g, "maxOutputTokens", req.max_tokens);
    insert_opt(&mut g, "temperature", req.temperature);
    insert_opt(&mut g, "topP", req.top_p);
    if !req.stop.is_empty() {
        g.insert("stopSequences".into(), json!(req.stop));
    }
    if let Some(budget) = req.reasoning.as_ref().and_then(|r| r.budget_tokens) {
        g.insert("thinkingConfig".into(), json!({"thinkingBudget": budget}));
    }
    if !g.is_empty() {
        body.insert("generationConfig".into(), Value::Object(g));
    }

    let bytes = serde_json::to_vec(&Value::Object(body))?;
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    Ok((bytes, headers))
}

fn emit_content(m: &Message) -> Option<Value> {
    let role = match m.role {
        Role::Assistant => "model",
        Role::User | Role::Tool => "user",
        Role::System | Role::Developer => return None,
    };
    let parts: Vec<Value> = m.content.iter().filter_map(emit_part).collect();
    Some(json!({"role": role, "parts": parts}))
}

fn emit_part(b: &ContentBlock) -> Option<Value> {
    match b {
        // A block only another provider understands has no Gemini equivalent,
        // so it is skipped rather than mistranslated.
        ContentBlock::Native { .. } => None,
        ContentBlock::Text { text } => Some(json!({"text": text})),
        ContentBlock::Image { media_type, data, url } => match (data, url) {
            (Some(data), _) => Some(json!({"inline_data": {
                "mime_type": media_type.clone().unwrap_or_else(|| "image/png".into()),
                "data": data,
            }})),
            (None, Some(url)) => Some(json!({"fileData": {"fileUri": url}})),
            _ => None,
        },
        ContentBlock::ToolUse { name, input, .. } => {
            Some(json!({"functionCall": {"name": name, "args": input}}))
        }
        ContentBlock::ToolResult { tool_use_id, content, .. } => {
            Some(json!({"functionResponse": {
                "name": tool_use_id,
                "response": response_object(content),
            }}))
        }
        // Gemini has no separate thinking part on input; drop it.
        ContentBlock::Thinking { .. } => None,
    }
}

/// Build a Gemini `functionResponse.response` object from tool-result content:
/// reuse a JSON object verbatim, else wrap text as `{ "result": <text> }`.
fn response_object(content: &[ContentBlock]) -> Value {
    let text = join_text(content);
    match serde_json::from_str::<Value>(&text) {
        Ok(v @ Value::Object(_)) => v,
        _ => json!({"result": text}),
    }
}

// ===========================================================================
// Response
// ===========================================================================

/// Parse a Gemini `generateContent` response body into the IR.
pub fn parse_response(bytes: &[u8]) -> Result<ChatResponse> {
    let v: Value = serde_json::from_slice(bytes)?;
    let candidate = v
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|a| a.first());

    let content = candidate
        .and_then(|c| c.get("content"))
        .map(|c| parse_parts(c.get("parts")))
        .unwrap_or_default();
    let has_tool = content.iter().any(|b| matches!(b, ContentBlock::ToolUse { .. }));
    let finish = candidate.and_then(|c| opt_str(c, "finishReason"));

    Ok(ChatResponse {
        id: opt_str(&v, "responseId").unwrap_or_default().to_string(),
        model: opt_str(&v, "modelVersion").unwrap_or_default().to_string(),
        content,
        stop_reason: gemini_finish_to_stop(finish, has_tool),
        usage: parse_usage(v.get("usageMetadata")),
        prompt_cache_key: None,
        prompt_cache_retention: None,
    })
}

/// Emit an IR response as a Gemini `generateContent` response body.
pub fn emit_response(resp: &ChatResponse) -> Result<Vec<u8>> {
    let parts: Vec<Value> = resp.content.iter().filter_map(emit_part).collect();
    let has_tool = resp.content.iter().any(|b| matches!(b, ContentBlock::ToolUse { .. }));
    let finish = stop_to_gemini_finish(&resp.stop_reason, has_tool);
    let u = &resp.usage;
    let body = json!({
        "candidates": [{
            "content": {"role": "model", "parts": parts},
            "finishReason": finish,
            "index": 0,
        }],
        "usageMetadata": {
            "promptTokenCount": u.input_tokens,
            "candidatesTokenCount": u.output_tokens,
            "totalTokenCount": u.input_tokens + u.output_tokens,
            "cachedContentTokenCount": u.cache_read_tokens,
        },
        "modelVersion": resp.model,
    });
    Ok(serde_json::to_vec(&body)?)
}

fn parse_usage(v: Option<&Value>) -> Usage {
    let Some(v) = v else { return Usage::default() };
    Usage {
        input_tokens: opt_u32(v, "promptTokenCount").unwrap_or(0),
        output_tokens: opt_u32(v, "candidatesTokenCount").unwrap_or(0),
        cache_read_tokens: opt_u32(v, "cachedContentTokenCount").unwrap_or(0),
        cache_write_tokens: 0,
    }
}

// ===========================================================================
// Shared helpers
// ===========================================================================

fn parse_parts(v: Option<&Value>) -> Vec<ContentBlock> {
    let Some(parts) = v.and_then(Value::as_array) else {
        return vec![];
    };
    let mut out = Vec::new();
    for p in parts {
        if let Some(text) = opt_str(p, "text") {
            out.push(ContentBlock::text(text));
        } else if let Some(inline) = p.get("inline_data").or_else(|| p.get("inlineData")) {
            out.push(ContentBlock::Image {
                media_type: opt_str(inline, "mime_type")
                    .or_else(|| opt_str(inline, "mimeType"))
                    .map(str::to_string),
                data: opt_str(inline, "data").map(str::to_string),
                url: None,
            });
        } else if let Some(fc) = p.get("functionCall").or_else(|| p.get("function_call")) {
            let name = opt_str(fc, "name").unwrap_or_default().to_string();
            out.push(ContentBlock::ToolUse {
                id: name.clone(),
                name,
                input: fc.get("args").cloned().unwrap_or(json!({})),
            });
        } else if let Some(fr) = p.get("functionResponse").or_else(|| p.get("function_response")) {
            let name = opt_str(fr, "name").unwrap_or_default().to_string();
            let text = match fr.get("response") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            out.push(ContentBlock::ToolResult {
                tool_use_id: name,
                content: vec![ContentBlock::text(text)],
                is_error: false,
            });
        }
    }
    out
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

fn parse_tool_choice(cfg: &Value) -> ToolChoice {
    match opt_str(cfg, "mode").map(|s| s.to_ascii_uppercase()) {
        Some(ref m) if m == "NONE" => ToolChoice::None,
        Some(ref m) if m == "ANY" => {
            let names = str_vec(cfg.get("allowedFunctionNames"));
            if names.len() == 1 {
                ToolChoice::Tool(names.into_iter().next().unwrap())
            } else {
                ToolChoice::Required
            }
        }
        _ => ToolChoice::Auto,
    }
}

fn emit_tool_choice(tc: &ToolChoice) -> Value {
    let cfg = match tc {
        ToolChoice::Auto => json!({"mode": "AUTO"}),
        ToolChoice::None => json!({"mode": "NONE"}),
        ToolChoice::Required => json!({"mode": "ANY"}),
        ToolChoice::Tool(name) => json!({"mode": "ANY", "allowedFunctionNames": [name]}),
    };
    json!({"functionCallingConfig": cfg})
}

fn gemini_finish_to_stop(s: Option<&str>, has_tool: bool) -> StopReason {
    match s {
        Some("STOP") if has_tool => StopReason::ToolUse,
        Some("STOP") => StopReason::EndTurn,
        Some("MAX_TOKENS") => StopReason::MaxTokens,
        Some(other) => StopReason::Other(other.to_ascii_lowercase()),
        None if has_tool => StopReason::ToolUse,
        None => StopReason::EndTurn,
    }
}

fn stop_to_gemini_finish(s: &StopReason, _has_tool: bool) -> &'static str {
    match s {
        StopReason::MaxTokens => "MAX_TOKENS",
        StopReason::StopSequence => "STOP",
        _ => "STOP",
    }
}

// ===========================================================================
// Streaming
// ===========================================================================

/// Decoder state for a Gemini `streamGenerateContent` SSE stream.
#[derive(Debug, Default)]
pub struct SseState {
    started: bool,
    tool_open: bool,
}

/// Decode one line of a Gemini stream into IR events.
pub fn decode_sse(line: &str, state: &mut SseState) -> Vec<StreamEvent> {
    let Some(data) = crate::anthropic::sse_data(line) else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<Value>(data) else {
        return vec![];
    };

    let mut out = Vec::new();
    if !state.started {
        state.started = true;
        out.push(StreamEvent::MessageStart {
            model: opt_str(&v, "modelVersion").unwrap_or_default().to_string(),
        });
    }

    let candidate = v
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|a| a.first());
    if let Some(candidate) = candidate {
        let parts = candidate
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array);
        if let Some(parts) = parts {
            for p in parts {
                if let Some(text) = opt_str(p, "text") {
                    out.push(StreamEvent::TextDelta { text: text.to_string() });
                } else if let Some(fc) = p.get("functionCall").or_else(|| p.get("function_call")) {
                    state.tool_open = true;
                    out.push(StreamEvent::ToolUseStart {
                        id: opt_str(fc, "name").unwrap_or_default().to_string(),
                        name: opt_str(fc, "name").unwrap_or_default().to_string(),
                    });
                    let args = fc.get("args").cloned().unwrap_or(json!({}));
                    out.push(StreamEvent::ToolUseDelta { partial_json: args.to_string() });
                }
            }
        }
        if let Some(reason) = opt_str(candidate, "finishReason") {
            if let Some(u) = v.get("usageMetadata").filter(|u| !u.is_null()) {
                out.push(StreamEvent::UsageDelta { usage: parse_usage(Some(u)) });
            }
            out.push(StreamEvent::Done {
                stop_reason: gemini_finish_to_stop(Some(reason), state.tool_open),
            });
        }
    }
    out
}

/// Encoder state for producing a Gemini client SSE stream from IR events.
#[derive(Debug, Default)]
pub struct EmitState {
    model: String,
    usage: Option<Usage>,
    /// Gemini has no partial-tool-call encoding (`functionCall.args` must be a
    /// complete object), so this is the ONE place we buffer: the pending tool's
    /// (name, accumulated-args-json). Text keeps streaming; only tool args wait
    /// until they are complete (next tool start, or Done).
    pending_tool: Option<(String, String)>,
}

impl EmitState {
    /// Emit the pending tool call, if any, as one complete `functionCall` part.
    fn flush_tool(&mut self, out: &mut String) {
        if let Some((name, args)) = self.pending_tool.take() {
            let args: Value =
                serde_json::from_str(&args).unwrap_or_else(|_| json!({}));
            write_chunk(out, &json!({
                "candidates": [{"content": {"role": "model",
                    "parts": [{"functionCall": {"name": name, "args": args}}]}, "index": 0}],
                "modelVersion": self.model,
            }));
        }
    }
}

/// Encode IR events into Gemini-native client SSE bytes.
pub fn encode_sse(events: &[StreamEvent], state: &mut EmitState) -> Vec<u8> {
    let mut out = String::new();
    for ev in events {
        match ev {
            StreamEvent::MessageStart { model } => state.model = model.clone(),
            StreamEvent::TextDelta { text } => {
                write_chunk(&mut out, &json!({
                    "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "index": 0}],
                    "modelVersion": state.model,
                }));
            }
            StreamEvent::ThinkingDelta { .. } => {}
            StreamEvent::ToolUseStart { name, .. } => {
                // Close out any previous tool call, then start accumulating this
                // one — Gemini requires complete args on the functionCall part.
                state.flush_tool(&mut out);
                state.pending_tool = Some((name.clone(), String::new()));
            }
            StreamEvent::ToolUseDelta { partial_json } => {
                if let Some((_, args)) = state.pending_tool.as_mut() {
                    args.push_str(partial_json);
                }
            }
            StreamEvent::UsageDelta { usage } => {
                state.usage.get_or_insert_default().merge(usage);
            }
            StreamEvent::Done { stop_reason } => {
                state.flush_tool(&mut out);
                let u = state.usage.unwrap_or_default();
                let has_tool = matches!(stop_reason, StopReason::ToolUse);
                write_chunk(&mut out, &json!({
                    "candidates": [{"content": {"role": "model", "parts": []},
                        "finishReason": stop_to_gemini_finish(stop_reason, has_tool), "index": 0}],
                    "usageMetadata": {
                        "promptTokenCount": u.input_tokens,
                        "candidatesTokenCount": u.output_tokens,
                        "totalTokenCount": u.input_tokens + u.output_tokens,
                    },
                    "modelVersion": state.model,
                }));
            }
        }
    }
    out.into_bytes()
}

fn write_chunk(out: &mut String, data: &Value) {
    out.push_str("data: ");
    out.push_str(&data.to_string());
    out.push_str("\n\n");
}
