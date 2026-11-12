//! Requests: an Anthropic Messages or OpenAI Responses body as the QE Chat
//! Completions body that QE prepares identically.
//!
//! QE normalizes all three of its surfaces into one internal request whose
//! messages are chat-format (`server.rs` `struct Prepared`). These functions
//! port QE's own Anthropic (`anthropic.rs` `convert` / `prepare`) and
//! Responses (`server.rs` `responses_messages` / `prepare_responses`)
//! normalization, and spell each result out in the Chat fields that
//! `prepare_chat` reads back into the same `Prepared`: messages already in
//! their normalized form (pre-joined strings, object arguments, chat-format
//! tools), the effort as the string or integer QE resolves, budgets, stops,
//! grammar, tool choice, parallel calls and cache breakpoints.
//!
//! What has no Chat spelling is refused rather than approximated (see
//! [`Gaps`] for what is carried over approximately and why).

use serde_json::{json, Map, Value};

use crate::error::{Result, WireError};

fn bad(msg: impl Into<String>) -> WireError {
    WireError::InvalidRequest(msg.into())
}

/// Sampling fields every QE surface parses the same way (`parse_sampling`):
/// copied as given.
const SAMPLING: [&str; 5] = ["temperature", "top_p", "top_k", "seed", "min_p"];

fn copy(from: &Value, to: &mut Map<String, Value>, keys: &[&str]) {
    for k in keys {
        if let Some(v) = from.get(*k) {
            to.insert((*k).to_string(), v.clone());
        }
    }
}

/// Where a translation could only approximate QE's native handling of the
/// request: reported to the caller (logged), never silently.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Gaps(pub Vec<String>);

impl Gaps {
    fn note(&mut self, s: impl Into<String>) {
        let s = s.into();
        if !self.0.contains(&s) {
            self.0.push(s);
        }
    }
}

// ---------------------------------------------------------------------------
// Cache breakpoints
// ---------------------------------------------------------------------------

/// The Chat spelling of a breakpoint: QE's Chat parser reads a mark on a
/// message as "after this message's text" (its last part, or its string
/// content). A breakpoint resolves to the first message boundary at or after
/// the marked text, so a mark anywhere inside one message lands on the same
/// boundary as a mark on the message itself.
fn mark(m: &mut Value) {
    m["cache_control"] = json!({"type": "ephemeral"});
}

// ---------------------------------------------------------------------------
// Anthropic Messages
// ---------------------------------------------------------------------------

/// `anthropic.rs` `image_url`.
fn image_url(block: &Value) -> Result<String> {
    let src = block
        .get("source")
        .ok_or_else(|| bad("image block needs a source"))?;
    match src.get("type").and_then(|t| t.as_str()) {
        Some("base64") => {
            let mt = src
                .get("media_type")
                .and_then(|m| m.as_str())
                .unwrap_or("image/png");
            let data = src
                .get("data")
                .and_then(|d| d.as_str())
                .ok_or_else(|| bad("base64 image source needs data"))?;
            Ok(format!("data:{mt};base64,{data}"))
        }
        Some("url") => Ok(src
            .get("url")
            .and_then(|u| u.as_str())
            .ok_or_else(|| bad("url image source needs a url"))?
            .to_string()),
        other => Err(bad(format!("image source type {other:?} is not supported"))),
    }
}

/// `anthropic.rs` `tool_result_content`.
fn tool_result_content(block: &Value) -> Result<(String, Option<Vec<Value>>)> {
    match block.get("content") {
        None | Some(Value::Null) => Ok((String::new(), None)),
        Some(Value::String(s)) => Ok((s.clone(), None)),
        Some(Value::Array(parts)) => {
            let mut texts = Vec::new();
            let mut chat = Vec::new();
            let mut images = false;
            for p in parts {
                match p.get("type").and_then(|t| t.as_str()) {
                    Some("text") => {
                        let t = p.get("text").and_then(|t| t.as_str()).unwrap_or("");
                        texts.push(t);
                        chat.push(json!({"type": "text", "text": t}));
                    }
                    Some("image") => {
                        images = true;
                        chat.push(
                            json!({"type": "image_url", "image_url": {"url": image_url(p)?}}),
                        );
                    }
                    other => {
                        return Err(bad(format!(
                            "tool_result content type {other:?} is not supported (text and images)"
                        )))
                    }
                }
            }
            Ok((texts.join("\n"), images.then_some(chat)))
        }
        _ => Err(bad("tool_result content must be a string or an array")),
    }
}

fn marked(v: &Value) -> bool {
    v.get("cache_control").is_some_and(|c| !c.is_null())
}

/// `anthropic.rs` `tool_use` input coercion: an object as given; a string
/// holding JSON (twice-encoded at most) parsed; anything else wrapped.
fn object_input(orig: &Value) -> Value {
    let mut input = orig.clone();
    if !input.is_object() {
        for _ in 0..2 {
            match &input {
                Value::String(s) => {
                    match serde_json::from_str::<Value>(if s.trim().is_empty() { "{}" } else { s })
                    {
                        Ok(v) => input = v,
                        Err(_) => break,
                    }
                }
                _ => break,
            }
        }
        if !input.is_object() {
            input = if orig.is_null() {
                json!({})
            } else {
                json!({"arguments": orig})
            };
        }
    }
    input
}

/// `anthropic.rs` `convert`: system + messages as QE's chat messages, each
/// breakpoint as a mark on the message it falls in.
fn anthropic_messages(body: &Value, gaps: &mut Gaps) -> Result<(Vec<Value>, bool)> {
    let mut msgs: Vec<Value> = Vec::new();
    let mut system_marked = false;
    match body.get("system") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => msgs.push(json!({"role": "system", "content": s})),
        Some(Value::Array(blocks)) => {
            let mut texts = Vec::new();
            for b in blocks {
                let t = b
                    .get("text")
                    .and_then(|t| t.as_str())
                    .ok_or_else(|| bad("system blocks must be text blocks"))?;
                system_marked |= marked(b);
                texts.push(t);
            }
            let mut m = json!({"role": "system", "content": texts.join("\n")});
            if system_marked {
                mark(&mut m);
            }
            msgs.push(m);
        }
        _ => return Err(bad("system must be a string or an array of text blocks")),
    }
    let has_system = !msgs.is_empty();
    for m in body
        .get("messages")
        .and_then(|m| m.as_array())
        .ok_or_else(|| bad("messages must be an array"))?
    {
        let role = m
            .get("role")
            .and_then(|r| r.as_str())
            .ok_or_else(|| bad("every message needs a role"))?;
        if role != "user" && role != "assistant" {
            return Err(bad(format!(
                "message role {role:?} must be user or assistant"
            )));
        }
        let blocks = match m.get("content") {
            Some(Value::String(s)) => {
                msgs.push(json!({"role": role, "content": s}));
                continue;
            }
            Some(Value::Array(b)) => b,
            _ => {
                return Err(bad(
                    "message content must be a string or an array of blocks",
                ))
            }
        };
        let mut parts: Vec<Value> = Vec::new();
        let mut parts_marked = false;
        let mut has_image = false;
        let mut reasoning = String::new();
        let mut calls = Vec::new();
        let mut assistant_marked = false;
        let flush = |msgs: &mut Vec<Value>,
                     parts: &mut Vec<Value>,
                     has_image: &mut bool,
                     marked: &mut bool| {
            if parts.is_empty() {
                return;
            }
            let content = if *has_image {
                Value::Array(std::mem::take(parts))
            } else {
                parts
                    .drain(..)
                    .filter_map(|p| p.get("text").and_then(|t| t.as_str()).map(str::to_string))
                    .collect::<Vec<_>>()
                    .join("\n")
                    .into()
            };
            let mut m = json!({"role": "user", "content": content});
            if std::mem::take(marked) {
                mark(&mut m);
            }
            msgs.push(m);
            *has_image = false;
        };
        for b in blocks {
            let ty = b.get("type").and_then(|t| t.as_str()).unwrap_or("");
            match (role, ty) {
                (_, "text") => {
                    let t = b
                        .get("text")
                        .and_then(|t| t.as_str())
                        .ok_or_else(|| bad("text block needs text"))?;
                    if marked(b) {
                        if role == "user" {
                            parts_marked = true;
                        } else {
                            assistant_marked = true;
                        }
                    }
                    parts.push(json!({"type": "text", "text": t}));
                }
                ("user", "image") => {
                    let mut p = json!({"type": "image_url", "image_url": {"url": image_url(b)?}});
                    if marked(b) {
                        // An image part carries its own mark in Chat.
                        mark(&mut p);
                    }
                    parts.push(p);
                    has_image = true;
                }
                ("user", "tool_result") => {
                    flush(&mut msgs, &mut parts, &mut has_image, &mut parts_marked);
                    let (mut text, chat) = tool_result_content(b)?;
                    let is_error = b.get("is_error").and_then(|e| e.as_bool()) == Some(true);
                    if is_error && !text.starts_with("Error") {
                        text = format!("Error: {text}");
                    }
                    let content = match chat {
                        Some(mut parts) => {
                            if is_error {
                                parts.insert(0, json!({"type": "text", "text": "Error: "}));
                            }
                            Value::Array(parts)
                        }
                        None => text.into(),
                    };
                    let mut t = json!({"role": "tool", "tool_call_id": b.get("tool_use_id"), "content": content});
                    if marked(b) {
                        mark(&mut t);
                    }
                    msgs.push(t);
                }
                ("assistant", "thinking") => {
                    let t = b.get("thinking").and_then(|t| t.as_str()).unwrap_or("");
                    if marked(b) {
                        gaps.note(
                            "cache_control on a thinking block (marked as its assistant message)",
                        );
                        assistant_marked = true;
                    }
                    reasoning.push_str(t);
                }
                ("assistant", "redacted_thinking") => {}
                ("assistant", "tool_use") => {
                    let name = b
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| bad("tool_use needs a name"))?;
                    let input = object_input(&b.get("input").cloned().unwrap_or(json!({})));
                    if marked(b) {
                        gaps.note(
                            "cache_control on a tool_use block (marked as its assistant message)",
                        );
                        assistant_marked = true;
                    }
                    calls.push(json!({"id": b.get("id"), "type": "function",
                                      "function": {"name": name, "arguments": input}}));
                }
                (r, t) => {
                    return Err(bad(format!(
                        "content block type {t:?} is not supported in {r} messages"
                    )))
                }
            }
        }
        if role == "user" {
            flush(&mut msgs, &mut parts, &mut has_image, &mut parts_marked);
        } else {
            let text: String = parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("");
            let mut msg = json!({"role": "assistant", "content": text});
            if !reasoning.is_empty() {
                msg["reasoning_content"] = reasoning.into();
            }
            if !calls.is_empty() {
                msg["tool_calls"] = calls.into();
            }
            if assistant_marked {
                mark(&mut msg);
            }
            msgs.push(msg);
        }
    }
    Ok((msgs, has_system))
}

/// QE `structured::restore_required_property_order`: `properties` with the
/// `required` keys first, in `required` order (clients that serialize schemas
/// through sorted maps lose the declaration order; `required` keeps it).
pub fn restore_required_property_order(v: &mut Value) {
    match v {
        Value::Object(m) => {
            let req: Vec<String> = m
                .get("required")
                .and_then(|r| r.as_array())
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            if !req.is_empty() {
                if let Some(Value::Object(props)) = m.get_mut("properties") {
                    let old = std::mem::take(props);
                    let mut ordered = Map::new();
                    for k in &req {
                        if let Some(val) = old.get(k) {
                            ordered.insert(k.clone(), val.clone());
                        }
                    }
                    for (k, val) in old {
                        if !ordered.contains_key(&k) {
                            ordered.insert(k, val);
                        }
                    }
                    *props = ordered;
                }
            }
            for (_, child) in m.iter_mut() {
                restore_required_property_order(child);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(restore_required_property_order),
        _ => {}
    }
}

/// An Anthropic Messages body as the QE Chat Completions body QE prepares
/// identically (`anthropic.rs` `prepare`).
pub fn anthropic_to_chat(body: &Value) -> Result<(Value, Gaps)> {
    let mut gaps = Gaps::default();
    for key in ["container", "mcp_servers"] {
        if body.get(key).is_some_and(|v| !v.is_null()) {
            return Err(bad(format!("{key} is not supported by this server")));
        }
    }
    let mut out = Map::new();
    copy(body, &mut out, &["model"]);
    let (mut messages, has_system) = anthropic_messages(body, &mut gaps)?;

    let mut tools_marked = false;
    let mut tools = None;
    if let Some(arr) = body
        .get("tools")
        .and_then(|t| t.as_array())
        .filter(|a| !a.is_empty())
    {
        let mut list = Vec::new();
        for t in arr {
            if let Some(ty) = t
                .get("type")
                .and_then(|x| x.as_str())
                .filter(|&ty| ty != "custom")
            {
                let kind = if [
                    "web_search",
                    "web_fetch",
                    "code_execution",
                    "mcp",
                    "tool_search",
                ]
                .iter()
                .any(|k| ty.starts_with(k))
                {
                    "a server tool Anthropic runs"
                } else {
                    "an Anthropic-defined client tool (declare it as a custom tool with an input_schema instead)"
                };
                return Err(bad(format!(
                    "tools: type {ty:?} is {kind}; not available on this server"
                )));
            }
            tools_marked |= marked(t);
            let mut f = Map::new();
            f.insert("name".into(), t.get("name").cloned().unwrap_or(Value::Null));
            if let Some(d) = t.get("description").filter(|d| !d.is_null()) {
                f.insert("description".into(), d.clone());
            }
            let mut params = t
                .get("input_schema")
                .cloned()
                .unwrap_or(json!({"type": "object"}));
            restore_required_property_order(&mut params);
            f.insert("parameters".into(), params);
            if let Some(st) = t.get("strict").filter(|v| !v.is_null()) {
                f.insert("strict".into(), st.clone());
            }
            // Always a function tool: Anthropic's `custom` is a plain client
            // tool, where Chat's `custom` is OpenAI's freeform tool.
            list.push(json!({"type": "function", "function": f}));
        }
        tools = Some(Value::Array(list));
    }
    // Tool definitions render in the leading system run: a breakpoint on them
    // is the end of that run, which is where a breakpoint on the system
    // message lands.
    if tools_marked {
        match messages.first_mut().filter(|_| has_system) {
            Some(m) => mark(m),
            None => gaps.note("cache_control on tools without a system prompt (dropped)"),
        }
    }
    // A top-level cache_control is a breakpoint before the generation turn:
    // the end of the last message.
    if marked(body) {
        match messages.last_mut() {
            Some(m) if m.get("content").is_some_and(|c| c.as_str() != Some("")) => mark(m),
            _ => gaps.note("top-level cache_control after an empty last message (dropped)"),
        }
    }
    out.insert("messages".into(), Value::Array(messages));
    if let Some(t) = tools {
        out.insert("tools".into(), t);
    }

    match body.get("tool_choice").filter(|v| !v.is_null()) {
        None => {}
        Some(tc) => {
            let c = match tc.get("type").and_then(|t| t.as_str()) {
                Some("auto") => json!("auto"),
                Some("any") => json!("required"),
                Some("none") => json!("none"),
                Some("tool") => {
                    let n = tc
                        .get("name")
                        .and_then(|n| n.as_str())
                        .ok_or_else(|| bad("tool_choice needs a name"))?;
                    json!({"type": "function", "function": {"name": n}})
                }
                _ => return Err(bad("tool_choice type must be auto, any, tool or none")),
            };
            out.insert("tool_choice".into(), c);
        }
    }
    let max_tokens = body
        .get("max_tokens")
        .and_then(|m| m.as_u64())
        .ok_or_else(|| bad("max_tokens is required"))?;
    out.insert("max_tokens".into(), max_tokens.into());

    // Template kwargs, built in the order QE's Anthropic parser inserts them
    // (its `chat_template_kwargs`, the thinking switch, an integer effort), so
    // QE's Chat parser ends with the same map.
    let mut kwargs = body
        .get("chat_template_kwargs")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let raw_effort = body
        .pointer("/output_config/effort")
        .and_then(|e| e.as_str())
        .or_else(|| body.get("reasoning_effort").and_then(|e| e.as_str()))
        .or_else(|| body.pointer("/reasoning/effort").and_then(|e| e.as_str()))
        .or_else(|| body.pointer("/thinking/effort").and_then(|e| e.as_str()));
    match body.pointer("/thinking/type").and_then(|t| t.as_str()) {
        None => {}
        Some("disabled") => {
            kwargs.insert("enable_thinking".into(), false.into());
        }
        Some("enabled") => {
            // budget_tokens is vLLM's thinking_token_budget on QE's Chat
            // surface: it can only lower the effort's cap there too.
            if let Some(b) = body
                .pointer("/thinking/budget_tokens")
                .and_then(|b| b.as_u64())
            {
                out.insert("thinking_token_budget".into(), b.into());
            }
            kwargs.insert("enable_thinking".into(), true.into());
        }
        Some("adaptive") => {
            kwargs.insert("enable_thinking".into(), true.into());
        }
        Some(other) => return Err(bad(format!("unsupported thinking type {other:?}"))),
    }
    // Anthropic's `max` is QE's deepest level, `xhigh` (QE's own `max` is a
    // different budget key).
    let effort = match raw_effort {
        None => None,
        Some(e @ ("none" | "minimal" | "low" | "medium" | "high" | "xhigh")) => Some(e),
        Some("max") => Some("xhigh"),
        Some(other) => {
            return Err(bad(format!(
                "output_config.effort {other:?} must be low, medium, high or max"
            )))
        }
    };
    if let Some(n) = body
        .get("reasoning_effort")
        .and_then(|v| v.as_i64())
        .or_else(|| {
            body.pointer("/output_config/effort")
                .and_then(|v| v.as_i64())
        })
    {
        // An integer effort is DeepSeek's 1-100 level, read from the kwargs.
        kwargs.insert("reasoning_effort".into(), n.into());
    }
    if !kwargs.is_empty() {
        out.insert("chat_template_kwargs".into(), Value::Object(kwargs));
    }
    if let Some(e) = effort {
        out.insert("reasoning_effort".into(), e.into());
    }

    match body.get("stop_sequences").filter(|v| !v.is_null()) {
        None => {}
        Some(v) => {
            let stops: Vec<Value> = v
                .as_array()
                .ok_or_else(|| bad("stop_sequences must be an array"))?
                .iter()
                .map(|s| {
                    s.as_str()
                        .filter(|s| !s.is_empty())
                        .map(Value::from)
                        .ok_or_else(|| bad("stop_sequences must be non-empty strings"))
                })
                .collect::<Result<_>>()?;
            if stops.len() > 4 {
                return Err(WireError::Unsupported(
                    "more than 4 stop_sequences cannot be translated to Chat Completions; \
                     serve the anthropic shape natively"
                        .into(),
                ));
            }
            if !stops.is_empty() {
                out.insert("stop".into(), stops.into());
            }
        }
    }
    if let Some(f) = body
        .pointer("/output_config/format")
        .or_else(|| body.get("output_format"))
    {
        out.insert("response_format".into(), f.clone());
    }
    copy(body, &mut out, &SAMPLING);
    if body
        .pointer("/tool_choice/disable_parallel_tool_use")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        out.insert("parallel_tool_calls".into(), false.into());
    }
    if let Some(s) = body.get("stream").and_then(|s| s.as_bool()) {
        out.insert("stream".into(), s.into());
    }
    Ok((Value::Object(out), gaps))
}

// ---------------------------------------------------------------------------
// OpenAI Responses
// ---------------------------------------------------------------------------

/// What a Responses translation needs from the gateway's store of earlier
/// responses (QE keeps the same store in memory).
pub trait ResponseItems {
    /// The stored conversation of a response (`previous_response_id`).
    fn history(&self, id: &str) -> Option<Vec<Value>>;
    /// A stored output or input item by id (`item_reference`).
    fn item(&self, id: &str) -> Option<Value>;
    /// How many responses are kept (for QE's not-found message).
    fn cap(&self) -> usize;
}

/// No store: `previous_response_id` and `item_reference` fail as for a QE
/// whose response store is off.
pub struct NoItems;

impl ResponseItems for NoItems {
    fn history(&self, _id: &str) -> Option<Vec<Value>> {
        None
    }
    fn item(&self, _id: &str) -> Option<Value> {
        None
    }
    fn cap(&self) -> usize {
        0
    }
}

/// `server.rs` `RESPONSES_INCLUDE`.
const RESPONSES_INCLUDE: [&str; 8] = [
    "reasoning.encrypted_content",
    "message.output_text.logprobs",
    "message.input_image.image_url",
    "file_search_call.results",
    "web_search_call.results",
    "web_search_call.action.sources",
    "computer_call_output.output.image_url",
    "code_interpreter_call.outputs",
];

/// `server.rs` `check_responses_request`.
fn check_responses_request(body: &Value) -> Result<()> {
    if body.get("prompt").is_some_and(|v| !v.is_null()) {
        return Err(bad("prompt: reusable prompt templates are not supported by this server (send input / instructions)"));
    }
    for (i, t) in body
        .get("tools")
        .and_then(|t| t.as_array())
        .into_iter()
        .flatten()
        .enumerate()
    {
        match t.get("type").and_then(|x| x.as_str()) {
            Some("function") | Some("custom") => {}
            Some(ty) => {
                return Err(bad(format!(
                    "tools[{i}].type: {ty:?} is a hosted tool, not available on this \
                     self-hosted server (function and custom tools are supported)"
                )))
            }
            None => return Err(bad(format!("tools[{i}].type: missing"))),
        }
    }
    if let Some(tc) = body.get("tool_choice").filter(|v| v.is_object()) {
        match tc.get("type").and_then(|x| x.as_str()) {
            Some("function") | Some("custom") | Some("allowed_tools") | None => {}
            Some(ty) => {
                return Err(bad(format!(
                    "tool_choice: {ty:?} is a hosted tool, not available on this server"
                )))
            }
        }
    }
    for v in body
        .get("include")
        .and_then(|i| i.as_array())
        .into_iter()
        .flatten()
    {
        if !v.as_str().is_some_and(|x| RESPONSES_INCLUDE.contains(&x)) {
            return Err(bad(format!("include: unsupported value {v}")));
        }
    }
    match body
        .get("truncation")
        .filter(|v| !v.is_null())
        .map(|v| v.as_str())
    {
        None | Some(Some("auto")) | Some(Some("disabled")) => {}
        _ => return Err(bad("truncation: must be \"auto\" or \"disabled\"")),
    }
    if let Some(m) = body.get("max_tool_calls").filter(|v| !v.is_null()) {
        if m.as_u64().is_none_or(|n| n == 0) {
            return Err(bad("max_tool_calls: must be a positive integer"));
        }
    }
    if let Some(v) = body.pointer("/text/verbosity").filter(|v| !v.is_null()) {
        if !matches!(v.as_str(), Some("low" | "medium" | "high")) {
            return Err(bad("text.verbosity: must be low, medium or high"));
        }
    }
    let background = body
        .get("background")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    if background && body.get("store").and_then(|s| s.as_bool()) == Some(false) {
        return Err(bad("background: background responses require store=true"));
    }
    Ok(())
}

/// `server.rs` `resolve_item_refs`: `item_reference` inputs replaced by the
/// stored items they name.
pub fn resolve_item_refs(body: &Value, store: &dyn ResponseItems) -> Result<Value> {
    let Some(items) = body.get("input").and_then(|i| i.as_array()) else {
        return Ok(body.clone());
    };
    if !items
        .iter()
        .any(|it| it.get("type").and_then(|t| t.as_str()) == Some("item_reference"))
    {
        return Ok(body.clone());
    }
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        if it.get("type").and_then(|t| t.as_str()) == Some("item_reference") {
            let id = it
                .get("id")
                .and_then(|x| x.as_str())
                .ok_or_else(|| bad("input: item_reference needs an id"))?;
            out.push(store.item(id).ok_or_else(|| {
                bad(format!(
                    "input: item {id:?} not found (stored responses only)"
                ))
            })?);
        } else {
            out.push(it.clone());
        }
    }
    let mut b = body.clone();
    b["input"] = out.into();
    Ok(b)
}

/// QE's `encrypted_content` for a reasoning item: the text, encoded (not
/// encrypted), so it comes back intact in the next turn's input.
pub fn encode_reasoning(text: &str) -> String {
    use base64::Engine as _;
    format!(
        "qe1:{}",
        base64::engine::general_purpose::STANDARD.encode(text)
    )
}

/// `server.rs` `reasoning_text`: our encrypted_content, else the item's
/// reasoning_text content, else its summary.
fn reasoning_text(it: &Value) -> String {
    use base64::Engine as _;
    if let Some(e) = it
        .get("encrypted_content")
        .and_then(|e| e.as_str())
        .and_then(|e| e.strip_prefix("qe1:"))
    {
        if let Some(t) = base64::engine::general_purpose::STANDARD
            .decode(e)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        {
            return t;
        }
    }
    let join = |k: &str| {
        it.get(k).and_then(|c| c.as_array()).map(|a| {
            a.iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
    };
    join("content")
        .filter(|t| !t.is_empty())
        .or_else(|| join("summary"))
        .unwrap_or_default()
}

/// `server.rs` `reject_media` for one item's parts.
fn reject_media(parts: &[Value]) -> Result<()> {
    for part in parts {
        let ty = part.get("type").and_then(|t| t.as_str()).unwrap_or("text");
        if !matches!(
            ty,
            "text" | "input_text" | "output_text" | "image_url" | "input_image" | "image"
        ) {
            return Err(bad(format!(
                "content part type {ty:?} is not supported by this server (text and images only)"
            )));
        }
    }
    Ok(())
}

fn is_marked(v: &Value) -> bool {
    ["prompt_cache_breakpoint", "cache_control"]
        .iter()
        .any(|k| v.get(*k).is_some_and(|b| !b.is_null() && b != false))
}

/// Whether a breakpoint on this input item (or any of its parts) means a
/// breakpoint after the message QE makes of it.
fn item_marked(it: &Value) -> bool {
    is_marked(it)
        || it
            .get("content")
            .or_else(|| it.get("output"))
            .and_then(|c| c.as_array())
            .is_some_and(|ps| ps.iter().any(is_marked))
}

/// `server.rs` `push_call`.
fn push_call(msgs: &mut Vec<Value>, call: Value, reasoning: &mut Option<String>) {
    match msgs.last_mut() {
        Some(last) if last["role"] == "assistant" => {
            if last.get("tool_calls").is_none() {
                last["tool_calls"] = json!([]);
            }
            last["tool_calls"].as_array_mut().unwrap().push(call);
        }
        _ => {
            let mut m = json!({"role": "assistant", "content": "", "tool_calls": [call]});
            if let Some(r) = reasoning.take() {
                m["reasoning_content"] = r.into();
            }
            msgs.push(m);
        }
    }
}

/// `server.rs` `responses_messages`: input items as chat messages, a
/// breakpoint on an item as a mark on the message it becomes.
fn responses_messages(body: &Value, gaps: &mut Gaps) -> Result<Vec<Value>> {
    let mut msgs = Vec::new();
    if let Some(i) = body.get("instructions").and_then(|i| i.as_str()) {
        msgs.push(json!({"role": "system", "content": i}));
    }
    match body.get("input") {
        Some(Value::String(s)) => msgs.push(json!({"role": "user", "content": s})),
        Some(Value::Array(items)) => {
            let mut reasoning: Option<String> = None;
            for it in items {
                let ty = it.get("type").and_then(|t| t.as_str()).unwrap_or("message");
                match ty {
                    "message" => {
                        let role = it.get("role").and_then(|r| r.as_str()).unwrap_or("user");
                        if let Some(parts) = it.get("content").and_then(|c| c.as_array()) {
                            reject_media(parts)?;
                        }
                        let has_image = it
                            .get("content")
                            .and_then(|c| c.as_array())
                            .is_some_and(|ps| ps.iter().any(|p| p.get("image_url").is_some()));
                        let content = match it.get("content") {
                            Some(Value::String(s)) => json!(s),
                            Some(Value::Array(parts)) if has_image => parts
                                .iter()
                                .filter_map(|p| {
                                    if let Some(u) = p.get("image_url") {
                                        let url = u
                                            .as_str()
                                            .or_else(|| u.get("url").and_then(|x| x.as_str()))
                                            .unwrap_or("");
                                        let mut part =
                                            json!({"type": "image_url", "image_url": {"url": url}});
                                        if is_marked(p) {
                                            mark(&mut part);
                                        }
                                        Some(part)
                                    } else {
                                        p.get("text")
                                            .and_then(|t| t.as_str())
                                            .map(|t| json!({"type": "text", "text": t}))
                                    }
                                })
                                .collect::<Vec<_>>()
                                .into(),
                            Some(Value::Array(parts)) => parts
                                .iter()
                                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                                .collect::<Vec<_>>()
                                .join("")
                                .into(),
                            _ => json!(""),
                        };
                        let role = if role == "developer" { "system" } else { role };
                        let mut m = json!({"role": role, "content": content});
                        if role == "assistant" {
                            if let Some(r) = reasoning.take() {
                                m["reasoning_content"] = r.into();
                            }
                        }
                        if item_marked(it) && !has_image {
                            mark(&mut m);
                        }
                        msgs.push(m);
                    }
                    "function_call" => {
                        let args: Value = it
                            .get("arguments")
                            .and_then(|a| a.as_str())
                            .and_then(|a| serde_json::from_str(a).ok())
                            .unwrap_or(json!({}));
                        let call = json!({"id": it.get("call_id"), "type": "function",
                            "function": {"name": it.get("name"), "arguments": args}});
                        push_call(&mut msgs, call, &mut reasoning);
                    }
                    "custom_tool_call" => {
                        let call = json!({"id": it.get("call_id"), "type": "function",
                            "function": {"name": it.get("name"),
                                         "arguments": {"input": it.get("input").and_then(|i| i.as_str()).unwrap_or("")}}});
                        push_call(&mut msgs, call, &mut reasoning);
                    }
                    "function_call_output" | "custom_tool_call_output" => {
                        let out = match it.get("output") {
                            Some(Value::String(s)) => s.clone(),
                            Some(Value::Array(parts)) => parts
                                .iter()
                                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                                .collect::<Vec<_>>()
                                .join(""),
                            _ => String::new(),
                        };
                        let mut m = json!({"role": "tool", "tool_call_id": it.get("call_id"), "content": out});
                        if item_marked(it) {
                            mark(&mut m);
                        }
                        msgs.push(m);
                    }
                    "reasoning" => {
                        if item_marked(it) {
                            gaps.note("cache breakpoint on a reasoning item (dropped)");
                        }
                        reasoning = Some(reasoning_text(it));
                    }
                    other => return Err(bad(format!("unsupported input item type {other:?}"))),
                }
            }
        }
        _ => return Err(bad("input must be a string or an array")),
    }
    Ok(msgs)
}

/// A Responses request translated for QE's Chat surface.
#[derive(Debug, Clone)]
pub struct ResponsesChat {
    /// The Chat Completions body.
    pub body: Value,
    /// This turn's conversation as QE stores it for `previous_response_id`
    /// (without the instructions, which do not carry over), before the
    /// assistant's reply is appended.
    pub history: Vec<Value>,
    /// The request with `item_reference`s resolved (for the echo and the
    /// stored input items).
    pub request: Value,
    pub gaps: Gaps,
}

/// An OpenAI Responses body (with the stored conversation it continues) as
/// the QE Chat Completions body QE prepares identically
/// (`server.rs` `prepare_responses`).
pub fn responses_to_chat(body: &Value, store: &dyn ResponseItems) -> Result<ResponsesChat> {
    let mut gaps = Gaps::default();
    check_responses_request(body)?;
    let body = &resolve_item_refs(body, store)?;
    if body.get("conversation").is_some_and(|v| !v.is_null()) {
        return Err(bad(
            "conversation is not supported (use previous_response_id)",
        ));
    }
    let mut messages = responses_messages(body, &mut gaps)?;
    let history_from = usize::from(body.get("instructions").and_then(|i| i.as_str()).is_some());
    if let Some(prev) = body.get("previous_response_id").and_then(|v| v.as_str()) {
        let Some(history) = store.history(prev) else {
            return Err(bad(format!(
                "previous response {prev:?} not found (responses are kept in memory, the latest {})",
                store.cap()
            )));
        };
        for (k, m) in history.into_iter().enumerate() {
            messages.insert(history_from + k, m);
        }
    }
    if body.get("truncation").and_then(|t| t.as_str()) == Some("auto") {
        gaps.note("truncation \"auto\" (not applied: the gateway does not tokenize)");
    }
    let mut out = Map::new();
    copy(body, &mut out, &["model"]);
    let history: Vec<Value> = messages[history_from..]
        .iter()
        .map(|m| {
            let mut m = m.clone();
            if let Some(o) = m.as_object_mut() {
                o.shift_remove("cache_control");
            }
            m
        })
        .collect();
    out.insert("messages".into(), Value::Array(messages));

    if let Some(arr) = body
        .get("tools")
        .and_then(|t| t.as_array())
        .filter(|a| !a.is_empty())
    {
        let mut list = Vec::new();
        for t in arr {
            match t.get("type").and_then(|x| x.as_str()) {
                Some("function") => {
                    // Absent fields stay absent: the template prints every key.
                    let mut f = Map::new();
                    for k in ["name", "description", "parameters", "strict"] {
                        if let Some(v) = t.get(k).filter(|v| !v.is_null()) {
                            f.insert(k.into(), v.clone());
                        }
                    }
                    list.push(json!({"type": "function", "function": f}));
                }
                // Chat reads a custom tool's fields from the tool itself when
                // there is no nested `custom`, as Responses spells it.
                Some("custom") => list.push(t.clone()),
                other => {
                    return Err(bad(format!(
                        "tool type {other:?} is not supported (function and custom tools)"
                    )))
                }
            }
        }
        out.insert("tools".into(), Value::Array(list));
    }
    // Chat parses every Responses tool_choice spelling (function / custom by
    // `name`, allowed_tools un-nested) the same way.
    copy(body, &mut out, &["tool_choice", "chat_template_kwargs"]);
    if let Some(e) = body.pointer("/reasoning/effort").filter(|e| e.is_string()) {
        out.insert("reasoning_effort".into(), e.clone());
    }
    if let Some(m) = body.get("max_output_tokens").and_then(|m| m.as_u64()) {
        out.insert("max_tokens".into(), m.into());
    }
    copy(body, &mut out, &["stop", "thinking_token_budget"]);
    if let Some(f) = body.pointer("/text/format") {
        out.insert("response_format".into(), f.clone());
    }
    copy(
        body,
        &mut out,
        &["prompt_cache_options", "prompt_cache_key"],
    );
    copy(body, &mut out, &SAMPLING);
    copy(body, &mut out, &["parallel_tool_calls"]);
    copy(
        body,
        &mut out,
        &[
            "presence_penalty",
            "frequency_penalty",
            "repetition_penalty",
            "ignore_eos",
            "logit_bias",
        ],
    );
    // Logprobs: Responses asks with top_logprobs or the include value; Chat
    // with logprobs (top_logprobs alone is a 400 there).
    let top = body.get("top_logprobs").filter(|v| !v.is_null());
    let wanted = top.is_some()
        || body
            .get("include")
            .and_then(|i| i.as_array())
            .is_some_and(|a| a.iter().any(|x| x == "message.output_text.logprobs"));
    if wanted {
        out.insert("logprobs".into(), true.into());
        if let Some(t) = top {
            out.insert("top_logprobs".into(), t.clone());
        }
    }
    if let Some(s) = body.get("stream").and_then(|s| s.as_bool()) {
        out.insert("stream".into(), s.into());
    }
    Ok(ResponsesChat {
        body: Value::Object(out),
        history,
        request: body.clone(),
        gaps,
    })
}
