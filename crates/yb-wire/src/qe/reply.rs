//! Replies: QE's Chat Completions answer (a buffered body or its SSE stream)
//! as the Anthropic Messages or OpenAI Responses answer QE's own encoder for
//! that shape writes (`anthropic.rs` `messages`, `server.rs` `responses`).
//!
//! QE produces every shape from one event sequence (reasoning text, answer
//! text, tool call start / arguments / end, logprobs). Its Chat stream carries
//! that sequence nearly one-to-one, so the Chat answer is read back into it
//! ([`ChatEvents`]) and fed to ports of QE's Anthropic and Responses encoders.
//! The one event Chat does not send, a function call's end, is implied by
//! whatever follows the call; DSML formats stream arguments whose deltas add
//! up to the final arguments, which is what both encoders use.

use serde_json::{json, Value};

use super::request::encode_reasoning;

/// One event of QE's output (`output.rs` `OutEvent`).
#[derive(Debug, Clone, PartialEq)]
pub enum Ev {
    Reasoning(String),
    Text(String),
    ToolStart {
        index: usize,
        name: String,
    },
    ToolArgs {
        index: usize,
        delta: String,
    },
    ToolEnd {
        index: usize,
        name: String,
        arguments: String,
    },
    /// A custom (freeform) tool call, which Chat sends whole at its end.
    Custom {
        index: usize,
        name: String,
        input: String,
    },
    Logprobs(Vec<Value>),
}

/// One tool call of a finished answer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Call {
    pub name: String,
    /// The JSON arguments (function calls).
    pub arguments: String,
    /// The raw input (custom tool calls).
    pub input: Option<String>,
}

/// Everything a finished answer produced (`server.rs` `Collected`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Collected {
    pub reasoning: String,
    pub text: String,
    pub calls: Vec<Call>,
    /// Chat finish_reason "length".
    pub length: bool,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub reasoning_tokens: u64,
    pub cached: u64,
    pub written: u64,
    pub logprobs: Vec<Value>,
    pub error: Option<String>,
    /// The Chat answer reported usage (a stream reports it only on request).
    pub has_usage: bool,
}

impl Collected {
    fn take_usage(&mut self, u: &Value) {
        let n = |p: &str| u.pointer(p).and_then(|v| v.as_u64()).unwrap_or(0);
        self.prompt_tokens = n("/prompt_tokens");
        self.completion_tokens = n("/completion_tokens");
        self.reasoning_tokens = n("/completion_tokens_details/reasoning_tokens");
        self.cached = n("/prompt_tokens_details/cached_tokens");
        self.written = n("/prompt_tokens_details/cache_write_tokens");
        self.has_usage = true;
    }

    fn push(&mut self, e: &Ev) {
        match e {
            Ev::Reasoning(s) => self.reasoning.push_str(s),
            Ev::Text(s) => self.text.push_str(s),
            Ev::ToolEnd {
                name, arguments, ..
            } => self.calls.push(Call {
                name: name.clone(),
                arguments: arguments.clone(),
                input: None,
            }),
            Ev::Custom { name, input, .. } => self.calls.push(Call {
                name: name.clone(),
                arguments: json!({"input": input}).to_string(),
                input: Some(input.clone()),
            }),
            Ev::Logprobs(v) => self.logprobs.extend(v.iter().cloned()),
            _ => {}
        }
    }

    /// The answer was cut by the output cap. Chat reports `tool_calls`
    /// whenever calls were made, so a cap reached after (or inside, dropping
    /// it) a later call reads as complete; `max_tokens` (what the request
    /// asked for) recovers that case: the answer used all of it.
    pub fn cut(&self, max_tokens: Option<u64>) -> bool {
        self.length
            || (!self.calls.is_empty()
                && max_tokens.is_some_and(|m| m > 0 && self.completion_tokens >= m))
    }
}

/// A buffered QE Chat answer (choice 0) as its events and totals.
pub fn collect_chat(resp: &Value) -> Collected {
    let mut c = Collected::default();
    if let Some(e) = resp.pointer("/error/message").and_then(|m| m.as_str()) {
        c.error = Some(e.to_string());
        return c;
    }
    let ch = resp.pointer("/choices/0").cloned().unwrap_or(Value::Null);
    let msg = ch.get("message").cloned().unwrap_or(Value::Null);
    c.reasoning = msg
        .get("reasoning_content")
        .or_else(|| msg.get("reasoning"))
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();
    c.text = msg
        .get("content")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    for t in msg
        .get("tool_calls")
        .and_then(|t| t.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(cu) = t.get("custom") {
            let input = cu
                .get("input")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            c.calls.push(Call {
                name: cu
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string(),
                arguments: json!({"input": input}).to_string(),
                input: Some(input),
            });
        } else {
            let f = t.get("function").cloned().unwrap_or(Value::Null);
            c.calls.push(Call {
                name: f
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string(),
                arguments: match f.get("arguments") {
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                    None => String::new(),
                },
                input: None,
            });
        }
    }
    c.length = ch.get("finish_reason").and_then(|f| f.as_str()) == Some("length");
    if let Some(lp) = ch.pointer("/logprobs/content").and_then(|l| l.as_array()) {
        c.logprobs = lp.clone();
    }
    if let Some(u) = resp.get("usage").filter(|u| !u.is_null()) {
        c.take_usage(u);
    }
    c
}

/// Reads a QE Chat SSE stream (one `data:` payload at a time) back into
/// QE's event sequence, collecting the totals on the way.
#[derive(Debug, Default)]
pub struct ChatEvents {
    /// The open function call: (index, name, arguments so far).
    call: Option<(usize, String, String)>,
    pub collected: Collected,
    pub finished: bool,
}

impl ChatEvents {
    fn close_call(&mut self, out: &mut Vec<Ev>) {
        if let Some((index, name, arguments)) = self.call.take() {
            let e = Ev::ToolEnd {
                index,
                name,
                arguments,
            };
            self.collected.push(&e);
            out.push(e);
        }
    }

    fn emit(&mut self, e: Ev, out: &mut Vec<Ev>) {
        if !matches!(e, Ev::ToolArgs { .. } | Ev::Logprobs(_)) {
            self.close_call(out);
        }
        self.collected.push(&e);
        out.push(e);
    }

    /// The events of one Chat SSE `data:` payload.
    pub fn push(&mut self, data: &str) -> Vec<Ev> {
        let mut out = Vec::new();
        let data = data.trim();
        if data == "[DONE]" {
            self.close_call(&mut out);
            return out;
        }
        let Ok(v) = serde_json::from_str::<Value>(data) else {
            return out;
        };
        if let Some(e) = v.pointer("/error/message").and_then(|m| m.as_str()) {
            self.close_call(&mut out);
            self.collected.error = Some(e.to_string());
            return out;
        }
        if let Some(u) = v.get("usage").filter(|u| !u.is_null()) {
            self.collected.take_usage(u);
        }
        let Some(ch) = v.pointer("/choices/0") else {
            return out;
        };
        let delta = ch.get("delta").cloned().unwrap_or(Value::Null);
        // The opening chunk ({role, content: ""}) is no event.
        if delta.get("role").is_none() {
            if let Some(r) = delta
                .get("reasoning_content")
                .or_else(|| delta.get("reasoning"))
                .and_then(|r| r.as_str())
            {
                self.emit(Ev::Reasoning(r.to_string()), &mut out);
            }
            if let Some(t) = delta.get("content").and_then(|t| t.as_str()) {
                self.emit(Ev::Text(t.to_string()), &mut out);
            }
        }
        for tc in delta
            .get("tool_calls")
            .and_then(|t| t.as_array())
            .into_iter()
            .flatten()
        {
            let index = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
            if let Some(cu) = tc.get("custom") {
                let name = cu
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let input = cu
                    .get("input")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                self.emit(Ev::Custom { index, name, input }, &mut out);
                continue;
            }
            let f = tc.get("function").cloned().unwrap_or(Value::Null);
            if let Some(name) = f.get("name").and_then(|n| n.as_str()) {
                self.emit(
                    Ev::ToolStart {
                        index,
                        name: name.to_string(),
                    },
                    &mut out,
                );
                self.call = Some((index, name.to_string(), String::new()));
            }
            if let Some(d) = f
                .get("arguments")
                .and_then(|a| a.as_str())
                .filter(|d| !d.is_empty())
            {
                if let Some((_, _, args)) = &mut self.call {
                    args.push_str(d);
                }
                self.emit(
                    Ev::ToolArgs {
                        index,
                        delta: d.to_string(),
                    },
                    &mut out,
                );
            }
        }
        if let Some(lp) = ch.pointer("/logprobs/content").and_then(|l| l.as_array()) {
            self.emit(Ev::Logprobs(lp.clone()), &mut out);
        }
        if let Some(f) = ch.get("finish_reason").and_then(|f| f.as_str()) {
            // A call the output cap cut off is dropped by QE (it never ends);
            // a complete call's arguments are whole JSON.
            if f == "length"
                && self
                    .call
                    .as_ref()
                    .is_some_and(|(_, _, a)| serde_json::from_str::<Value>(a).is_err())
            {
                self.call = None;
            }
            self.close_call(&mut out);
            self.collected.length = f == "length";
            self.finished = true;
        }
        out
    }

    /// Events still owed when the stream ends.
    pub fn finish(&mut self) -> Vec<Ev> {
        let mut out = Vec::new();
        self.close_call(&mut out);
        out
    }
}

/// One SSE event as QE's server writes it (`event:` name, the payload with
/// its `type` appended).
fn sse(name: &str, mut data: Value) -> Vec<u8> {
    data["type"] = name.into();
    format!("event: {name}\ndata: {data}\n\n").into_bytes()
}

// ---------------------------------------------------------------------------
// Anthropic Messages
// ---------------------------------------------------------------------------

/// `anthropic.rs` `usage`: `input_tokens` is the uncached remainder.
pub fn anthropic_usage(
    prompt: u64,
    cached: u64,
    written: u64,
    output: u64,
    reasoning: u64,
) -> Value {
    json!({"input_tokens": prompt.saturating_sub(cached + written), "output_tokens": output,
           "cache_read_input_tokens": cached, "cache_creation_input_tokens": written,
           "output_tokens_details": {"reasoning_tokens": reasoning, "thinking_tokens": reasoning}})
}

/// `anthropic.rs` `stop_reason`. A stop sequence ends a QE Chat answer as
/// plain `stop`, without saying which: it reads as `end_turn` here.
fn stop_reason(c: &Collected) -> &'static str {
    if !c.calls.is_empty() {
        "tool_use"
    } else if c.length {
        "max_tokens"
    } else {
        "end_turn"
    }
}

/// `anthropic.rs` `signature`: an FNV-1a check of the thinking text, so
/// clients that require a signature can send the block back.
pub fn signature(thinking: &str) -> String {
    let h = thinking.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100_0000_01b3)
    });
    format!("qe1{h:016x}")
}

fn tool_input(arguments: &str) -> Value {
    serde_json::from_str(arguments).unwrap_or(json!({}))
}

/// The buffered Anthropic answer.
pub fn anthropic_message(c: &Collected, id: &str, model: &str) -> Value {
    let mut content = Vec::new();
    if !c.reasoning.is_empty() {
        content.push(json!({"type": "thinking", "thinking": c.reasoning, "signature": signature(&c.reasoning)}));
    }
    if !c.text.is_empty() {
        content.push(json!({"type": "text", "text": c.text}));
    }
    for (i, call) in c.calls.iter().enumerate() {
        content.push(
            json!({"type": "tool_use", "id": format!("toolu_{id}_{i}"), "name": call.name,
                            "input": tool_input(&call.arguments)}),
        );
    }
    json!({"id": id, "type": "message", "role": "assistant", "model": model, "content": content,
           "stop_reason": stop_reason(c), "stop_sequence": null,
           "usage": anthropic_usage(c.prompt_tokens, c.cached, c.written, c.completion_tokens, c.reasoning_tokens)})
}

/// The Anthropic event stream QE writes, fed QE's events.
#[derive(Debug)]
pub struct AnthropicStream {
    id: String,
    model: String,
    open: Option<(usize, &'static str)>,
    thought: String,
    next: usize,
    started: bool,
}

impl AnthropicStream {
    pub fn new(id: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            model: model.into(),
            open: None,
            thought: String::new(),
            next: 0,
            started: false,
        }
    }

    /// QE sends `message_start` once its engine admitted the request, with
    /// the prompt and cache counts. A Chat stream reports those only at its
    /// end, so this `message_start` carries zeros; `message_delta` has them.
    fn start(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        out.extend(sse(
            "message_start",
            json!({"message": {"id": self.id, "type": "message", "role": "assistant", "model": self.model,
                "content": [], "stop_reason": null, "stop_sequence": null,
                "usage": anthropic_usage(0, 0, 0, 1, 0)}}),
        ));
        out.extend(sse("ping", json!({})));
    }

    fn close(&mut self, out: &mut Vec<u8>) {
        if let Some((i, k)) = self.open.take() {
            if k == "thinking" {
                let sig = signature(&std::mem::take(&mut self.thought));
                out.extend(sse(
                    "content_block_delta",
                    json!({"index": i, "delta": {"type": "signature_delta", "signature": sig}}),
                ));
            }
            out.extend(sse("content_block_stop", json!({"index": i})));
        }
    }

    pub fn event(&mut self, e: &Ev) -> Vec<u8> {
        let mut out = Vec::new();
        if matches!(e, Ev::ToolEnd { .. } | Ev::Logprobs(_)) {
            return out;
        }
        self.start(&mut out);
        let (kind, start_block, delta) = match e {
            Ev::Reasoning(s) => {
                self.thought.push_str(s);
                (
                    "thinking",
                    json!({"type": "thinking", "thinking": "", "signature": ""}),
                    json!({"type": "thinking_delta", "thinking": s}),
                )
            }
            Ev::Text(s) => (
                "text",
                json!({"type": "text", "text": ""}),
                json!({"type": "text_delta", "text": s}),
            ),
            Ev::ToolStart { index, name } | Ev::Custom { index, name, .. } => {
                self.close(&mut out);
                let i = self.next;
                self.next += 1;
                self.open = Some((i, "tool_use"));
                out.extend(sse(
                    "content_block_start",
                    json!({"index": i, "content_block": {"type": "tool_use",
                        "id": format!("toolu_{}_{index}", self.id), "name": name, "input": {}}}),
                ));
                return out;
            }
            Ev::ToolArgs { delta, .. } => {
                if let Some((i, _)) = self.open {
                    out.extend(sse(
                        "content_block_delta",
                        json!({"index": i, "delta": {"type": "input_json_delta", "partial_json": delta}}),
                    ));
                }
                return out;
            }
            Ev::ToolEnd { .. } | Ev::Logprobs(_) => return out,
        };
        if self.open.map(|o| o.1) != Some(kind) {
            self.close(&mut out);
            let i = self.next;
            self.next += 1;
            self.open = Some((i, kind));
            out.extend(sse(
                "content_block_start",
                json!({"index": i, "content_block": start_block}),
            ));
        }
        out.extend(sse(
            "content_block_delta",
            json!({"index": self.open.unwrap().0, "delta": delta}),
        ));
        out
    }

    /// The stream's end: the open block closed, the stop reason and usage.
    pub fn end(&mut self, c: &Collected) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(e) = &c.error {
            out.extend(sse(
                "error",
                json!({"error": {"type": "api_error", "message": e}}),
            ));
            return out;
        }
        self.start(&mut out);
        self.close(&mut out);
        out.extend(sse(
            "message_delta",
            json!({"delta": {"stop_reason": stop_reason(c), "stop_sequence": null},
                   "usage": anthropic_usage(c.prompt_tokens, c.cached, c.written, c.completion_tokens, c.reasoning_tokens)}),
        ));
        out.extend(sse("message_stop", json!({})));
        out
    }
}

// ---------------------------------------------------------------------------
// OpenAI Responses
// ---------------------------------------------------------------------------

/// QE's sampling defaults (its model's generation_config), which a Responses
/// object echoes when the request did not set them. QE's Chat answer does not
/// carry them, so they are configured on the provider.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SamplingDefaults {
    pub temperature: f32,
    pub top_p: f32,
}

impl Default for SamplingDefaults {
    fn default() -> Self {
        Self {
            temperature: 1.0,
            top_p: 1.0,
        }
    }
}

/// What a Responses answer echoes and how it is written, from the request.
#[derive(Debug, Clone)]
pub struct ResponsesCtx {
    /// `response_echo`: the request's own settings.
    pub echo: Value,
    /// Reasoning items carry `encrypted_content`.
    pub encrypt: bool,
    /// Names of the request's custom tools.
    pub custom: Vec<String>,
    /// Logprobs were asked for.
    pub want_lp: bool,
    /// The request's `max_output_tokens`.
    pub max_tokens: Option<u64>,
}

/// QE reads numbers as f32 and echoes them widened back.
fn f32_json(x: f32) -> Value {
    json!(x)
}

impl ResponsesCtx {
    /// `server.rs` `response_echo` (with `store` / `background` as decided by
    /// the gateway's response store).
    pub fn new(body: &Value, defaults: SamplingDefaults, store: bool, background: bool) -> Self {
        let g = |k: &str| body.get(k).cloned().unwrap_or(Value::Null);
        let num = |k: &str, d: f32| {
            body.get(k)
                .filter(|v| !v.is_null())
                .and_then(|v| v.as_f64())
                .map(|v| v as f32)
                .unwrap_or(d)
        };
        let max_tokens = body.get("max_output_tokens").and_then(|m| m.as_u64());
        let echo = json!({
            "instructions": g("instructions"),
            "tools": body.get("tools").cloned().unwrap_or(json!([])),
            "tool_choice": body.get("tool_choice").cloned().unwrap_or(json!("auto")),
            "parallel_tool_calls": body.get("parallel_tool_calls").cloned().unwrap_or(json!(true)),
            "temperature": f32_json(num("temperature", defaults.temperature)),
            "top_p": f32_json(num("top_p", defaults.top_p)),
            "max_output_tokens": max_tokens.map_or(Value::Null, Value::from),
            "reasoning": g("reasoning"),
            "text": body.get("text").cloned().unwrap_or(json!({"format": {"type": "text"}})),
            "truncation": body.get("truncation").cloned().unwrap_or(json!("disabled")),
            "metadata": g("metadata"),
            "user": g("user"),
            "store": store,
            "previous_response_id": g("previous_response_id"),
            "background": background,
            "max_tool_calls": g("max_tool_calls"),
            "top_logprobs": body.get("top_logprobs").cloned().unwrap_or(json!(0)),
            "service_tier": body.get("service_tier").cloned().filter(|v| !v.is_null()).unwrap_or(json!("default")),
            "prompt_cache_key": g("prompt_cache_key"),
            "safety_identifier": g("safety_identifier"),
        });
        let custom = body
            .get("tools")
            .and_then(|t| t.as_array())
            .into_iter()
            .flatten()
            .filter(|t| t.get("type").and_then(|x| x.as_str()) == Some("custom"))
            .filter_map(|t| {
                t.get("name")
                    .or_else(|| t.pointer("/custom/name"))
                    .and_then(|n| n.as_str())
                    .map(str::to_string)
            })
            .collect();
        let encrypt = body
            .get("include")
            .and_then(|i| i.as_array())
            .is_some_and(|a| a.iter().any(|x| x == "reasoning.encrypted_content"));
        let want_lp = body.get("top_logprobs").is_some_and(|v| !v.is_null())
            || body
                .get("include")
                .and_then(|i| i.as_array())
                .is_some_and(|a| a.iter().any(|x| x == "message.output_text.logprobs"));
        Self {
            echo,
            encrypt,
            custom,
            want_lp,
            max_tokens,
        }
    }

    /// `server.rs` `response_object`.
    pub fn object(
        &self,
        id: &str,
        model: &str,
        created: u64,
        status: &str,
        output: Vec<Value>,
        c: Option<&Collected>,
    ) -> Value {
        let mut r = json!({"id": id, "object": "response", "created_at": created, "model": model, "status": status,
                           "output": output, "error": null, "incomplete_details": null, "usage": null,
                           "background": false, "previous_response_id": null, "prompt": null, "service_tier": "auto",
                           "top_logprobs": null, "max_tool_calls": null, "user": null, "metadata": null,
                           "presence_penalty": 0.0, "frequency_penalty": 0.0});
        if let Some(e) = self.echo.as_object() {
            for (k, v) in e {
                r[k.as_str()] = v.clone();
            }
        }
        if let Some(c) = c {
            r["usage"] = json!({"input_tokens": c.prompt_tokens, "output_tokens": c.completion_tokens,
                                "total_tokens": c.prompt_tokens + c.completion_tokens,
                                "input_tokens_details": {"cached_tokens": c.cached, "cache_write_tokens": c.written},
                                "output_tokens_details": {"reasoning_tokens": c.reasoning_tokens}});
            if c.cut(self.max_tokens) {
                r["status"] = "incomplete".into();
                r["incomplete_details"] = json!({"reason": "max_output_tokens"});
            }
        }
        r
    }

    /// `server.rs` `response_output`.
    pub fn output(&self, id: &str, c: &Collected) -> Vec<Value> {
        let mut out = Vec::new();
        if !c.reasoning.is_empty() {
            out.push(
                json!({"type": "reasoning", "id": format!("rs_{id}"), "summary": [],
                "content": [{"type": "reasoning_text", "text": c.reasoning}],
                "encrypted_content": self.encrypt.then(|| encode_reasoning(&c.reasoning)),
                "status": "completed"}),
            );
        }
        if !c.text.is_empty() {
            out.push(json!({"type": "message", "id": format!("msg_{id}"), "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": c.text, "annotations": [], "logprobs": c.logprobs}]}));
        }
        for (i, call) in c.calls.iter().enumerate() {
            if self.custom.contains(&call.name) {
                out.push(
                    json!({"type": "custom_tool_call", "id": format!("ctc_{id}_{i}"),
                    "call_id": format!("call_{id}_{i}"), "name": call.name,
                    "input": call.input.clone().unwrap_or_else(|| custom_input(&call.arguments)),
                    "status": "completed"}),
                );
                continue;
            }
            out.push(json!({"type": "function_call", "id": format!("fc_{id}_{i}"), "call_id": format!("call_{id}_{i}"),
                "name": call.name, "arguments": call.arguments, "status": "completed"}));
        }
        out
    }

    /// The finished response object: completed, incomplete or failed.
    pub fn finished(&self, id: &str, model: &str, created: u64, c: &Collected) -> Value {
        match &c.error {
            Some(e) => {
                let mut r = self.object(id, model, created, "failed", vec![], None);
                r["error"] = json!({"code": "server_error", "message": e});
                r
            }
            None => self.object(id, model, created, "completed", self.output(id, c), Some(c)),
        }
    }
}

/// `server.rs` `custom_input`.
fn custom_input(arguments: &str) -> String {
    serde_json::from_str::<Value>(arguments)
        .ok()
        .and_then(|v| v.get("input").and_then(|i| i.as_str()).map(str::to_string))
        .unwrap_or_default()
}

/// `server.rs` `assistant_message`: the reply as the chat message QE stores
/// for `previous_response_id` (call ids as the output names them).
pub fn assistant_message(id: &str, c: &Collected) -> Value {
    let mut m = json!({"role": "assistant", "content": c.text});
    if !c.reasoning.is_empty() {
        m["reasoning_content"] = c.reasoning.clone().into();
    }
    if !c.calls.is_empty() {
        m["tool_calls"] = c
            .calls
            .iter()
            .enumerate()
            .map(|(i, call)| {
                json!({"id": format!("call_{id}_{i}"), "type": "function",
                       "function": {"name": call.name,
                                    "arguments": serde_json::from_str::<Value>(&call.arguments).unwrap_or(json!({}))}})
            })
            .collect();
    }
    m
}

/// `server.rs` `input_item_list`: the request's input as items with ids.
pub fn input_items(body: &Value, id: &str) -> Vec<Value> {
    let items = match body.get("input") {
        Some(Value::String(s)) => {
            vec![
                json!({"type": "message", "role": "user", "content": [{"type": "input_text", "text": s}]}),
            ]
        }
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    items
        .into_iter()
        .enumerate()
        .map(|(k, mut it)| {
            if it.get("type").is_none() {
                it["type"] = "message".into();
            }
            if let Some(Value::String(t)) = it.get("content").cloned() {
                it["content"] = json!([{"type": "input_text", "text": t}]);
            }
            if it.get("id").is_none_or(|x| x.is_null()) {
                it["id"] = format!("in_{id}_{k}").into();
            }
            it
        })
        .collect()
}

enum Open {
    None,
    Reasoning {
        index: usize,
        text: String,
        item: String,
    },
    Message {
        index: usize,
        text: String,
        item: String,
    },
    Call {
        index: usize,
        item: String,
        call_id: String,
        name: String,
        args: String,
    },
    Custom {
        index: usize,
        item: String,
        call_id: String,
        name: String,
        input: String,
    },
}

/// The Responses event stream QE writes (`server.rs` `RespStream` and the
/// `responses` envelope), fed QE's events.
pub struct ResponsesStream {
    id: String,
    seq: u64,
    next_index: usize,
    open: Open,
    custom: Vec<String>,
    encrypt: bool,
    messages_seen: bool,
    want_lp: bool,
    held: Option<String>,
    lps: Vec<Value>,
}

impl ResponsesStream {
    pub fn new(id: impl Into<String>, ctx: &ResponsesCtx) -> Self {
        Self {
            id: id.into(),
            seq: 0,
            next_index: 0,
            open: Open::None,
            custom: ctx.custom.clone(),
            encrypt: ctx.encrypt,
            messages_seen: false,
            want_lp: ctx.want_lp,
            held: None,
            lps: Vec::new(),
        }
    }

    /// One event, numbered.
    pub fn send(&mut self, ty: &str, mut v: Value) -> Vec<u8> {
        v["type"] = ty.into();
        v["sequence_number"] = self.seq.into();
        self.seq += 1;
        format!("event: {ty}\ndata: {v}\n\n").into_bytes()
    }

    /// `response.created` and `response.in_progress`.
    pub fn begin(&mut self, r0: &Value) -> Vec<u8> {
        let mut out = self.send("response.created", json!({"response": r0}));
        out.extend(self.send("response.in_progress", json!({"response": r0})));
        out
    }

    fn flush(&mut self, logprobs: Vec<Value>, out: &mut Vec<u8>) {
        let Some(d) = self.held.take() else { return };
        let Open::Message { index, item, .. } = &self.open else {
            return;
        };
        let (index, item) = (*index, item.clone());
        self.lps.extend(logprobs.iter().cloned());
        let e = self.send(
            "response.output_text.delta",
            json!({"item_id": item, "output_index": index, "content_index": 0, "delta": d, "logprobs": logprobs}),
        );
        out.extend(e);
    }

    /// Close the open item.
    pub fn close(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.flush(Vec::new(), &mut out);
        let lps = std::mem::take(&mut self.lps);
        match std::mem::replace(&mut self.open, Open::None) {
            Open::None => {}
            Open::Reasoning { index, text, item } => {
                let part = json!({"type": "reasoning_text", "text": text});
                out.extend(self.send(
                    "response.reasoning_text.done",
                    json!({"item_id": item, "output_index": index, "content_index": 0, "text": text}),
                ));
                out.extend(self.send(
                    "response.reasoning_part.done",
                    json!({"item_id": item, "output_index": index, "content_index": 0, "part": part}),
                ));
                let enc = self.encrypt.then(|| encode_reasoning(&text));
                out.extend(self.send(
                    "response.output_item.done",
                    json!({"output_index": index, "item": {"type": "reasoning", "id": item, "summary": [],
                        "content": [part], "encrypted_content": enc, "status": "completed"}}),
                ));
            }
            Open::Message { index, text, item } => {
                let part = json!({"type": "output_text", "text": text, "annotations": [], "logprobs": lps});
                out.extend(self.send(
                    "response.output_text.done",
                    json!({"item_id": item, "output_index": index, "content_index": 0, "text": text, "logprobs": lps}),
                ));
                out.extend(self.send(
                    "response.content_part.done",
                    json!({"item_id": item, "output_index": index, "content_index": 0, "part": part}),
                ));
                out.extend(self.send(
                    "response.output_item.done",
                    json!({"output_index": index, "item": {"type": "message", "id": item, "role": "assistant",
                        "status": "completed", "content": [part]}}),
                ));
            }
            Open::Custom {
                index,
                item,
                call_id,
                name,
                input,
            } => {
                out.extend(self.send(
                    "response.custom_tool_call_input.done",
                    json!({"item_id": item, "output_index": index, "input": input}),
                ));
                out.extend(self.send(
                    "response.output_item.done",
                    json!({"output_index": index, "item": {"type": "custom_tool_call", "id": item, "call_id": call_id,
                        "name": name, "input": input, "status": "completed"}}),
                ));
            }
            Open::Call {
                index,
                item,
                call_id,
                name,
                args,
            } => {
                out.extend(self.send(
                    "response.function_call_arguments.done",
                    json!({"item_id": item, "output_index": index, "name": name, "arguments": args}),
                ));
                out.extend(self.send(
                    "response.output_item.done",
                    json!({"output_index": index, "item": {"type": "function_call", "id": item, "call_id": call_id,
                        "name": name, "arguments": args, "status": "completed"}}),
                ));
            }
        }
        out
    }

    fn tool_start(&mut self, k: usize, name: &str, out: &mut Vec<u8>) {
        out.extend(self.close());
        let index = self.next_index;
        self.next_index += 1;
        let id = &self.id;
        if self.custom.iter().any(|c| c == name) {
            let (item, call_id) = (format!("ctc_{id}_{k}"), format!("call_{id}_{k}"));
            let e = self.send(
                "response.output_item.added",
                json!({"output_index": index, "item": {"type": "custom_tool_call", "id": item, "call_id": call_id,
                    "name": name, "input": "", "status": "in_progress"}}),
            );
            out.extend(e);
            self.open = Open::Custom {
                index,
                item,
                call_id,
                name: name.to_string(),
                input: String::new(),
            };
            return;
        }
        let (item, call_id) = (format!("fc_{id}_{k}"), format!("call_{id}_{k}"));
        let e = self.send(
            "response.output_item.added",
            json!({"output_index": index, "item": {"type": "function_call", "id": item, "call_id": call_id,
                "name": name, "arguments": "", "status": "in_progress"}}),
        );
        out.extend(e);
        self.open = Open::Call {
            index,
            item,
            call_id,
            name: name.to_string(),
            args: String::new(),
        };
    }

    pub fn event(&mut self, e: &Ev) -> Vec<u8> {
        let mut out = Vec::new();
        if let Ev::Logprobs(v) = e {
            self.flush(v.clone(), &mut out);
            return out;
        }
        self.flush(Vec::new(), &mut out);
        let id = self.id.clone();
        match e {
            Ev::Reasoning(s) => {
                if !matches!(self.open, Open::Reasoning { .. }) {
                    out.extend(self.close());
                    let index = self.next_index;
                    self.next_index += 1;
                    let item = if index == 0 {
                        format!("rs_{id}")
                    } else {
                        format!("rs_{id}_{index}")
                    };
                    self.open = Open::Reasoning {
                        index,
                        text: String::new(),
                        item: item.clone(),
                    };
                    out.extend(self.send(
                        "response.output_item.added",
                        json!({"output_index": index, "item": {"type": "reasoning", "id": item, "summary": [],
                            "content": null, "encrypted_content": null, "status": "in_progress"}}),
                    ));
                    out.extend(self.send(
                        "response.reasoning_part.added",
                        json!({"item_id": item, "output_index": index, "content_index": 0,
                            "part": {"type": "reasoning_text", "text": ""}}),
                    ));
                }
                let Open::Reasoning { index, text, item } = &mut self.open else {
                    unreachable!()
                };
                text.push_str(s);
                let (index, item) = (*index, item.clone());
                out.extend(self.send(
                    "response.reasoning_text.delta",
                    json!({"item_id": item, "output_index": index, "content_index": 0, "delta": s}),
                ));
            }
            Ev::Text(s) => {
                if !matches!(self.open, Open::Message { .. }) {
                    out.extend(self.close());
                    let index = self.next_index;
                    self.next_index += 1;
                    let first = !self.messages_seen;
                    self.messages_seen = true;
                    let item = if first {
                        format!("msg_{id}")
                    } else {
                        format!("msg_{id}_{index}")
                    };
                    self.open = Open::Message {
                        index,
                        text: String::new(),
                        item: item.clone(),
                    };
                    out.extend(self.send(
                        "response.output_item.added",
                        json!({"output_index": index, "item": {"type": "message", "id": item, "role": "assistant",
                            "status": "in_progress", "content": []}}),
                    ));
                    out.extend(self.send(
                        "response.content_part.added",
                        json!({"item_id": item, "output_index": index, "content_index": 0,
                            "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}}),
                    ));
                }
                let Open::Message { index, text, item } = &mut self.open else {
                    unreachable!()
                };
                text.push_str(s);
                let (index, item) = (*index, item.clone());
                if self.want_lp {
                    self.held = Some(s.clone());
                    return out;
                }
                out.extend(self.send(
                    "response.output_text.delta",
                    json!({"item_id": item, "output_index": index, "content_index": 0, "delta": s, "logprobs": []}),
                ));
            }
            Ev::ToolStart { index: k, name } => self.tool_start(*k, name, &mut out),
            Ev::ToolArgs { delta, .. } => {
                if let Open::Call {
                    index, item, args, ..
                } = &mut self.open
                {
                    args.push_str(delta);
                    let (index, item) = (*index, item.clone());
                    out.extend(self.send(
                        "response.function_call_arguments.delta",
                        json!({"item_id": item, "output_index": index, "delta": delta}),
                    ));
                }
            }
            Ev::ToolEnd { arguments, .. } => {
                if let Open::Call { args, .. } = &mut self.open {
                    *args = arguments.clone();
                }
                out.extend(self.close());
            }
            Ev::Custom {
                index: k,
                name,
                input,
            } => {
                self.tool_start(*k, name, &mut out);
                if let Open::Custom {
                    index,
                    item,
                    input: held,
                    ..
                } = &mut self.open
                {
                    *held = input.clone();
                    let v = json!({"item_id": item, "output_index": index, "delta": input});
                    out.extend(self.send("response.custom_tool_call_input.delta", v));
                } else if let Open::Call { args, .. } = &mut self.open {
                    // A freeform call of a tool the request declared as a
                    // function: its arguments are the input object.
                    *args = json!({"input": input}).to_string();
                }
                out.extend(self.close());
            }
            Ev::Logprobs(_) => {}
        }
        out
    }

    /// The terminal event: completed / incomplete, or failed after an
    /// `error` event.
    pub fn end(&mut self, r: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        let ty = match r["status"].as_str() {
            Some("failed") => {
                let msg = r["error"]["message"].clone();
                out.extend(self.send(
                    "error",
                    json!({"code": "server_error", "message": msg, "param": null}),
                ));
                "response.failed"
            }
            Some("incomplete") | Some("cancelled") => "response.incomplete",
            _ => "response.completed",
        };
        out.extend(self.send(ty, json!({"response": r})));
        out
    }
}
