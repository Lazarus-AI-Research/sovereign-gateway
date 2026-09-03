//! Cassette-driven, fully offline conformance tests for yb-wire.
//!
//! A cassette (`tests/cassettes/<name>.json`) is a yakbak-style fixture:
//!
//! ```json
//! {
//!   "inbound_format": "...", "inbound_body": { ... },
//!   "target_format": "...",  "target_model": "...",
//!   "expected_upstream_body": { ... },
//!   "upstream_sse": ["data: ...", ...],
//!   "client_format": "...",  "expected_client_sse": "event: ...\n..."
//! }
//! ```
//!
//! Two kinds of assertions run, either or both per cassette:
//!
//! 1. **Request translation** — `emit_request(parse_request(inbound))` in the
//!    target format must equal `expected_upstream_body`, compared as parsed JSON
//!    `Value`s (not raw bytes), so key order and whitespace are irrelevant.
//! 2. **Stream translation** — decode `upstream_sse` (in `target_format`) into IR
//!    events, re-encode them into `client_format`, and compare to
//!    `expected_client_sse` *semantically* (parsed per-event, so formatting is
//!    irrelevant).
//!
//! A [`record`] helper can regenerate a request cassette from live inputs, but
//! all committed fixtures run offline.

use serde_json::Value;
use yb_wire::ir::StreamEvent;
use yb_wire::{anthropic, gemini, openai_chat, openai_responses, ChatRequest, EmitOptions};

// --------------------------------------------------------------------------
// Format dispatch
// --------------------------------------------------------------------------

fn parse_request(format: &str, body: &[u8]) -> ChatRequest {
    let r = match format {
        "anthropic" => anthropic::parse_request(body),
        "openai_chat" => openai_chat::parse_request(body),
        "openai_responses" => openai_responses::parse_request(body),
        "gemini" => gemini::parse_request(body),
        other => panic!("unknown inbound_format {other}"),
    };
    r.unwrap_or_else(|e| panic!("parse_request({format}) failed: {e}"))
}

fn emit_request(format: &str, req: &ChatRequest, opts: &EmitOptions) -> Vec<u8> {
    let r = match format {
        "anthropic" => anthropic::emit_request(req, opts),
        "openai_chat" => openai_chat::emit_request(req, opts),
        "openai_responses" => openai_responses::emit_request(req, opts),
        "gemini" => gemini::emit_request(req, opts),
        other => panic!("unknown target_format {other}"),
    };
    r.unwrap_or_else(|e| panic!("emit_request({format}) failed: {e}")).0
}

fn decode_stream(format: &str, lines: &[String]) -> Vec<StreamEvent> {
    let mut out = Vec::new();
    match format {
        "anthropic" => {
            let mut st = anthropic::SseState::default();
            for l in lines {
                out.extend(anthropic::decode_sse(l, &mut st));
            }
        }
        "openai_chat" => {
            let mut st = openai_chat::SseState::default();
            for l in lines {
                out.extend(openai_chat::decode_sse(l, &mut st));
            }
        }
        "openai_responses" => {
            let mut st = openai_responses::SseState::default();
            for l in lines {
                out.extend(openai_responses::decode_sse(l, &mut st));
            }
        }
        "gemini" => {
            let mut st = gemini::SseState::default();
            for l in lines {
                out.extend(gemini::decode_sse(l, &mut st));
            }
        }
        other => panic!("unknown stream format {other}"),
    }
    out
}

/// Encode IR events into the client's format.
///
/// `include_usage` comes from the cassette's own `inbound_body`, because on the
/// real path the client's request shapes the response encoder — OpenAI only
/// relays usage on a stream when `stream_options.include_usage` asked for it.
/// Passing it here is what lets a cassette cover the relay rather than stopping
/// at the decode.
fn encode_stream(format: &str, events: &[StreamEvent], include_usage: bool) -> Vec<u8> {
    match format {
        "anthropic" => anthropic::encode_sse(events, &mut anthropic::EmitState::default()),
        "openai_chat" => {
            let mut st = openai_chat::EmitState::default();
            st.set_include_usage(include_usage);
            let mut out = openai_chat::encode_sse(events, &mut st);
            // The surface holds [DONE] back while waiting on a trailing usage
            // chunk; the real driver flushes at end of stream, so do the same.
            out.extend(st.finish());
            out
        }
        "openai_responses" => {
            let mut st = openai_responses::EmitState::default();
            let mut out = openai_responses::encode_sse(events, &mut st);
            // Same deferral as the chat surface: response.completed waits on
            // usage, and the real driver flushes at end of stream.
            out.extend(st.finish());
            out
        }
        "gemini" => gemini::encode_sse(events, &mut gemini::EmitState::default()),
        other => panic!("unknown client format {other}"),
    }
}

// --------------------------------------------------------------------------
// SSE semantic comparison
// --------------------------------------------------------------------------

/// Parse an SSE stream into `(event_name, data_json)` pairs, skipping `[DONE]`.
fn parse_sse(s: &str) -> Vec<(Option<String>, Value)> {
    let mut out = Vec::new();
    let mut event_name: Option<String> = None;
    for line in s.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            event_name = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            event_name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("data:") {
            let data = rest.trim();
            if data == "[DONE]" {
                continue;
            }
            let v: Value = serde_json::from_str(data)
                .unwrap_or_else(|e| panic!("bad SSE data line {data:?}: {e}"));
            out.push((event_name.clone(), v));
        }
    }
    out
}

// --------------------------------------------------------------------------
// Cassette runner
// --------------------------------------------------------------------------

fn load(name: &str) -> Value {
    let path = format!("{}/tests/cassettes/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse cassette {name}: {e}"))
}

fn run(name: &str) {
    let c = load(name);

    // 1. Request translation.
    if let (Some(inbound_format), Some(inbound_body), Some(target_format), Some(expected)) = (
        c.get("inbound_format").and_then(Value::as_str),
        c.get("inbound_body"),
        c.get("target_format").and_then(Value::as_str),
        c.get("expected_upstream_body"),
    ) {
        let body = serde_json::to_vec(inbound_body).unwrap();
        let req = parse_request(inbound_format, &body);
        let opts = EmitOptions {
            target_model: c
                .get("target_model")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            force_reasoning_effort: None,
            stream: req.stream,
        };
        let emitted = emit_request(target_format, &req, &opts);
        let got: Value = serde_json::from_slice(&emitted).unwrap();
        assert_eq!(
            &got, expected,
            "[{name}] request {inbound_format} -> {target_format} mismatch\n got: {}\nwant: {}",
            serde_json::to_string_pretty(&got).unwrap(),
            serde_json::to_string_pretty(expected).unwrap(),
        );
    }

    // 2. Stream translation.
    if let (Some(upstream_sse), Some(expected_sse)) = (
        c.get("upstream_sse").and_then(Value::as_array),
        c.get("expected_client_sse").and_then(Value::as_str),
    ) {
        let target_format = c.get("target_format").and_then(Value::as_str).unwrap();
        let client_format = c
            .get("client_format")
            .and_then(Value::as_str)
            .or_else(|| c.get("inbound_format").and_then(Value::as_str))
            .unwrap();
        let lines: Vec<String> = upstream_sse
            .iter()
            .map(|l| l.as_str().unwrap().to_string())
            .collect();
        let events = decode_stream(target_format, &lines);
        // What the client asked for on the way in governs what it gets back.
        let include_usage = c
            .get("inbound_body")
            .and_then(|b| b.get("stream_options"))
            .and_then(|o| o.get("include_usage"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let encoded = encode_stream(client_format, &events, include_usage);
        let got = String::from_utf8(encoded).unwrap();
        assert_eq!(
            parse_sse(&got),
            parse_sse(expected_sse),
            "[{name}] stream {target_format} -> {client_format} mismatch\n got: {got}",
        );
    }
}

// --------------------------------------------------------------------------
// One #[test] per cassette
// --------------------------------------------------------------------------

#[test]
fn anthropic_to_openai_text() {
    run("anthropic_to_openai_text");
}

#[test]
fn openai_to_anthropic_text() {
    run("openai_to_anthropic_text");
}

#[test]
fn anthropic_to_openai_tools() {
    run("anthropic_to_openai_tools");
}

#[test]
fn openai_to_anthropic_tools() {
    run("openai_to_anthropic_tools");
}

#[test]
fn anthropic_to_openai_image() {
    run("anthropic_to_openai_image");
}

#[test]
fn gemini_to_openai_tools() {
    run("gemini_to_openai_tools");
}

#[test]
fn anthropic_to_responses_tools() {
    run("anthropic_to_responses_tools");
}

#[test]
fn openai_stream_to_anthropic() {
    run("openai_stream_to_anthropic");
}

/// Usage must survive the relay, not just the decode.
///
/// Recorded live from Kimi k3 over OpenAI Chat Completions with
/// `stream_options.include_usage`. The upstream's trailing choices-less usage
/// chunk was being decoded, accumulated for billing, and then dropped on the
/// way out, so a downstream metering proxy saw nothing.
/// A Codex turn's tool exchange must survive translation to a chat upstream.
///
/// Recorded from the shapes Codex actually sends: `custom_tool_call` /
/// `custom_tool_call_output` for freeform tools like `exec_command`. Losing
/// either half leaves an assistant `tool_calls` unanswered, and the upstream
/// rejects the whole turn.
#[test]
fn codex_tool_call_pairing() {
    run("codex_tool_call_pairing");
}

#[test]
fn openai_stream_usage_relay() {
    run("openai_stream_usage_relay");
}

#[test]
fn responses_stream_to_openai() {
    run("responses_stream_to_openai");
}

// --------------------------------------------------------------------------
// Direct assertions beyond the generic runner
// --------------------------------------------------------------------------

/// Gemini `parse_request` maps roles, function calls, function responses, the
/// system instruction, and generation config into the IR correctly.
#[test]
fn gemini_parse_request_shapes_ir() {
    use yb_wire::{ContentBlock, Role};

    let c = load("gemini_to_openai_tools");
    let body = serde_json::to_vec(c.get("inbound_body").unwrap()).unwrap();
    let req = gemini::parse_request(&body).unwrap();

    assert_eq!(req.system.as_ref().unwrap()[0], ContentBlock::text("You are helpful."));
    assert_eq!(req.messages.len(), 3);
    assert_eq!(req.messages[0].role, Role::User);
    assert_eq!(req.messages[1].role, Role::Assistant);
    assert_eq!(req.messages[2].role, Role::Tool);

    match &req.messages[1].content[0] {
        ContentBlock::ToolUse { name, input, .. } => {
            assert_eq!(name, "get_weather");
            assert_eq!(input["location"], "Paris");
        }
        other => panic!("expected tool_use, got {other:?}"),
    }
    match &req.messages[2].content[0] {
        ContentBlock::ToolResult { tool_use_id, .. } => assert_eq!(tool_use_id, "get_weather"),
        other => panic!("expected tool_result, got {other:?}"),
    }
    assert_eq!(req.max_tokens, Some(256));
    assert_eq!(req.tools.len(), 1);
}

/// Usage tokens and stop reasons survive an Anthropic response round-trip.
#[test]
fn anthropic_response_usage_and_stop_reason() {
    use yb_wire::StopReason;

    let body = serde_json::json!({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [{"type": "text", "text": "Hi"}],
        "stop_reason": "max_tokens",
        "usage": {
            "input_tokens": 100,
            "output_tokens": 50,
            "cache_read_input_tokens": 20,
            "cache_creation_input_tokens": 10
        }
    });
    let resp = anthropic::parse_response(&serde_json::to_vec(&body).unwrap()).unwrap();
    assert_eq!(resp.stop_reason, StopReason::MaxTokens);
    assert_eq!(resp.usage.input_tokens, 100);
    assert_eq!(resp.usage.output_tokens, 50);
    assert_eq!(resp.usage.cache_read_tokens, 20);
    assert_eq!(resp.usage.cache_write_tokens, 10);

    // Re-emit to OpenAI chat and confirm the token mapping carries across.
    let out = openai_chat::emit_response(&resp).unwrap();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["usage"]["prompt_tokens"], 100);
    assert_eq!(v["usage"]["completion_tokens"], 50);
    assert_eq!(v["choices"][0]["finish_reason"], "length");
}

/// A regeneration helper: parse an inbound body and emit it to the target
/// format, returning the cassette's `expected_upstream_body`. Tests do not call
/// this (they read committed fixtures); it exists to (re)record them offline.
#[allow(dead_code)]
pub fn record(inbound_format: &str, inbound_body: &Value, target_format: &str, target_model: &str) -> Value {
    let body = serde_json::to_vec(inbound_body).unwrap();
    let req = parse_request(inbound_format, &body);
    let opts = EmitOptions {
        target_model: target_model.to_string(),
        force_reasoning_effort: None,
        stream: req.stream,
    };
    let emitted = emit_request(target_format, &req, &opts);
    serde_json::from_slice(&emitted).unwrap()
}

// --------------------------------------------------------------------------
// Verbatim vLLM replay fixtures (recorded from a real backend; yakbak-style).
// These assert semantic invariants of decode -> IR -> encode rather than exact
// golden bytes, so they stay robust to cosmetic encoder changes while pinning
// the real event grammar: item/part lifecycle ordering, reasoning capture,
// tool-argument reassembly, and usage totals.
// --------------------------------------------------------------------------

/// Decode a verbatim recorded vLLM Responses stream into IR events.
fn replay_vllm(name: &str) -> Vec<StreamEvent> {
    let c = load(name);
    let lines: Vec<String> = c["upstream_sse"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect();
    decode_stream("openai_responses", &lines)
}

/// Assert a re-encoded Responses stream is lifecycle-correct: every delta names
/// an item already announced by `output_item.added`, every added item is closed
/// by `output_item.done`, and `response.completed` carries usage totals.
fn assert_responses_lifecycle(bytes: &[u8]) {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let mut open: std::collections::HashSet<String> = Default::default();
    let mut saw_completed = false;
    for line in text.lines().filter(|l| l.starts_with("data:")) {
        let v: Value = serde_json::from_str(line[5..].trim()).unwrap();
        match v["type"].as_str().unwrap_or_default() {
            "response.output_item.added" => {
                open.insert(v["item"]["id"].as_str().unwrap().to_string());
            }
            "response.output_item.done" => {
                let id = v["item"]["id"].as_str().unwrap();
                assert!(open.remove(id), "output_item.done for unopened item {id}");
            }
            t if t.ends_with(".delta") => {
                let id = v["item_id"].as_str().expect("delta carries item_id");
                assert!(open.contains(id), "{t} for item {id} before output_item.added");
            }
            "response.completed" => {
                saw_completed = true;
                let u = &v["response"]["usage"];
                assert!(u["total_tokens"].is_u64(), "usage.total_tokens missing: {u}");
            }
            _ => {}
        }
    }
    assert!(saw_completed, "stream never emitted response.completed");
    assert!(open.is_empty(), "items left open at end of stream: {open:?}");
}

/// Tool-lifecycle recording: reasoning -> message -> function_call in one turn.
#[test]
fn vllm_replay_tool_stream_decodes_and_reencodes() {
    let events = replay_vllm("vllm_responses_stream_tool");

    let thinking: String = events.iter().filter_map(|e| match e {
        StreamEvent::ThinkingDelta { text } => Some(text.as_str()), _ => None }).collect();
    assert!(!thinking.is_empty(), "reasoning_text deltas must decode to ThinkingDelta");

    let starts: Vec<_> = events.iter().filter_map(|e| match e {
        StreamEvent::ToolUseStart { name, .. } => Some(name.clone()), _ => None }).collect();
    assert_eq!(starts, vec!["calc".to_string()], "one tool call to calc");

    let args: String = events.iter().filter_map(|e| match e {
        StreamEvent::ToolUseDelta { partial_json } => Some(partial_json.as_str()), _ => None }).collect();
    let parsed: Value = serde_json::from_str(&args).expect("tool args reassemble to JSON");
    assert_eq!(parsed["answer"], 42);

    // Re-encode to every client surface without panicking; Responses output must
    // be lifecycle-correct end to end.
    assert_responses_lifecycle(&encode_stream("openai_responses", &events, false));
    let _ = encode_stream("anthropic", &events, false);
    let _ = encode_stream("openai_chat", &events, false);

    // Gemini has no partial-tool encoding, so its encoder buffers tool args and
    // must emit ONE functionCall part carrying the complete args object.
    let gem = String::from_utf8(encode_stream("gemini", &events, false)).unwrap();
    assert!(gem.contains("\"functionCall\""), "gemini output missing functionCall");
    assert!(
        gem.contains("\"answer\":42") || gem.contains("\"answer\": 42"),
        "gemini functionCall must carry the complete args, got: {gem}"
    );
}

/// Large real-agent recording: a codex turn (47 input items, 13 tools) replayed
/// verbatim; long text answer.
#[test]
fn vllm_replay_codex_stream_decodes_and_reencodes() {
    let events = replay_vllm("vllm_responses_stream_codex");

    let text: String = events.iter().filter_map(|e| match e {
        StreamEvent::TextDelta { text } => Some(text.as_str()), _ => None }).collect();
    assert!(text.len() > 1000, "expected a long text answer, got {} chars", text.len());

    let done = events.iter().any(|e| matches!(e, StreamEvent::Done { .. }));
    assert!(done, "stream must terminate with Done");

    assert_responses_lifecycle(&encode_stream("openai_responses", &events, false));
    let _ = encode_stream("anthropic", &events, false);
    let _ = encode_stream("openai_chat", &events, false);
}

/// `prompt_cache_key` round-trips on both OpenAI shapes, always accompanied by
/// `prompt_cache_retention` (defaulting to "24h"); other surfaces ignore it.
#[test]
fn prompt_cache_key_roundtrips_on_openai_shapes() {
    let inbound = serde_json::json!({
        "model": "m", "input": "hi", "prompt_cache_key": "cache-abc"
    });
    let req = parse_request("openai_responses", &serde_json::to_vec(&inbound).unwrap());
    assert_eq!(req.prompt_cache_key.as_deref(), Some("cache-abc"));

    // responses -> responses: key + default retention
    let out: Value = serde_json::from_slice(&emit_request(
        "openai_responses", &req, &EmitOptions::new("m"))).unwrap();
    assert_eq!(out["prompt_cache_key"], "cache-abc");
    assert_eq!(out["prompt_cache_retention"], "24h");

    // responses -> chat: same fields on the chat shape
    let chat: Value = serde_json::from_slice(&emit_request(
        "openai_chat", &req, &EmitOptions::new("m"))).unwrap();
    assert_eq!(chat["prompt_cache_key"], "cache-abc");
    assert_eq!(chat["prompt_cache_retention"], "24h");

    // an explicit client retention wins over the default
    let inbound2 = serde_json::json!({
        "model": "m", "input": "hi",
        "prompt_cache_key": "k2", "prompt_cache_retention": "1h"
    });
    let req2 = parse_request("openai_responses", &serde_json::to_vec(&inbound2).unwrap());
    let out2: Value = serde_json::from_slice(&emit_request(
        "openai_responses", &req2, &EmitOptions::new("m"))).unwrap();
    assert_eq!(out2["prompt_cache_retention"], "1h");

    // responses -> anthropic: no leak
    let ant: Value = serde_json::from_slice(&emit_request(
        "anthropic", &req, &EmitOptions::new("m"))).unwrap();
    assert!(ant.get("prompt_cache_key").is_none());
    assert!(ant.get("prompt_cache_retention").is_none());
}

/// The Responses **response object** also carries the prompt-cache fields: an
/// upstream echo is parsed into the IR and re-emitted; the streaming envelopes
/// carry them when seeded (the gateway seeds from the request).
#[test]
fn prompt_cache_fields_echo_on_response_object() {
    // Upstream response echoes the fields -> parse_response captures them.
    let upstream = serde_json::json!({
        "id": "resp_1", "model": "m", "object": "response", "status": "completed",
        "output": [{"type": "message", "role": "assistant",
                    "content": [{"type": "output_text", "text": "hi"}]}],
        "usage": {"input_tokens": 1, "output_tokens": 1},
        "prompt_cache_key": "k", "prompt_cache_retention": "1h"
    });
    let resp = openai_responses::parse_response(&serde_json::to_vec(&upstream).unwrap()).unwrap();
    assert_eq!(resp.prompt_cache_key.as_deref(), Some("k"));
    assert_eq!(resp.prompt_cache_retention.as_deref(), Some("1h"));

    // ...and emit_response reflects them back on the client-facing object.
    let out: Value =
        serde_json::from_slice(&openai_responses::emit_response(&resp).unwrap()).unwrap();
    assert_eq!(out["prompt_cache_key"], "k");
    assert_eq!(out["prompt_cache_retention"], "1h");

    // Streaming: a seeded encoder carries the echo on the response envelopes.
    let mut st = openai_responses::EmitState::default();
    st.set_prompt_cache(Some("k2".into()), None);
    let events = vec![
        StreamEvent::MessageStart { model: "m".into() },
        StreamEvent::TextDelta { text: "hi".into() },
        StreamEvent::Done { stop_reason: yb_wire::StopReason::EndTurn },
    ];
    // No UsageDelta here, so `response.completed` is deferred; the real driver
    // flushes at end of stream, and so must this.
    let mut bytes = openai_responses::encode_sse(&events, &mut st);
    bytes.extend(st.finish());
    let sse = String::from_utf8(bytes).unwrap();
    let completed = sse.lines()
        .filter(|l| l.starts_with("data:"))
        .map(|l| serde_json::from_str::<Value>(l[5..].trim()).unwrap())
        .find(|v| v["type"] == "response.completed")
        .expect("has response.completed");
    assert_eq!(completed["response"]["prompt_cache_key"], "k2");
    assert_eq!(completed["response"]["prompt_cache_retention"], "24h");
}
