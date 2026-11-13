//! QE dialect translation: requests as the QE Chat bodies QE prepares the
//! same way, and QE Chat answers as QE's own Anthropic / Responses answers.
//! The cassettes under `tests/cassettes/qe/` were recorded against a QE
//! server (see `scripts/qe-lossless-check`); these unit tests pin the rules.

use serde_json::{json, Value};
use yb_wire::qe::{
    anthropic_message, anthropic_to_chat, collect_chat, encode_reasoning, responses_to_chat,
    AnthropicStream, ChatEvents, Ev, NoItems, ResponseItems, ResponsesCtx, ResponsesStream,
    SamplingDefaults,
};

fn chat(body: Value) -> Value {
    anthropic_to_chat(&body).unwrap().0
}

#[test]
fn anthropic_effort_budget_and_switch_are_spelled_as_qe_reads_them() {
    let c = chat(json!({"model": "m", "max_tokens": 100, "messages": [],
        "thinking": {"type": "enabled", "budget_tokens": 1500}, "output_config": {"effort": "medium"}}));
    assert_eq!(c["reasoning_effort"], "medium");
    assert_eq!(c["thinking_token_budget"], 1500);
    assert_eq!(c["chat_template_kwargs"], json!({"enable_thinking": true}));
    // Anthropic's max is QE's deepest level, xhigh.
    let c = chat(json!({"max_tokens": 1, "messages": [], "output_config": {"effort": "max"}}));
    assert_eq!(c["reasoning_effort"], "xhigh");
    // An integer effort is read from the template kwargs, after the switch.
    let c = chat(
        json!({"max_tokens": 1, "messages": [], "reasoning_effort": 62,
        "thinking": {"type": "disabled"}, "chat_template_kwargs": {"x": 1}}),
    );
    assert_eq!(
        serde_json::to_string(&c["chat_template_kwargs"]).unwrap(),
        r#"{"x":1,"enable_thinking":false,"reasoning_effort":62}"#
    );
    assert!(c.get("reasoning_effort").is_none());
    assert!(anthropic_to_chat(&json!({"max_tokens": 1, "messages": [],
        "output_config": {"effort": "huge"}}))
    .is_err());
    assert!(
        anthropic_to_chat(&json!({"messages": []})).is_err(),
        "max_tokens is required"
    );
}

#[test]
fn anthropic_messages_join_as_qe_joins_them() {
    let c = chat(json!({"max_tokens": 9,
        "system": [{"type": "text", "text": "A"}, {"type": "text", "text": "B", "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "u1"}, {"type": "text", "text": "u2"}]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "t", "signature": "x"},
                {"type": "text", "text": "a1"}, {"type": "text", "text": "a2"},
                {"type": "tool_use", "id": "t1", "name": "f", "input": "{\"z\": 1, \"a\": 2}"}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "r1"}, {"type": "text", "text": "r2"}], "is_error": true},
                {"type": "text", "text": "next", "cache_control": {"type": "ephemeral"}}]}]}));
    let m = c["messages"].as_array().unwrap();
    assert_eq!(
        m[0],
        json!({"role": "system", "content": "A\nB", "cache_control": {"type": "ephemeral"}})
    );
    assert_eq!(m[1], json!({"role": "user", "content": "u1\nu2"}));
    assert_eq!(m[2]["content"], "a1a2");
    assert_eq!(m[2]["reasoning_content"], "t");
    // String input parsed, key order kept.
    assert_eq!(
        serde_json::to_string(&m[2]["tool_calls"][0]["function"]["arguments"]).unwrap(),
        r#"{"z":1,"a":2}"#
    );
    assert_eq!(
        m[3],
        json!({"role": "tool", "tool_call_id": "t1", "content": "Error: r1\nr2"})
    );
    assert_eq!(
        m[4],
        json!({"role": "user", "content": "next", "cache_control": {"type": "ephemeral"}})
    );
}

#[test]
fn anthropic_tools_and_choices() {
    let c = chat(
        json!({"max_tokens": 9, "system": "s", "messages": [{"role": "user", "content": "q"}],
        "tools": [{"type": "custom", "name": "f", "input_schema": {"type": "object",
            "properties": {"b": {"type": "string"}, "a": {"type": "string"}}, "required": ["a", "b"]},
            "cache_control": {"type": "ephemeral"}}],
        "tool_choice": {"type": "any", "disable_parallel_tool_use": true},
        "stop_sequences": ["END"], "top_k": 5, "seed": 3, "temperature": 0.5,
        "cache_control": {"type": "ephemeral"}}),
    );
    assert_eq!(
        c["tools"][0]["type"], "function",
        "Anthropic custom is a plain function tool"
    );
    assert_eq!(
        serde_json::to_string(&c["tools"][0]["function"]["parameters"]["properties"]).unwrap(),
        r#"{"a":{"type":"string"},"b":{"type":"string"}}"#,
        "required properties first, as QE restores them"
    );
    assert_eq!(c["tool_choice"], "required");
    assert_eq!(c["parallel_tool_calls"], false);
    assert_eq!(c["stop"], json!(["END"]));
    assert_eq!(
        (c["top_k"].clone(), c["seed"].clone()),
        (json!(5), json!(3))
    );
    // The tool breakpoint lands on the system message, the top-level one on
    // the last message.
    assert!(c["messages"][0].get("cache_control").is_some());
    assert!(c["messages"][1].get("cache_control").is_some());
    let named = chat(
        json!({"max_tokens": 1, "messages": [], "tools": [{"name": "f", "input_schema": {}}],
        "tool_choice": {"type": "tool", "name": "f"}}),
    );
    assert_eq!(
        named["tool_choice"],
        json!({"type": "function", "function": {"name": "f"}})
    );
    let none = chat(json!({"max_tokens": 1, "messages": [], "tools": []}));
    assert!(
        none.get("tools").is_none(),
        "no tools is not an empty tool list"
    );
    let five =
        json!({"max_tokens": 1, "messages": [], "stop_sequences": ["a", "b", "c", "d", "e"]});
    assert!(
        anthropic_to_chat(&five).is_err(),
        "Chat takes at most 4 stops"
    );
    // Penalties are not Anthropic fields; QE ignores them there.
    let p = chat(json!({"max_tokens": 1, "messages": [], "presence_penalty": 1.0}));
    assert!(p.get("presence_penalty").is_none());
}

struct Store(Vec<Value>);
impl ResponseItems for Store {
    fn history(&self, id: &str) -> Option<Vec<Value>> {
        (id == "resp_prev").then(|| self.0.clone())
    }
    fn item(&self, id: &str) -> Option<Value> {
        (id == "fc_1").then(|| json!({"type": "function_call", "id": "fc_1", "call_id": "c1", "name": "f", "arguments": "{}"}))
    }
    fn cap(&self) -> usize {
        8
    }
}

#[test]
fn responses_input_items_become_qe_messages() {
    let body = json!({"model": "m", "instructions": "be brief", "previous_response_id": "resp_prev",
        "input": [
            {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "d1"}, {"type": "input_text", "text": "d2"}]},
            {"type": "reasoning", "encrypted_content": encode_reasoning("why"), "summary": []},
            {"type": "item_reference", "id": "fc_1"},
            {"type": "function_call_output", "call_id": "c1", "output": "42"},
            {"role": "user", "content": "go"}],
        "reasoning": {"effort": "none"}, "max_output_tokens": 77, "top_logprobs": 2,
        "tools": [{"type": "function", "name": "f", "parameters": {"type": "object"}, "strict": null}],
        "text": {"format": {"type": "json_object"}}, "prompt_cache_key": "k"});
    let t = responses_to_chat(
        &body,
        &Store(vec![json!({"role": "user", "content": "earlier"})]),
    )
    .unwrap();
    let m = t.body["messages"].as_array().unwrap();
    assert_eq!(m[0], json!({"role": "system", "content": "be brief"}));
    assert_eq!(
        m[1],
        json!({"role": "user", "content": "earlier"}),
        "history after the instructions"
    );
    assert_eq!(m[2], json!({"role": "system", "content": "d1d2"}));
    assert_eq!(m[3]["reasoning_content"], "why");
    assert_eq!(m[3]["tool_calls"][0]["function"]["arguments"], json!({}));
    assert_eq!(
        m[4],
        json!({"role": "tool", "tool_call_id": "c1", "content": "42"})
    );
    assert_eq!(t.body["reasoning_effort"], "none");
    assert_eq!(t.body["max_tokens"], 77);
    assert_eq!(
        (t.body["logprobs"].clone(), t.body["top_logprobs"].clone()),
        (json!(true), json!(2))
    );
    assert_eq!(
        t.body["tools"][0],
        json!({"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}})
    );
    assert_eq!(t.body["response_format"], json!({"type": "json_object"}));
    assert_eq!(t.body["prompt_cache_key"], "k");
    assert_eq!(
        t.history.len(),
        m.len() - 1,
        "stored without the instructions"
    );
    assert!(responses_to_chat(
        &json!({"input": "x", "previous_response_id": "nope"}),
        &NoItems
    )
    .is_err());
    assert!(responses_to_chat(&json!({"input": "x", "conversation": "c"}), &NoItems).is_err());
    assert!(responses_to_chat(
        &json!({"input": "x", "tools": [{"type": "web_search"}]}),
        &NoItems
    )
    .is_err());
}

fn sse_data(lines: &[Value]) -> Vec<String> {
    lines.iter().map(|l| l.to_string()).collect()
}

fn events(chunks: &[Value]) -> (Vec<Ev>, ChatEvents) {
    let mut ce = ChatEvents::default();
    let mut out = Vec::new();
    for d in sse_data(chunks) {
        out.extend(ce.push(&d));
    }
    out.extend(ce.push("[DONE]"));
    (out, ce)
}

fn qe_chat_stream() -> Vec<Value> {
    let c = |delta: Value, finish: Value| json!({"id": "x", "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]});
    vec![
        c(json!({"role": "assistant", "content": ""}), Value::Null),
        c(
            json!({"reasoning": "hm", "reasoning_content": "hm"}),
            Value::Null,
        ),
        c(json!({"content": "Let me "}), Value::Null),
        c(json!({"content": "check."}), Value::Null),
        c(
            json!({"tool_calls": [{"index": 0, "id": "call_x_0_0", "type": "function", "function": {"name": "f", "arguments": ""}}]}),
            Value::Null,
        ),
        c(
            json!({"tool_calls": [{"index": 0, "function": {"arguments": "{\"a\": "}}]}),
            Value::Null,
        ),
        c(
            json!({"tool_calls": [{"index": 0, "function": {"arguments": "1}"}}]}),
            Value::Null,
        ),
        c(json!({}), json!("tool_calls")),
        json!({"id": "x", "choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
            "prompt_tokens_details": {"cached_tokens": 4, "cache_write_tokens": 2}, "completion_tokens_details": {"reasoning_tokens": 1}}}),
    ]
}

#[test]
fn a_chat_stream_reads_back_into_qe_events() {
    let (evs, ce) = events(&qe_chat_stream());
    assert_eq!(
        evs,
        vec![
            Ev::Reasoning("hm".into()),
            Ev::Text("Let me ".into()),
            Ev::Text("check.".into()),
            Ev::ToolStart {
                index: 0,
                name: "f".into()
            },
            Ev::ToolArgs {
                index: 0,
                delta: "{\"a\": ".into()
            },
            Ev::ToolArgs {
                index: 0,
                delta: "1}".into()
            },
            Ev::ToolEnd {
                index: 0,
                name: "f".into(),
                arguments: "{\"a\": 1}".into()
            },
        ]
    );
    let c = ce.collected;
    assert_eq!(
        (
            c.prompt_tokens,
            c.completion_tokens,
            c.reasoning_tokens,
            c.cached,
            c.written
        ),
        (10, 5, 1, 4, 2)
    );
    assert_eq!(c.calls[0].arguments, "{\"a\": 1}");
}

fn data_of(sse: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(sse)
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

#[test]
fn anthropic_stream_has_qe_block_lifecycle() {
    let (evs, ce) = events(&qe_chat_stream());
    let mut a = AnthropicStream::new("msg_1", "m");
    let mut out = Vec::new();
    for e in &evs {
        out.extend(a.event(e));
    }
    out.extend(a.end(&ce.collected));
    let d = data_of(&out);
    let types: Vec<&str> = d.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(
        types,
        [
            "message_start",
            "ping",
            "content_block_start",
            "content_block_delta",
            "content_block_delta",
            "content_block_stop",
            "content_block_start",
            "content_block_delta",
            "content_block_delta",
            "content_block_stop",
            "content_block_start",
            "content_block_delta",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "message_stop"
        ]
    );
    assert_eq!(d[4]["delta"]["type"], "signature_delta");
    assert_eq!(d[10]["content_block"]["id"], "toolu_msg_1_0");
    assert_eq!(d[14]["delta"]["stop_reason"], "tool_use");
    assert_eq!(
        d[14]["usage"]["input_tokens"], 4,
        "Anthropic input excludes cache reads and writes"
    );
    assert_eq!(d[14]["usage"]["cache_read_input_tokens"], 4);
}

#[test]
fn buffered_anthropic_answer() {
    let resp = json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": null,
        "reasoning": "r", "reasoning_content": "r",
        "tool_calls": [{"id": "c", "type": "function", "function": {"name": "f", "arguments": "{\"x\":1}"}}]},
        "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                  "completion_tokens_details": {"reasoning_tokens": 1}}});
    let c = collect_chat(&resp);
    let m = anthropic_message(&c, "msg_9", "m");
    assert_eq!(m["content"][0]["type"], "thinking");
    assert_eq!(
        m["content"][0]["signature"],
        yb_wire::qe::reply::signature("r")
    );
    assert_eq!(
        m["content"][1],
        json!({"type": "tool_use", "id": "toolu_msg_9_0", "name": "f", "input": {"x": 1}})
    );
    assert_eq!(m["stop_reason"], "tool_use");
    assert_eq!(
        m["usage"]["output_tokens_details"],
        json!({"reasoning_tokens": 1, "thinking_tokens": 1})
    );
}

#[test]
fn responses_stream_and_object() {
    let body = json!({"model": "m", "input": "q", "include": ["reasoning.encrypted_content"], "max_output_tokens": 5});
    let ctx = ResponsesCtx::new(
        &body,
        SamplingDefaults {
            temperature: 1.0,
            top_p: 0.95,
        },
        true,
        false,
    );
    assert_eq!(
        ctx.echo["top_p"],
        json!(0.95f32),
        "QE echoes its f32 default"
    );
    let (evs, ce) = events(&qe_chat_stream());
    let mut r = ResponsesStream::new("resp_1", &ctx);
    let mut out = r.begin(&ctx.object("resp_1", "m", 0, "in_progress", vec![], None));
    for e in &evs {
        out.extend(r.event(e));
    }
    out.extend(r.close());
    let fin = ctx.finished("resp_1", "m", 0, &ce.collected);
    out.extend(r.end(&fin));
    let d = data_of(&out);
    let types: Vec<&str> = d.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(
        types[..4],
        [
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "response.reasoning_part.added"
        ]
    );
    assert!(types.contains(&"response.function_call_arguments.done"));
    assert_eq!(
        d.iter()
            .map(|e| e["sequence_number"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        (0..d.len() as u64).collect::<Vec<_>>()
    );
    // A call cut at the output cap: Chat says tool_calls, the object says
    // incomplete, as QE's Responses surface does.
    assert_eq!(fin["status"], "incomplete");
    assert_eq!(
        fin["output"][0]["encrypted_content"],
        encode_reasoning("hm")
    );
    assert_eq!(fin["output"][2]["call_id"], "call_resp_1_0");
    assert_eq!(
        fin["usage"]["input_tokens"], 10,
        "OpenAI input includes the cached prompt"
    );
}
