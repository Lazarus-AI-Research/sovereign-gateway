//! Offline replay of the QE differential check (`scripts/qe-lossless-check`).
//!
//! Each cassette under `tests/cassettes/qe/` was recorded against a QE server:
//! an Anthropic or Responses request (`inbound_body`), the QE Chat body the
//! translation made of it (`expected_chat_body`), QE's answer to that Chat
//! body (`chat_answer`), and QE's native answer to the request
//! (`native_answer`). The replay checks that the translation still makes the
//! same Chat body, and that QE's Chat answer, translated back, is QE's native
//! answer, modulo ids, timestamps and SSE chunk boundaries, and the
//! exclusions documented in the check (message_start usage; which stop
//! sequence matched, and the timing-dependent token count at a stop).

use std::path::PathBuf;

use serde_json::{json, Value};
use yb_wire::qe::{
    anthropic_message, anthropic_to_chat, collect_chat, responses_to_chat, AnthropicStream,
    ChatEvents, NoItems, ResponsesCtx, ResponsesStream, SamplingDefaults,
};

const PREFIXES: [&str; 9] = [
    "chatcmpl-",
    "resp_",
    "msg_",
    "rs_",
    "fc_",
    "ctc_",
    "call_",
    "toolu_",
    "in_",
];

/// Ids to their prefix, timestamps to 0.
fn normalize(v: &mut Value) {
    match v {
        Value::String(s) => {
            if let Some(p) = PREFIXES.iter().find(|p| s.starts_with(*p)) {
                *s = format!("{p}X");
            }
        }
        Value::Array(a) => a.iter_mut().for_each(normalize),
        Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                if matches!(k.as_str(), "created" | "created_at") {
                    *x = json!(0);
                } else {
                    normalize(x);
                }
            }
        }
        _ => {}
    }
}

/// SSE `data:` payloads, in order.
fn sse(text: &str) -> Vec<Value> {
    text.split("\n\n")
        .filter_map(|block| {
            let data: Vec<&str> = block
                .lines()
                .filter_map(|l| l.strip_prefix("data:").map(str::trim_start))
                .collect();
            (!data.is_empty() && data != ["[DONE]"])
                .then(|| serde_json::from_str(&data.join("\n")).unwrap())
        })
        .collect()
}

/// Consecutive deltas of one block / item merged (chunking is timing), and
/// Responses sequence numbers renumbered.
fn coalesce(events: Vec<Value>) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for e in events {
        if let Some(p) = out.last_mut() {
            let t = e["type"].as_str().unwrap_or("");
            if t == "content_block_delta"
                && p["type"] == "content_block_delta"
                && p["index"] == e["index"]
                && p["delta"]["type"] == e["delta"]["type"]
            {
                let key = match e["delta"]["type"].as_str() {
                    Some("text_delta") => Some("text"),
                    Some("thinking_delta") => Some("thinking"),
                    Some("input_json_delta") => Some("partial_json"),
                    _ => None,
                };
                if let Some(k) = key {
                    let add = e["delta"][k].as_str().unwrap_or("").to_string();
                    let cur = p["delta"][k].as_str().unwrap_or("").to_string();
                    p["delta"][k] = json!(cur + &add);
                    continue;
                }
            }
            if matches!(
                t,
                "response.output_text.delta"
                    | "response.reasoning_text.delta"
                    | "response.function_call_arguments.delta"
            ) && p["type"] == t
                && p["item_id"] == e["item_id"]
            {
                let cur = p["delta"].as_str().unwrap_or("").to_string();
                p["delta"] = json!(cur + e["delta"].as_str().unwrap_or(""));
                if let (Some(a), Some(b)) =
                    (p["logprobs"].as_array().cloned(), e["logprobs"].as_array())
                {
                    p["logprobs"] =
                        json!(a.into_iter().chain(b.iter().cloned()).collect::<Vec<_>>());
                }
                continue;
            }
        }
        out.push(e);
    }
    let mut seq = 0;
    for e in &mut out {
        if e.get("sequence_number").is_some() {
            e["sequence_number"] = json!(seq);
            seq += 1;
        }
    }
    out
}

fn drop_ptr(v: &mut Value, ptr: &str) {
    let (parent, last) = ptr.rsplit_once('/').unwrap();
    if let Some(Value::Object(o)) = v.pointer_mut(parent) {
        o.shift_remove(last);
    }
}

/// What the check excludes for this cassette (see check.py `EXCLUDED`).
fn exclude(v: &mut Value, shape: &str, stop: bool) {
    let t = v["type"].as_str().unwrap_or("").to_string();
    if shape == "anthropic" && t == "message_start" {
        drop_ptr(v, "/message/usage");
    }
    if stop {
        match t.as_str() {
            "message" => {
                for p in ["/stop_reason", "/stop_sequence", "/usage/output_tokens"] {
                    drop_ptr(v, p);
                }
            }
            "message_delta" => {
                drop_ptr(v, "/delta");
                drop_ptr(v, "/usage/output_tokens");
            }
            "response.completed" => {
                drop_ptr(v, "/response/usage/output_tokens");
                drop_ptr(v, "/response/usage/total_tokens");
            }
            "" if v.get("object") == Some(&json!("response")) => {
                drop_ptr(v, "/usage/output_tokens");
                drop_ptr(v, "/usage/total_tokens");
            }
            _ => {}
        }
    }
}

fn view(text: &str, stream: bool, shape: &str, stop: bool) -> Value {
    let mut v = if stream {
        Value::Array(coalesce(sse(text)))
    } else {
        serde_json::from_str(text).unwrap()
    };
    normalize(&mut v);
    match &mut v {
        Value::Array(a) => a.iter_mut().for_each(|e| exclude(e, shape, stop)),
        o => exclude(o, shape, stop),
    }
    v
}

/// QE's Chat answer, translated back the way the gateway does.
fn translate_answer(c: &Value) -> String {
    let shape = c["shape"].as_str().unwrap();
    let inbound = &c["inbound_body"];
    let model = inbound["model"].as_str().unwrap();
    let answer = c["chat_answer"].as_str().unwrap();
    let ctx = || {
        let store = inbound
            .get("store")
            .and_then(|s| s.as_bool())
            .unwrap_or(true);
        ResponsesCtx::new(
            inbound,
            SamplingDefaults {
                temperature: 1.0,
                top_p: 0.95,
            },
            store,
            false,
        )
    };
    if !c["stream"].as_bool().unwrap() {
        let col = collect_chat(&serde_json::from_str(answer).unwrap());
        let out = match shape {
            "anthropic" => anthropic_message(&col, "msg_1", model),
            _ => ctx().finished("resp_1", model, 0, &col),
        };
        return out.to_string();
    }
    let mut events = ChatEvents::default();
    let mut evs = Vec::new();
    for d in answer
        .split("\n\n")
        .filter_map(|b| b.lines().find_map(|l| l.strip_prefix("data:")))
    {
        evs.extend(events.push(d));
    }
    evs.extend(events.finish());
    let col = events.collected.clone();
    let mut out = Vec::new();
    match shape {
        "anthropic" => {
            let mut a = AnthropicStream::new("msg_1", model);
            for e in &evs {
                out.extend(a.event(e));
            }
            out.extend(a.end(&col));
        }
        _ => {
            let ctx = ctx();
            let mut r = ResponsesStream::new("resp_1", &ctx);
            out.extend(r.begin(&ctx.object("resp_1", model, 0, "in_progress", vec![], None)));
            for e in &evs {
                out.extend(r.event(e));
            }
            if col.error.is_none() {
                out.extend(r.close());
            }
            out.extend(r.end(&ctx.finished("resp_1", model, 0, &col)));
        }
    }
    String::from_utf8(out).unwrap()
}

#[test]
fn qe_cassettes_replay_lossless() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/cassettes/qe");
    let mut n = 0;
    let mut failures = Vec::new();
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    for path in paths {
        let c: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let name = c["name"].as_str().unwrap().to_string();
        let shape = c["shape"].as_str().unwrap();
        let chat = match shape {
            "anthropic" => anthropic_to_chat(&c["inbound_body"]).unwrap().0,
            _ => {
                responses_to_chat(&c["inbound_body"], &NoItems)
                    .unwrap()
                    .body
            }
        };
        if chat != c["expected_chat_body"] {
            failures.push(format!("{name}: Chat body changed"));
        }
        let stop = c["tags"].as_array().unwrap().iter().any(|t| t == "stop");
        let stream = c["stream"].as_bool().unwrap();
        let got = view(&translate_answer(&c), stream, shape, stop);
        let want = view(c["native_answer"].as_str().unwrap(), stream, shape, stop);
        if got != want {
            failures.push(format!(
                "{name}: answer differs\n  got:  {}\n  want: {}",
                got.to_string().chars().take(600).collect::<String>(),
                want.to_string().chars().take(600).collect::<String>()
            ));
        }
        n += 1;
    }
    assert!(n >= 70, "expected the recorded corpus, found {n} cassettes");
    assert!(
        failures.is_empty(),
        "{} of {n} cassettes:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
