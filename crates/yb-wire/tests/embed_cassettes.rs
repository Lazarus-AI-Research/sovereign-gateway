//! Cassette-driven, fully offline conformance tests for embeddings translation.
//!
//! An embed cassette (`tests/cassettes/embed/<name>.json`) is:
//!
//! ```json
//! {
//!   "inbound_format": "...",  "inbound_body": { ... },
//!   "target_format": "...",   "target_model": "...",
//!   "expected_upstream_body": { ... },
//!   "upstream_response_body": { ... },
//!   "expected_client_body": { ... }
//! }
//! ```
//!
//! Two assertions per cassette (no SSE — embeddings never stream):
//! 1. `emit_request(parse_request(inbound))` in the target format equals
//!    `expected_upstream_body` (compared as parsed JSON).
//! 2. `emit_response(parse_response(upstream_response_body), parsed_request)`
//!    on the **inbound** format equals `expected_client_body`.

use serde_json::Value;
use yb_wire::embed::{self, EmbedEmitOptions, EmbedRequest, EmbedResponse};

fn parse_request(format: &str, body: &[u8]) -> EmbedRequest {
    let r = match format {
        "openai_embed" => embed::openai::parse_request(body),
        "gemini_embed" => embed::gemini::parse_request(body),
        "cohere_embed" => embed::cohere::parse_request(body),
        "voyage_embed" => embed::voyage::parse_request(body),
        "ollama_embed" => embed::ollama::parse_request(body),
        other => panic!("unknown inbound_format {other}"),
    };
    r.unwrap_or_else(|e| panic!("parse_request({format}) failed: {e}"))
}

fn emit_request(format: &str, req: &EmbedRequest, opts: &EmbedEmitOptions) -> Vec<u8> {
    let r = match format {
        "openai_embed" => embed::openai::emit_request(req, opts),
        "gemini_embed" => embed::gemini::emit_request(req, opts),
        "cohere_embed" => embed::cohere::emit_request(req, opts),
        "voyage_embed" => embed::voyage::emit_request(req, opts),
        "ollama_embed" => embed::ollama::emit_request(req, opts),
        other => panic!("unknown target_format {other}"),
    };
    r.unwrap_or_else(|e| panic!("emit_request({format}) failed: {e}")).0
}

fn parse_response(format: &str, body: &[u8]) -> EmbedResponse {
    let r = match format {
        "openai_embed" => embed::openai::parse_response(body),
        "gemini_embed" => embed::gemini::parse_response(body),
        "cohere_embed" => embed::cohere::parse_response(body),
        "voyage_embed" => embed::voyage::parse_response(body),
        "ollama_embed" => embed::ollama::parse_response(body),
        other => panic!("unknown target_format {other}"),
    };
    r.unwrap_or_else(|e| panic!("parse_response({format}) failed: {e}"))
}

fn emit_response(format: &str, resp: &EmbedResponse, req: &EmbedRequest) -> Vec<u8> {
    let r = match format {
        "openai_embed" => embed::openai::emit_response(resp, req),
        "gemini_embed" => embed::gemini::emit_response(resp, req),
        "cohere_embed" => embed::cohere::emit_response(resp, req),
        "voyage_embed" => embed::voyage::emit_response(resp, req),
        "ollama_embed" => embed::ollama::emit_response(resp, req),
        other => panic!("unknown client format {other}"),
    };
    r.unwrap_or_else(|e| panic!("emit_response({format}) failed: {e}"))
}

fn load(name: &str) -> Value {
    let path = format!("{}/tests/cassettes/embed/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse cassette {name}: {e}"))
}

fn run(name: &str) {
    let c = load(name);
    let inbound_format = c["inbound_format"].as_str().unwrap();
    let target_format = c["target_format"].as_str().unwrap();
    let target_model = c["target_model"].as_str().unwrap_or("");

    let body = serde_json::to_vec(&c["inbound_body"]).unwrap();
    let req = parse_request(inbound_format, &body);

    // 1. Request translation.
    let emitted = emit_request(target_format, &req, &EmbedEmitOptions::new(target_model));
    let got: Value = serde_json::from_slice(&emitted).unwrap();
    assert_eq!(
        got, c["expected_upstream_body"],
        "[{name}] request {inbound_format} -> {target_format} mismatch\n got: {}\nwant: {}",
        serde_json::to_string_pretty(&got).unwrap(),
        serde_json::to_string_pretty(&c["expected_upstream_body"]).unwrap(),
    );

    // 2. Response translation.
    let up = serde_json::to_vec(&c["upstream_response_body"]).unwrap();
    let parsed = parse_response(target_format, &up);
    let out = emit_response(inbound_format, &parsed, &req);
    let got: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        got, c["expected_client_body"],
        "[{name}] response {target_format} -> {inbound_format} mismatch\n got: {}\nwant: {}",
        serde_json::to_string_pretty(&got).unwrap(),
        serde_json::to_string_pretty(&c["expected_client_body"]).unwrap(),
    );
}

#[test]
fn openai_to_cohere_texts() {
    run("openai_to_cohere_texts");
}

#[test]
fn openai_base64_echo() {
    run("openai_base64_echo");
}

#[test]
fn openai_array_to_gemini_batch() {
    run("openai_array_to_gemini_batch");
}

#[test]
fn gemini_single_to_openai() {
    run("gemini_single_to_openai");
}

#[test]
fn openai_jina_multimodal_to_voyage() {
    run("openai_jina_multimodal_to_voyage");
}

#[test]
fn cohere_query_to_openai() {
    run("cohere_query_to_openai");
}

#[test]
fn voyage_to_cohere_images() {
    run("voyage_to_cohere_images");
}

#[test]
fn openai_to_ollama() {
    run("openai_to_ollama");
}
