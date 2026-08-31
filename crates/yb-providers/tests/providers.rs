//! Unit tests for URL/auth construction, status classification, and the mock
//! client. No real network calls.

use futures::StreamExt;
use yb_core::WireFormat;

use yb_providers::{append_headers, cloudflare_access_headers, 
    auth_headers, build_url, is_model_not_found, is_retryable, MockClient, ResponseBody,
    UpstreamClient, UpstreamRequest,
};

fn req(url: &str, stream: bool) -> UpstreamRequest {
    UpstreamRequest {
        url: url.to_string(),
        method: Default::default(),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: b"{}".to_vec(),
        stream,
    }
}

#[test]
fn build_url_anthropic_default_base() {
    let url = build_url(WireFormat::Anthropic, None, "claude-3-5-sonnet", false);
    assert_eq!(url, "https://api.anthropic.com/v1/messages");
    // Streaming does not change the Anthropic URL (toggle is in the body).
    let url_stream = build_url(WireFormat::Anthropic, None, "claude-3-5-sonnet", true);
    assert_eq!(url_stream, "https://api.anthropic.com/v1/messages");
}

#[test]
fn build_url_openai_chat_and_responses() {
    let chat = build_url(WireFormat::OpenaiChat, None, "gpt-4o", false);
    assert_eq!(chat, "https://api.openai.com/v1/chat/completions");

    // The Responses adapter targets /responses, not /chat/completions.
    let responses = build_url(WireFormat::OpenaiResponses, None, "gpt-5.5", false);
    assert_eq!(responses, "https://api.openai.com/v1/responses");
}

#[test]
fn build_url_does_not_double_the_version_segment() {
    // A model whose api_base already includes /v1 must not become /v1/v1/...
    let resp = build_url(
        WireFormat::OpenaiResponses,
        Some("https://api.example.com/v1"),
        "gpt-5.4-mini",
        false,
    );
    assert_eq!(resp, "https://api.example.com/v1/responses");

    // Same for a Gemini base that already ends in /v1beta.
    let gem = build_url(
        WireFormat::Gemini,
        Some("https://api.example.com/v1beta"),
        "gemini-3-pro-preview",
        false,
    );
    assert_eq!(
        gem,
        "https://api.example.com/v1beta/models/gemini-3-pro-preview:generateContent"
    );

    // A base WITHOUT the version still gets it added.
    let compat = build_url(
        WireFormat::OpenaiChat,
        Some("https://openrouter.ai/api/"),
        "x",
        true,
    );
    assert_eq!(compat, "https://openrouter.ai/api/v1/chat/completions");
}

#[test]
fn build_url_gemini_stream_vs_nonstream() {
    let non_stream = build_url(WireFormat::Gemini, None, "gemini-flash-latest", false);
    assert_eq!(
        non_stream,
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"
    );

    let streamed = build_url(WireFormat::Gemini, None, "gemini-flash-latest", true);
    assert_eq!(
        streamed,
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:streamGenerateContent?alt=sse"
    );
}

#[test]
fn cloudflare_access_headers_are_the_service_token_pair() {
    let h = yb_providers::cloudflare_access_headers("abc.access", "s3cret");
    assert_eq!(
        h,
        vec![
            ("cf-access-client-id".to_string(), "abc.access".to_string()),
            ("cf-access-client-secret".to_string(), "s3cret".to_string()),
        ]
    );
}

/// Edge auth composes with, and never replaces, the origin credential: a vLLM
/// server behind Cloudflare Access needs both the service token and its Bearer.
#[test]
fn cloudflare_access_composes_with_upstream_auth() {
    let mut headers = auth_headers(WireFormat::OpenaiChat, "sk-vllm");
    headers.extend(yb_providers::cloudflare_access_headers("abc.access", "s3cret"));
    let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        vec!["authorization", "cf-access-client-id", "cf-access-client-secret"]
    );
    assert_eq!(headers[0].1, "Bearer sk-vllm");
}

#[test]
fn auth_headers_per_vendor() {
    let anthropic = auth_headers(WireFormat::Anthropic, "sk-ant-123");
    assert_eq!(
        anthropic,
        vec![
            ("x-api-key".to_string(), "sk-ant-123".to_string()),
            ("anthropic-version".to_string(), "2023-06-01".to_string()),
        ]
    );

    let openai = auth_headers(WireFormat::OpenaiChat, "sk-oai-123");
    assert_eq!(
        openai,
        vec![("authorization".to_string(), "Bearer sk-oai-123".to_string())]
    );

    let responses = auth_headers(WireFormat::OpenaiResponses, "sk-oai-456");
    assert_eq!(
        responses,
        vec![("authorization".to_string(), "Bearer sk-oai-456".to_string())]
    );

    let gemini = auth_headers(WireFormat::Gemini, "goog-key");
    assert_eq!(
        gemini,
        vec![("x-goog-api-key".to_string(), "goog-key".to_string())]
    );
}

#[test]
fn retryable_classification() {
    for s in [500, 502, 503, 504, 408, 429] {
        assert!(is_retryable(s), "{s} should be retryable");
    }
    for s in [200, 400, 401, 403, 404, 422] {
        assert!(!is_retryable(s), "{s} should not be retryable");
    }
}

#[test]
fn model_not_found_classification() {
    assert!(is_model_not_found(404));
    assert!(!is_model_not_found(200));
    assert!(!is_model_not_found(400));
    assert!(!is_model_not_found(500));
}

#[tokio::test]
async fn mock_full_response_and_request_capture() {
    let client = MockClient::json(br#"{"ok":true}"#.to_vec()).with_status(201);

    let resp = client
        .send(req("https://example.test/v1/messages", false))
        .await
        .expect("mock send");

    assert_eq!(resp.status, 201);
    assert_eq!(resp.header("content-type"), Some("application/json"));
    match resp.body {
        ResponseBody::Full(b) => assert_eq!(b, br#"{"ok":true}"#),
        ResponseBody::Stream(_) => panic!("expected full body"),
    }

    // The request was recorded for inspection.
    assert_eq!(client.request_count(), 1);
    let last = client.last_request().expect("a request");
    assert_eq!(last.url, "https://example.test/v1/messages");
    assert_eq!(last.body, b"{}");
}

#[tokio::test]
async fn mock_sse_stream_replays_chunks() {
    let events = vec![
        "data: {\"delta\":\"He\"}\n\n".to_string(),
        "data: {\"delta\":\"llo\"}\n\n".to_string(),
        "data: [DONE]\n\n".to_string(),
    ];
    let client = MockClient::sse(events.clone());

    let resp = client
        .send(req("https://example.test/stream", true))
        .await
        .expect("mock send");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("content-type"), Some("text/event-stream"));

    let mut collected = Vec::new();
    match resp.body {
        ResponseBody::Stream(mut s) => {
            while let Some(item) = s.next().await {
                let bytes = item.expect("chunk ok");
                collected.push(String::from_utf8(bytes.to_vec()).unwrap());
            }
        }
        ResponseBody::Full(_) => panic!("expected stream body"),
    }
    assert_eq!(collected, events);
}

#[tokio::test]
async fn mock_can_simulate_retryable_status() {
    let client = MockClient::full(Vec::new()).with_status(503);
    let resp = client
        .send(req("https://example.test/x", false))
        .await
        .unwrap();
    assert!(is_retryable(resp.status));
}

/// `append_headers` is first-writer-wins, which is what stops a database row's
/// literal `extra.headers` from forging the file-owned Cloudflare service token
/// or slipping a second `authorization` past the origin.
#[test]
fn extra_headers_can_never_displace_auth_or_the_service_token() {
    let mut headers = auth_headers(WireFormat::OpenaiChat, "sk-origin");
    append_headers(
        &mut headers,
        cloudflare_access_headers("id.access", "shh"),
    );
    // A row trying to override all three, plus one legitimate addition.
    append_headers(
        &mut headers,
        vec![
            ("authorization".to_string(), "Bearer stolen".to_string()),
            ("CF-Access-Client-Id".to_string(), "forged".to_string()),
            ("cf-access-client-secret".to_string(), "forged".to_string()),
            ("x-tenant".to_string(), "acme".to_string()),
        ],
    );

    let get = |n: &str| -> Vec<&str> {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
            .collect()
    };
    assert_eq!(get("authorization"), vec!["Bearer sk-origin"]);
    assert_eq!(get("cf-access-client-id"), vec!["id.access"]);
    assert_eq!(get("cf-access-client-secret"), vec!["shh"]);
    // ...while a non-colliding header is still added.
    assert_eq!(get("x-tenant"), vec!["acme"]);
}

