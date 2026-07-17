//! The OpenAI embeddings wire format (`POST /v1/embeddings`).
//!
//! The dominant dialect: OpenAI itself, plus vLLM, TEI, LiteLLM, Together,
//! Fireworks, Voyage's text endpoint, and Jina — whose multimodal extension
//! (`input: [{"text": ...} | {"image": ...}]`) is also parsed/emitted here.
//! `encoding_format` is honored on the client side (SDKs default to base64);
//! the upstream is always asked for explicit floats.

use serde_json::{json, Map, Value};

use crate::common::*;
use crate::error::{Result, WireError};
use crate::EmittedRequest;

use super::*;

/// Parse an OpenAI embeddings request body into the IR.
pub fn parse_request(body: &[u8]) -> Result<EmbedRequest> {
    let v: Value = serde_json::from_slice(body)?;
    v.as_object()
        .ok_or_else(|| WireError::InvalidRequest("body is not a JSON object".into()))?;

    let model = opt_str(&v, "model").unwrap_or_default().to_string();
    // `messages` is the multimodal superset (see parse_messages); `input` is
    // stock OpenAI. A body carrying both is ambiguous about which to embed.
    let inputs = match (v.get("input"), v.get("messages")) {
        (Some(_), Some(_)) => {
            return Err(WireError::InvalidRequest(
                "send either `input` or `messages`, not both".into(),
            ))
        }
        (None, Some(messages)) => parse_messages(messages)?,
        (input, None) => parse_input(input)?,
    };
    if inputs.is_empty() {
        return Err(WireError::InvalidRequest("input must not be empty".into()));
    }

    let encoding_format = match opt_str(&v, "encoding_format") {
        Some("base64") => Some(EncodingFormat::Base64),
        Some("float") => Some(EncodingFormat::Float),
        Some(other) => {
            return Err(WireError::invalid("encoding_format", format!("unknown {other}")))
        }
        None => None,
    };

    Ok(EmbedRequest {
        model,
        inputs,
        input_type: None, // OpenAI's shape has no task hint
        output_dimensions: opt_u32(&v, "dimensions"),
        truncate: None,
        encoding_format,
        cohere_embedding_types: None,
        gemini_batch: false,
    })
}

/// `input` accepts: a string, an array of strings, or Jina-style objects
/// (`{"text": ...}` / `{"image": "<url | data-uri | raw b64>"}`). Token arrays
/// are rejected — they cannot be translated across formats.
fn parse_input(v: Option<&Value>) -> Result<Vec<EmbedInput>> {
    let token_err = || {
        WireError::InvalidRequest(
            "token-array inputs are not supported by the gateway; resubmit as strings".into(),
        )
    };
    match v {
        Some(Value::String(s)) => Ok(vec![EmbedInput::text(s.clone())]),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => out.push(EmbedInput::text(s.clone())),
                    Value::Number(_) | Value::Array(_) => return Err(token_err()),
                    Value::Object(o) => {
                        if let Some(Value::String(text)) = o.get("text") {
                            out.push(EmbedInput::text(text.clone()));
                        } else if let Some(Value::String(image)) = o.get("image") {
                            out.push(EmbedInput { parts: vec![parse_image_value(image)] });
                        } else {
                            return Err(WireError::invalid(
                                "input[]",
                                "object inputs must carry `text` or `image`",
                            ));
                        }
                    }
                    _ => return Err(WireError::invalid("input[]", "unsupported input element")),
                }
            }
            Ok(out)
        }
        Some(Value::Number(_)) => Err(token_err()),
        _ => Err(WireError::missing("input")),
    }
}

/// Emit the `messages` superset: one message per input, parts in order.
fn emit_messages(req: &EmbedRequest) -> Result<Value> {
    let mut messages = Vec::with_capacity(req.inputs.len());
    for input in &req.inputs {
        let mut content = Vec::with_capacity(input.parts.len());
        for part in &input.parts {
            content.push(match part {
                EmbedPart::Text { text } => json!({"type": "text", "text": text}),
                EmbedPart::Image { media_type, data, url } => {
                    let url = match (url, data) {
                        (Some(u), _) => u.clone(),
                        (None, Some(_)) => image_to_data_uri(media_type.as_deref(), data.as_deref())?,
                        _ => {
                            return Err(WireError::invalid(
                                "messages[].content[]",
                                "image without data or url",
                            ))
                        }
                    };
                    json!({"type": "image_url", "image_url": {"url": url}})
                }
                EmbedPart::Audio { format, data, url } => match (data, url) {
                    // `data` is bare base64 and `format` names the container —
                    // the shape the runtime contract specifies.
                    (Some(d), _) => json!({
                        "type": "input_audio",
                        "input_audio": {"data": d, "format": format.as_deref().unwrap_or("wav")},
                    }),
                    (None, Some(u)) => json!({
                        "type": "input_audio",
                        "input_audio": {"url": u, "format": format.as_deref().unwrap_or("wav")},
                    }),
                    _ => {
                        return Err(WireError::invalid(
                            "messages[].content[]",
                            "audio without data or url",
                        ))
                    }
                },
            });
        }
        messages.push(json!({"role": "user", "content": content}));
    }
    Ok(Value::Array(messages))
}

/// `messages` — the multimodal superset of OpenAI's embeddings request.
///
/// Content parts arrive in OpenAI chat shape, and one message yields one
/// vector, so unlike `input`'s Jina objects a message may interleave parts:
///
/// ```json
/// {"messages": [{"role": "user", "content": [
///   {"type": "image_url",    "image_url": {"url": "data:image/png;base64,…"}},
///   {"type": "input_audio",  "input_audio": {"data": "<base64>", "format": "wav"}},
///   {"type": "text",         "text": "accompanying text"}
/// ]}]}
/// ```
///
/// A plain string `content` is shorthand for one text part. Deployments that
/// forbid egress reject remote URLs, but that is policy at the edge — the IR
/// carries whatever it is handed.
fn parse_messages(v: &Value) -> Result<Vec<EmbedInput>> {
    let Value::Array(messages) = v else {
        return Err(WireError::invalid("messages", "must be an array"));
    };
    let mut out = Vec::with_capacity(messages.len());
    for message in messages {
        let obj = message
            .as_object()
            .ok_or_else(|| WireError::invalid("messages[]", "must be an object"))?;
        let parts = match obj.get("content") {
            Some(Value::String(s)) => vec![EmbedPart::Text { text: s.clone() }],
            Some(Value::Array(items)) => {
                let mut parts = Vec::with_capacity(items.len());
                for item in items {
                    parts.push(parse_content_part(item)?);
                }
                parts
            }
            _ => return Err(WireError::invalid("messages[].content", "must be a string or array")),
        };
        if parts.is_empty() {
            return Err(WireError::invalid("messages[].content", "must not be empty"));
        }
        out.push(EmbedInput { parts });
    }
    Ok(out)
}

/// One OpenAI-chat-shaped content part.
fn parse_content_part(item: &Value) -> Result<EmbedPart> {
    let obj = item
        .as_object()
        .ok_or_else(|| WireError::invalid("messages[].content[]", "must be an object"))?;
    match obj.get("type").and_then(Value::as_str) {
        Some("text") => Ok(EmbedPart::Text {
            text: obj
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| WireError::missing("messages[].content[].text"))?
                .to_string(),
        }),
        Some("image_url") => {
            let url = obj
                .get("image_url")
                .and_then(|u| u.get("url"))
                .and_then(Value::as_str)
                .ok_or_else(|| WireError::missing("messages[].content[].image_url.url"))?;
            Ok(parse_image_value(url))
        }
        Some("input_audio") => {
            let audio = obj
                .get("input_audio")
                .and_then(Value::as_object)
                .ok_or_else(|| WireError::missing("messages[].content[].input_audio"))?;
            let format = audio.get("format").and_then(Value::as_str).map(str::to_string);
            match audio.get("data").and_then(Value::as_str) {
                // A `data:` URI is accepted as well as bare base64: the field is
                // specified as base64, but clients send both.
                Some(s) => Ok(match parse_data_url(s) {
                    Some((media_type, data)) => EmbedPart::Audio {
                        format: format.or_else(|| audio_format_from_media_type(&media_type)),
                        data: Some(data),
                        url: None,
                    },
                    None => EmbedPart::Audio { format, data: Some(s.to_string()), url: None },
                }),
                None => match audio.get("url").and_then(Value::as_str) {
                    Some(u) => Ok(EmbedPart::Audio { format, data: None, url: Some(u.to_string()) }),
                    None => Err(WireError::missing("messages[].content[].input_audio.data")),
                },
            }
        }
        Some(other) => Err(WireError::invalid(
            "messages[].content[].type",
            format!("unsupported part type {other}"),
        )),
        None => Err(WireError::missing("messages[].content[].type")),
    }
}

/// `audio/wav` -> `wav`, so a data URI still yields OpenAI's `format`.
fn audio_format_from_media_type(media_type: &str) -> Option<String> {
    media_type.strip_prefix("audio/").map(|s| s.to_string())
}

/// A Jina-style image value: http(s) URL, `data:` URI, or raw base64.
fn parse_image_value(s: &str) -> EmbedPart {
    if s.starts_with("http://") || s.starts_with("https://") {
        EmbedPart::Image { media_type: None, data: None, url: Some(s.to_string()) }
    } else if let Some((media_type, data)) = parse_data_url(s) {
        EmbedPart::Image { media_type: Some(media_type), data: Some(data), url: None }
    } else {
        EmbedPart::Image { media_type: None, data: Some(s.to_string()), url: None }
    }
}

/// Emit an IR request as an OpenAI embeddings request body plus headers.
pub fn emit_request(req: &EmbedRequest, opts: &EmbedEmitOptions) -> Result<EmittedRequest> {
    let mut body = Map::new();
    let model = if opts.target_model.is_empty() {
        req.model.clone()
    } else {
        opts.target_model.clone()
    };
    body.insert("model".into(), json!(model));

    // Three shapes, cheapest first. `input` is stock OpenAI and is what a
    // vanilla upstream understands; `messages` is the superset, emitted only
    // when the request genuinely needs it (interleaved parts, or audio).
    let all_text = req.inputs.iter().all(|i| i.as_single_text().is_some());
    let needs_messages = req.inputs.iter().any(EmbedInput::needs_multipart);

    if needs_messages {
        body.insert("messages".into(), emit_messages(req)?);
    } else if all_text {
        body.insert(
            "input".into(),
            Value::Array(req.inputs.iter().map(|i| json!(i.as_single_text().unwrap())).collect()),
        );
    } else {
        // Jina-style objects; one part per input.
        let mut items = Vec::with_capacity(req.inputs.len());
        for i in &req.inputs {
            match i.parts.as_slice() {
                [EmbedPart::Text { text }] => items.push(json!({"text": text})),
                [EmbedPart::Image { media_type, data, url }] => {
                    let image = match (url, data) {
                        (Some(u), _) => u.clone(),
                        (None, Some(_)) => {
                            image_to_data_uri(media_type.as_deref(), data.as_deref())?
                        }
                        _ => return Err(WireError::invalid("input[]", "image without data or url")),
                    };
                    items.push(json!({"image": image}));
                }
                // needs_multipart covers interleaving and audio, so this arm is
                // unreachable; keep it explicit rather than silently dropping.
                _ => {
                    return Err(WireError::InvalidRequest(
                        "openai_embed could not represent this input".into(),
                    ))
                }
            }
        }
        body.insert("input".into(), Value::Array(items));
    }

    // Always explicit floats upstream: the client's encoding choice shapes only
    // the client response, and float parses unambiguously.
    body.insert("encoding_format".into(), json!("float"));
    insert_opt(&mut body, "dimensions", req.output_dimensions);
    // input_type has no representation in this dialect: dropped.

    let bytes = serde_json::to_vec(&Value::Object(body))?;
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    Ok((bytes, headers))
}

/// Parse an OpenAI embeddings response body into the IR.
pub fn parse_response(body: &[u8]) -> Result<EmbedResponse> {
    let v: Value = serde_json::from_slice(body)?;
    let mut rows: Vec<(usize, Vec<f32>)> = Vec::new();
    if let Some(data) = opt_arr(&v, "data") {
        for (pos, item) in data.iter().enumerate() {
            let index = opt_u32(item, "index").map(|i| i as usize).unwrap_or(pos);
            let emb = match item.get("embedding") {
                Some(Value::Array(nums)) => nums
                    .iter()
                    .map(|n| n.as_f64().unwrap_or(0.0) as f32)
                    .collect(),
                // Defensive: some upstreams return base64 regardless of the
                // requested encoding.
                Some(Value::String(s)) => base64_to_f32s(s)?,
                _ => return Err(WireError::missing("data[].embedding")),
            };
            rows.push((index, emb));
        }
    }
    rows.sort_by_key(|(i, _)| *i);
    let usage = v.get("usage");
    Ok(EmbedResponse {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        embeddings: rows.into_iter().map(|(_, e)| e).collect(),
        usage: EmbedUsage {
            input_tokens: usage.and_then(|u| opt_u32(u, "prompt_tokens")).unwrap_or(0),
            image_units: 0,
        },
    })
}

/// Emit an IR response as an OpenAI embeddings response body. `req` supplies
/// the client's `encoding_format` choice.
pub fn emit_response(resp: &EmbedResponse, req: &EmbedRequest) -> Result<Vec<u8>> {
    let base64 = req.encoding_format == Some(EncodingFormat::Base64);
    let data: Vec<Value> = resp
        .embeddings
        .iter()
        .enumerate()
        .map(|(index, emb)| {
            let embedding: Value = if base64 {
                json!(f32s_to_base64(emb))
            } else {
                json!(emb)
            };
            json!({"object": "embedding", "index": index, "embedding": embedding})
        })
        .collect();
    let body = json!({
        "object": "list",
        "data": data,
        "model": resp.model,
        "usage": {
            "prompt_tokens": resp.usage.input_tokens,
            "total_tokens": resp.usage.input_tokens,
        },
    });
    Ok(serde_json::to_vec(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact body SovereignStack's runtime contract specifies for a
    /// multimodal embedding: interleaved image + audio + text in one message,
    /// yielding one vector. It must survive parse → IR → emit unchanged in
    /// substance; anything the IR fails to model is silently lost, which is the
    /// whole hazard this path exists to avoid.
    #[test]
    fn sovereign_multimodal_messages_round_trip() {
        let body = serde_json::to_vec(&json!({
            "model": "embedding-omni-default",
            "messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,aW1n"}},
                {"type": "input_audio", "input_audio": {"data": "YXVkaW8=", "format": "wav"}},
                {"type": "text", "text": "accompanying text"},
            ]}],
        }))
        .unwrap();

        let req = parse_request(&body).expect("parse the sovereign superset");
        assert_eq!(req.inputs.len(), 1, "one message -> one vector");
        let parts = &req.inputs[0].parts;
        assert_eq!(parts.len(), 3, "no part may be dropped");
        assert_eq!(
            parts[0],
            EmbedPart::Image {
                media_type: Some("image/png".into()),
                data: Some("aW1n".into()),
                url: None
            }
        );
        assert_eq!(
            parts[1],
            EmbedPart::Audio {
                format: Some("wav".into()),
                data: Some("YXVkaW8=".into()),
                url: None
            }
        );
        assert_eq!(parts[2], EmbedPart::Text { text: "accompanying text".into() });

        // Emit must use the superset, not stock `input`, or the upstream loses
        // everything but the text.
        let out = emit_request(&req, &EmbedEmitOptions::default()).unwrap();
        let v: Value = serde_json::from_slice(&out.0).unwrap();
        assert!(v.get("input").is_none(), "must not downgrade to `input`");
        let content = &v["messages"][0]["content"];
        assert_eq!(content[0]["type"], "image_url");
        assert_eq!(content[0]["image_url"]["url"], "data:image/png;base64,aW1n");
        assert_eq!(content[1]["type"], "input_audio");
        assert_eq!(content[1]["input_audio"]["data"], "YXVkaW8=");
        assert_eq!(content[1]["input_audio"]["format"], "wav");
        assert_eq!(content[2]["type"], "text");
        assert_eq!(content[2]["text"], "accompanying text");
    }

    /// Audio alone is still the superset — `input` cannot carry it.
    #[test]
    fn audio_only_message_emits_superset() {
        let body = serde_json::to_vec(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "input_audio", "input_audio": {"data": "YXVkaW8=", "format": "mp3"}},
            ]}],
        }))
        .unwrap();
        let req = parse_request(&body).unwrap();
        assert!(req.inputs[0].has_audio());
        let out = emit_request(&req, &EmbedEmitOptions::default()).unwrap();
        let v: Value = serde_json::from_slice(&out.0).unwrap();
        assert_eq!(v["messages"][0]["content"][0]["input_audio"]["format"], "mp3");
    }

    /// A data URI is accepted where the contract says base64, and the container
    /// format is recovered from the media type when not given explicitly.
    #[test]
    fn audio_data_uri_yields_format() {
        let body = serde_json::to_vec(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "input_audio", "input_audio": {"data": "data:audio/wav;base64,YXVkaW8="}},
            ]}],
        }))
        .unwrap();
        let req = parse_request(&body).unwrap();
        assert_eq!(
            req.inputs[0].parts[0],
            EmbedPart::Audio {
                format: Some("wav".into()),
                data: Some("YXVkaW8=".into()),
                url: None
            }
        );
    }

    /// Text-only bodies must keep using stock `input`: a vanilla OpenAI
    /// upstream does not understand `messages` on this endpoint.
    #[test]
    fn text_only_still_emits_stock_input() {
        let body = serde_json::to_vec(&json!({"model": "m", "input": ["a", "b"]})).unwrap();
        let req = parse_request(&body).unwrap();
        let out = emit_request(&req, &EmbedEmitOptions::default()).unwrap();
        let v: Value = serde_json::from_slice(&out.0).unwrap();
        assert_eq!(v["input"], json!(["a", "b"]));
        assert!(v.get("messages").is_none());
    }

    /// A plain-string content is shorthand for one text part.
    #[test]
    fn string_content_is_text() {
        let body = serde_json::to_vec(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
        }))
        .unwrap();
        let req = parse_request(&body).unwrap();
        assert_eq!(req.inputs[0].as_single_text(), Some("hello"));
    }

    #[test]
    fn input_and_messages_together_rejected() {
        let body = serde_json::to_vec(&json!({
            "model": "m",
            "input": "a",
            "messages": [{"role": "user", "content": "b"}],
        }))
        .unwrap();
        assert!(parse_request(&body).is_err(), "ambiguous: which one gets embedded?");
    }

    #[test]
    fn unknown_content_part_rejected() {
        let body = serde_json::to_vec(&json!({
            "model": "m",
            "messages": [{"role": "user", "content": [{"type": "video_url", "video_url": {}}]}],
        }))
        .unwrap();
        assert!(parse_request(&body).is_err(), "an unmodeled part must fail, not vanish");
    }

    #[test]
    fn token_arrays_rejected() {
        let body = serde_json::to_vec(&json!({"model": "m", "input": [[1, 2, 3]]})).unwrap();
        assert!(parse_request(&body).is_err());
        let body = serde_json::to_vec(&json!({"model": "m", "input": [1, 2, 3]})).unwrap();
        assert!(parse_request(&body).is_err());
    }

    #[test]
    fn empty_input_rejected() {
        let body = serde_json::to_vec(&json!({"model": "m", "input": []})).unwrap();
        assert!(parse_request(&body).is_err());
    }

    #[test]
    fn base64_echo_and_float_upstream() {
        let body = serde_json::to_vec(&json!({
            "model": "m", "input": "hello", "encoding_format": "base64"
        }))
        .unwrap();
        let req = parse_request(&body).unwrap();
        assert_eq!(req.encoding_format, Some(EncodingFormat::Base64));

        // Upstream always asks for floats.
        let (up, _) = emit_request(&req, &EmbedEmitOptions::new("m2")).unwrap();
        let up: Value = serde_json::from_slice(&up).unwrap();
        assert_eq!(up["encoding_format"], "float");
        assert_eq!(up["model"], "m2");

        // Client response honors base64.
        let resp = EmbedResponse {
            model: "m".into(),
            embeddings: vec![vec![1.0, 2.0]],
            usage: EmbedUsage { input_tokens: 3, image_units: 0 },
        };
        let out: Value = serde_json::from_slice(&emit_response(&resp, &req).unwrap()).unwrap();
        assert_eq!(out["data"][0]["embedding"], json!(f32s_to_base64(&[1.0, 2.0])));
    }

    #[test]
    fn jina_multimodal_inputs_parse() {
        let body = serde_json::to_vec(&json!({
            "model": "jina-clip-v2",
            "input": [
                {"text": "a banana"},
                {"image": "data:image/png;base64,QUJD"},
                {"image": "https://example.com/x.png"}
            ]
        }))
        .unwrap();
        let req = parse_request(&body).unwrap();
        assert_eq!(req.inputs.len(), 3);
        assert!(req.inputs[1].has_image());
        assert_eq!(
            req.inputs[1].parts[0],
            EmbedPart::Image {
                media_type: Some("image/png".into()),
                data: Some("QUJD".into()),
                url: None
            }
        );
        assert!(matches!(&req.inputs[2].parts[0],
            EmbedPart::Image { url: Some(u), .. } if u == "https://example.com/x.png"));
    }

    /// Interleaved parts used to be rejected here ("openai_embed cannot
    /// represent a mixed text+image input"). They now emit the `messages`
    /// superset instead.
    ///
    /// That needs an upstream which accepts it — a Sovereign runtime or vLLM,
    /// not api.openai.com. Nothing is lost by trying: stock `/v1/embeddings`
    /// has *no* encoding for an interleaved input, so the alternative was an
    /// error either way, just raised here instead of upstream.
    #[test]
    fn mixed_part_input_emits_superset() {
        let req = EmbedRequest {
            model: "m".into(),
            inputs: vec![EmbedInput {
                parts: vec![
                    EmbedPart::Text { text: "t".into() },
                    EmbedPart::Image { media_type: None, data: Some("QUJD".into()), url: None },
                ],
            }],
            input_type: None,
            output_dimensions: None,
            truncate: None,
            encoding_format: None,
            cohere_embedding_types: None,
            gemini_batch: false,
        };
        let out = emit_request(&req, &EmbedEmitOptions::default()).unwrap();
        let v: Value = serde_json::from_slice(&out.0).unwrap();
        assert!(v.get("input").is_none());
        assert_eq!(v["messages"][0]["content"][0]["text"], "t");
        assert_eq!(v["messages"][0]["content"][1]["type"], "image_url");
    }

    #[test]
    fn response_accepts_base64_and_orders_by_index() {
        let body = serde_json::to_vec(&json!({
            "object": "list", "model": "m",
            "data": [
                {"object": "embedding", "index": 1, "embedding": [3.0, 4.0]},
                {"object": "embedding", "index": 0, "embedding": f32s_to_base64(&[1.0, 2.0])}
            ],
            "usage": {"prompt_tokens": 7, "total_tokens": 7}
        }))
        .unwrap();
        let resp = parse_response(&body).unwrap();
        assert_eq!(resp.embeddings, vec![vec![1.0, 2.0], vec![3.0, 4.0]]);
        assert_eq!(resp.usage.input_tokens, 7);
    }
}
