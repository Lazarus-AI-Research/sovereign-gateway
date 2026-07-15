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
    let inputs = parse_input(v.get("input"))?;
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

    let all_text = req.inputs.iter().all(|i| i.as_single_text().is_some());
    let input: Value = if all_text {
        Value::Array(
            req.inputs.iter().map(|i| json!(i.as_single_text().unwrap())).collect(),
        )
    } else {
        // Jina-style objects; each input must be a single part (this dialect
        // cannot interleave text+image into one vector).
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
                _ => {
                    return Err(WireError::InvalidRequest(
                        "openai_embed cannot represent a mixed text+image input; \
                         use a multimodal upstream (voyage_embed)"
                            .into(),
                    ))
                }
            }
        }
        Value::Array(items)
    };
    body.insert("input".into(), input);

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

    #[test]
    fn mixed_part_input_cannot_emit() {
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
        assert!(emit_request(&req, &EmbedEmitOptions::default()).is_err());
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
