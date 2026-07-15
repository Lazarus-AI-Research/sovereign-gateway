//! The Ollama embeddings wire format (`POST /api/embed`) — **upstream only**;
//! The gateway exposes no inbound Ollama surface. Text-only.

use serde_json::{json, Map, Value};

use crate::common::*;
use crate::error::{Result, WireError};
use crate::EmittedRequest;

use super::*;

/// Parse an Ollama embed request body into the IR (used by tests/passthrough;
/// there is no inbound surface).
pub fn parse_request(body: &[u8]) -> Result<EmbedRequest> {
    let v: Value = serde_json::from_slice(body)?;
    let inputs = match v.get("input") {
        Some(Value::String(s)) => vec![EmbedInput::text(s.clone())],
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(EmbedInput::text)
                    .ok_or_else(|| WireError::invalid("input[]", "not a string"))
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(WireError::missing("input")),
    };
    if inputs.is_empty() {
        return Err(WireError::InvalidRequest("input must not be empty".into()));
    }
    Ok(EmbedRequest {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        inputs,
        input_type: None,
        output_dimensions: opt_u32(&v, "dimensions"),
        truncate: v.get("truncate").and_then(Value::as_bool),
        encoding_format: None,
        cohere_embedding_types: None,
        gemini_batch: false,
    })
}

/// Emit an IR request as an Ollama embed body plus headers. Text-only.
pub fn emit_request(req: &EmbedRequest, opts: &EmbedEmitOptions) -> Result<EmittedRequest> {
    let mut body = Map::new();
    let model = if opts.target_model.is_empty() {
        req.model.clone()
    } else {
        opts.target_model.clone()
    };
    body.insert("model".into(), json!(model));

    let mut texts = Vec::with_capacity(req.inputs.len());
    for input in &req.inputs {
        match input.as_single_text() {
            Some(t) => texts.push(json!(t)),
            None => {
                return Err(WireError::InvalidRequest(
                    "ollama_embed is text-only; route image inputs to a multimodal upstream \
                     (voyage_embed)"
                        .into(),
                ))
            }
        }
    }
    body.insert("input".into(), Value::Array(texts));
    insert_opt(&mut body, "dimensions", req.output_dimensions);
    if let Some(t) = req.truncate {
        body.insert("truncate".into(), json!(t));
    }

    let bytes = serde_json::to_vec(&Value::Object(body))?;
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    Ok((bytes, headers))
}

/// Parse an Ollama embed response body into the IR.
pub fn parse_response(body: &[u8]) -> Result<EmbedResponse> {
    let v: Value = serde_json::from_slice(body)?;
    let list = opt_arr(&v, "embeddings").ok_or_else(|| WireError::missing("embeddings"))?;
    let embeddings: Vec<Vec<f32>> = list
        .iter()
        .map(|row| {
            row.as_array()
                .map(|nums| nums.iter().map(|n| n.as_f64().unwrap_or(0.0) as f32).collect())
                .unwrap_or_default()
        })
        .collect();
    Ok(EmbedResponse {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        embeddings,
        usage: EmbedUsage {
            input_tokens: opt_u32(&v, "prompt_eval_count").unwrap_or(0),
            image_units: 0,
        },
    })
}

/// Emit an IR response as an Ollama embed response body (tests/passthrough).
pub fn emit_response(resp: &EmbedResponse, _req: &EmbedRequest) -> Result<Vec<u8>> {
    let body = json!({
        "model": resp.model,
        "embeddings": resp.embeddings,
        "prompt_eval_count": resp.usage.input_tokens,
    });
    Ok(serde_json::to_vec(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_roundtrip_and_image_rejection() {
        let body = serde_json::to_vec(&json!({"model": "m", "input": ["a", "b"]})).unwrap();
        let req = parse_request(&body).unwrap();
        let (up, _) = emit_request(&req, &EmbedEmitOptions::new("nomic-embed-text")).unwrap();
        let up: Value = serde_json::from_slice(&up).unwrap();
        assert_eq!(up["input"], json!(["a", "b"]));
        assert_eq!(up["model"], "nomic-embed-text");

        let img = EmbedRequest {
            inputs: vec![EmbedInput {
                parts: vec![EmbedPart::Image {
                    media_type: None,
                    data: Some("QUJD".into()),
                    url: None,
                }],
            }],
            ..req
        };
        assert!(emit_request(&img, &EmbedEmitOptions::default()).is_err());
    }

    #[test]
    fn response_maps_prompt_eval_count() {
        let body = serde_json::to_vec(&json!({
            "model": "m", "embeddings": [[0.5, 0.25]], "prompt_eval_count": 9
        }))
        .unwrap();
        let resp = parse_response(&body).unwrap();
        assert_eq!(resp.usage.input_tokens, 9);
        assert_eq!(resp.embeddings[0], vec![0.5, 0.25]);
    }
}
