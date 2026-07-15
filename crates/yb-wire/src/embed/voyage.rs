//! The Voyage multimodal embeddings wire format (`POST /v1/multimodalembeddings`).
//!
//! The one dialect with genuinely interleaved text+image inputs: each input is
//! a `content` array of `text` / `image_base64` (data URI) / `image_url`
//! blocks, producing one vector per input. Voyage's *text* endpoint
//! (`/v1/embeddings`) is OpenAI-shaped — configure text models as
//! `openai_embed` with a Voyage `api_base` instead.

use serde_json::{json, Map, Value};

use crate::common::*;
use crate::error::{Result, WireError};
use crate::EmittedRequest;

use super::*;

/// Parse a Voyage multimodal embeddings request body into the IR.
pub fn parse_request(body: &[u8]) -> Result<EmbedRequest> {
    let v: Value = serde_json::from_slice(body)?;
    v.as_object()
        .ok_or_else(|| WireError::InvalidRequest("body is not a JSON object".into()))?;

    let items = opt_arr(&v, "inputs").ok_or_else(|| WireError::missing("inputs"))?;
    let mut inputs = Vec::with_capacity(items.len());
    for item in items {
        let content =
            opt_arr(item, "content").ok_or_else(|| WireError::missing("inputs[].content"))?;
        let mut parts = Vec::with_capacity(content.len());
        for block in content {
            match opt_str(block, "type") {
                Some("text") => parts.push(EmbedPart::Text {
                    text: opt_str(block, "text").unwrap_or_default().to_string(),
                }),
                Some("image_base64") => {
                    let uri = opt_str(block, "image_base64")
                        .ok_or_else(|| WireError::missing("inputs[].content[].image_base64"))?;
                    let (media_type, data) = parse_data_url(uri).ok_or_else(|| {
                        WireError::invalid("image_base64", "expected a data: URI")
                    })?;
                    parts.push(EmbedPart::Image {
                        media_type: Some(media_type),
                        data: Some(data),
                        url: None,
                    });
                }
                Some("image_url") => {
                    let url = opt_str(block, "image_url")
                        .ok_or_else(|| WireError::missing("inputs[].content[].image_url"))?;
                    parts.push(EmbedPart::Image {
                        media_type: None,
                        data: None,
                        url: Some(url.to_string()),
                    });
                }
                other => {
                    return Err(WireError::invalid(
                        "inputs[].content[].type",
                        format!("unknown {other:?}"),
                    ))
                }
            }
        }
        if parts.is_empty() {
            return Err(WireError::InvalidRequest("inputs[].content is empty".into()));
        }
        inputs.push(EmbedInput { parts });
    }
    if inputs.is_empty() {
        return Err(WireError::InvalidRequest("inputs must not be empty".into()));
    }

    let encoding_format = match opt_str(&v, "encoding_format") {
        Some("base64") => Some(EncodingFormat::Base64),
        _ => None,
    };

    Ok(EmbedRequest {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        inputs,
        input_type: match opt_str(&v, "input_type") {
            Some("query") => Some("query".into()),
            Some("document") => Some("document".into()),
            _ => None,
        },
        output_dimensions: None,
        truncate: v.get("truncation").and_then(Value::as_bool),
        encoding_format,
        cohere_embedding_types: None,
        gemini_batch: false,
    })
}

/// Emit an IR request as a Voyage multimodal embeddings body plus headers.
pub fn emit_request(req: &EmbedRequest, opts: &EmbedEmitOptions) -> Result<EmittedRequest> {
    let mut body = Map::new();
    let model = if opts.target_model.is_empty() {
        req.model.clone()
    } else {
        opts.target_model.clone()
    };
    body.insert("model".into(), json!(model));

    let mut items = Vec::with_capacity(req.inputs.len());
    for input in &req.inputs {
        let mut content = Vec::with_capacity(input.parts.len());
        for p in &input.parts {
            match p {
                EmbedPart::Text { text } => content.push(json!({"type": "text", "text": text})),
                EmbedPart::Image { media_type, data, url } => match (data, url) {
                    (Some(_), _) => content.push(json!({
                        "type": "image_base64",
                        "image_base64": image_to_data_uri(media_type.as_deref(), data.as_deref())?,
                    })),
                    (None, Some(u)) => content.push(json!({"type": "image_url", "image_url": u})),
                    _ => return Err(WireError::invalid("inputs[]", "image without data or url")),
                },
            }
        }
        items.push(json!({"content": content}));
    }
    body.insert("inputs".into(), Value::Array(items));

    // Only query|document exist on this dialect.
    if let Some(t @ ("query" | "document")) = req.input_type.as_deref() {
        body.insert("input_type".into(), json!(t));
    }
    if let Some(t) = req.truncate {
        body.insert("truncation".into(), json!(t));
    }
    // output_dimensions has no representation here: omitted silently.

    let bytes = serde_json::to_vec(&Value::Object(body))?;
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    Ok((bytes, headers))
}

/// Parse a Voyage multimodal embeddings response body into the IR.
pub fn parse_response(body: &[u8]) -> Result<EmbedResponse> {
    let v: Value = serde_json::from_slice(body)?;
    let mut rows: Vec<(usize, Vec<f32>)> = Vec::new();
    let data = opt_arr(&v, "data").ok_or_else(|| WireError::missing("data"))?;
    for (pos, item) in data.iter().enumerate() {
        let index = opt_u32(item, "index").map(|i| i as usize).unwrap_or(pos);
        let emb = match item.get("embedding") {
            Some(Value::Array(nums)) => {
                nums.iter().map(|n| n.as_f64().unwrap_or(0.0) as f32).collect()
            }
            Some(Value::String(s)) => base64_to_f32s(s)?,
            _ => return Err(WireError::missing("data[].embedding")),
        };
        rows.push((index, emb));
    }
    rows.sort_by_key(|(i, _)| *i);
    let usage = v.get("usage");
    Ok(EmbedResponse {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        embeddings: rows.into_iter().map(|(_, e)| e).collect(),
        usage: EmbedUsage {
            input_tokens: usage
                .and_then(|u| opt_u32(u, "total_tokens").or_else(|| opt_u32(u, "text_tokens")))
                .unwrap_or(0),
            image_units: usage.and_then(|u| opt_u32(u, "image_pixels")).unwrap_or(0),
        },
    })
}

/// Emit an IR response as a Voyage multimodal embeddings response body.
pub fn emit_response(resp: &EmbedResponse, req: &EmbedRequest) -> Result<Vec<u8>> {
    let base64 = req.encoding_format == Some(EncodingFormat::Base64);
    let data: Vec<Value> = resp
        .embeddings
        .iter()
        .enumerate()
        .map(|(index, emb)| {
            let embedding: Value =
                if base64 { json!(f32s_to_base64(emb)) } else { json!(emb) };
            json!({"object": "embedding", "index": index, "embedding": embedding})
        })
        .collect();
    let body = json!({
        "object": "list",
        "data": data,
        "model": resp.model,
        "usage": {"total_tokens": resp.usage.input_tokens},
    });
    Ok(serde_json::to_vec(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_multimodal_roundtrip() {
        let body = serde_json::to_vec(&json!({
            "model": "voyage-multimodal-3",
            "input_type": "document",
            "inputs": [{"content": [
                {"type": "text", "text": "This is a banana."},
                {"type": "image_base64", "image_base64": "data:image/jpeg;base64,QUJD"}
            ]}]
        }))
        .unwrap();
        let req = parse_request(&body).unwrap();
        assert_eq!(req.inputs[0].parts.len(), 2);
        assert_eq!(req.input_type.as_deref(), Some("document"));

        let (up, _) = emit_request(&req, &EmbedEmitOptions::new("voyage-multimodal-3")).unwrap();
        let up: Value = serde_json::from_slice(&up).unwrap();
        assert_eq!(up["inputs"][0]["content"][1]["type"], "image_base64");
        assert_eq!(up["input_type"], "document");
    }

    #[test]
    fn usage_maps_pixels() {
        let body = serde_json::to_vec(&json!({
            "object": "list", "model": "m",
            "data": [{"object": "embedding", "index": 0, "embedding": [0.1]}],
            "usage": {"total_tokens": 12, "image_pixels": 313600}
        }))
        .unwrap();
        let resp = parse_response(&body).unwrap();
        assert_eq!(resp.usage.input_tokens, 12);
        assert_eq!(resp.usage.image_units, 313600);
    }
}
