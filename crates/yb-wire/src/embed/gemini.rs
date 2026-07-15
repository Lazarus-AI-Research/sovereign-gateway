//! The Gemini embeddings wire format (`:embedContent` / `:batchEmbedContents`).
//!
//! Text-only. The upstream is **always** called via `:batchEmbedContents` (one
//! uniform path regardless of input count); the client's single-vs-batch choice
//! travels on the IR (`gemini_batch`, injected by the server from the URL
//! action) and shapes only the client response.

use serde_json::{json, Map, Value};

use crate::common::*;
use crate::error::{Result, WireError};
use crate::EmittedRequest;

use super::*;

/// Parse a Gemini embeddings request body into the IR. The server injects
/// `model` (from the URL path) and `batch` (from the URL action) into the body,
/// mirroring how the chat surface injects `model`/`stream`.
pub fn parse_request(body: &[u8]) -> Result<EmbedRequest> {
    let v: Value = serde_json::from_slice(body)?;
    v.as_object()
        .ok_or_else(|| WireError::InvalidRequest("body is not a JSON object".into()))?;

    let model = opt_str(&v, "model").unwrap_or_default().to_string();
    let batch = opt_bool(&v, "batch");

    let mut inputs = Vec::new();
    let mut input_type = None;
    let mut output_dimensions = None;

    if let Some(requests) = opt_arr(&v, "requests") {
        // :batchEmbedContents shape.
        for r in requests {
            inputs.push(content_to_input(r.get("content"))?);
            if input_type.is_none() {
                input_type = task_type_of(r);
            }
            if output_dimensions.is_none() {
                output_dimensions = dims_of(r);
            }
        }
    } else if v.get("content").is_some() {
        // single :embedContent shape.
        inputs.push(content_to_input(v.get("content"))?);
        input_type = task_type_of(&v);
        output_dimensions = dims_of(&v);
    } else {
        return Err(WireError::missing("content (or requests)"));
    }
    if inputs.is_empty() {
        return Err(WireError::InvalidRequest("requests must not be empty".into()));
    }

    Ok(EmbedRequest {
        model,
        inputs,
        input_type,
        output_dimensions,
        truncate: None,
        encoding_format: None,
        cohere_embedding_types: None,
        gemini_batch: batch,
    })
}

/// A Gemini `content.parts` list → one text input. Multiple text parts are
/// preserved as multiple parts of the same input; inline/file data → error.
fn content_to_input(content: Option<&Value>) -> Result<EmbedInput> {
    let parts = content
        .and_then(|c| opt_arr(c, "parts"))
        .ok_or_else(|| WireError::missing("content.parts"))?;
    let mut out = Vec::new();
    for p in parts {
        if let Some(text) = opt_str(p, "text") {
            out.push(EmbedPart::Text { text: text.to_string() });
        } else if p.get("inlineData").is_some()
            || p.get("inline_data").is_some()
            || p.get("fileData").is_some()
            || p.get("file_data").is_some()
        {
            return Err(WireError::InvalidRequest(
                "gemini embeddings are text-only; image parts are not supported".into(),
            ));
        }
    }
    if out.is_empty() {
        return Err(WireError::InvalidRequest("content has no text parts".into()));
    }
    Ok(EmbedInput { parts: out })
}

/// The task hint of a request object: `taskType` (top-level, deprecated) or
/// under `embedContentConfig`.
fn task_type_of(v: &Value) -> Option<String> {
    let raw = opt_str(v, "taskType")
        .or_else(|| v.get("embedContentConfig").and_then(|c| opt_str(c, "taskType")))
        .or_else(|| v.get("embedContentConfig").and_then(|c| opt_str(c, "task_type")))?;
    gemini_to_input_type(raw).map(str::to_string)
}

fn dims_of(v: &Value) -> Option<u32> {
    opt_u32(v, "outputDimensionality")
        .or_else(|| v.get("embedContentConfig").and_then(|c| opt_u32(c, "outputDimensionality")))
}

/// Emit an IR request as a `:batchEmbedContents` body plus headers. Any image
/// part is an error (text-only dialect).
pub fn emit_request(req: &EmbedRequest, opts: &EmbedEmitOptions) -> Result<EmittedRequest> {
    let model = if opts.target_model.is_empty() {
        req.model.clone()
    } else {
        opts.target_model.clone()
    };
    let task_type = req.input_type.as_deref().and_then(input_type_to_gemini);

    let mut requests = Vec::with_capacity(req.inputs.len());
    for input in &req.inputs {
        if input.has_image() {
            return Err(WireError::InvalidRequest(
                "gemini_embed is text-only; route image inputs to a multimodal upstream \
                 (voyage_embed)"
                    .into(),
            ));
        }
        let parts: Vec<Value> = input
            .parts
            .iter()
            .filter_map(|p| match p {
                EmbedPart::Text { text } => Some(json!({"text": text})),
                EmbedPart::Image { .. } => None,
            })
            .collect();
        let mut r = Map::new();
        r.insert("model".into(), json!(format!("models/{model}")));
        r.insert("content".into(), json!({"parts": parts}));
        if let Some(tt) = task_type {
            r.insert("taskType".into(), json!(tt));
        }
        insert_opt(&mut r, "outputDimensionality", req.output_dimensions);
        requests.push(Value::Object(r));
    }

    let bytes = serde_json::to_vec(&json!({"requests": requests}))?;
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    Ok((bytes, headers))
}

/// Parse a Gemini embeddings response (batch `{embeddings:[{values}]}`, or
/// defensively the single `{embedding:{values}}` shape).
pub fn parse_response(body: &[u8]) -> Result<EmbedResponse> {
    let v: Value = serde_json::from_slice(body)?;
    let mut embeddings: Vec<Vec<f32>> = Vec::new();
    if let Some(list) = opt_arr(&v, "embeddings") {
        for e in list {
            embeddings.push(values_of(e)?);
        }
    } else if let Some(e) = v.get("embedding") {
        embeddings.push(values_of(e)?);
    } else {
        return Err(WireError::missing("embeddings"));
    }
    let input_tokens = v
        .get("usageMetadata")
        .and_then(|u| opt_u32(u, "promptTokenCount"))
        .unwrap_or(0);
    Ok(EmbedResponse {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        embeddings,
        usage: EmbedUsage { input_tokens, image_units: 0 },
    })
}

fn values_of(e: &Value) -> Result<Vec<f32>> {
    let values = opt_arr(e, "values").ok_or_else(|| WireError::missing("embedding.values"))?;
    Ok(values.iter().map(|n| n.as_f64().unwrap_or(0.0) as f32).collect())
}

/// Emit an IR response in the shape the client called with: single
/// `{embedding:{values}}` for `:embedContent`, else `{embeddings:[...]}`.
pub fn emit_response(resp: &EmbedResponse, req: &EmbedRequest) -> Result<Vec<u8>> {
    let body = if req.gemini_batch {
        json!({"embeddings": resp.embeddings.iter().map(|e| json!({"values": e})).collect::<Vec<_>>()})
    } else {
        if resp.embeddings.len() != 1 {
            return Err(WireError::InvalidRequest(format!(
                "embedContent expects exactly one embedding, got {}",
                resp.embeddings.len()
            )));
        }
        json!({"embedding": {"values": resp.embeddings[0]}})
    };
    Ok(serde_json::to_vec(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_batch_parse_and_emit() {
        // single :embedContent (server injected model + batch=false)
        let body = serde_json::to_vec(&json!({
            "model": "gemini-embedding-001", "batch": false,
            "content": {"parts": [{"text": "hi"}]},
            "taskType": "RETRIEVAL_QUERY"
        }))
        .unwrap();
        let req = parse_request(&body).unwrap();
        assert!(!req.gemini_batch);
        assert_eq!(req.input_type.as_deref(), Some("query"));

        // upstream is always batch-shaped
        let (up, _) = emit_request(&req, &EmbedEmitOptions::new("target")).unwrap();
        let up: Value = serde_json::from_slice(&up).unwrap();
        assert_eq!(up["requests"][0]["model"], "models/target");
        assert_eq!(up["requests"][0]["taskType"], "RETRIEVAL_QUERY");

        // client response mirrors the single shape
        let resp = EmbedResponse {
            model: String::new(),
            embeddings: vec![vec![0.5]],
            usage: EmbedUsage::default(),
        };
        let out: Value = serde_json::from_slice(&emit_response(&resp, &req).unwrap()).unwrap();
        assert_eq!(out["embedding"]["values"][0], 0.5);
    }

    #[test]
    fn image_parts_rejected() {
        let body = serde_json::to_vec(&json!({
            "model": "m", "batch": false,
            "content": {"parts": [{"inlineData": {"mimeType": "image/png", "data": "QUJD"}}]}
        }))
        .unwrap();
        assert!(parse_request(&body).is_err());
    }

    #[test]
    fn batch_response_shape() {
        let req = parse_request(
            &serde_json::to_vec(&json!({
                "model": "m", "batch": true,
                "requests": [
                    {"content": {"parts": [{"text": "a"}]}},
                    {"content": {"parts": [{"text": "b"}]}}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(req.gemini_batch);
        assert_eq!(req.inputs.len(), 2);
        let resp = EmbedResponse {
            model: String::new(),
            embeddings: vec![vec![1.0], vec![2.0]],
            usage: EmbedUsage::default(),
        };
        let out: Value = serde_json::from_slice(&emit_response(&resp, &req).unwrap()).unwrap();
        assert_eq!(out["embeddings"][1]["values"][0], 2.0);
    }
}
