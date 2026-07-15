//! The Cohere embeddings wire format (`POST /v2/embed`).
//!
//! Accepts `texts`, `images` (data URIs), or the multimodal `inputs` form
//! (`content` arrays mixing text and `image_url` blocks — embed-v4). Cohere
//! v3+ requires `input_type` (default `search_document`). `embedding_types`:
//! `float` and `base64` are served (base64 computed from floats); quantized
//! types (`int8`/`uint8`/`binary`/`ubinary`) are model-side and rejected.

use serde_json::{json, Map, Value};

use crate::common::*;
use crate::error::{Result, WireError};
use crate::EmittedRequest;

use super::*;

/// Parse a Cohere v2 embed request body into the IR.
pub fn parse_request(body: &[u8]) -> Result<EmbedRequest> {
    let v: Value = serde_json::from_slice(body)?;
    v.as_object()
        .ok_or_else(|| WireError::InvalidRequest("body is not a JSON object".into()))?;

    let model = opt_str(&v, "model").unwrap_or_default().to_string();

    let has_texts = v.get("texts").is_some();
    let has_images = v.get("images").is_some();
    let has_inputs = v.get("inputs").is_some();
    if [has_texts, has_images, has_inputs].iter().filter(|b| **b).count() > 1 {
        return Err(WireError::InvalidRequest(
            "texts, images, and inputs are mutually exclusive".into(),
        ));
    }

    let mut inputs = Vec::new();
    if let Some(texts) = opt_arr(&v, "texts") {
        for t in texts {
            let s = t.as_str().ok_or_else(|| WireError::invalid("texts[]", "not a string"))?;
            inputs.push(EmbedInput::text(s));
        }
    } else if let Some(images) = opt_arr(&v, "images") {
        for i in images {
            let s = i.as_str().ok_or_else(|| WireError::invalid("images[]", "not a string"))?;
            inputs.push(EmbedInput { parts: vec![data_uri_to_part(s)?] });
        }
    } else if let Some(items) = opt_arr(&v, "inputs") {
        for item in items {
            let content = opt_arr(item, "content")
                .ok_or_else(|| WireError::missing("inputs[].content"))?;
            let mut parts = Vec::new();
            for block in content {
                match opt_str(block, "type") {
                    Some("text") => parts.push(EmbedPart::Text {
                        text: opt_str(block, "text").unwrap_or_default().to_string(),
                    }),
                    Some("image_url") => {
                        let url = block
                            .get("image_url")
                            .and_then(|u| opt_str(u, "url"))
                            .ok_or_else(|| WireError::missing("inputs[].content[].image_url.url"))?;
                        parts.push(if url.starts_with("data:") {
                            data_uri_to_part(url)?
                        } else {
                            EmbedPart::Image {
                                media_type: None,
                                data: None,
                                url: Some(url.to_string()),
                            }
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
    }
    if inputs.is_empty() {
        return Err(WireError::InvalidRequest(
            "one of texts, images, or inputs is required".into(),
        ));
    }

    // embedding_types: validate the supported subset; quantized types cannot be
    // derived from floats and are rejected.
    let cohere_embedding_types = match opt_arr(&v, "embedding_types") {
        Some(types) => {
            let mut out = Vec::new();
            for t in types {
                match t.as_str() {
                    Some("float") | Some("base64") => out.push(t.as_str().unwrap().to_string()),
                    Some(other) => {
                        return Err(WireError::InvalidRequest(format!(
                            "embedding_types `{other}` is not supported through the gateway \
                             (quantization is model-side); use float or base64"
                        )))
                    }
                    None => return Err(WireError::invalid("embedding_types[]", "not a string")),
                }
            }
            Some(out)
        }
        None => None,
    };

    let truncate = match opt_str(&v, "truncate") {
        Some("NONE") => Some(false),
        Some(_) => Some(true), // START | END
        None => None,
    };

    Ok(EmbedRequest {
        model,
        inputs,
        input_type: opt_str(&v, "input_type").and_then(cohere_to_input_type).map(str::to_string),
        output_dimensions: opt_u32(&v, "output_dimension"),
        truncate,
        encoding_format: None,
        cohere_embedding_types,
        gemini_batch: false,
    })
}

/// A Cohere image string (must be a data URI) → an image part.
fn data_uri_to_part(s: &str) -> Result<EmbedPart> {
    let (media_type, data) = parse_data_url(s)
        .ok_or_else(|| WireError::invalid("images[]", "expected a data: URI"))?;
    Ok(EmbedPart::Image { media_type: Some(media_type), data: Some(data), url: None })
}

/// Emit an IR request as a Cohere v2 embed body plus headers. All-text inputs
/// use `texts` (keeps embed-v3 models working); anything else uses the
/// multimodal `inputs` form with inline data-URI images.
pub fn emit_request(req: &EmbedRequest, opts: &EmbedEmitOptions) -> Result<EmittedRequest> {
    let mut body = Map::new();
    let model = if opts.target_model.is_empty() {
        req.model.clone()
    } else {
        opts.target_model.clone()
    };
    body.insert("model".into(), json!(model));
    body.insert("input_type".into(), json!(input_type_to_cohere(req.input_type.as_deref())));

    let all_text = req.inputs.iter().all(|i| i.as_single_text().is_some());
    if all_text {
        body.insert(
            "texts".into(),
            Value::Array(req.inputs.iter().map(|i| json!(i.as_single_text().unwrap())).collect()),
        );
    } else {
        let mut items = Vec::with_capacity(req.inputs.len());
        for input in &req.inputs {
            let mut content = Vec::with_capacity(input.parts.len());
            for p in &input.parts {
                match p {
                    EmbedPart::Text { text } => content.push(json!({"type": "text", "text": text})),
                    EmbedPart::Image { media_type, data, url: _ } => {
                        let uri = image_to_data_uri(media_type.as_deref(), data.as_deref())?;
                        content.push(json!({"type": "image_url", "image_url": {"url": uri}}));
                    }
                }
            }
            items.push(json!({"content": content}));
        }
        body.insert("inputs".into(), Value::Array(items));
    }

    body.insert("embedding_types".into(), json!(["float"]));
    insert_opt(&mut body, "output_dimension", req.output_dimensions);
    if req.truncate == Some(false) {
        body.insert("truncate".into(), json!("NONE"));
    }

    let bytes = serde_json::to_vec(&Value::Object(body))?;
    let headers = vec![("content-type".to_string(), "application/json".to_string())];
    Ok((bytes, headers))
}

/// Parse a Cohere v2 embed response body into the IR.
pub fn parse_response(body: &[u8]) -> Result<EmbedResponse> {
    let v: Value = serde_json::from_slice(body)?;
    let floats = v
        .get("embeddings")
        .and_then(|e| e.get("float"))
        .and_then(Value::as_array)
        .ok_or_else(|| WireError::missing("embeddings.float"))?;
    let embeddings: Vec<Vec<f32>> = floats
        .iter()
        .map(|row| {
            row.as_array()
                .map(|nums| nums.iter().map(|n| n.as_f64().unwrap_or(0.0) as f32).collect())
                .unwrap_or_default()
        })
        .collect();
    let billed = v.get("meta").and_then(|m| m.get("billed_units"));
    let input_tokens = billed.and_then(|b| opt_u32(b, "input_tokens")).unwrap_or(0);
    let image_tokens = billed.and_then(|b| opt_u32(b, "image_tokens")).unwrap_or(0);
    Ok(EmbedResponse {
        model: opt_str(&v, "model").unwrap_or_default().to_string(),
        embeddings,
        usage: EmbedUsage {
            // Both are billed as input.
            input_tokens: input_tokens + image_tokens,
            image_units: image_tokens,
        },
    })
}

/// Emit an IR response as a Cohere v2 embed response body, serving exactly the
/// embedding_types the client asked for (default float).
pub fn emit_response(resp: &EmbedResponse, req: &EmbedRequest) -> Result<Vec<u8>> {
    let requested: Vec<&str> = req
        .cohere_embedding_types
        .as_ref()
        .map(|v| v.iter().map(String::as_str).collect())
        .unwrap_or_else(|| vec!["float"]);
    let mut embeddings = Map::new();
    if requested.contains(&"float") {
        embeddings.insert("float".into(), json!(resp.embeddings));
    }
    if requested.contains(&"base64") {
        embeddings.insert(
            "base64".into(),
            json!(resp.embeddings.iter().map(|e| f32s_to_base64(e)).collect::<Vec<_>>()),
        );
    }
    let body = json!({
        "id": uuid_ish(&resp.model, resp.embeddings.len()),
        "embeddings": embeddings,
        "texts": [],
        "meta": {
            "api_version": {"version": "2"},
            "billed_units": {"input_tokens": resp.usage.input_tokens},
        },
    });
    Ok(serde_json::to_vec(&body)?)
}

/// A deterministic-ish response id (the crate has no uuid/rand dependency; the
/// id is purely informational on this surface).
fn uuid_ish(model: &str, n: usize) -> String {
    format!("emb-{}-{n}", model.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantized_embedding_types_rejected() {
        let body = serde_json::to_vec(&json!({
            "model": "embed-v4.0", "texts": ["x"], "embedding_types": ["int8"]
        }))
        .unwrap();
        assert!(parse_request(&body).is_err());
    }

    #[test]
    fn input_type_defaults_to_search_document() {
        let body = serde_json::to_vec(&json!({"model": "m", "texts": ["a"]})).unwrap();
        let req = parse_request(&body).unwrap();
        let (up, _) = emit_request(&req, &EmbedEmitOptions::default()).unwrap();
        let up: Value = serde_json::from_slice(&up).unwrap();
        assert_eq!(up["input_type"], "search_document");
        assert_eq!(up["texts"][0], "a");
        assert_eq!(up["embedding_types"], json!(["float"]));
    }

    #[test]
    fn multimodal_inputs_roundtrip() {
        let body = serde_json::to_vec(&json!({
            "model": "embed-v4.0", "input_type": "search_query",
            "inputs": [{"content": [
                {"type": "text", "text": "a banana"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,QUJD"}}
            ]}]
        }))
        .unwrap();
        let req = parse_request(&body).unwrap();
        assert_eq!(req.input_type.as_deref(), Some("query"));
        assert_eq!(req.inputs[0].parts.len(), 2);
        let (up, _) = emit_request(&req, &EmbedEmitOptions::default()).unwrap();
        let up: Value = serde_json::from_slice(&up).unwrap();
        assert_eq!(up["inputs"][0]["content"][1]["image_url"]["url"], "data:image/png;base64,QUJD");
        assert!(up.get("texts").is_none());
    }

    #[test]
    fn url_image_to_cohere_rejected_at_emit() {
        let req = EmbedRequest {
            model: "m".into(),
            inputs: vec![EmbedInput {
                parts: vec![EmbedPart::Image {
                    media_type: None,
                    data: None,
                    url: Some("https://example.com/x.png".into()),
                }],
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
    fn response_usage_folds_image_tokens() {
        let body = serde_json::to_vec(&json!({
            "id": "x", "embeddings": {"float": [[0.25, 0.5]]},
            "meta": {"billed_units": {"input_tokens": 3, "image_tokens": 7}}
        }))
        .unwrap();
        let resp = parse_response(&body).unwrap();
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.image_units, 7);
        assert_eq!(resp.embeddings[0], vec![0.25, 0.5]);
    }

    #[test]
    fn base64_embedding_type_served() {
        let req = parse_request(
            &serde_json::to_vec(&json!({
                "model": "m", "texts": ["a"], "embedding_types": ["float", "base64"]
            }))
            .unwrap(),
        )
        .unwrap();
        let resp = EmbedResponse {
            model: "m".into(),
            embeddings: vec![vec![1.0, 2.0]],
            usage: EmbedUsage::default(),
        };
        let out: Value = serde_json::from_slice(&emit_response(&resp, &req).unwrap()).unwrap();
        assert_eq!(out["embeddings"]["float"][0][1], 2.0);
        assert_eq!(out["embeddings"]["base64"][0], json!(f32s_to_base64(&[1.0, 2.0])));
    }
}
