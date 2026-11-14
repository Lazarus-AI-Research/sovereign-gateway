//! SystemOne (`POST /v1/systemone`, `"jev"`) and Decisions
//! (`POST /v1/decisions`, `"decisions"`) wire helpers.
//!
//! Both surfaces share the same request schema — single-forward-pass logit
//! probing (`max_tokens = 0`) over `state` (or `input`) and structured
//! `questions` — and differ only in response envelope fields:
//! - `/v1/systemone` returns `"id": "s1-..."`, `"object": "systemone"`, and
//!   `"answers": {...}`.
//! - `/v1/decisions` returns `"id": "dec-..."`, `"object": "decision"`,
//!   `"answers": {...}`, and `"decisions": {...}`.
//!
//! Same-shape turns relay request and response bytes directly (with only the
//! upstream `model` spliced in); cross-shape turns (`jev` ↔ `decisions`) adapt
//! the response envelope losslessly.

use serde_json::Value;

use crate::error::{Result, WireError};
use crate::ir::Usage;

/// Routing metadata extracted from an inbound SystemOne / Decisions request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionMeta {
    pub model: String,
    pub estimated_chars: usize,
    pub has_images: bool,
}

/// Validate an inbound SystemOne / Decisions request body and extract routing
/// metadata without re-serializing or perturbing the caller's bytes.
pub fn parse_decision_request(body: &[u8]) -> Result<DecisionMeta> {
    let v: Value = serde_json::from_slice(body)?;
    let obj = v
        .as_object()
        .ok_or_else(|| WireError::InvalidRequest("request body must be a JSON object".into()))?;

    let model = match obj.get("model") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
        Some(_) => return Err(WireError::invalid("model", "must be a non-empty string")),
        None => return Err(WireError::missing("model")),
    };

    let state = obj
        .get("state")
        .filter(|x| !x.is_null())
        .or_else(|| obj.get("input").filter(|x| !x.is_null()))
        .ok_or_else(|| WireError::missing("state"))?;

    let questions = obj
        .get("questions")
        .ok_or_else(|| WireError::missing("questions"))?;
    let non_empty_questions = match questions {
        Value::Object(m) => !m.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => false,
    };
    if !non_empty_questions {
        return Err(WireError::invalid(
            "questions",
            "must be a non-empty object or array",
        ));
    }

    if obj.get("stream").and_then(|x| x.as_bool()) == Some(true) {
        return Err(WireError::invalid(
            "stream",
            "streaming is not supported for decision/systemone endpoints",
        ));
    }

    let estimated_chars = state.to_string().len() + questions.to_string().len();
    let has_images = value_has_images(state);

    Ok(DecisionMeta {
        model,
        estimated_chars,
        has_images,
    })
}

fn value_has_images(v: &Value) -> bool {
    match v {
        Value::Array(parts) => parts.iter().any(|p| {
            p.as_object().is_some_and(|m| {
                m.contains_key("image_url")
                    || matches!(
                        m.get("type").and_then(|t| t.as_str()),
                        Some("image_url" | "input_image" | "image")
                    )
            })
        }),
        _ => false,
    }
}

/// Extract token and prompt-cache accounting from a SystemOne / Decisions
/// response body.
///
/// `usage.prompt_tokens` carries total scheduled prompt tokens (including any
/// cached prefix), matching `ModelPrice::cost_micros` which subtracts
/// `cache_read_tokens + cache_write_tokens` from `input_tokens`.
pub fn parse_decision_usage(body: &[u8]) -> Result<Usage> {
    let v: Value = serde_json::from_slice(body)?;
    let Some(u) = v.get("usage").and_then(|u| u.as_object()) else {
        return Ok(Usage::default());
    };
    let input_tokens = u
        .get("prompt_tokens")
        .or_else(|| u.get("input_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;
    let output_tokens = u
        .get("completion_tokens")
        .or_else(|| u.get("output_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;
    let details = u.get("prompt_tokens_details").and_then(|d| d.as_object());
    let cache_read_tokens = details
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;
    let cache_write_tokens = details
        .and_then(|d| d.get("cache_write_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;

    Ok(Usage {
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cache_write_tokens,
        ..Usage::default()
    })
}

/// Adapt a buffered SystemOne / Decisions response between `jev`
/// (`/v1/systemone`) and `decisions` (`/v1/decisions`), or return it
/// byte-for-byte unchanged when `from_jev == to_jev`.
pub fn translate_decision_response(from_jev: bool, to_jev: bool, body: &[u8]) -> Result<Vec<u8>> {
    if from_jev == to_jev {
        return Ok(body.to_vec());
    }
    let mut v: Value = serde_json::from_slice(body)?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| WireError::InvalidResponse("response body must be a JSON object".into()))?;

    if to_jev {
        // decisions -> systemone (jev)
        if let Some(id) = obj.get("id").and_then(|x| x.as_str()).map(str::to_string) {
            if let Some(rest) = id.strip_prefix("dec-") {
                obj.insert("id".into(), Value::String(format!("s1-{rest}")));
            } else if let Some(rest) = id.strip_prefix("dec_") {
                obj.insert("id".into(), Value::String(format!("s1_{rest}")));
            }
        }
        obj.insert("object".into(), Value::String("systemone".into()));
        let answers = obj
            .get("answers")
            .cloned()
            .or_else(|| obj.get("decisions").cloned());
        obj.remove("decisions");
        if let Some(ans) = answers {
            obj.insert("answers".into(), ans);
        }
    } else {
        // systemone (jev) -> decisions
        if let Some(id) = obj.get("id").and_then(|x| x.as_str()).map(str::to_string) {
            if let Some(rest) = id.strip_prefix("s1-") {
                obj.insert("id".into(), Value::String(format!("dec-{rest}")));
            } else if let Some(rest) = id.strip_prefix("s1_") {
                obj.insert("id".into(), Value::String(format!("dec_{rest}")));
            }
        }
        obj.insert("object".into(), Value::String("decision".into()));
        if let Some(ans) = obj.get("answers").cloned() {
            obj.entry("decisions").or_insert(ans);
        }
    }

    Ok(serde_json::to_vec(&v)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_systemone_and_decisions_requests() {
        let req = json!({
            "model": "qwen3.8-27b",
            "state": "User asks whether to deploy.",
            "questions": {
                "approve": { "type": "noul", "question": "Should we deploy?" }
            }
        });
        let meta = parse_decision_request(&serde_json::to_vec(&req).unwrap()).unwrap();
        assert_eq!(meta.model, "qwen3.8-27b");
        assert!(!meta.has_images);
        assert!(meta.estimated_chars > 20);

        // Multimodal input array with image_url + array-style questions.
        let mm = json!({
            "model": "qwen3.8-vl",
            "input": [
                { "type": "text", "text": "Inspect chart" },
                { "type": "image_url", "image_url": { "url": "data:image/png;base64,AAA=" } }
            ],
            "questions": [
                { "name": "kind", "type": "choice", "question": "Chart type?", "choices": ["bar", "line"] }
            ]
        });
        let meta = parse_decision_request(&serde_json::to_vec(&mm).unwrap()).unwrap();
        assert_eq!(meta.model, "qwen3.8-vl");
        assert!(meta.has_images);

        // Reject missing model / state / empty questions.
        assert!(parse_decision_request(br#"{"state":"x","questions":{"a":1}}"#).is_err());
        assert!(parse_decision_request(br#"{"model":"m","questions":{"a":1}}"#).is_err());
        assert!(parse_decision_request(br#"{"model":"m","state":"x","questions":{}}"#).is_err());
    }

    #[test]
    fn parses_usage_with_cached_and_cache_write_tokens() {
        let resp = json!({
            "id": "s1-123",
            "object": "systemone",
            "model": "qwen3.8",
            "answers": { "ok": { "answer": "yes", "probability": 0.94 } },
            "usage": {
                "prompt_tokens": 120,
                "input_tokens": 100,
                "completion_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 120,
                "prompt_tokens_details": {
                    "cached_tokens": 80,
                    "cache_write_tokens": 20
                }
            }
        });
        let u = parse_decision_usage(&serde_json::to_vec(&resp).unwrap()).unwrap();
        assert_eq!(u.input_tokens, 120);
        assert_eq!(u.output_tokens, 0);
        assert_eq!(u.cache_read_tokens, 80);
        assert_eq!(u.cache_write_tokens, 20);
    }

    #[test]
    fn translates_losslessly_between_jev_and_decisions() {
        let jev_raw = br#"{"id":"s1-abc","object":"systemone","created":1700000000,"model":"m","answers":{"q":{"answer":"yes","probability":0.9}},"usage":{"prompt_tokens":10,"output_tokens":0}}"#;
        // Same-shape is byte-identical.
        assert_eq!(
            translate_decision_response(true, true, jev_raw).unwrap(),
            jev_raw
        );

        // jev -> decisions
        let as_dec = translate_decision_response(true, false, jev_raw).unwrap();
        let dec_v: Value = serde_json::from_slice(&as_dec).unwrap();
        assert_eq!(dec_v["id"], "dec-abc");
        assert_eq!(dec_v["object"], "decision");
        assert_eq!(dec_v["answers"]["q"]["answer"], "yes");
        assert_eq!(dec_v["decisions"]["q"]["answer"], "yes");

        // decisions -> jev
        let back_jev = translate_decision_response(false, true, &as_dec).unwrap();
        let jev_v: Value = serde_json::from_slice(&back_jev).unwrap();
        assert_eq!(jev_v["id"], "s1-abc");
        assert_eq!(jev_v["object"], "systemone");
        assert_eq!(jev_v["answers"]["q"]["answer"], "yes");
        assert!(jev_v.get("decisions").is_none());
    }
}
