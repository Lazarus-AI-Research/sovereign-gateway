//! OpenAI's image generation, speech and transcription requests.
//!
//! The gateway does not translate these: it reads the model to route, points
//! the request at the deployment's model, and forwards the rest as it came.
//! Image and speech requests are JSON; a transcription is a multipart form
//! whose `model` field names the model.

use serde_json::{json, Value};

use crate::{Result, WireError};

/// The requested model and the body to send upstream, with the model replaced
/// by the deployment's own name.
pub fn route_media_request(body: &[u8], content_type: &str) -> Result<MediaRequest> {
    if is_multipart(content_type) {
        let boundary = multipart_boundary(content_type)
            .ok_or_else(|| WireError::InvalidRequest("multipart body without a boundary".into()))?;
        let model =
            multipart_field(body, &boundary, "model").ok_or_else(|| WireError::missing("model"))?;
        return Ok(MediaRequest {
            model,
            multipart_boundary: Some(boundary),
        });
    }
    let value: Value = serde_json::from_slice(body)?;
    let model = value
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| WireError::missing("model"))?
        .to_string();
    Ok(MediaRequest {
        model,
        multipart_boundary: None,
    })
}

/// The model a video's id names. An engine that makes videos as jobs names
/// each one `video_` followed by the base64url of `model/job`, so a later
/// request about the video is routed to the deployment that made it without
/// the gateway keeping any state.
pub fn video_model(id: &str) -> Result<String> {
    use base64::Engine as _;
    let invalid = || WireError::invalid("video", "not a video this gateway routes");
    let encoded = id.strip_prefix("video_").ok_or_else(invalid)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid())?;
    let raw = String::from_utf8(raw).map_err(|_| invalid())?;
    match raw.split_once('/') {
        Some((model, job)) if !model.is_empty() && !job.is_empty() => Ok(model.to_string()),
        _ => Err(invalid()),
    }
}

/// What routing needs from a media request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRequest {
    /// The public model the caller asked for.
    pub model: String,
    /// Set when the body is a multipart form.
    pub multipart_boundary: Option<String>,
}

impl MediaRequest {
    /// The body to forward, naming `upstream_model` in place of the public
    /// model. A multipart form is forwarded unchanged apart from its `model`
    /// field; a JSON body keeps every other field.
    pub fn upstream_body(&self, body: &[u8], upstream_model: &str) -> Result<Vec<u8>> {
        match &self.multipart_boundary {
            Some(boundary) => Ok(replace_multipart_field(
                body,
                boundary,
                "model",
                upstream_model,
            )),
            None => {
                let mut value: Value = serde_json::from_slice(body)?;
                if let Some(object) = value.as_object_mut() {
                    object.insert("model".into(), json!(upstream_model));
                }
                Ok(serde_json::to_vec(&value)?)
            }
        }
    }
}

fn is_multipart(content_type: &str) -> bool {
    content_type
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("multipart/form-data")
}

fn multipart_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.trim().split_once('=')?;
        name.eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"').to_string())
            .filter(|boundary| !boundary.is_empty())
    })
}

/// Where one form field's value sits in the body.
struct FieldSpan {
    value: std::ops::Range<usize>,
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| at + from)
}

/// Locates a simple (non-file) field of a multipart form.
fn multipart_span(body: &[u8], boundary: &str, name: &str) -> Option<FieldSpan> {
    let delimiter = format!("--{boundary}");
    let wanted_quoted = format!("name=\"{name}\"");
    let wanted_bare = format!("name={name}");
    let mut at = find(body, delimiter.as_bytes(), 0)?;
    loop {
        let headers_start = at + delimiter.len();
        let next = find(body, delimiter.as_bytes(), headers_start)?;
        let headers_end = find(body, b"\r\n\r\n", headers_start).filter(|end| *end < next)?;
        let headers = String::from_utf8_lossy(&body[headers_start..headers_end]);
        let disposition = headers
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("content-disposition"))
            .unwrap_or_default();
        let names_field = disposition
            .split(';')
            .any(|part| part.trim() == wanted_quoted || part.trim() == wanted_bare);
        if names_field {
            let value_start = headers_end + 4;
            // The value ends at the CRLF before the next delimiter.
            let value_end = next.saturating_sub(2).max(value_start);
            return Some(FieldSpan {
                value: value_start..value_end,
            });
        }
        at = next;
    }
}

fn multipart_field(body: &[u8], boundary: &str, name: &str) -> Option<String> {
    let span = multipart_span(body, boundary, name)?;
    let value = String::from_utf8(body[span.value].to_vec()).ok()?;
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn replace_multipart_field(body: &[u8], boundary: &str, name: &str, value: &str) -> Vec<u8> {
    match multipart_span(body, boundary, name) {
        Some(span) => {
            let mut out = Vec::with_capacity(body.len() + value.len());
            out.extend_from_slice(&body[..span.value.start]);
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(&body[span.value.end..]);
            out
        }
        None => body.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDARY: &str = "----form7";

    fn transcription_form(model: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\nContent-Type: audio/wav\r\n\r\n").as_bytes());
        body.extend_from_slice(b"RIFF\x00\x01name=\"model\"\r\n--not-a-delimiter");
        body.extend_from_slice(format!("\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{model}\r\n").as_bytes());
        body.extend_from_slice(format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"language\"\r\n\r\nen\r\n--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    #[test]
    fn a_transcription_form_is_routed_by_its_model_field() {
        let body = transcription_form("assistant-transcribe");
        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let request = route_media_request(&body, &content_type).unwrap();
        assert_eq!(request.model, "assistant-transcribe");

        let sent = request.upstream_body(&body, "whisper-small").unwrap();
        let expected = transcription_form("whisper-small");
        assert_eq!(
            sent, expected,
            "only the model field changes; the audio is untouched"
        );
    }

    #[test]
    fn a_quoted_boundary_is_understood() {
        let body = transcription_form("m");
        let request = route_media_request(
            &body,
            &format!("multipart/form-data; boundary=\"{BOUNDARY}\""),
        )
        .unwrap();
        assert_eq!(request.model, "m");
    }

    #[test]
    fn a_json_request_keeps_every_other_field() {
        let body = br#"{"model":"assistant-images","prompt":"a red bicycle","size":"1024x1024","response_format":"b64_json","n":1}"#;
        let request = route_media_request(body, "application/json").unwrap();
        assert_eq!(request.model, "assistant-images");
        let sent: Value =
            serde_json::from_slice(&request.upstream_body(body, "flux-schnell").unwrap()).unwrap();
        assert_eq!(sent["model"], "flux-schnell");
        assert_eq!(sent["prompt"], "a red bicycle");
        assert_eq!(sent["response_format"], "b64_json");
        assert_eq!(sent["size"], "1024x1024");
    }

    #[test]
    fn a_video_id_names_its_model() {
        assert_eq!(
            video_model("video_YXNzaXN0YW50LXZpZGVvL2pvYl8x").unwrap(),
            "assistant-video"
        );
        for id in [
            "YXNzaXN0YW50LXZpZGVvL2pvYl8x",
            "video_!!",
            "video_bm8tam9i",
            "video_L2pvYg",
        ] {
            assert!(video_model(id).is_err(), "{id}");
        }
    }

    #[test]
    fn a_request_without_a_model_is_refused() {
        assert!(route_media_request(br#"{"input":"hi"}"#, "application/json").is_err());
        let form = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nx\r\n--{BOUNDARY}--\r\n");
        assert!(route_media_request(
            form.as_bytes(),
            &format!("multipart/form-data; boundary={BOUNDARY}")
        )
        .is_err());
        assert!(route_media_request(form.as_bytes(), "multipart/form-data").is_err());
    }
}
