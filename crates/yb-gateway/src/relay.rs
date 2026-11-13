//! Same-shape relay: a request in a shape its provider serves natively goes
//! upstream as the client sent it, and the answer comes back as the provider
//! sent it.
//!
//! Only two things in the body change. The public model id becomes the
//! deployment's upstream model id, spliced into the original bytes so every
//! other byte (key order, number spelling, whitespace) is what the client
//! wrote. And a streaming Chat Completions request that did not ask for usage
//! is made to ask for it, so the turn can be metered; the one usage chunk that
//! buys is taken back out of the stream before the client sees it.
//!
//! Gemini carries the model and the stream switch in the URL; the server lifts
//! both into the body for routing, and they are removed again here.

use yb_core::{Error, Result, WireFormat};

/// The upstream body for a same-shape relay of `body`.
///
/// `ask_usage`: add `stream_options.include_usage = true` (Chat Completions
/// streams only; see [`is_usage_only_chunk`] for the matching filter).
pub fn relay_body(
    surface: WireFormat,
    body: &[u8],
    upstream_model: &str,
    ask_usage: bool,
) -> Result<Vec<u8>> {
    let model = serde_json::to_vec(upstream_model).map_err(|e| Error::Internal(e.to_string()))?;
    match surface {
        WireFormat::Gemini => {
            let mut v: serde_json::Value = serde_json::from_slice(body)
                .map_err(|e| Error::BadRequest(format!("invalid JSON body: {e}")))?;
            let obj = v
                .as_object_mut()
                .ok_or_else(|| Error::BadRequest("body is not a JSON object".into()))?;
            obj.remove("model");
            obj.remove("stream");
            serde_json::to_vec(&v).map_err(|e| Error::Internal(e.to_string()))
        }
        _ => {
            let mut out = set_top_level(body, "model", &model)?;
            if ask_usage {
                let options = match top_level_span(&out, "stream_options")? {
                    Some((a, b)) => {
                        let mut o: serde_json::Value = serde_json::from_slice(&out[a..b])
                            .map_err(|e| Error::BadRequest(format!("stream_options: {e}")))?;
                        match o.as_object_mut() {
                            Some(m) => {
                                m.insert("include_usage".into(), true.into());
                            }
                            None => o = serde_json::json!({"include_usage": true}),
                        }
                        serde_json::to_vec(&o).map_err(|e| Error::Internal(e.to_string()))?
                    }
                    None => br#"{"include_usage":true}"#.to_vec(),
                };
                out = set_top_level(&out, "stream_options", &options)?;
            }
            Ok(out)
        }
    }
}

/// Whether an SSE frame is the trailing usage-only Chat Completions chunk
/// (`"choices": []` with `usage`), which a relay that asked for usage on the
/// client's behalf drops.
pub fn is_usage_only_chunk(frame: &[u8]) -> bool {
    let text = String::from_utf8_lossy(frame);
    let mut data = String::new();
    for line in text.lines() {
        if let Some(d) = line.strip_prefix("data:") {
            data.push_str(d.trim_start());
        }
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(data.trim()) else {
        return false;
    };
    v.get("usage").is_some_and(|u| !u.is_null())
        && v.get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|c| c.is_empty())
}

/// `body` with the top-level `key` set to the JSON text `value`: the existing
/// value's bytes are replaced in place, or the member is added first.
fn set_top_level(body: &[u8], key: &str, value: &[u8]) -> Result<Vec<u8>> {
    if let Some((a, b)) = top_level_span(body, key)? {
        let mut out = Vec::with_capacity(body.len() + value.len());
        out.extend_from_slice(&body[..a]);
        out.extend_from_slice(value);
        out.extend_from_slice(&body[b..]);
        return Ok(out);
    }
    let open = body
        .iter()
        .position(|&c| c == b'{')
        .ok_or_else(|| Error::BadRequest("body is not a JSON object".into()))?;
    let empty = body[open + 1..]
        .iter()
        .find(|c| !c.is_ascii_whitespace())
        .is_some_and(|&c| c == b'}');
    let mut out = Vec::with_capacity(body.len() + key.len() + value.len() + 4);
    out.extend_from_slice(&body[..=open]);
    out.extend_from_slice(&serde_json::to_vec(key).map_err(|e| Error::Internal(e.to_string()))?);
    out.push(b':');
    out.extend_from_slice(value);
    if !empty {
        out.push(b',');
    }
    out.extend_from_slice(&body[open + 1..]);
    Ok(out)
}

/// The byte span of the value of the top-level member `key` (the last one,
/// as a JSON parser keeps it), or `None` when the object has no such member.
/// The body must be one JSON object.
fn top_level_span(body: &[u8], key: &str) -> Result<Option<(usize, usize)>> {
    let bad = || Error::BadRequest("body is not a JSON object".into());
    // Validate first: the scanner below assumes well-formed JSON.
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| Error::BadRequest(format!("invalid JSON body: {e}")))?;
    if !v.is_object() {
        return Err(bad());
    }
    let mut i = skip_ws(body, 0);
    if body.get(i) != Some(&b'{') {
        return Err(bad());
    }
    i += 1;
    let mut found = None;
    loop {
        i = skip_ws(body, i);
        match body.get(i) {
            Some(b'}') | None => return Ok(found),
            Some(b',') => {
                i += 1;
                continue;
            }
            Some(b'"') => {}
            Some(_) => return Err(bad()),
        }
        let key_end = string_end(body, i);
        let name: String = serde_json::from_slice(&body[i..key_end]).map_err(|_| bad())?;
        i = skip_ws(body, key_end);
        if body.get(i) != Some(&b':') {
            return Err(bad());
        }
        let start = skip_ws(body, i + 1);
        let end = value_end(body, start);
        if name == key {
            found = Some((start, end));
        }
        i = end;
    }
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// One past the closing quote of the string starting at `i`.
fn string_end(b: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

/// One past the end of the (well-formed) JSON value starting at `i`.
fn value_end(b: &[u8], i: usize) -> usize {
    match b.get(i) {
        Some(b'"') => string_end(b, i),
        Some(b'{') | Some(b'[') => {
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = string_end(b, j);
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return j + 1;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            b.len()
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']') && !b[j].is_ascii_whitespace()
            {
                j += 1;
            }
            j
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_model_id_changes() {
        let body = br#"{ "messages":[{"role":"user","content":"h\u00e9 \"model\": x"}],
  "model" : "public", "max_tokens":1e3, "tools":[{"z":1,"a":2}] }"#;
        let out = relay_body(WireFormat::Anthropic, body, "up/stream", false).unwrap();
        let want = br#"{ "messages":[{"role":"user","content":"h\u00e9 \"model\": x"}],
  "model" : "up/stream", "max_tokens":1e3, "tools":[{"z":1,"a":2}] }"#;
        assert_eq!(
            String::from_utf8(out).unwrap(),
            String::from_utf8(want.to_vec()).unwrap()
        );
    }

    #[test]
    fn a_missing_model_is_added_first() {
        let out = relay_body(WireFormat::OpenaiChat, br#"{"messages":[]}"#, "m", false).unwrap();
        assert_eq!(out, br#"{"model":"m","messages":[]}"#);
        let out = relay_body(WireFormat::OpenaiChat, b"{ }", "m", false).unwrap();
        assert_eq!(out, br#"{"model":"m" }"#);
    }

    #[test]
    fn a_chat_stream_is_made_to_report_usage() {
        let out = relay_body(
            WireFormat::OpenaiChat,
            br#"{"model":"p","stream":true,"messages":[]}"#,
            "m",
            true,
        )
        .unwrap();
        assert_eq!(
            out,
            br#"{"stream_options":{"include_usage":true},"model":"m","stream":true,"messages":[]}"#
        );
        let out = relay_body(
            WireFormat::OpenaiChat,
            br#"{"model":"p","stream_options":{"include_usage":false},"stream":true}"#,
            "m",
            true,
        )
        .unwrap();
        assert_eq!(
            out,
            br#"{"model":"m","stream_options":{"include_usage":true},"stream":true}"#
        );
    }

    #[test]
    fn gemini_loses_the_url_borne_fields() {
        let out = relay_body(
            WireFormat::Gemini,
            br#"{"model":"g","stream":true,"contents":[]}"#,
            "m",
            false,
        )
        .unwrap();
        assert_eq!(out, br#"{"contents":[]}"#);
    }

    #[test]
    fn rejects_what_is_not_an_object() {
        assert!(relay_body(WireFormat::OpenaiChat, b"[1]", "m", false).is_err());
        assert!(relay_body(WireFormat::OpenaiChat, b"{\"a\":", "m", false).is_err());
    }

    #[test]
    fn recognises_the_usage_only_chunk() {
        assert!(is_usage_only_chunk(
            b"data: {\"id\":\"x\",\"choices\":[],\"usage\":{\"prompt_tokens\":3}}\n\n"
        ));
        assert!(!is_usage_only_chunk(
            b"data: {\"choices\":[{\"index\":0,\"delta\":{}}],\"usage\":null}\n\n"
        ));
        assert!(!is_usage_only_chunk(b"data: [DONE]\n\n"));
    }
}
