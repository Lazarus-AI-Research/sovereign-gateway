//! Internal helpers shared by the per-format modules. Not part of the public
//! API. Keeping these here avoids copy-pasting the same JSON-walking and
//! data-URL plumbing into every format module.

use crate::error::{Result, WireError};
use serde_json::{Map, Value};

/// Borrow an object field as a `&str`, or `None` if absent / not a string.
pub(crate) fn opt_str<'a>(obj: &'a Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

/// Borrow an object field as an array slice, or `None`.
pub(crate) fn opt_arr<'a>(obj: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    obj.get(key).and_then(Value::as_array)
}

/// Require an object field as a `&str`.
pub(crate) fn req_str<'a>(obj: &'a Value, key: &str) -> Result<&'a str> {
    opt_str(obj, key).ok_or_else(|| WireError::missing(key))
}

/// Extract a `u32` from a numeric field.
pub(crate) fn opt_u32(obj: &Value, key: &str) -> Option<u32> {
    obj.get(key).and_then(Value::as_u64).map(|n| n as u32)
}

/// Extract an `f32` from a numeric field.
pub(crate) fn opt_f32(obj: &Value, key: &str) -> Option<f32> {
    obj.get(key).and_then(Value::as_f64).map(|n| n as f32)
}

/// Extract a `bool` field, defaulting to `false`.
pub(crate) fn opt_bool(obj: &Value, key: &str) -> bool {
    obj.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Collect a `Vec<String>` from a JSON array of strings.
pub(crate) fn str_vec(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Split a `data:<mime>;base64,<data>` URL into its parts. Returns
/// `(media_type, base64_data)` when the URL is a base64 data URL.
pub(crate) fn parse_data_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let media_type = meta.strip_suffix(";base64").unwrap_or(meta);
    Some((media_type.to_string(), data.to_string()))
}

/// Build a `data:<mime>;base64,<data>` URL from inline image parts.
pub(crate) fn build_data_url(media_type: Option<&str>, data: &str) -> String {
    let mt = media_type.unwrap_or("image/png");
    format!("data:{mt};base64,{data}")
}

/// Insert `key => value` into a map only when the option is `Some`.
pub(crate) fn insert_opt<T: Into<Value>>(map: &mut Map<String, Value>, key: &str, value: Option<T>) {
    if let Some(v) = value {
        map.insert(key.to_string(), v.into());
    }
}
