//! Small dialect-agnostic helpers shared by both store backends.
//!
//! [`AccessPolicy`] columns are persisted as JSON text in both SQLite and
//! Postgres, so the encode/decode helpers live here once.

use yb_core::{AccessPolicy, Error, Result, Timestamp};

/// Encode an [`AccessPolicy`] as a JSON object string (defaults to `{}`).
pub(crate) fn enc_access(a: &AccessPolicy) -> String {
    serde_json::to_string(a).unwrap_or_else(|_| "{}".to_string())
}

/// Decode an [`AccessPolicy`] from JSON (unrestricted on garbage/empty).
pub(crate) fn dec_access(s: &str) -> AccessPolicy {
    serde_json::from_str(s).unwrap_or_default()
}

/// Parse an RFC3339 timestamp string into a UTC [`Timestamp`].
pub(crate) fn parse_ts(s: &str) -> Result<Timestamp> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Storage(format!("invalid timestamp {s:?}: {e}")))
}

/// Parse an optional RFC3339 timestamp string.
pub(crate) fn parse_ts_opt(s: Option<String>) -> Result<Option<Timestamp>> {
    match s {
        Some(s) => Ok(Some(parse_ts(&s)?)),
        None => Ok(None),
    }
}

/// Map any error carrying a `Display` impl onto [`Error::Storage`].
pub(crate) fn storage_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Storage(e.to_string())
}
