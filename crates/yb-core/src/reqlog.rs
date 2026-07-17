//! Request/response logging contract for training-data capture.
//!
//! The concrete sink (DuckDB WAL + compressed shards) lives in `yb-reqlog`; the
//! gateway only ever sees this trait, so the inner ring never imports DuckDB.

use crate::ids::Timestamp;

/// One captured turn: the redacted inbound request and client-native response.
#[derive(Debug, Clone)]
pub struct RequestLogRecord {
    pub ts: Timestamp,
    pub request_id: String,
    pub trace_id: Option<String>,
    /// `anthropic` | `openai_chat` | `openai_responses` | `gemini`.
    pub surface: String,
    pub requested_model: String,
    pub decision_model: String,
    pub decision_provider: String,
    pub upstream_status: i32,
    pub is_error: bool,
    pub request_bytes: i64,
    pub response_bytes: i64,
    pub response_truncated: bool,
    /// Redacted request body (client-native bytes).
    pub request_body: Vec<u8>,
    /// The response as normalized IR (`ChatResponse` serialized to JSON) — one
    /// uniform schema across all surfaces, streaming or buffered. Empty when
    /// truncated/dropped.
    pub response_body: Vec<u8>,
}

/// A non-blocking sink. `log` must enqueue and return immediately; it must never
/// block the request path. Dropping on a full queue is acceptable (and counted).
pub trait RequestLogger: Send + Sync {
    fn log(&self, record: RequestLogRecord);
}

/// A logger that discards everything (the default when capture is disabled).
pub struct NullLogger;

impl RequestLogger for NullLogger {
    fn log(&self, _record: RequestLogRecord) {}
}
