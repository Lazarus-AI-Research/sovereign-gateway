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
    pub installation_id: String,
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
    /// The key the turn came with and its owner, so a capture can be sorted
    /// by who asked.
    pub api_key_id: Option<String>,
    pub user_id: Option<String>,
    /// What the caller said the turn belongs to, as a JSON object from its
    /// `x-gateway-tags` header (a space, a conversation).
    pub tags: Option<String>,
    /// How the bodies were redacted before storage (see
    /// [`crate::Redaction`]).
    pub redaction: String,
}

/// Which captured turns an export takes: those in `[from, to)`, narrowed by
/// any of the rest that are not empty.
#[derive(Debug, Clone, Default)]
pub struct CaptureFilter {
    pub from: Option<Timestamp>,
    pub to: Option<Timestamp>,
    pub models: Vec<String>,
    pub api_key_ids: Vec<String>,
    /// `(key, value)` pairs a turn's tags must all carry.
    pub tags: Vec<(String, String)>,
    pub redaction: Option<String>,
}

/// One captured turn as an export reads it back.
#[derive(Debug, Clone)]
pub struct CapturedTurn {
    pub ts: Timestamp,
    pub request_id: String,
    pub surface: String,
    pub requested_model: String,
    pub api_key_id: Option<String>,
    pub user_id: Option<String>,
    pub tags: Option<String>,
    pub redaction: String,
    pub request_body: Vec<u8>,
    pub response_body: Vec<u8>,
}

/// A non-blocking sink. `log` must enqueue and return immediately; it must never
/// block the request path. Dropping on a full queue is acceptable (and counted).
pub trait RequestLogger: Send + Sync {
    fn log(&self, record: RequestLogRecord);

    /// Whether and how turns are captured from now on.
    fn apply_policy(&self, _policy: &crate::CapturePolicy) {}

    /// The policy in force; off for a logger that keeps nothing.
    fn policy(&self) -> crate::CapturePolicy {
        crate::CapturePolicy {
            enabled: false,
            ..Default::default()
        }
    }

    /// Whether this logger can capture at all; one that discards everything
    /// cannot be turned on.
    fn captures(&self) -> bool {
        false
    }

    /// The successful captured turns the filter takes, oldest first.
    fn export(&self, _filter: &CaptureFilter) -> crate::Result<Vec<CapturedTurn>> {
        Ok(Vec::new())
    }
}

/// A logger that discards everything (the default when capture is disabled).
pub struct NullLogger;

impl RequestLogger for NullLogger {
    fn log(&self, _record: RequestLogRecord) {}
}
