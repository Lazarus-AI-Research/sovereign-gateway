//! Error and Result types shared across all gateway crates.

use std::time::Duration;

/// The crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// A domain error. Variants map cleanly onto HTTP status codes at the
/// presentation boundary (see `Error::http_status`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("conflict: {0}")]
    Conflict(String),

    /// Hard budget breach — over the spend cap. Maps to 429 (quota exceeded),
    /// the customary status for a configured spend/usage cap.
    #[error("budget exceeded: {0}")]
    BudgetExceeded(String),

    /// Rate limited. Maps to 429 with a `Retry-After` header.
    #[error("rate limited: retry after {retry_after:?}")]
    RateLimited { retry_after: Duration, reason: String },

    /// No deployment can serve the request after access/exclusion filtering.
    /// Distinct from an upstream outage — this is a 4xx client/config error.
    #[error("no eligible provider for model {0}")]
    NoEligibleProvider(String),

    /// An upstream provider returned an error status.
    #[error("upstream {provider} returned {status}: {message}")]
    Upstream {
        provider: String,
        status: u16,
        message: String,
    },

    #[error("storage error: {0}")]
    Storage(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("wire translation error: {0}")]
    Wire(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Map a domain error onto an HTTP status code.
    pub fn http_status(&self) -> u16 {
        match self {
            Error::NotFound(_) => 404,
            Error::BadRequest(_) => 400,
            Error::Unauthorized(_) => 401,
            Error::Forbidden(_) => 403,
            Error::Conflict(_) => 409,
            Error::BudgetExceeded(_) => 429,
            Error::RateLimited { .. } => 429,
            Error::NoEligibleProvider(_) => 400,
            Error::Upstream { status, .. } => *status,
            // Wire errors overwhelmingly stem from a client body the
            // translators cannot represent (unknown fields/roles, token
            // arrays, unsupported content): a client error, not a server one.
            Error::Wire(_) => 400,
            Error::Storage(_) | Error::Crypto(_) | Error::Config(_) | Error::Internal(_) => 500,
        }
    }

    /// A stable machine-readable error code for API envelopes.
    pub fn code(&self) -> &'static str {
        match self {
            Error::NotFound(_) => "not_found",
            Error::BadRequest(_) => "bad_request",
            Error::Unauthorized(_) => "unauthorized",
            Error::Forbidden(_) => "forbidden",
            Error::Conflict(_) => "conflict",
            Error::BudgetExceeded(_) => "budget_exceeded",
            Error::RateLimited { .. } => "rate_limited",
            Error::NoEligibleProvider(_) => "no_eligible_provider",
            Error::Upstream { .. } => "upstream_error",
            Error::Storage(_) => "storage_error",
            Error::Crypto(_) => "crypto_error",
            Error::Config(_) => "config_error",
            Error::Wire(_) => "wire_error",
            Error::Internal(_) => "internal_error",
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Wire(e.to_string())
    }
}
