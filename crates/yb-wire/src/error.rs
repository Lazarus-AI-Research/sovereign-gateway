//! The standalone error type for yb-wire.
//!
//! yb-wire MUST NOT depend on yb-core. At the gateway boundary a `WireError` is
//! mapped onto `yb_core::Error::Wire(_)`; here we keep our own `thiserror` enum.

/// The crate-wide result alias for wire translation.
pub type Result<T> = std::result::Result<T, WireError>;

/// An error raised while parsing or emitting a wire format.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The bytes were not valid JSON, or did not match the expected shape.
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),

    /// A required field was absent.
    #[error("missing field: {0}")]
    MissingField(String),

    /// A field held a value we cannot represent (wrong type, unknown enum, …).
    #[error("invalid field {field}: {reason}")]
    InvalidField { field: String, reason: String },

    /// The request was structurally valid JSON but not a valid request body.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The response was structurally valid JSON but not a valid response body.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// A feature of the source format has no representation in the target.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl WireError {
    /// Convenience constructor for [`WireError::MissingField`].
    pub fn missing(field: impl Into<String>) -> Self {
        WireError::MissingField(field.into())
    }

    /// Convenience constructor for [`WireError::InvalidField`].
    pub fn invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        WireError::InvalidField {
            field: field.into(),
            reason: reason.into(),
        }
    }
}
