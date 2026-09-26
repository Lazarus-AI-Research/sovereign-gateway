//! Request capture: whether the prompts and responses that pass through the
//! gateway are kept, and in what form (off unless an operator turns it on).

use serde::{Deserialize, Serialize};

/// How much of a captured body is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Redaction {
    /// Personal data recognised by its shape is replaced by a marker.
    #[default]
    Patterns,
    /// Only the turn's metadata is kept, never its text.
    MetadataOnly,
    /// Bodies are kept as they came.
    None,
}

impl Redaction {
    pub fn as_str(self) -> &'static str {
        match self {
            Redaction::Patterns => "patterns",
            Redaction::MetadataOnly => "metadata_only",
            Redaction::None => "none",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "patterns" => Some(Redaction::Patterns),
            "metadata_only" => Some(Redaction::MetadataOnly),
            "none" => Some(Redaction::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePolicy {
    pub enabled: bool,
    pub redaction: Redaction,
    /// Captures older than this are deleted; 0 keeps them until deleted.
    pub retention_days: u32,
}

impl Default for CapturePolicy {
    fn default() -> Self {
        CapturePolicy {
            enabled: false,
            redaction: Redaction::Patterns,
            retention_days: 30,
        }
    }
}
