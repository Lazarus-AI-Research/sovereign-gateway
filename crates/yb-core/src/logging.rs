//! How much the gateway logs, which an operator changes at runtime.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "error" => Some(LogLevel::Error),
            "warn" => Some(LogLevel::Warn),
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            _ => None,
        }
    }
}

/// Changes the level of the running process's logging.
pub trait LogControl: Send + Sync {
    fn apply(&self, level: LogLevel) -> crate::Result<()>;

    /// Back to the level the process started with, before any was set.
    fn reset(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// For a process whose logging is fixed, and for tests.
pub struct FixedLogging;

impl LogControl for FixedLogging {
    fn apply(&self, _level: LogLevel) -> crate::Result<()> {
        Ok(())
    }
}
