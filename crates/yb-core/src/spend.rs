//! Spend tracking and budget enforcement types.

use crate::ids::{Id, Micros, Timestamp};
use chrono::{Datelike, TimeZone, Utc};
use serde::{Deserialize, Serialize};

/// What a budget/spend row is attributed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Key,
    User,
    Team,
}

impl SubjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectType::Key => "key",
            SubjectType::User => "user",
            SubjectType::Team => "team",
        }
    }
    pub fn parse(s: &str) -> crate::Result<Self> {
        Ok(match s {
            "key" => SubjectType::Key,
            "user" => SubjectType::User,
            "team" => SubjectType::Team,
            o => return Err(crate::Error::BadRequest(format!("bad subject type: {o}"))),
        })
    }
}

/// A budget period. `Total` is all-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Period {
    Day,
    Week,
    Month,
    Total,
}

impl Period {
    pub fn as_str(self) -> &'static str {
        match self {
            Period::Day => "day",
            Period::Week => "week",
            Period::Month => "month",
            Period::Total => "total",
        }
    }
    pub fn parse(s: &str) -> crate::Result<Self> {
        Ok(match s {
            "day" => Period::Day,
            "week" => Period::Week,
            "month" => Period::Month,
            "total" => Period::Total,
            o => return Err(crate::Error::BadRequest(format!("bad period: {o}"))),
        })
    }

    /// The UTC-truncated start of the period bucket containing `at`.
    pub fn bucket_start(self, at: Timestamp) -> Timestamp {
        match self {
            Period::Total => Utc.timestamp_opt(0, 0).single().unwrap(),
            Period::Day => Utc
                .with_ymd_and_hms(at.year(), at.month(), at.day(), 0, 0, 0)
                .single()
                .unwrap(),
            Period::Month => Utc
                .with_ymd_and_hms(at.year(), at.month(), 1, 0, 0, 0)
                .single()
                .unwrap(),
            Period::Week => {
                // ISO week: Monday 00:00 UTC.
                let weekday = at.weekday().num_days_from_monday() as i64;
                let midnight = Utc
                    .with_ymd_and_hms(at.year(), at.month(), at.day(), 0, 0, 0)
                    .single()
                    .unwrap();
                midnight - chrono::Duration::days(weekday)
            }
        }
    }
}

/// What to do when a budget is breached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetAction {
    Block,
    Alert,
}

/// A configured spend cap for a subject over a period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub id: Id,
    pub subject_type: SubjectType,
    pub subject_id: String,
    pub period: Period,
    pub hard_limit_micros: Micros,
    pub soft_limit_micros: Option<Micros>,
    pub action: BudgetAction,
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub deleted_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreachKind {
    None,
    Soft,
    Hard,
}

/// The result of a budget check.
#[derive(Debug, Clone)]
pub struct BudgetDecision {
    pub allowed: bool,
    pub breach: BreachKind,
    pub spent_micros: Micros,
    pub limit_micros: Micros,
    pub period: Period,
    pub period_reset_at: Timestamp,
}

impl BudgetDecision {
    pub fn ok() -> Self {
        BudgetDecision {
            allowed: true,
            breach: BreachKind::None,
            spent_micros: 0,
            limit_micros: 0,
            period: Period::Total,
            period_reset_at: Utc.timestamp_opt(0, 0).single().unwrap(),
        }
    }
}

/// An atomic increment to a spend rollup row.
#[derive(Debug, Clone)]
pub struct RollupDelta {
    pub subject_type: SubjectType,
    pub subject_id: String,
    pub period: Period,
    pub period_start: Timestamp,
    pub spend_micros: Micros,
    pub request_count: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

/// A spend report row for the admin API.
#[derive(Debug, Clone, Serialize)]
pub struct SpendRow {
    pub subject_type: String,
    pub subject_id: String,
    pub period: String,
    pub period_start: Timestamp,
    pub spend_micros: Micros,
    pub request_count: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn week_bucket_is_monday() {
        // 2026-06-29 is a Monday.
        let at = Utc.with_ymd_and_hms(2026, 6, 29, 13, 0, 0).single().unwrap();
        let start = Period::Week.bucket_start(at);
        assert_eq!(start.weekday(), chrono::Weekday::Mon);
        assert_eq!(
            start,
            Utc.with_ymd_and_hms(2026, 6, 29, 0, 0, 0).single().unwrap()
        );
    }
}
