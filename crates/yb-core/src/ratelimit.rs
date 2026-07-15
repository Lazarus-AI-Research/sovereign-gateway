//! Rate limiting: a pure token-bucket plus an in-process `Limiter`.
//!
//! RPM and concurrency are checked preflight; TPM is charged in arrears at the
//! post-turn usage seam. On any store/lookup error the caller should fail *open*
//! (rate limits protect, they don't bill).

use crate::ids::Timestamp;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Resolved per-subject limits. Zero means "unlimited".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    pub rpm: i64,
    pub tpm: i64,
    pub max_concurrent: i64,
}

impl Limits {
    pub fn is_unlimited(&self) -> bool {
        self.rpm == 0 && self.tpm == 0 && self.max_concurrent == 0
    }
}

/// The outcome of a preflight rate-limit check.
#[derive(Debug, Clone)]
pub struct RateDecision {
    pub allowed: bool,
    pub retry_after: Duration,
    pub reason: &'static str,
}

impl RateDecision {
    pub fn allow() -> Self {
        RateDecision {
            allowed: true,
            retry_after: Duration::ZERO,
            reason: "",
        }
    }
}

/// A single lazy-refill token bucket.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    capacity: f64,
    /// tokens added per second
    refill_per_sec: f64,
    last: Timestamp,
}

impl Bucket {
    fn new(capacity: f64, window: Duration, now: Timestamp) -> Self {
        let refill_per_sec = capacity / window.as_secs_f64().max(0.001);
        Bucket {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last: now,
        }
    }

    fn refill(&mut self, now: Timestamp) {
        let elapsed = (now - self.last).num_milliseconds().max(0) as f64 / 1000.0;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
    }

    fn take(&mut self, cost: f64, now: Timestamp) -> (bool, Duration) {
        self.refill(now);
        if self.tokens >= cost {
            self.tokens -= cost;
            (true, Duration::ZERO)
        } else {
            let deficit = cost - self.tokens;
            let secs = deficit / self.refill_per_sec.max(1e-9);
            (false, Duration::from_secs_f64(secs))
        }
    }
}

#[derive(Default)]
struct Scope {
    rpm: Option<Bucket>,
    tpm: Option<Bucket>,
    in_flight: i64,
}

type Scopes = Arc<Mutex<HashMap<String, Scope>>>;

/// An in-process rate limiter keyed by an opaque scope string (typically the
/// api-key id, falling back to user/installation). Exact for a single replica.
pub struct Limiter {
    window: Duration,
    scopes: Scopes,
}

impl Limiter {
    pub fn new(window: Duration) -> Self {
        Limiter {
            window,
            scopes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Preflight RPM + concurrency. Returns a guard that releases the concurrency
    /// slot on drop.
    pub fn check(
        &self,
        scope: &str,
        limits: Limits,
        now: Timestamp,
    ) -> (RateDecision, ConcurrencyGuard) {
        if limits.is_unlimited() {
            return (RateDecision::allow(), ConcurrencyGuard::noop());
        }
        let mut map = self.scopes.lock().unwrap();
        let entry = map.entry(scope.to_string()).or_default();

        if limits.max_concurrent > 0 && entry.in_flight >= limits.max_concurrent {
            return (
                RateDecision {
                    allowed: false,
                    retry_after: Duration::from_secs(1),
                    reason: "concurrency",
                },
                ConcurrencyGuard::noop(),
            );
        }

        if limits.rpm > 0 {
            let bucket = entry
                .rpm
                .get_or_insert_with(|| Bucket::new(limits.rpm as f64, self.window, now));
            bucket.capacity = limits.rpm as f64;
            let (ok, retry) = bucket.take(1.0, now);
            if !ok {
                return (
                    RateDecision {
                        allowed: false,
                        retry_after: retry,
                        reason: "rpm",
                    },
                    ConcurrencyGuard::noop(),
                );
            }
        }

        entry.in_flight += 1;
        let guard = ConcurrencyGuard {
            scopes: Some(self.scopes.clone()),
            scope: scope.to_string(),
        };
        (RateDecision::allow(), guard)
    }

    /// Charge token usage in arrears (TPM). Returns whether the subject is now
    /// over budget — the *next* request will be rejected, this one is served.
    pub fn charge_tokens(&self, scope: &str, limits: Limits, tokens: i64, now: Timestamp) -> bool {
        if limits.tpm <= 0 {
            return false;
        }
        let mut map = self.scopes.lock().unwrap();
        let entry = map.entry(scope.to_string()).or_default();
        let bucket = entry
            .tpm
            .get_or_insert_with(|| Bucket::new(limits.tpm as f64, self.window, now));
        bucket.capacity = limits.tpm as f64;
        let (ok, _) = bucket.take(tokens as f64, now);
        !ok
    }

    /// Preflight TPM: reject if the bucket is already empty from prior arrears.
    pub fn tpm_exhausted(&self, scope: &str, limits: Limits, now: Timestamp) -> (bool, Duration) {
        if limits.tpm <= 0 {
            return (false, Duration::ZERO);
        }
        let mut map = self.scopes.lock().unwrap();
        let entry = map.entry(scope.to_string()).or_default();
        let bucket = entry
            .tpm
            .get_or_insert_with(|| Bucket::new(limits.tpm as f64, self.window, now));
        bucket.refill(now);
        if bucket.tokens < 1.0 {
            let secs = 1.0 / bucket.refill_per_sec.max(1e-9);
            (true, Duration::from_secs_f64(secs).max(Duration::from_secs(1)))
        } else {
            (false, Duration::ZERO)
        }
    }
}

/// Releases a concurrency slot when dropped.
pub struct ConcurrencyGuard {
    scopes: Option<Scopes>,
    scope: String,
}

impl ConcurrencyGuard {
    fn noop() -> Self {
        ConcurrencyGuard {
            scopes: None,
            scope: String::new(),
        }
    }
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        if let Some(scopes) = &self.scopes {
            if let Ok(mut map) = scopes.lock() {
                if let Some(entry) = map.get_mut(&self.scope) {
                    entry.in_flight = (entry.in_flight - 1).max(0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn rpm_blocks_after_capacity() {
        let lim = Limiter::new(Duration::from_secs(60));
        let limits = Limits {
            rpm: 2,
            tpm: 0,
            max_concurrent: 0,
        };
        let now = Utc::now();
        assert!(lim.check("k", limits, now).0.allowed);
        assert!(lim.check("k", limits, now).0.allowed);
        let (d, _g) = lim.check("k", limits, now);
        assert!(!d.allowed);
        assert_eq!(d.reason, "rpm");
    }

    #[test]
    fn concurrency_guard_releases() {
        let lim = Limiter::new(Duration::from_secs(60));
        let limits = Limits {
            rpm: 0,
            tpm: 0,
            max_concurrent: 1,
        };
        let now = Utc::now();
        {
            let (d, _g) = lim.check("k", limits, now);
            assert!(d.allowed);
            let (d2, _g2) = lim.check("k", limits, now);
            assert!(!d2.allowed);
            assert_eq!(d2.reason, "concurrency");
        }
        assert!(lim.check("k", limits, now).0.allowed);
    }
}
