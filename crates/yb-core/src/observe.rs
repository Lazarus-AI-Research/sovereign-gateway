//! The observability export seam.
//!
//! [`Observer`] receives one call per served turn with the same
//! [`TelemetryRecord`] that is written to the store — structured metadata only
//! (ids, models, tokens, cost, latency, status; never request/response bodies).
//! The concrete exporter (`yb-otel`) aggregates metrics and forwards per-turn
//! events/spans; [`NullObserver`] is the default no-op when telemetry is off.

use crate::model::TelemetryRecord;

/// A non-blocking observability sink. `turn` must enqueue/aggregate and return
/// immediately; it must never fail or slow the request path.
pub trait Observer: Send + Sync {
    /// Observe one served turn.
    fn turn(&self, rec: &TelemetryRecord);

    /// Render current metric aggregates in Prometheus text exposition format,
    /// or `None` when this observer does not serve a scrape endpoint.
    fn prometheus(&self) -> Option<String> {
        None
    }
}

/// The default sink: drops everything.
pub struct NullObserver;

impl Observer for NullObserver {
    fn turn(&self, _rec: &TelemetryRecord) {}
}
