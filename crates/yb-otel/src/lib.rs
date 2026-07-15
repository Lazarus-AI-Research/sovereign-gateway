//! # yb-otel
//!
//! OpenTelemetry export for the gateway, implementing `yb_core::Observer`:
//!
//! - **metrics** — aggregated in an in-memory [`registry::Registry`], exported
//!   two ways: OTLP/HTTP JSON push to `{endpoint}/v1/metrics`, and Prometheus
//!   text via [`Observer::prometheus`] (served by yb-server at `GET /metrics`).
//! - **events** — one OTLP log record per served turn (`{endpoint}/v1/logs`),
//!   carrying structured turn metadata (ids, models, tokens, cost, latency,
//!   status) — never request/response bodies.
//! - **spans** — one OTLP span per turn (`{endpoint}/v1/traces`), honoring a
//!   client-supplied 32-hex trace id.
//!
//! OTLP is hand-rolled over HTTP/JSON (see [`otlp`]) so the crate stays on the
//! workspace's existing reqwest/serde stack — no protobuf/grpc dependencies.
//! Push failures are logged and dropped; export never blocks or fails a turn.

pub mod otlp;
pub mod registry;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yb_core::config::TelemetryConfig;
use yb_core::model::TelemetryRecord;
use yb_core::Observer;

use registry::Registry;

/// Cap on buffered per-turn events awaiting a push; oldest are dropped first.
const EVENT_QUEUE_CAP: usize = 8192;

/// The concrete [`Observer`]: aggregates metrics and queues per-turn events;
/// a background task pushes OTLP JSON on an interval when an endpoint is set.
pub struct OtelSink {
    registry: Registry,
    events: Mutex<VecDeque<TelemetryRecord>>,
    prometheus: bool,
    /// Count of events dropped due to a full queue (surfaced in logs).
    dropped: Mutex<u64>,
}

impl OtelSink {
    /// Build the sink and, when `otlp_endpoint` is configured, spawn the push
    /// worker on the current tokio runtime.
    pub fn start(cfg: &TelemetryConfig) -> Arc<Self> {
        let sink = Arc::new(OtelSink {
            registry: Registry::new(),
            events: Mutex::new(VecDeque::new()),
            prometheus: cfg.prometheus,
            dropped: Mutex::new(0),
        });
        if let Some(endpoint) = cfg.otlp_endpoint.clone() {
            let endpoint = endpoint.trim_end_matches('/').to_string();
            let service = cfg.service_name.clone();
            let interval = Duration::from_secs(cfg.push_interval_secs.max(1));
            let sink2 = Arc::clone(&sink);
            tokio::spawn(async move {
                push_worker(sink2, endpoint, service, interval).await;
            });
        }
        sink
    }

    /// Drain up to the full queue of pending events.
    fn drain_events(&self) -> Vec<TelemetryRecord> {
        let mut q = self.events.lock().unwrap();
        q.drain(..).collect()
    }
}

impl Observer for OtelSink {
    fn turn(&self, rec: &TelemetryRecord) {
        self.registry.record(rec);
        let mut q = self.events.lock().unwrap();
        if q.len() >= EVENT_QUEUE_CAP {
            q.pop_front();
            *self.dropped.lock().unwrap() += 1;
        }
        q.push_back(rec.clone());
    }

    fn prometheus(&self) -> Option<String> {
        self.prometheus.then(|| self.registry.render_prometheus())
    }
}

/// Periodically push metrics/events/spans as OTLP JSON. Best-effort: failures
/// are logged; events from a failed push are dropped (metrics are cumulative,
/// so nothing is lost there).
async fn push_worker(sink: Arc<OtelSink>, endpoint: String, service: String, interval: Duration) {
    let client = reqwest::Client::new();
    let start_ns = yb_core::now().timestamp_nanos_opt().unwrap_or(0).to_string();
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;

        let dropped = std::mem::take(&mut *sink.dropped.lock().unwrap());
        if dropped > 0 {
            tracing::warn!(dropped, "otel: event queue overflowed; oldest events dropped");
        }

        let now_ns = yb_core::now().timestamp_nanos_opt().unwrap_or(0).to_string();
        let snapshot = sink.registry.snapshot();
        if !snapshot.is_empty() {
            let body = otlp::metrics_payload(&service, &snapshot, &start_ns, &now_ns);
            post(&client, &format!("{endpoint}/v1/metrics"), &body).await;
        }
        let events = sink.drain_events();
        if !events.is_empty() {
            let logs = otlp::logs_payload(&service, &events);
            post(&client, &format!("{endpoint}/v1/logs"), &logs).await;
            let traces = otlp::traces_payload(&service, &events);
            post(&client, &format!("{endpoint}/v1/traces"), &traces).await;
        }
    }
}

async fn post(client: &reqwest::Client, url: &str, body: &serde_json::Value) {
    match client.post(url).json(body).timeout(Duration::from_secs(10)).send().await {
        Ok(resp) if !resp.status().is_success() => {
            tracing::warn!(url, status = %resp.status(), "otel: push rejected");
        }
        Err(e) => tracing::warn!(url, error = %e, "otel: push failed"),
        _ => {}
    }
}
