//! In-memory metric aggregates, keyed by a bounded label set.
//!
//! One [`Registry`] instance accumulates counters and latency histograms per
//! `(surface, model, provider, status)` — deliberately low-cardinality labels
//! (public model names and HTTP statuses, never per-request ids). The same
//! aggregates back both export paths: OTLP push snapshots and the Prometheus
//! text rendering for `GET /metrics`.

use std::collections::HashMap;
use std::sync::Mutex;

use yb_core::model::TelemetryRecord;

/// Latency histogram bucket upper bounds, in milliseconds.
pub const LATENCY_BUCKETS_MS: &[f64] = &[
    25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 5_000.0, 10_000.0, 30_000.0, 60_000.0,
    120_000.0,
];

/// The label set every series is keyed by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Labels {
    pub surface: String,
    pub model: String,
    pub provider: String,
    pub status: u16,
}

/// Aggregates for one label set.
#[derive(Debug, Clone, Default)]
pub struct Series {
    pub requests: u64,
    pub errors: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_micros: u64,
    /// Cumulative counts per `LATENCY_BUCKETS_MS` bound, plus the +Inf overflow
    /// implied by `latency_count`.
    pub latency_bucket_counts: Vec<u64>,
    pub latency_sum_ms: f64,
    pub latency_count: u64,
}

/// The shared metric store. Cheap locks: one uncontended mutex grab per turn.
#[derive(Debug, Default)]
pub struct Registry {
    series: Mutex<HashMap<Labels, Series>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one served turn into the aggregates.
    pub fn record(&self, rec: &TelemetryRecord) {
        let labels = Labels {
            surface: rec.surface.clone(),
            model: rec.decision_model.clone(),
            provider: rec.decision_provider.clone(),
            status: rec.status as u16,
        };
        let mut map = self.series.lock().unwrap();
        let s = map.entry(labels).or_insert_with(|| Series {
            latency_bucket_counts: vec![0; LATENCY_BUCKETS_MS.len()],
            ..Default::default()
        });
        s.requests += 1;
        if rec.is_error {
            s.errors += 1;
        }
        s.input_tokens += rec.input_tokens.max(0) as u64;
        s.output_tokens += rec.output_tokens.max(0) as u64;
        s.cache_read_tokens += rec.cache_read_tokens.max(0) as u64;
        s.cache_write_tokens += rec.cache_write_tokens.max(0) as u64;
        s.cost_micros += rec.cost_micros.max(0) as u64;
        let ms = rec.latency_ms.max(0) as f64;
        for (i, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if ms <= *bound {
                s.latency_bucket_counts[i] += 1;
            }
        }
        s.latency_sum_ms += ms;
        s.latency_count += 1;
    }

    /// A point-in-time copy of every series (for OTLP snapshots).
    pub fn snapshot(&self) -> Vec<(Labels, Series)> {
        let map = self.series.lock().unwrap();
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Render the aggregates in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut snap = self.snapshot();
        // Deterministic output: stable ordering across scrapes.
        snap.sort_by(|a, b| {
            (&a.0.surface, &a.0.model, &a.0.provider, a.0.status)
                .cmp(&(&b.0.surface, &b.0.model, &b.0.provider, b.0.status))
        });
        let mut out = String::new();

        let label_str = |l: &Labels| {
            format!(
                "surface=\"{}\",model=\"{}\",provider=\"{}\",status=\"{}\"",
                escape(&l.surface),
                escape(&l.model),
                escape(&l.provider),
                l.status
            )
        };

        out.push_str("# TYPE gateway_requests_total counter\n");
        for (l, s) in &snap {
            out.push_str(&format!("gateway_requests_total{{{}}} {}\n", label_str(l), s.requests));
        }
        out.push_str("# TYPE gateway_errors_total counter\n");
        for (l, s) in &snap {
            out.push_str(&format!("gateway_errors_total{{{}}} {}\n", label_str(l), s.errors));
        }
        out.push_str("# TYPE gateway_tokens_total counter\n");
        for (l, s) in &snap {
            let ls = label_str(l);
            for (dir, v) in [
                ("input", s.input_tokens),
                ("output", s.output_tokens),
                ("cache_read", s.cache_read_tokens),
                ("cache_write", s.cache_write_tokens),
            ] {
                out.push_str(&format!(
                    "gateway_tokens_total{{{ls},direction=\"{dir}\"}} {v}\n"
                ));
            }
        }
        out.push_str("# TYPE gateway_cost_micros_total counter\n");
        for (l, s) in &snap {
            out.push_str(&format!(
                "gateway_cost_micros_total{{{}}} {}\n",
                label_str(l),
                s.cost_micros
            ));
        }
        out.push_str("# TYPE gateway_request_duration_ms histogram\n");
        for (l, s) in &snap {
            let ls = label_str(l);
            for (i, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
                out.push_str(&format!(
                    "gateway_request_duration_ms_bucket{{{ls},le=\"{bound}\"}} {}\n",
                    s.latency_bucket_counts[i]
                ));
            }
            out.push_str(&format!(
                "gateway_request_duration_ms_bucket{{{ls},le=\"+Inf\"}} {}\n",
                s.latency_count
            ));
            out.push_str(&format!(
                "gateway_request_duration_ms_sum{{{ls}}} {}\n",
                s.latency_sum_ms
            ));
            out.push_str(&format!(
                "gateway_request_duration_ms_count{{{ls}}} {}\n",
                s.latency_count
            ));
        }
        out
    }
}

/// Escape a Prometheus label value (backslash, quote, newline).
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use yb_core::{new_id, now};

    fn rec(model: &str, status: i32, latency_ms: i64) -> TelemetryRecord {
        TelemetryRecord {
            id: new_id(),
            request_id: new_id(),
            trace_id: None,
            api_key_id: None,
            user_id: None,
            team_id: None,
            surface: "anthropic".into(),
            requested_model: "alias".into(),
            decision_model: model.into(),
            decision_provider: "prov".into(),
            input_tokens: 10,
            output_tokens: 5,
            cache_read_tokens: 2,
            cache_write_tokens: 0,
            cost_micros: 123,
            status,
            is_error: status >= 400,
            latency_ms,
            created_at: now(),
        }
    }

    #[test]
    fn aggregates_and_renders() {
        let r = Registry::new();
        r.record(&rec("m1", 200, 80));
        r.record(&rec("m1", 200, 300));
        r.record(&rec("m1", 400, 10));

        let text = r.render_prometheus();
        assert!(text.contains(
            "gateway_requests_total{surface=\"anthropic\",model=\"m1\",provider=\"prov\",status=\"200\"} 2"
        ));
        assert!(text.contains(
            "gateway_errors_total{surface=\"anthropic\",model=\"m1\",provider=\"prov\",status=\"400\"} 1"
        ));
        // 80ms lands in le=100 for the 200-status series; 300ms does not.
        assert!(text.contains("le=\"100\"} 1"));
        // tokens split by direction
        assert!(text.contains("direction=\"input\"} 20"));
        assert!(text.contains("direction=\"cache_read\"} 4"));
        // histogram count/sum present
        assert!(text.contains("gateway_request_duration_ms_count{surface=\"anthropic\",model=\"m1\",provider=\"prov\",status=\"200\"} 2"));
    }
}
