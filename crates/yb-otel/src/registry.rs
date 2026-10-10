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

/// Time-to-first-token and waiting histogram bounds, in milliseconds: a
/// first token is due within a second, a long prompt or a queue takes
/// minutes.
pub const FIRST_TOKEN_BUCKETS_MS: &[f64] = &[
    50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 5_000.0, 10_000.0, 30_000.0, 60_000.0, 120_000.0,
    300_000.0,
];

/// Output tokens per second histogram bounds.
pub const OUTPUT_RATE_BUCKETS: &[f64] = &[
    5.0, 10.0, 20.0, 30.0, 40.0, 60.0, 80.0, 100.0, 150.0, 200.0, 300.0,
];

/// A distribution of observations over fixed bounds: cumulative counts per
/// bound, as Prometheus reads them, with the sum and count.
#[derive(Debug, Clone)]
pub struct Histogram {
    pub bounds: &'static [f64],
    pub bucket_counts: Vec<u64>,
    pub sum: f64,
    pub count: u64,
}

impl Histogram {
    fn new(bounds: &'static [f64]) -> Self {
        Histogram {
            bounds,
            bucket_counts: vec![0; bounds.len()],
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, value: f64) {
        for (i, bound) in self.bounds.iter().enumerate() {
            if value <= *bound {
                self.bucket_counts[i] += 1;
            }
        }
        self.sum += value;
        self.count += 1;
    }
}

/// The label set every series is keyed by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Labels {
    pub surface: String,
    pub model: String,
    pub provider: String,
    pub status: u16,
}

/// Aggregates for one label set.
#[derive(Debug, Clone)]
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
    /// Time to first token, in milliseconds.
    pub first_token: Histogram,
    /// Time waited before the engine began reading the prompt, in
    /// milliseconds, for engines that report it.
    pub queue: Histogram,
    /// Output tokens per second while the answer was written.
    pub output_rate: Histogram,
}

impl Default for Series {
    fn default() -> Self {
        Series {
            requests: 0,
            errors: 0,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            cost_micros: 0,
            latency_bucket_counts: vec![0; LATENCY_BUCKETS_MS.len()],
            latency_sum_ms: 0.0,
            latency_count: 0,
            first_token: Histogram::new(FIRST_TOKEN_BUCKETS_MS),
            queue: Histogram::new(FIRST_TOKEN_BUCKETS_MS),
            output_rate: Histogram::new(OUTPUT_RATE_BUCKETS),
        }
    }
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
        let s = map.entry(labels).or_default();
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
        if let Some(first) = rec.first_token_ms {
            s.first_token.observe(first.max(0) as f64);
        }
        if let Some(queue) = rec.queue_ms {
            s.queue.observe(queue.max(0) as f64);
        }
        if let Some(rate) = output_rate(rec) {
            s.output_rate.observe(rate);
        }
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
            (&a.0.surface, &a.0.model, &a.0.provider, a.0.status).cmp(&(
                &b.0.surface,
                &b.0.model,
                &b.0.provider,
                b.0.status,
            ))
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
            out.push_str(&format!(
                "gateway_requests_total{{{}}} {}\n",
                label_str(l),
                s.requests
            ));
        }
        out.push_str("# TYPE gateway_errors_total counter\n");
        for (l, s) in &snap {
            out.push_str(&format!(
                "gateway_errors_total{{{}}} {}\n",
                label_str(l),
                s.errors
            ));
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
        render_histogram(
            &mut out,
            "gateway_time_to_first_token_ms",
            &snap,
            &label_str,
            |s| &s.first_token,
        );
        render_histogram(&mut out, "gateway_queue_wait_ms", &snap, &label_str, |s| {
            &s.queue
        });
        render_histogram(
            &mut out,
            "gateway_output_tokens_per_second",
            &snap,
            &label_str,
            |s| &s.output_rate,
        );
        out
    }
}

/// Output tokens per second while a turn's answer was written, where its
/// writing time is known.
pub fn output_rate(rec: &TelemetryRecord) -> Option<f64> {
    let ms = rec.generation_ms.filter(|ms| *ms > 0)?;
    (rec.output_tokens > 0).then(|| rec.output_tokens as f64 * 1000.0 / ms as f64)
}

/// A histogram in Prometheus text, one series per label set.
fn render_histogram(
    out: &mut String,
    name: &str,
    snap: &[(Labels, Series)],
    label_str: &dyn Fn(&Labels) -> String,
    histogram: fn(&Series) -> &Histogram,
) {
    out.push_str(&format!("# TYPE {name} histogram\n"));
    for (l, s) in snap {
        let h = histogram(s);
        let ls = label_str(l);
        for (i, bound) in h.bounds.iter().enumerate() {
            out.push_str(&format!(
                "{name}_bucket{{{ls},le=\"{bound}\"}} {}\n",
                h.bucket_counts[i]
            ));
        }
        out.push_str(&format!("{name}_bucket{{{ls},le=\"+Inf\"}} {}\n", h.count));
        out.push_str(&format!("{name}_sum{{{ls}}} {}\n", h.sum));
        out.push_str(&format!("{name}_count{{{ls}}} {}\n", h.count));
    }
}

/// Escape a Prometheus label value (backslash, quote, newline).
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
            parent_span_id: None,
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
            first_token_ms: None,
            generation_ms: None,
            queue_ms: None,
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
        // A turn's speed: 300 ms to its first token, 40 tokens in two seconds.
        let mut timed = rec("m2", 200, 2400);
        timed.output_tokens = 40;
        timed.first_token_ms = Some(300);
        timed.generation_ms = Some(2000);
        r.record(&timed);
        let text = r.render_prometheus();
        let series = "surface=\"anthropic\",model=\"m2\",provider=\"prov\",status=\"200\"";
        assert!(text.contains(&format!(
            "gateway_time_to_first_token_ms_bucket{{{series},le=\"250\"}} 0"
        )));
        assert!(text.contains(&format!(
            "gateway_time_to_first_token_ms_bucket{{{series},le=\"500\"}} 1"
        )));
        assert!(text.contains(&format!(
            "gateway_output_tokens_per_second_sum{{{series}}} 20"
        )));
        assert!(text.contains(&format!("gateway_queue_wait_ms_count{{{series}}} 0")));
    }
}
