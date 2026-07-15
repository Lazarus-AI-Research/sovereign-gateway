//! OTLP/HTTP **JSON** encoding (hand-rolled against the OTLP 1.x JSON mapping —
//! no protobuf/tonic dependency stack).
//!
//! Three payload builders, one per signal, all sharing the same resource block:
//! - [`metrics_payload`] → `POST {endpoint}/v1/metrics` (cumulative sums +
//!   the latency histogram),
//! - [`logs_payload`] → `POST {endpoint}/v1/logs` (one `gateway.turn` event
//!   per served turn),
//! - [`traces_payload`] → `POST {endpoint}/v1/traces` (one span per turn,
//!   honoring a client-supplied 32-hex trace id).

use serde_json::{json, Value};
use yb_core::model::TelemetryRecord;

use crate::registry::{Labels, Series, LATENCY_BUCKETS_MS};

/// The shared `resource` block (`service.name`).
fn resource(service_name: &str) -> Value {
    json!({"attributes": [
        {"key": "service.name", "value": {"stringValue": service_name}}
    ]})
}

fn kv_str(key: &str, v: &str) -> Value {
    json!({"key": key, "value": {"stringValue": v}})
}

fn kv_int(key: &str, v: i64) -> Value {
    json!({"key": key, "value": {"intValue": v.to_string()}})
}

fn label_attrs(l: &Labels) -> Vec<Value> {
    vec![
        kv_str("surface", &l.surface),
        kv_str("model", &l.model),
        kv_str("provider", &l.provider),
        kv_int("status", l.status as i64),
    ]
}

fn nanos(t: &chrono::DateTime<chrono::Utc>) -> String {
    t.timestamp_nanos_opt().unwrap_or(0).to_string()
}

/// Build the `/v1/metrics` body from a registry snapshot. `now_ns` is the
/// observation time; `start_ns` the process/aggregation start (cumulative
/// temporality).
pub fn metrics_payload(
    service_name: &str,
    snapshot: &[(Labels, Series)],
    start_ns: &str,
    now_ns: &str,
) -> Value {
    let sum_metric = |name: &str, unit: &str, points: Vec<Value>| {
        json!({"name": name, "unit": unit, "sum": {
            "dataPoints": points,
            "aggregationTemporality": 2, // cumulative
            "isMonotonic": true,
        }})
    };
    let point = |attrs: Vec<Value>, v: u64| {
        json!({"attributes": attrs, "startTimeUnixNano": start_ns,
               "timeUnixNano": now_ns, "asInt": v.to_string()})
    };

    let mut requests = Vec::new();
    let mut errors = Vec::new();
    let mut tokens = Vec::new();
    let mut cost = Vec::new();
    let mut latency = Vec::new();
    for (l, s) in snapshot {
        let attrs = label_attrs(l);
        requests.push(point(attrs.clone(), s.requests));
        errors.push(point(attrs.clone(), s.errors));
        for (dir, v) in [
            ("input", s.input_tokens),
            ("output", s.output_tokens),
            ("cache_read", s.cache_read_tokens),
            ("cache_write", s.cache_write_tokens),
        ] {
            let mut a = attrs.clone();
            a.push(kv_str("direction", dir));
            tokens.push(point(a, v));
        }
        cost.push(point(attrs.clone(), s.cost_micros));

        // Histogram data point: bucketCounts are per-interval (non-cumulative
        // across bounds) in OTLP, unlike Prometheus text.
        let mut bucket_counts: Vec<String> = Vec::with_capacity(LATENCY_BUCKETS_MS.len() + 1);
        let mut prev = 0u64;
        for c in &s.latency_bucket_counts {
            bucket_counts.push((c - prev).to_string());
            prev = *c;
        }
        bucket_counts.push((s.latency_count - prev).to_string()); // +Inf
        latency.push(json!({
            "attributes": attrs,
            "startTimeUnixNano": start_ns,
            "timeUnixNano": now_ns,
            "count": s.latency_count.to_string(),
            "sum": s.latency_sum_ms,
            "bucketCounts": bucket_counts,
            "explicitBounds": LATENCY_BUCKETS_MS,
        }));
    }

    json!({"resourceMetrics": [{
        "resource": resource(service_name),
        "scopeMetrics": [{
            "scope": {"name": "gateway"},
            "metrics": [
                sum_metric("gateway.requests", "1", requests),
                sum_metric("gateway.errors", "1", errors),
                sum_metric("gateway.tokens", "1", tokens),
                sum_metric("gateway.cost", "us$1e-6", cost),
                {"name": "gateway.request.duration", "unit": "ms", "histogram": {
                    "dataPoints": latency,
                    "aggregationTemporality": 2,
                }},
            ],
        }],
    }]})
}

/// Per-turn attributes shared by the event and the span: structured metadata
/// only, never request/response bodies.
fn turn_attrs(rec: &TelemetryRecord) -> Vec<Value> {
    let mut attrs = vec![
        kv_str("request_id", &rec.request_id),
        kv_str("surface", &rec.surface),
        kv_str("requested_model", &rec.requested_model),
        kv_str("model", &rec.decision_model),
        kv_str("provider", &rec.decision_provider),
        kv_int("status", rec.status as i64),
        kv_int("input_tokens", rec.input_tokens),
        kv_int("output_tokens", rec.output_tokens),
        kv_int("cache_read_tokens", rec.cache_read_tokens),
        kv_int("cache_write_tokens", rec.cache_write_tokens),
        kv_int("cost_micros", rec.cost_micros),
        kv_int("latency_ms", rec.latency_ms),
        json!({"key": "error", "value": {"boolValue": rec.is_error}}),
    ];
    for (key, v) in [
        ("api_key_id", &rec.api_key_id),
        ("user_id", &rec.user_id),
        ("team_id", &rec.team_id),
    ] {
        if let Some(v) = v {
            attrs.push(kv_str(key, v));
        }
    }
    attrs
}

/// Build the `/v1/logs` body: one `gateway.turn` event per record.
pub fn logs_payload(service_name: &str, recs: &[TelemetryRecord]) -> Value {
    let records: Vec<Value> = recs
        .iter()
        .map(|rec| {
            let mut attrs = turn_attrs(rec);
            attrs.push(kv_str("event.name", "gateway.turn"));
            let (severity, text) = if rec.is_error { (13, "WARN") } else { (9, "INFO") };
            json!({
                "timeUnixNano": nanos(&rec.created_at),
                "severityNumber": severity,
                "severityText": text,
                "body": {"stringValue": "gateway.turn"},
                "attributes": attrs,
            })
        })
        .collect();
    json!({"resourceLogs": [{
        "resource": resource(service_name),
        "scopeLogs": [{"scope": {"name": "gateway"}, "logRecords": records}],
    }]})
}

/// Build the `/v1/traces` body: one span per turn. A client-supplied 32-hex
/// trace id is honored so the turn joins the caller's trace; otherwise a fresh
/// id is minted.
pub fn traces_payload(service_name: &str, recs: &[TelemetryRecord]) -> Value {
    let spans: Vec<Value> = recs
        .iter()
        .map(|rec| {
            let trace_id = rec
                .trace_id
                .as_deref()
                .filter(|t| t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()))
                .map(|t| t.to_ascii_lowercase())
                .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
            let span_id = &uuid::Uuid::new_v4().simple().to_string()[..16];
            let start = rec.created_at.timestamp_nanos_opt().unwrap_or(0);
            let end = start + rec.latency_ms.max(0) * 1_000_000;
            json!({
                "traceId": trace_id,
                "spanId": span_id,
                "name": "gateway.turn",
                "kind": 2, // SERVER
                "startTimeUnixNano": start.to_string(),
                "endTimeUnixNano": end.to_string(),
                "attributes": turn_attrs(rec),
                "status": {"code": if rec.is_error { 2 } else { 1 }},
            })
        })
        .collect();
    json!({"resourceSpans": [{
        "resource": resource(service_name),
        "scopeSpans": [{"scope": {"name": "gateway"}, "spans": spans}],
    }]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use yb_core::{new_id, now};

    fn rec() -> TelemetryRecord {
        TelemetryRecord {
            id: new_id(),
            request_id: "req-1".into(),
            trace_id: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            api_key_id: Some("key-1".into()),
            user_id: Some("user-1".into()),
            team_id: None,
            surface: "openai_responses".into(),
            requested_model: "claude-opus-4-8".into(),
            decision_model: "gpt-5.6-sol".into(),
            decision_provider: "silver-rain".into(),
            input_tokens: 100,
            output_tokens: 20,
            cache_read_tokens: 50,
            cache_write_tokens: 0,
            cost_micros: 4200,
            status: 200,
            is_error: false,
            latency_ms: 1234,
            created_at: now(),
        }
    }

    #[test]
    fn metrics_payload_shape() {
        let reg = Registry::new();
        reg.record(&rec());
        let v = metrics_payload("gateway", &reg.snapshot(), "1", "2");
        let metrics = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
        assert_eq!(metrics[0]["name"], "gateway.requests");
        assert_eq!(metrics[0]["sum"]["dataPoints"][0]["asInt"], "1");
        assert_eq!(metrics[0]["sum"]["aggregationTemporality"], 2);
        // histogram: bucketCounts has bounds+1 entries and sums to count
        let h = &metrics[4]["histogram"]["dataPoints"][0];
        let buckets = h["bucketCounts"].as_array().unwrap();
        assert_eq!(buckets.len(), LATENCY_BUCKETS_MS.len() + 1);
        let total: u64 = buckets.iter().map(|b| b.as_str().unwrap().parse::<u64>().unwrap()).sum();
        assert_eq!(total.to_string(), h["count"].as_str().unwrap());
    }

    #[test]
    fn logs_payload_shape() {
        let v = logs_payload("gateway", &[rec()]);
        let lr = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(lr["body"]["stringValue"], "gateway.turn");
        let attrs = lr["attributes"].as_array().unwrap();
        assert!(attrs.iter().any(|a| a["key"] == "request_id"));
        assert!(attrs.iter().any(|a| a["key"] == "requested_model"
            && a["value"]["stringValue"] == "claude-opus-4-8"));
        // no body-like fields, only structured metadata
        assert!(!attrs.iter().any(|a| a["key"] == "request_body"));
    }

    #[test]
    fn traces_payload_honors_client_trace_id() {
        let v = traces_payload("gateway", &[rec()]);
        let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["traceId"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(span["spanId"].as_str().unwrap().len(), 16);
        assert_eq!(span["name"], "gateway.turn");
        let start: i64 = span["startTimeUnixNano"].as_str().unwrap().parse().unwrap();
        let end: i64 = span["endTimeUnixNano"].as_str().unwrap().parse().unwrap();
        assert_eq!(end - start, 1234 * 1_000_000);
    }
}
