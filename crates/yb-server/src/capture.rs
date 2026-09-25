//! `/admin/v1/capture`: whether prompts and responses are captured, and the
//! captured conversations exported as a training dataset.

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use serde_json::{json, Value};

use yb_core::{CaptureFilter, CapturePolicy, CapturedTurn, Error, WireFormat};
use yb_wire::{ChatResponse, ContentBlock, EmitOptions};

use crate::admin::Principal;
use crate::{error_response, AppState};

/// The refusal for anyone but an administrator; none for one.
fn refused(principal: &Principal) -> Option<Response> {
    (!principal.is_admin()).then(|| {
        error_response(&Error::Forbidden(
            "request capture is for administrators".into(),
        ))
    })
}

/// `GET /capture` — the policy in force.
pub(crate) async fn get_policy(principal: Principal, State(state): State<AppState>) -> Response {
    if let Some(refusal) = refused(&principal) {
        return refusal;
    }
    match state.store.capture_policy().await {
        Ok(policy) => Json(policy).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `PUT /capture` — a new policy, kept and applied at once.
pub(crate) async fn put_policy(
    principal: Principal,
    State(state): State<AppState>,
    Json(policy): Json<CapturePolicy>,
) -> Response {
    if let Some(refusal) = refused(&principal) {
        return refusal;
    }
    if let Err(e) = state.store.set_capture_policy(&policy).await {
        return error_response(&e);
    }
    state.request_log.apply_policy(&policy);
    Json(policy).into_response()
}

#[derive(Deserialize, Default)]
pub(crate) struct ExportQuery {
    from: Option<chrono::NaiveDate>,
    to: Option<chrono::NaiveDate>,
    /// Comma-separated.
    model: Option<String>,
    /// Comma-separated key ids.
    key: Option<String>,
    /// Comma-separated `name:value` pairs a turn's tags must all carry.
    tag: Option<String>,
    redaction: Option<String>,
}

fn list(value: &Option<String>) -> Vec<String> {
    value
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `GET /capture/export` — the captured conversations as JSON Lines, one
/// training example each in the OpenAI chat format: the messages as sent,
/// the model's answer last, and where it came from. Days are UTC and both
/// ends included; turns captured as metadata only carry no text and are left
/// out.
pub(crate) async fn export(
    principal: Principal,
    State(state): State<AppState>,
    Query(query): Query<ExportQuery>,
) -> Response {
    if let Some(refusal) = refused(&principal) {
        return refusal;
    }
    let midnight = |day: chrono::NaiveDate| day.and_time(chrono::NaiveTime::MIN).and_utc();
    let mut tags = Vec::new();
    for pair in list(&query.tag) {
        match pair.split_once(':') {
            Some((name, value)) => tags.push((name.to_string(), value.to_string())),
            None => {
                return error_response(&Error::BadRequest(format!(
                    "a tag is name:value, not {pair}"
                )))
            }
        }
    }
    let filter = CaptureFilter {
        from: query.from.map(midnight),
        to: query
            .to
            .map(|day| midnight(day) + chrono::Duration::days(1)),
        models: list(&query.model),
        api_key_ids: list(&query.key),
        tags,
        redaction: query.redaction.clone(),
    };
    let log = state.request_log.clone();
    let turns = match tokio::task::spawn_blocking(move || log.export(&filter)).await {
        Ok(Ok(turns)) => turns,
        Ok(Err(e)) => return error_response(&e),
        Err(e) => return error_response(&Error::Internal(e.to_string())),
    };
    let mut body = String::new();
    for turn in &turns {
        if let Some(example) = training_example(turn) {
            body.push_str(&example.to_string());
            body.push('\n');
        }
    }
    ([(header::CONTENT_TYPE, "application/x-ndjson")], body).into_response()
}

/// A captured turn as one training example, or nothing for a turn with no
/// text (metadata only) or one that is not a chat.
pub fn training_example(turn: &CapturedTurn) -> Option<Value> {
    let surface = match turn.surface.as_str() {
        "openai_chat" => WireFormat::OpenaiChat,
        "openai_responses" => WireFormat::OpenaiResponses,
        "anthropic" => WireFormat::Anthropic,
        "gemini" => WireFormat::Gemini,
        _ => return None,
    };
    if turn.request_body.is_empty() || turn.response_body.is_empty() {
        return None;
    }
    let request = yb_gateway::wire::parse_request(surface, &turn.request_body).ok()?;
    let (sent, _) = yb_gateway::wire::emit_request(
        WireFormat::OpenaiChat,
        &request,
        &EmitOptions::new(turn.requested_model.clone()),
    )
    .ok()?;
    let sent: Value = serde_json::from_slice(&sent).ok()?;
    let response: ChatResponse = serde_json::from_slice(&turn.response_body).ok()?;
    let mut messages = sent.get("messages")?.as_array()?.clone();
    messages.push(answer(&response));
    let mut example = json!({
        "messages": messages,
        "metadata": {
            "request_id": turn.request_id,
            "captured_at": turn.ts.to_rfc3339(),
            "model": turn.requested_model,
            "key": turn.api_key_id,
            "redaction": turn.redaction,
            "tags": turn.tags.as_deref().and_then(|t| serde_json::from_str::<Value>(t).ok()),
        },
    });
    if let Some(tools) = sent.get("tools") {
        example["tools"] = tools.clone();
    }
    Some(example)
}

/// The model's answer as the assistant message that ends an example.
fn answer(response: &ChatResponse) -> Value {
    let mut text = String::new();
    let mut calls = Vec::new();
    for block in &response.content {
        match block {
            ContentBlock::Text { text: t } => text.push_str(t),
            ContentBlock::ToolUse { id, name, input } => calls.push(json!({
                "id": id, "type": "function",
                "function": {"name": name, "arguments": input.to_string()},
            })),
            _ => {}
        }
    }
    let mut message = json!({"role": "assistant", "content": text});
    if !calls.is_empty() {
        message["tool_calls"] = Value::Array(calls);
    }
    message
}
