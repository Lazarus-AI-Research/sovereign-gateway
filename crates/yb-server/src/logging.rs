//! `/admin/v1/log-level`: how much the gateway logs, kept and applied at once.

use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use yb_core::{Error, LogLevel};

use crate::admin::Principal;
use crate::{error_response, AppState};

#[derive(Serialize, Deserialize)]
pub(crate) struct Level {
    level: LogLevel,
}

/// No level until an operator sets one: the environment's filter applies.
#[derive(Serialize)]
struct Kept {
    level: Option<LogLevel>,
}

fn refused(principal: &Principal) -> Option<Response> {
    (!principal.is_admin()).then(|| {
        error_response(&Error::Forbidden(
            "the log level is for administrators".into(),
        ))
    })
}

/// `GET /log-level` — the level an operator set; null while `RUST_LOG` (or
/// info) applies.
pub(crate) async fn get_level(principal: Principal, State(state): State<AppState>) -> Response {
    if let Some(refusal) = refused(&principal) {
        return refusal;
    }
    match state.store.log_level().await {
        Ok(level) => Json(Kept { level }).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `PUT /log-level` — a new level, kept so a restart keeps it.
pub(crate) async fn put_level(
    principal: Principal,
    State(state): State<AppState>,
    Json(body): Json<Level>,
) -> Response {
    if let Some(refusal) = refused(&principal) {
        return refusal;
    }
    // Applied before it is kept, so a level the process cannot take is never
    // stored; under one lock and on a task of its own, as capture is.
    let level = body.level;
    let change = tokio::spawn(async move {
        let _settings = state.settings.lock().await;
        let before = state.store.log_level().await?;
        state.logging.apply(level)?;
        if let Err(e) = state.store.set_log_level(level).await {
            // Not kept, so not run either.
            let _ = match before {
                Some(before) => state.logging.apply(before),
                None => state.logging.reset(),
            };
            return Err(e);
        }
        Ok(())
    });
    match change.await {
        Ok(Ok(())) => Json(body).into_response(),
        Ok(Err(e)) => error_response(&e),
        Err(e) => error_response(&Error::Internal(e.to_string())),
    }
}
