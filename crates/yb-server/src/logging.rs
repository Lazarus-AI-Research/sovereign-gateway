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

fn refused(principal: &Principal) -> Option<Response> {
    (!principal.is_admin()).then(|| {
        error_response(&Error::Forbidden(
            "the log level is for administrators".into(),
        ))
    })
}

/// `GET /log-level` — the level in force; info until one is set.
pub(crate) async fn get_level(principal: Principal, State(state): State<AppState>) -> Response {
    if let Some(refusal) = refused(&principal) {
        return refusal;
    }
    match state.store.log_level().await {
        Ok(level) => Json(Level {
            level: level.unwrap_or_default(),
        })
        .into_response(),
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
    if let Err(e) = state.store.set_log_level(body.level).await {
        return error_response(&e);
    }
    if let Err(e) = state.logging.apply(body.level) {
        return error_response(&e);
    }
    Json(body).into_response()
}
