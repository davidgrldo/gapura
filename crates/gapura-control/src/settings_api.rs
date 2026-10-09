//! `/api/settings`: the console's one setting, whether sign-up is open, which a superuser reads
//! and changes.
//!
//! The shape of `accounts_api`: the caller first, then the rule, then the body, then the store,
//! which decides again inside its transaction. A change to what is already set answers 204 and
//! writes nothing. Kubernetes mode keeps no settings and has no sign-up, so there these answer
//! 404.

use crate::access_api::CallerError;
use crate::configuration_api::{body, caller_of};
use crate::grants_api::unsaved;
use crate::state::AppState;
use crate::store::{sqlstate, WriteError};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio_postgres::error::SqlState;

/// What a route about settings answers in Kubernetes mode.
pub(crate) const NO_SETTINGS: &str = "This console keeps no settings: it runs without a database.";

/// What the console shows when another write got in the way.
const CONTENDED: &str =
    "Someone else was changing the settings at that moment, so this change was not saved. Try again.";

/// The settings, as read and as sent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    sign_up_open: bool,
}

/// `configuration_api::early`, but a console with no store keeps no settings.
fn early(error: CallerError) -> Response {
    match error {
        CallerError::Status(StatusCode::NOT_FOUND) => {
            crate::api::refuse(StatusCode::NOT_FOUND, NO_SETTINGS)
        }
        other => crate::configuration_api::early(other),
    }
}

/// `GET /api/settings`.
pub async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = crate::accounts::may_change_settings(&caller.me) {
        return r.into_response();
    }
    match store.sign_up_open().await {
        Ok(sign_up_open) => Json(Settings { sign_up_open }).into_response(),
        Err(error) => {
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = sqlstate(&error).map(SqlState::code),
                "reading the settings failed"
            );
            early(StatusCode::SERVICE_UNAVAILABLE.into())
        }
    }
}

/// `PUT /api/settings`: open or close sign-up.
pub async fn put_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = crate::accounts::may_change_settings(&caller.me) {
        return r.into_response();
    }
    let input: Settings = match body(raw, "a settings change") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match store
        .set_sign_up_open(caller.me.id, input.sign_up_open)
        .await
    {
        Ok(()) => {
            tracing::info!(user = %caller.me.id, open = input.sign_up_open, "set sign-up");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(WriteError::Store(error)) => {
            let code = sqlstate(&error);
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = code.map(SqlState::code),
                "a settings write failed"
            );
            crate::api::refuse(StatusCode::SERVICE_UNAVAILABLE, unsaved(code, CONTENDED))
        }
        Err(other) => crate::configuration_api::written(Err(other)),
    }
}
