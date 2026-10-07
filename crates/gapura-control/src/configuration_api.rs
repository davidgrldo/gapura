//! `/api/workspaces/{ws}/services` and `/routes`: store mode's configuration, per workspace.
//!
//! Each handler reads its caller back, finds the workspace by name among the rows that come with
//! them, and refuses cheaply with `configuration::allowed`; a write is then decided again by the
//! store, inside the transaction that makes it. Bodies are read only after the caller has been
//! checked, so a request that is both malformed and anonymous is 401. Every write answers 204,
//! and a field the console should mark answers 400 with `{"error": sentence, "field": field}`.
//! Kubernetes mode keeps no configuration in a store, so there these answer 404.

use crate::access_api::{store_caller, StoreCaller};
use crate::configuration::{self, Action, FieldError, Write};
use crate::grants::Refusal;
use crate::state::AppState;
use crate::store::{sqlstate, Store, WriteError};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

/// What the console shows when another write got in the way: a lock not granted in time, a
/// deadlock, or a duplicate, after the store has already tried again where that could settle it.
const CONTENDED: &str = "Someone else was changing this workspace at that moment, so this change was not saved. Try again.";

/// What the console shows when the store failed for any other reason. It does not say that
/// nothing was changed, because a commit that failed on the wire may or may not have happened.
const NOT_SAVED: &str = "The console could not save this change. Try again in a moment.";

/// `store_caller`'s refusals, and a missing store, in words.
fn early(status: StatusCode) -> Response {
    let sentence = match status {
        StatusCode::UNAUTHORIZED => "You are not signed in.",
        StatusCode::NOT_FOUND => "This console keeps no configuration: it runs without a database.",
        // The caller could not be read back from the store, and `store_caller` has logged why.
        StatusCode::SERVICE_UNAVAILABLE => NOT_SAVED,
        other => other
            .canonical_reason()
            .unwrap_or("The request was refused."),
    };
    crate::api::refuse(status, sentence)
}

/// A refused field, which the console shows beside it.
fn field_error(error: FieldError) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": error.sentence, "field": error.field })),
    )
        .into_response()
}

/// The answer once the store has had its say.
fn written(result: Result<(), WriteError>) -> Response {
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(WriteError::Refused(refusal)) => refusal.into_response(),
        Err(WriteError::Store(error)) => {
            let code = sqlstate(&error);
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = code.map(SqlState::code),
                "a configuration write failed"
            );
            let contended = code.is_some_and(|c| {
                *c == SqlState::LOCK_NOT_AVAILABLE
                    || *c == SqlState::T_R_DEADLOCK_DETECTED
                    || *c == SqlState::UNIQUE_VIOLATION
            });
            crate::api::refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                if contended { CONTENDED } else { NOT_SAVED },
            )
        }
    }
}

/// The store, the caller and the workspace `ws` names, when the caller may do `action` there.
/// A workspace that does not exist is answered as one the caller holds no role in.
async fn caller_in<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    ws: &str,
    action: Action,
) -> Result<(&'a Store, StoreCaller, Uuid), Response> {
    let store = state
        .store
        .as_deref()
        .ok_or_else(|| early(StatusCode::NOT_FOUND))?;
    let caller = store_caller(store, headers, &state.session_key)
        .await
        .map_err(early)?;
    let Some(workspace) = caller
        .rows
        .workspaces
        .iter()
        .find(|w| w.name == ws)
        .map(|w| w.id)
    else {
        return Err(configuration::no_role().into_response());
    };
    configuration::allowed(&caller.rows, &caller.me, workspace, action)
        .map_err(IntoResponse::into_response)?;
    Ok((store, caller, workspace))
}

/// The body read into a `what`. One that is too long or cut off keeps the status axum chose for
/// it, worded for the console; one that is not a `what` is a 400.
fn body<T: serde::de::DeserializeOwned>(
    body: Result<Bytes, BytesRejection>,
    what: &str,
) -> Result<T, Box<Response>> {
    let bytes = body.map_err(|rejection| {
        let status = rejection.status();
        let sentence = if status == StatusCode::PAYLOAD_TOO_LARGE {
            format!("That request is too large to be a {what}.")
        } else {
            "The request could not be read.".to_string()
        };
        Box::new(crate::api::refuse(status, &sentence))
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        Refusal::Invalid(format!(
            "The request is not a {what} this console understands."
        ))
        .into_response()
        .into()
    })
}

/// A read that failed in the store, which is not the caller's fault.
fn unavailable(error: &anyhow::Error) -> Response {
    tracing::warn!(error = format!("{error:#}"), "reading configuration failed");
    early(StatusCode::SERVICE_UNAVAILABLE)
}

/// What a replace needs `updated_at` for; `configuration` has already refused a replace without
/// one, so this is never taken.
fn unseen() -> Response {
    field_error(FieldError {
        field: "updated_at".into(),
        sentence: "Send the updated_at you last read.".into(),
    })
}

/// `GET /api/workspaces/{ws}/services`: the workspace's services, by name.
pub async fn list_services(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ws): Path<String>,
) -> Response {
    match caller_in(&state, &headers, &ws, Action::Read).await {
        Ok((store, _, workspace)) => match store.services(workspace).await {
            Ok(list) => Json(list).into_response(),
            Err(e) => unavailable(&e),
        },
        Err(r) => r,
    }
}

/// `POST /api/workspaces/{ws}/services`: create a service.
pub async fn create_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ws): Path<String>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller, workspace) = match caller_in(&state, &headers, &ws, Action::Write).await {
        Ok(found) => found,
        Err(r) => return r,
    };
    let input = match body(raw, "service") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match configuration::service(input, Write::Create) {
        Ok((service, _)) => written(
            store
                .create_service(caller.me.id, workspace, &service)
                .await,
        ),
        Err(e) => field_error(e),
    }
}

/// `PUT /api/workspaces/{ws}/services/{name}`: replace a service, which may rename it, when the
/// `updated_at` sent is the one it has.
pub async fn replace_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((ws, name)): Path<(String, String)>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller, workspace) = match caller_in(&state, &headers, &ws, Action::Write).await {
        Ok(found) => found,
        Err(r) => return r,
    };
    let input = match body(raw, "service") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match configuration::service(input, Write::Replace) {
        Ok((service, Some(seen))) => written(
            store
                .replace_service(caller.me.id, workspace, &name, &service, &seen)
                .await,
        ),
        Ok((_, None)) => unseen(),
        Err(e) => field_error(e),
    }
}

/// `DELETE /api/workspaces/{ws}/services/{name}`: delete a service no route uses.
pub async fn delete_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((ws, name)): Path<(String, String)>,
) -> Response {
    match caller_in(&state, &headers, &ws, Action::Delete).await {
        Ok((store, caller, workspace)) => {
            written(store.delete_service(caller.me.id, workspace, &name).await)
        }
        Err(r) => r,
    }
}

/// `GET /api/workspaces/{ws}/routes`: the workspace's routes, by name.
pub async fn list_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ws): Path<String>,
) -> Response {
    match caller_in(&state, &headers, &ws, Action::Read).await {
        Ok((store, _, workspace)) => match store.routes(workspace).await {
            Ok(list) => Json(list).into_response(),
            Err(e) => unavailable(&e),
        },
        Err(r) => r,
    }
}

/// `POST /api/workspaces/{ws}/routes`: create a route.
pub async fn create_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(ws): Path<String>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller, workspace) = match caller_in(&state, &headers, &ws, Action::Write).await {
        Ok(found) => found,
        Err(r) => return r,
    };
    let input = match body(raw, "route") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match configuration::route(input, Write::Create) {
        Ok((route, _)) => written(store.create_route(caller.me.id, workspace, &route).await),
        Err(e) => field_error(e),
    }
}

/// `PUT /api/workspaces/{ws}/routes/{name}`: replace a route, which may rename it, when the
/// `updated_at` sent is the one it has.
pub async fn replace_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((ws, name)): Path<(String, String)>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller, workspace) = match caller_in(&state, &headers, &ws, Action::Write).await {
        Ok(found) => found,
        Err(r) => return r,
    };
    let input = match body(raw, "route") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match configuration::route(input, Write::Replace) {
        Ok((route, Some(seen))) => written(
            store
                .replace_route(caller.me.id, workspace, &name, &route, &seen)
                .await,
        ),
        Ok((_, None)) => unseen(),
        Err(e) => field_error(e),
    }
}

/// `DELETE /api/workspaces/{ws}/routes/{name}`: delete a route no policy is attached to.
pub async fn delete_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((ws, name)): Path<(String, String)>,
) -> Response {
    match caller_in(&state, &headers, &ws, Action::Delete).await {
        Ok((store, caller, workspace)) => {
            written(store.delete_route(caller.me.id, workspace, &name).await)
        }
        Err(r) => r,
    }
}
