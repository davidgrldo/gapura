//! `/api/workspaces/{ws}/services` and `/routes`: store mode's configuration, per workspace.
//!
//! Each handler reads its caller back, finds the workspace by name among the rows that come with
//! them, and refuses cheaply with `configuration::allowed`; a write is then decided again by the
//! store, inside the transaction that makes it. Bodies are read only after the caller has been
//! checked, so a request that is both malformed and anonymous is 401. Every write answers 204,
//! and a field the console should mark answers 400 with `{"error": sentence, "field": field}`.
//! Kubernetes mode keeps no configuration in a store, so there these answer 404.

use crate::access_api::{store_caller, CallerError, StoreCaller};
use crate::configuration::{self, Action, FieldError, RouteInput, Write};
use crate::grants::Refusal;
use crate::grants_api::{unreadable, unsaved, NOT_SAVED};
use crate::state::AppState;
use crate::store::{sqlstate, Store, WriteError};
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

/// What the console shows when another write got in the way: a lock not granted in time, a
/// deadlock, or a duplicate, after the store has already tried again where that could settle it.
const CONTENDED: &str = "Someone else was changing this workspace at that moment, so this change was not saved. Try again.";

/// `store_caller`'s refusals, and a missing store, in words.
pub(crate) fn early(error: CallerError) -> Response {
    let status = match error {
        CallerError::MustChangePassword => return error.into_response(),
        CallerError::Status(status) => status,
    };
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
pub(crate) fn field_error(error: FieldError) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": error.sentence, "field": error.field })),
    )
        .into_response()
}

/// The answer once the store has had its say.
pub(crate) fn written(result: Result<(), WriteError>) -> Response {
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(WriteError::Refused(refusal)) => refusal.into_response(),
        Err(WriteError::Field(error)) => field_error(error),
        Err(WriteError::Busy) => {
            crate::api::refuse(StatusCode::SERVICE_UNAVAILABLE, crate::grants_api::BUSY)
        }
        Err(WriteError::Store(error)) => {
            let code = sqlstate(&error);
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = code.map(SqlState::code),
                "a configuration write failed"
            );
            crate::api::refuse(StatusCode::SERVICE_UNAVAILABLE, unsaved(code, CONTENDED))
        }
    }
}

/// The store and the caller behind `headers`, before anything about the request is looked at.
/// A refusal is one `early` words; returning it rather than the response keeps the error small.
pub(crate) async fn caller_of<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
) -> Result<(&'a Store, StoreCaller), CallerError> {
    let store = state.store.as_deref().ok_or(StatusCode::NOT_FOUND)?;
    let caller = store_caller(store, headers, &state.session_key).await?;
    Ok((store, caller))
}

/// The workspace `ws` names, when `caller` may do `action` there. A workspace that does not
/// exist is answered as one the caller holds no role in.
pub(crate) fn workspace_in(
    caller: &StoreCaller,
    ws: &str,
    action: Action,
) -> Result<Uuid, Refusal> {
    let Some(workspace) = caller
        .rows
        .workspaces
        .iter()
        .find(|w| w.name == ws)
        .map(|w| w.id)
    else {
        return Err(configuration::no_role());
    };
    configuration::allowed(&caller.rows, &caller.me, workspace, action)?;
    Ok(workspace)
}

/// A path that could not be read, which is a name that can never be a workspace's, so it reads
/// as an unknown one. Answered only once the caller is known, like a body that could not be read.
pub(crate) fn unnamed() -> Response {
    configuration::no_role().into_response()
}

/// A path name that could be nothing's, answered as the store answers a name that does not
/// exist but without a query, so a name the database would reject (a NUL byte) never reaches it
/// and is not logged as a store failure. Called once the caller's role is settled, like
/// `data_planes_api`, so a caller who may not write learns nothing about names.
pub(crate) fn refuse_name(kind: &str, name: &str) -> Option<Response> {
    configuration::name(name, "name").err().map(|_| {
        Refusal::NotFound(format!(
            "There is no {kind} named {name} in this workspace."
        ))
        .into_response()
    })
}

/// The body read into a `what` (with its article: "a service"). One that is too long or cut off
/// keeps the status axum chose for it; one that is not a `what` is a 400.
pub(crate) fn body<T: serde::de::DeserializeOwned>(
    body: Result<Bytes, BytesRejection>,
    what: &str,
) -> Result<T, Box<Response>> {
    let bytes = body.map_err(|rejection| Box::new(unreadable(&rejection, what)))?;
    serde_json::from_slice(&bytes).map_err(|_| {
        Refusal::Invalid(format!(
            "The request is not {what} this console understands."
        ))
        .into_response()
        .into()
    })
}

/// A read that failed in the store, which is not the caller's fault.
pub(crate) fn unavailable(error: &anyhow::Error) -> Response {
    tracing::warn!(error = format!("{error:#}"), "reading configuration failed");
    early(StatusCode::SERVICE_UNAVAILABLE.into())
}

/// What a replace without `updated_at` is told. `configuration` has already refused one, so this
/// is never taken; it says what `configuration` does.
fn unseen() -> Response {
    field_error(FieldError {
        field: "updated_at".into(),
        sentence: configuration::UNSEEN.into(),
    })
}

/// `GET /api/workspaces/{ws}/services`: the workspace's services, by name.
pub async fn list_services(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path(ws)) = ws else { return unnamed() };
    let workspace = match workspace_in(&caller, &ws, Action::Read) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    match store.services(workspace).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `POST /api/workspaces/{ws}/services`: create a service.
pub async fn create_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path(ws)) = ws else { return unnamed() };
    let workspace = match workspace_in(&caller, &ws, Action::Write) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    let input = match body(raw, "a service") {
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
    path: Result<Path<(String, String)>, PathRejection>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((ws, name))) = path else {
        return unnamed();
    };
    let workspace = match workspace_in(&caller, &ws, Action::Write) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    if let Some(r) = refuse_name("service", &name) {
        return r;
    }
    let input = match body(raw, "a service") {
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

/// `DELETE /api/workspaces/{ws}/services/{name}`: delete a service. One that routes use, or
/// that policies are attached to, is refused.
pub async fn delete_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((ws, name))) = path else {
        return unnamed();
    };
    match workspace_in(&caller, &ws, Action::Delete) {
        Ok(workspace) => {
            if let Some(r) = refuse_name("service", &name) {
                return r;
            }
            written(store.delete_service(caller.me.id, workspace, &name).await)
        }
        Err(r) => r.into_response(),
    }
}

/// `GET /api/workspaces/{ws}/routes`: the workspace's routes, highest priority first, then by
/// name.
pub async fn list_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path(ws)) = ws else { return unnamed() };
    let workspace = match workspace_in(&caller, &ws, Action::Read) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    match store.routes(workspace).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `POST /api/workspaces/{ws}/routes`: create a route.
pub async fn create_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path(ws)) = ws else { return unnamed() };
    let workspace = match workspace_in(&caller, &ws, Action::Write) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    let input = match body(raw, "a route") {
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
    path: Result<Path<(String, String)>, PathRejection>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((ws, name))) = path else {
        return unnamed();
    };
    let workspace = match workspace_in(&caller, &ws, Action::Write) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    if let Some(r) = refuse_name("route", &name) {
        return r;
    }
    let input: RouteInput = match body(raw, "a route") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    let service_seen = input.service_updated_at.clone();
    match configuration::route(input, Write::Replace) {
        Ok((route, Some(seen))) => written(
            store
                .replace_route(
                    caller.me.id,
                    workspace,
                    &name,
                    &route,
                    &seen,
                    service_seen.as_deref(),
                )
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
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((ws, name))) = path else {
        return unnamed();
    };
    match workspace_in(&caller, &ws, Action::Delete) {
        Ok(workspace) => {
            if let Some(r) = refuse_name("route", &name) {
                return r;
            }
            written(store.delete_route(caller.me.id, workspace, &name).await)
        }
        Err(r) => r.into_response(),
    }
}
