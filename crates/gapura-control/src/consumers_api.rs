//! `/api/workspaces/{ws}/consumers` and `/key-auth`: store mode's consumers, their API keys, and
//! the requirement that a request carry one, per workspace.
//!
//! The same shape as `configuration_api`, whose helpers these use: the caller first, then the
//! path, then the workspace and the role the action needs, then the body, then the store, which
//! decides a write again inside its transaction. Every write answers 204 except issuing a key,
//! which answers 200 with the key, the only time it is shown, and is never cached. Kubernetes mode
//! keeps no consumers in a store, so there these answer 404.

use crate::configuration::{Action, FieldError};
use crate::configuration_api::{
    body, caller_of, early, field_error, unavailable, unnamed, workspace_in, written,
};
use crate::consumers::{self, KeyInput, Target};
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use k8s_openapi::jiff::Timestamp;
use serde::Deserialize;

/// `GET /api/workspaces/{ws}/consumers`: the workspace's consumers, by name, each with its keys.
pub async fn list_consumers(
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
    match store.consumers(workspace).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `POST /api/workspaces/{ws}/consumers`: create a consumer, with no keys yet.
pub async fn create_consumer(
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
    let input = match body(raw, "a consumer") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match consumers::consumer(input) {
        Ok(name) => written(store.create_consumer(caller.me.id, workspace, &name).await),
        Err(e) => field_error(e),
    }
}

/// `DELETE /api/workspaces/{ws}/consumers/{name}`: delete a consumer, and its keys with it.
pub async fn delete_consumer(
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
        Ok(workspace) => written(store.delete_consumer(caller.me.id, workspace, &name).await),
        Err(r) => r.into_response(),
    }
}

/// `POST /api/workspaces/{ws}/consumers/{name}/keys`: issue a key, which answers with the key
/// itself. An empty body issues one that never expires.
pub async fn issue_key(
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
    let input = match raw {
        Ok(bytes) if bytes.is_empty() => KeyInput::default(),
        raw => match body(raw, "a request for a key") {
            Ok(i) => i,
            Err(r) => return *r,
        },
    };
    let expires_at = match consumers::expiry(&input, Timestamp::now()) {
        Ok(at) => at,
        Err(e) => return field_error(e),
    };
    match store
        .issue_key(caller.me.id, workspace, &name, expires_at.as_deref())
        .await
    {
        Ok(issued) => ([(header::CACHE_CONTROL, "no-store")], Json(issued)).into_response(),
        Err(e) => written(Err(e)),
    }
}

/// `DELETE /api/workspaces/{ws}/consumers/{name}/keys/{prefix}`: revoke one key, by the prefix
/// the list shows.
pub async fn revoke_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<(String, String, String)>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((ws, name, prefix))) = path else {
        return unnamed();
    };
    match workspace_in(&caller, &ws, Action::Delete) {
        Ok(workspace) => written(
            store
                .revoke_key(caller.me.id, workspace, &name, &prefix)
                .await,
        ),
        Err(r) => r.into_response(),
    }
}

/// `GET /api/workspaces/{ws}/key-auth`: where the workspace requires a key, and the header it is
/// read from.
pub async fn list_key_auth(
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
    match store.policies(workspace).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `PUT /api/workspaces/{ws}/key-auth`: require a key on the workspace, a service or a route.
pub async fn put_key_auth(
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
    let input: consumers::KeyAuthInput = match body(raw, "a key requirement") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    let target = match Target::parse(&input.target) {
        Ok(t) => t,
        Err(e) => return field_error(e),
    };
    match consumers::header(input.header.as_deref()) {
        Ok(header) => written(
            store
                .put_key_auth(caller.me.id, workspace, &target, &header)
                .await,
        ),
        Err(e) => field_error(e),
    }
}

/// `?target=`, as `delete_key_auth` reads it.
#[derive(Deserialize)]
pub struct TargetQuery {
    target: String,
}

/// The target a query names. One that names none is refused as an empty one, beside `target`.
fn target_in(query: Result<Query<TargetQuery>, QueryRejection>) -> Result<Target, FieldError> {
    match query {
        Ok(Query(q)) => Target::parse(&q.target),
        Err(_) => Target::parse(""),
    }
}

/// `DELETE /api/workspaces/{ws}/key-auth?target=…`: stop requiring a key there.
pub async fn delete_key_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
    query: Result<Query<TargetQuery>, QueryRejection>,
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
    match target_in(query) {
        Ok(target) => written(
            store
                .delete_key_auth(caller.me.id, workspace, &target)
                .await,
        ),
        Err(e) => field_error(e),
    }
}
