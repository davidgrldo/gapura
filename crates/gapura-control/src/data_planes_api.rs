//! `/api/data-planes`: the gateways that fetch their configuration from this control plane, and
//! their tokens.
//!
//! The same shape as `consumers_api`, whose helpers these share: the caller first, then the path,
//! then the rule, then the body, then the store, which decides a write again inside its
//! transaction. Anyone with a role in any workspace reads the list; every write is a superuser's.
//! Registering and issuing answer 200 with the token, the only time it is shown, and are never
//! cached; revoking and deleting answer 204. Kubernetes mode keeps no data planes in a store, so
//! there these answer 404.

use crate::config_api;
use crate::configuration_api::{body, caller_of, early, field_error, unavailable, written};
use crate::data_planes::{self, IssuedToken};
use crate::grants::Refusal;
use crate::state::AppState;
use crate::store::WriteError;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;

/// A path that could not be read, which can be no data plane's name, so it reads as one that
/// does not exist.
fn unknown() -> Response {
    Refusal::NotFound("There is no such data plane.".into()).into_response()
}

/// The answer to registering or issuing: the token, once, never cached.
fn issued(result: Result<IssuedToken, WriteError>) -> Response {
    match result {
        Ok(issued) => ([(header::CACHE_CONTROL, "no-store")], Json(issued)).into_response(),
        Err(e) => written(Err(e)),
    }
}

/// `GET /api/data-planes`: every data plane by name, with its tokens' prefixes, whether it called
/// lately and whether it holds what is served now.
pub async fn list_data_planes(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    if let Err(r) = data_planes::may_read(&caller.rows, &caller.me) {
        return r.into_response();
    }
    // The tag `/v1/config` serves now, computed the way it computes it, so the two agree.
    let (_, snapshot) = match store.snapshot().await {
        Ok(read) => read,
        Err(e) => return unavailable(&e),
    };
    let etag = match config_api::served(&snapshot, &state.store_settings) {
        Ok((_, etag)) => etag,
        Err(e) => return unavailable(&e.into()),
    };
    match store.data_planes(&etag).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `POST /api/data-planes`: register a data plane, which answers with its first token.
pub async fn register_data_plane(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    if let Err(r) = data_planes::may_write(&caller.me) {
        return r.into_response();
    }
    let input = match body(raw, "a data plane") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match data_planes::name(input) {
        Ok(name) => issued(store.register_data_plane(caller.me.id, &name).await),
        Err(e) => field_error(e),
    }
}

/// `DELETE /api/data-planes/{name}`: delete a data plane, and its tokens with it.
pub async fn delete_data_plane(
    State(state): State<AppState>,
    headers: HeaderMap,
    name: Result<Path<String>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path(name)) = name else {
        return unknown();
    };
    match data_planes::may_write(&caller.me) {
        Ok(()) => written(store.delete_data_plane(caller.me.id, &name).await),
        Err(r) => r.into_response(),
    }
}

/// `POST /api/data-planes/{name}/tokens`: issue another token, the first half of rotating one,
/// which answers with the token itself.
pub async fn issue_data_plane_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    name: Result<Path<String>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path(name)) = name else {
        return unknown();
    };
    match data_planes::may_write(&caller.me) {
        Ok(()) => issued(store.issue_data_plane_token(caller.me.id, &name).await),
        Err(r) => r.into_response(),
    }
}

/// `DELETE /api/data-planes/{name}/tokens/{prefix}`: revoke one token, by the prefix the list
/// shows.
pub async fn revoke_data_plane_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((name, prefix))) = path else {
        return unknown();
    };
    match data_planes::may_write(&caller.me) {
        Ok(()) => written(
            store
                .revoke_data_plane_token(caller.me.id, &name, &prefix)
                .await,
        ),
        Err(r) => r.into_response(),
    }
}
