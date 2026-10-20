//! `/api/workspaces/{ws}/consumers`, `/key-auth`, `/jwt` and `/rate-limit`: store mode's
//! consumers, their API keys, the requirements that a request carry one or a JWT, and the limits
//! on how many requests come, per workspace, for everyone or for one consumer alone.
//!
//! The same shape as `configuration_api`, whose helpers these use: the caller first, then the
//! path, then the workspace and the role the action needs, then the body, then the store, which
//! decides a write again inside its transaction. Every write answers 204 except issuing a key,
//! which answers 200 with the key, the only time it is shown, and is never cached. Kubernetes mode
//! keeps no consumers in a store, so there these answer 404.

use crate::configuration::{Action, FieldError};
use crate::configuration_api::{
    body, caller_of, early, field_error, refuse_name, unavailable, unnamed, workspace_in, written,
};
use crate::consumers::{self, KeyInput, Target};
use crate::grants::Refusal;
use crate::state::AppState;
use crate::store::PREFIX_LEN;
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
        Ok(workspace) => {
            if let Some(r) = refuse_name("consumer", &name) {
                return r;
            }
            written(store.delete_consumer(caller.me.id, workspace, &name).await)
        }
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
    if let Some(r) = refuse_name("consumer", &name) {
        return r;
    }
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
        Ok(workspace) => {
            if let Some(r) = refuse_name("consumer", &name) {
                return r;
            }
            // A prefix is exactly the length the list shows, of ASCII, which is also what keeps
            // the store from slicing a longer string in the middle of a character.
            if prefix.len() != PREFIX_LEN || !prefix.is_ascii() || prefix.contains('\0') {
                return Refusal::NotFound(format!("There is no key {prefix} for {name}."))
                    .into_response();
            }
            written(
                store
                    .revoke_key(caller.me.id, workspace, &name, &prefix)
                    .await,
            )
        }
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
    let header = match consumers::header(input.header.as_deref()) {
        Ok(h) => h,
        Err(e) => return field_error(e),
    };
    written(match input.seen_updated_at.as_deref() {
        None => {
            store
                .put_key_auth(caller.me.id, workspace, &target, &header)
                .await
        }
        Some(seen) => {
            store
                .replace_key_auth(caller.me.id, workspace, &target, &header, seen)
                .await
        }
    })
}

/// `?target=`, as `delete_key_auth` and `delete_jwt` read it.
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

/// `?target=`, which `list_jwt` reads when it is there.
#[derive(Deserialize)]
pub struct MaybeTarget {
    target: Option<String>,
}

/// `GET /api/workspaces/{ws}/jwt`: where the workspace requires a JWT, the issuer and audience it
/// asks for and how many keys verify it. With `?target=…`, that target's own requirement with
/// its JWKS, which the console edits.
pub async fn list_jwt(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
    query: Result<Query<MaybeTarget>, QueryRejection>,
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
    let target = match query {
        Ok(Query(MaybeTarget { target: None })) => {
            return match store.jwt_policies(workspace).await {
                Ok(list) => Json(list).into_response(),
                Err(e) => unavailable(&e),
            }
        }
        Ok(Query(MaybeTarget { target: Some(t) })) => Target::parse(&t),
        Err(_) => Target::parse(""),
    };
    let target = match target {
        Ok(t) => t,
        Err(e) => return field_error(e),
    };
    match store.jwt_policy(workspace, &target).await {
        Ok(Some(one)) => Json(one).into_response(),
        Ok(None) => Refusal::NotFound(format!("{} has no JWT requirement.", target.as_text()))
            .into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `PUT /api/workspaces/{ws}/jwt`: require a JWT on the workspace, a service or a route.
pub async fn put_jwt(
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
    let input: consumers::JwtInput = match body(raw, "a JWT requirement") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    let target = match Target::parse(&input.target) {
        Ok(t) => t,
        Err(e) => return field_error(e),
    };
    match consumers::jwt(&input) {
        Ok(policy) => written(
            store
                .put_jwt(
                    caller.me.id,
                    workspace,
                    &target,
                    &policy,
                    input.seen_updated_at.as_deref(),
                )
                .await,
        ),
        Err(e) => field_error(e),
    }
}

/// `DELETE /api/workspaces/{ws}/jwt?target=…`: stop requiring a JWT there.
pub async fn delete_jwt(
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
        Ok(target) => written(store.delete_jwt(caller.me.id, workspace, &target).await),
        Err(e) => field_error(e),
    }
}

/// `GET /api/workspaces/{ws}/rate-limit`: where the workspace limits requests, and to how many.
pub async fn list_rate_limit(
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
    match store.rate_limits(workspace).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `?target=…&consumer=…`, as `delete_rate_limit` reads it: the consumer's own limit when
/// `consumer` names one, the limit on everyone when it is absent. Like the body of a `PUT`, it
/// refuses any key it does not know, so a misspelt `consumer` is refused rather than read as no
/// consumer at all, which would remove the limit on everyone. `target` may be left out
/// here only so that `delete_rate_limit` can refuse a query without one as an empty one, as
/// `target_in` does.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitQuery {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    consumer: Option<String>,
}

/// What `delete_rate_limit` answers a query it cannot read: one that names a field it does not
/// know, or one field twice. It is refused beside `target`, the field every such query needs.
fn unread_rate_limit_query() -> FieldError {
    FieldError {
        field: "target".into(),
        sentence: "Name target, and consumer for a consumer's own limit, and nothing else.".into(),
    }
}

/// `PUT /api/workspaces/{ws}/rate-limit`: limit requests on the workspace, a service or a route,
/// for everyone or, when the body names a `consumer`, for that consumer alone. The two are
/// separate limits with stamps of their own, so the `seen_updated_at` sent is that of the one
/// this write replaces.
pub async fn put_rate_limit(
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
    let input: consumers::RateLimitInput = match body(raw, "a request limit") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    let target = match Target::parse(&input.target) {
        Ok(t) => t,
        Err(e) => return field_error(e),
    };
    let consumer = match consumers::consumer_named(input.consumer.as_deref()) {
        Ok(c) => c,
        Err(e) => return field_error(e),
    };
    match consumers::rate_limit(&input) {
        Ok(limit) => written(
            store
                .put_rate_limit(
                    caller.me.id,
                    workspace,
                    &target,
                    consumer.as_deref(),
                    limit,
                    input.seen_updated_at.as_deref(),
                )
                .await,
        ),
        Err(e) => field_error(e),
    }
}

/// `DELETE /api/workspaces/{ws}/rate-limit?target=…&consumer=…`: stop limiting requests there,
/// for the consumer `consumer` names alone, or for everyone when it is absent. Either leaves the
/// other in place. A query naming anything else is refused, and removes nothing.
pub async fn delete_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
    query: Result<Query<RateLimitQuery>, QueryRejection>,
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
    let Ok(Query(query)) = query else {
        return field_error(unread_rate_limit_query());
    };
    // A query that names no target is refused as an empty one, beside `target`, as `target_in`
    // refuses it.
    let target = match Target::parse(query.target.as_deref().unwrap_or("")) {
        Ok(t) => t,
        Err(e) => return field_error(e),
    };
    let consumer = match consumers::consumer_named(query.consumer.as_deref()) {
        Ok(c) => c,
        Err(e) => return field_error(e),
    };
    written(
        store
            .delete_rate_limit(caller.me.id, workspace, &target, consumer.as_deref())
            .await,
    )
}
