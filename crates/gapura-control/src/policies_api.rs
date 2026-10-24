//! `/api/workspaces/{ws}/policies/{kind}`: the policies whose configuration is the policy itself,
//! one endpoint for every such kind, for the whole workspace, a service or a route.
//!
//! The same shape as `consumers_api`: the caller first, then the path, then the workspace and the
//! role the action needs, then the kind, then the body, then the store, which decides a write
//! again inside its transaction. Every write answers 204. Kubernetes mode keeps no policies in a
//! store, so there these answer 404.

use crate::configuration::{self, Action};
use crate::configuration_api::{
    body, caller_of, early, field_error, unavailable, unnamed, workspace_in, written,
};
use crate::consumers::Target;
use crate::consumers_api::{target_in, TargetQuery};
use crate::grants::Refusal;
use crate::policies::{self, PolicyInput};
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// The kind a path names, or the answer to one this endpoint does not keep. The name is not
/// echoed back.
fn kind_in(kind: &str) -> Result<&'static str, Box<Response>> {
    policies::KINDS
        .iter()
        .copied()
        .find(|k| *k == kind)
        .ok_or_else(|| {
            Refusal::NotFound("There is no such policy kind.".to_string())
                .into_response()
                .into()
        })
}

/// `GET /api/workspaces/{ws}/policies/{kind}`: where the workspace has a policy of that kind,
/// and what it is. A caller who may change the workspace reads every policy whole, since the
/// console edits a policy from what it read; one who may only read it reads the form the audit
/// log records ([`policies::audited`]), a transformer's names without the values it writes.
pub async fn list_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((ws, kind))) = path else {
        return unnamed();
    };
    let workspace = match workspace_in(&caller, &ws, Action::Read) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    let kind = match kind_in(&kind) {
        Ok(k) => k,
        Err(r) => return *r,
    };
    let values = configuration::allowed(&caller.rows, &caller.me, workspace, Action::Write).is_ok();
    match store.policies_of(workspace, kind, values).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `PUT /api/workspaces/{ws}/policies/{kind}`: set a policy of that kind on the workspace, a
/// service or a route, replacing the one there from the stamp the caller read.
pub async fn put_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((ws, kind))) = path else {
        return unnamed();
    };
    let workspace = match workspace_in(&caller, &ws, Action::Write) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    let kind = match kind_in(&kind) {
        Ok(k) => k,
        Err(r) => return *r,
    };
    let input: PolicyInput = match body(raw, "a policy") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    let target = match Target::parse(&input.target) {
        Ok(t) => t,
        Err(e) => return field_error(e),
    };
    match policies::parse(kind, input.config) {
        Ok(plugin) => written(
            store
                .put_policy(
                    caller.me.id,
                    workspace,
                    &target,
                    &plugin,
                    input.seen_updated_at.as_deref(),
                )
                .await,
        ),
        Err(e) => field_error(e),
    }
}

/// `DELETE /api/workspaces/{ws}/policies/{kind}?target=…`: remove the policy of that kind there.
pub async fn delete_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<(String, String)>, PathRejection>,
    query: Result<Query<TargetQuery>, QueryRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return early(status),
    };
    let Ok(Path((ws, kind))) = path else {
        return unnamed();
    };
    let workspace = match workspace_in(&caller, &ws, Action::Write) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    let kind = match kind_in(&kind) {
        Ok(k) => k,
        Err(r) => return *r,
    };
    match target_in(query) {
        Ok(target) => written(
            store
                .delete_policy(caller.me.id, workspace, &target, kind)
                .await,
        ),
        Err(e) => field_error(e),
    }
}
