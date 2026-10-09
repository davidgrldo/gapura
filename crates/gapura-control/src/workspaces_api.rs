//! `/api/workspaces` and `/api/workspaces/{ws}`: the workspaces themselves, beside the routes
//! under them that hold each one's configuration.
//!
//! The same shape as `data_planes_api`, whose helpers these share: the caller first, then the
//! rule, then the path, then the body, then the store, which decides a write again inside its
//! transaction. Superusers and workspace admins read the list, an admin only the workspaces they
//! administer; creating, renaming and deleting are a superuser's, refused here before the path or
//! the body is looked at. Every write answers 204. Kubernetes mode keeps no workspaces in a store,
//! so there these answer 404.

use crate::access_api::CallerError;
use crate::configuration_api::{body, caller_of, field_error, unavailable};
use crate::grants::Refusal;
use crate::grants_api::unsaved;
use crate::state::AppState;
use crate::store::{sqlstate, WriteError};
use crate::workspaces::{self, WorkspaceInput};
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio_postgres::error::SqlState;

/// What a route about workspaces answers in Kubernetes mode, which keeps none.
const NO_WORKSPACES: &str = "This console keeps no workspaces: it runs without a database.";

/// What the console shows when another write got in the way, after the store has already tried
/// again where that could settle it. `configuration_api`'s says "this workspace", which reads
/// wrongly for a write to the workspaces themselves.
const CONTENDED: &str =
    "Someone else was changing workspaces at that moment, so this change was not saved. Try again.";

/// `configuration_api::early`, but a console with no store keeps no workspaces, not "no
/// configuration".
fn early(error: CallerError) -> Response {
    match error {
        CallerError::Status(StatusCode::NOT_FOUND) => {
            crate::api::refuse(StatusCode::NOT_FOUND, NO_WORKSPACES)
        }
        other => crate::configuration_api::early(other),
    }
}

/// `configuration_api::written`, with a workspace's words for a failure in the store, and its
/// own label in the log.
fn written(result: Result<(), WriteError>) -> Response {
    match result {
        Err(WriteError::Store(error)) => {
            let code = sqlstate(&error);
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = code.map(SqlState::code),
                "a workspace write failed"
            );
            crate::api::refuse(StatusCode::SERVICE_UNAVAILABLE, unsaved(code, CONTENDED))
        }
        other => crate::configuration_api::written(other),
    }
}

/// The workspace a path names, when it can name one. A path that cannot be read, or a name that
/// could be no workspace's, is answered as a workspace that does not exist, without a query, so
/// a name the database would reject (a NUL byte) never reaches it. Asked only once the caller is
/// known to be a superuser, so a refused caller learns nothing from the path.
fn workspace(ws: Result<Path<String>, PathRejection>) -> Result<String, Refusal> {
    let Ok(Path(ws)) = ws else {
        return Err(Refusal::NotFound("There is no such workspace.".into()));
    };
    match crate::configuration::name(&ws, "name") {
        Ok(_) => Ok(ws),
        Err(_) => Err(Refusal::NotFound(format!(
            "There is no workspace named {ws}."
        ))),
    }
}

/// `GET /api/workspaces`: the workspaces by name, with what each holds and how many grants and
/// mappings reach into it; to a workspace admin, only the ones they administer.
pub async fn list_workspaces(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    let only = match workspaces::may_list(&caller.rows, &caller.me) {
        Ok(only) => only,
        Err(r) => return r.into_response(),
    };
    match store.workspaces(only.as_ref()).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => unavailable(&e),
    }
}

/// `POST /api/workspaces`: create an empty workspace.
pub async fn create_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = workspaces::may_write(&caller.me) {
        return r.into_response();
    }
    let input: WorkspaceInput = match body(raw, "a workspace") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match workspaces::name(input) {
        Ok(name) => written(store.create_workspace(caller.me.id, &name).await),
        Err(e) => field_error(e),
    }
}

/// `PUT /api/workspaces/{ws}`: rename a workspace. What it holds, and the grants into it, follow.
pub async fn rename_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = workspaces::may_write(&caller.me) {
        return r.into_response();
    }
    let from = match workspace(ws) {
        Ok(from) => from,
        Err(r) => return r.into_response(),
    };
    let input: WorkspaceInput = match body(raw, "a workspace") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    match workspaces::name(input) {
        Ok(to) => written(store.rename_workspace(caller.me.id, &from, &to).await),
        Err(e) => field_error(e),
    }
}

/// `DELETE /api/workspaces/{ws}`: delete an empty workspace, and the grants and mappings into it.
pub async fn delete_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: Result<Path<String>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = workspaces::may_write(&caller.me) {
        return r.into_response();
    }
    let name = match workspace(ws) {
        Ok(name) => name,
        Err(r) => return r.into_response(),
    };
    written(store.delete_workspace(caller.me.id, &name).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn sentence_of(response: Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, body["error"].as_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn without_a_store_there_are_no_workspaces() {
        let (status, sentence) = sentence_of(early(StatusCode::NOT_FOUND.into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(sentence, NO_WORKSPACES);
    }

    #[tokio::test]
    async fn a_failed_workspace_write_is_worded_for_workspaces() {
        let (status, sentence) =
            sentence_of(written(Err(WriteError::Store(anyhow::anyhow!("down"))))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!sentence.contains("configuration"), "{sentence}");
        assert_eq!(
            unsaved(Some(&SqlState::T_R_DEADLOCK_DETECTED), CONTENDED),
            CONTENDED
        );
        assert!(!CONTENDED.contains("this workspace"));
    }
}
