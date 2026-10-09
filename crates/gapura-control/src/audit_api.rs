//! `GET /api/audit`: the audit log, a page at a time, newest first.
//!
//! The same shape as `workspaces_api`'s list: the caller first, then the rule, then the query,
//! then the store. Anyone with a role in a workspace reads that workspace's entries, a superuser
//! every entry; see `audit`. A query that cannot be read is refused beside the field at fault.
//! Kubernetes mode keeps no audit log, so there this answers 404.

use crate::access_api::CallerError;
use crate::audit::{self, QueryInput};
use crate::configuration_api::{caller_of, field_error};
use crate::grants::Refusal;
use crate::state::AppState;
use crate::store::sqlstate;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio_postgres::error::SqlState;

/// What the log answers in Kubernetes mode, which keeps none.
const NO_AUDIT: &str = "This console keeps no audit log: it runs without a database.";

/// What it answers when the store cannot be read, for the caller or for the page.
const UNREAD: &str = "The console could not read the audit log. Try again in a moment.";

/// `configuration_api::early`, in the log's words.
fn early(error: CallerError) -> Response {
    match error {
        CallerError::Status(StatusCode::NOT_FOUND) => {
            crate::api::refuse(StatusCode::NOT_FOUND, NO_AUDIT)
        }
        CallerError::Status(StatusCode::SERVICE_UNAVAILABLE) => {
            crate::api::refuse(StatusCode::SERVICE_UNAVAILABLE, UNREAD)
        }
        other => crate::configuration_api::early(other),
    }
}

/// `GET /api/audit?before=&limit=&workspace=&kind=`: one page of the entries the caller may read.
pub async fn audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<QueryInput>, QueryRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    let visible = match audit::visible(&caller.rows, &caller.me) {
        Ok(v) => v,
        Err(r) => return r.into_response(),
    };
    // Every value is read as text, so only a query that is not one at all (a key given twice)
    // is refused here; anything else is refused beside its field.
    let Ok(Query(input)) = query else {
        return Refusal::Invalid("The query is not one this console understands.".into())
            .into_response();
    };
    let q = match audit::query(input) {
        Ok(q) => q,
        Err(e) => return field_error(e),
    };
    match store.audit(visible, &q).await {
        Ok(page) => Json(page).into_response(),
        Err(error) => {
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = sqlstate(&error).map(SqlState::code),
                "reading the audit log failed"
            );
            early(StatusCode::SERVICE_UNAVAILABLE.into())
        }
    }
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
    async fn without_a_store_there_is_no_audit_log() {
        let (status, sentence) = sentence_of(early(StatusCode::NOT_FOUND.into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(sentence, NO_AUDIT);
    }

    #[tokio::test]
    async fn a_failed_read_says_it_could_not_read() {
        let (status, sentence) = sentence_of(early(StatusCode::SERVICE_UNAVAILABLE.into())).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(sentence, UNREAD);
        let (status, _) = sentence_of(early(StatusCode::UNAUTHORIZED.into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
