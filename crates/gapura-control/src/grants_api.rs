//! The console's writes to who holds what: `PATCH /api/users/{id}/roles`, and `PUT` and
//! `DELETE /api/group-mappings`.
//!
//! Each handler first refuses what it can cheaply, over the rows `admin_caller` reads anyway:
//! no live session is 401, someone who administers nothing is 403, and so is a workspace
//! outside what the caller administers. The decision that counts is made again by the store,
//! inside the transaction that writes. Every refusal carries `{"error": sentence}`, which the
//! console shows as it is. Kubernetes mode keeps no accounts, so there these answer 404.
//!
//! What a handler's extractors could not read is answered only after the caller has been
//! checked, so a request that is both malformed and anonymous is 401, not a 400 that tells a
//! stranger how the route is shaped.

use crate::access_api::{admin_caller, CallerError, StoreCaller};
use crate::grants::{self, GroupMapping, Refusal, RoleChanges};
use crate::state::AppState;
use crate::store::{sqlstate, WriteError};
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::collections::BTreeSet;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

/// The most a request body may hold. The longest real one names a few workspaces, a few hundred
/// bytes, so this leaves room for a thousand of them while buffering far less than axum's own
/// default of two mebibytes for a caller that has not been checked yet.
pub(crate) const MAX_BODY: usize = 64 * 1024;

/// What the console shows when another write got in the way: a lock not granted in time, a
/// deadlock, or a duplicate, after the store has already tried again where that could settle it.
/// Saving once more is likely to work, so the sentence says so.
const CONTENDED: &str = "Someone else was changing the same roles at that moment, so this change was not saved. Try again.";

/// What the console shows when the store failed for any other reason: unreachable, a table gone,
/// a role it does not know. It does not say that nothing was changed, because a commit that
/// failed on the wire may or may not have happened.
pub(crate) const NOT_SAVED: &str = "The console could not save this change. Try again in a moment.";

/// What a write is told when the password check or hash it needed found too many waiting.
pub(crate) const BUSY: &str = "The console is busy right now. Try again in a moment.";

/// What a route about accounts answers in Kubernetes mode, which keeps none.
pub(crate) const NO_ACCOUNTS: &str = "This console keeps no accounts: it runs without a database.";

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        crate::api::refuse(self.status(), self.sentence())
    }
}

/// `admin_caller`'s refusals, in words.
fn refused_early(error: CallerError) -> Response {
    let status = match error {
        CallerError::MustChangePassword => return error.into_response(),
        CallerError::Status(status) => status,
    };
    let sentence = match status {
        StatusCode::UNAUTHORIZED => "You are not signed in.",
        StatusCode::FORBIDDEN => "You do not administer any workspace.",
        StatusCode::NOT_FOUND => NO_ACCOUNTS,
        // The caller could not be read back from the store, and `store_caller` has logged why.
        StatusCode::SERVICE_UNAVAILABLE => NOT_SAVED,
        // `admin_caller` answers with nothing else, but a status it grows later should still
        // read as itself rather than as a failure of the store.
        other => other
            .canonical_reason()
            .unwrap_or("The request was refused."),
    };
    crate::api::refuse(status, sentence)
}

/// What to tell the console when the store could not make a write, by what Postgres answered:
/// `contended` when another write got in the way, `NOT_SAVED` for anything else.
pub(crate) fn unsaved(code: Option<&SqlState>, contended: &'static str) -> &'static str {
    match code {
        Some(code)
            if *code == SqlState::LOCK_NOT_AVAILABLE
                || *code == SqlState::T_R_DEADLOCK_DETECTED
                || *code == SqlState::UNIQUE_VIOLATION =>
        {
            contended
        }
        _ => NOT_SAVED,
    }
}

/// The answer once the store has had its say.
fn written(result: Result<(), WriteError>) -> Response {
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(WriteError::Refused(refusal)) => refusal.into_response(),
        Err(WriteError::Field(error)) => crate::configuration_api::field_error(error),
        Err(WriteError::Busy) => crate::api::refuse(StatusCode::SERVICE_UNAVAILABLE, BUSY),
        Err(WriteError::Store(error)) => {
            let code = sqlstate(&error);
            // An `anyhow::Error` shown with `%` prints only its outermost error, and for a
            // database error that is just "db error": the chain and the SQLSTATE hold the reason.
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = code.map(SqlState::code),
                "a write to the store failed"
            );
            crate::api::refuse(StatusCode::SERVICE_UNAVAILABLE, unsaved(code, CONTENDED))
        }
    }
}

/// A body that could not be read into memory: longer than `MAX_BODY`, or cut off. Axum's own
/// answer to either is plain text, which the console cannot show as it is, so it is worded here,
/// under the status axum chose: 413 for the first, 400 for the second. `what` is what the
/// request would have been, with its article: "a change to roles".
pub(crate) fn unreadable(rejection: &BytesRejection, what: &str) -> Response {
    let status = rejection.status();
    let sentence = if status == StatusCode::PAYLOAD_TOO_LARGE {
        format!("That request is too large to be {what}.")
    } else {
        "The request could not be read.".to_string()
    };
    crate::api::refuse(status, &sentence)
}

/// `PATCH /api/users/{id}/roles`: give, change or remove the account's direct grants in the
/// workspaces the body names, all of them or none.
pub async fn set_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    id: Result<Path<String>, PathRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller, _) = match admin_caller(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return refused_early(status),
    };
    let body = match body {
        Ok(body) => body,
        Err(rejection) => return unreadable(&rejection, "a change to roles"),
    };
    match role_changes(&caller, id, &body) {
        Ok((target, wanted)) => {
            written(store.set_direct_roles(caller.me.id, target, &wanted).await)
        }
        Err(refusal) => refusal.into_response(),
    }
}

/// What `set_roles` decides before the store is asked: the account, the changes, and that the
/// caller administers every workspace they name. Whether the account exists is the store's to
/// say, after the same check, so a refused request says nothing about it.
fn role_changes(
    caller: &StoreCaller,
    id: Result<Path<String>, PathRejection>,
    body: &[u8],
) -> Result<(Uuid, RoleChanges), Refusal> {
    // A path rejection is only a segment that does not decode as UTF-8, which is no more an
    // account id than text that fails to parse as one.
    let Path(id) = id.map_err(|_| Refusal::Invalid("That is not an account id.".into()))?;
    let target = id
        .parse()
        .map_err(|_| Refusal::Invalid(format!("{id:?} is not an account id.")))?;
    let wanted = grants::parse_role_changes(body)?;
    grants::authorise(&caller.rows, &caller.me, &wanted.keys().copied().collect())?;
    Ok((target, wanted))
}

/// `PUT /api/group-mappings`: map a group to a role in a workspace, or change the role it maps
/// to.
pub async fn put_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller, _) = match admin_caller(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return refused_early(status),
    };
    let body = match body {
        Ok(body) => body,
        Err(rejection) => return unreadable(&rejection, "a change to roles"),
    };
    match mapping_to_put(&caller, &body) {
        Ok(mapping) => written(
            store
                .put_group_mapping(
                    caller.me.id,
                    mapping.workspace,
                    &mapping.group,
                    mapping.role,
                )
                .await,
        ),
        Err(refusal) => refusal.into_response(),
    }
}

/// What `put_mapping` decides before the store is asked.
fn mapping_to_put(caller: &StoreCaller, body: &[u8]) -> Result<GroupMapping, Refusal> {
    let mapping = grants::parse_mapping(body)?;
    grants::authorise(
        &caller.rows,
        &caller.me,
        &BTreeSet::from([mapping.workspace]),
    )?;
    Ok(mapping)
}

/// Which mapping `DELETE /api/group-mappings` removes. In the query rather than the path,
/// because a group name such as `/platform-team` has slashes of its own. Like the body of a
/// `PUT`, it names these two fields and nothing else, so a misspelt one is refused rather than
/// ignored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingKey {
    workspace_id: String,
    group: String,
}

/// `DELETE /api/group-mappings?workspace_id=…&group=…`: remove one mapping.
pub async fn delete_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    key: Result<Query<MappingKey>, QueryRejection>,
) -> Response {
    let (store, caller, _) = match admin_caller(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return refused_early(status),
    };
    match mapping_to_remove(&caller, key) {
        Ok((workspace, group)) => written(
            store
                .delete_group_mapping(caller.me.id, workspace, &group)
                .await,
        ),
        Err(refusal) => refusal.into_response(),
    }
}

/// What `delete_mapping` decides before the store is asked.
///
/// The group name is not held to the rules a new one is. Removing a mapping grants nothing,
/// and one made before those rules, or by hand, has to stay removable from the console.
fn mapping_to_remove(
    caller: &StoreCaller,
    key: Result<Query<MappingKey>, QueryRejection>,
) -> Result<(Uuid, String), Refusal> {
    let Query(key) = key.map_err(|_| {
        Refusal::Invalid(
            "Name the mapping to remove with workspace_id and group in the query.".into(),
        )
    })?;
    let workspace = grants::workspace_id(&key.workspace_id)?;
    grants::group_to_remove(&key.group)?;
    grants::authorise(&caller.rows, &caller.me, &BTreeSet::from([workspace]))?;
    Ok((workspace, key.group))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_that_met_another_is_told_so_and_any_other_failure_is_not() {
        for code in [
            &SqlState::LOCK_NOT_AVAILABLE,
            &SqlState::T_R_DEADLOCK_DETECTED,
            &SqlState::UNIQUE_VIOLATION,
        ] {
            assert_eq!(unsaved(Some(code), CONTENDED), CONTENDED, "{}", code.code());
        }
        // A table gone, a connection lost, and an error that was never Postgres's own.
        for code in [
            Some(&SqlState::UNDEFINED_TABLE),
            Some(&SqlState::CONNECTION_FAILURE),
            None,
        ] {
            assert_eq!(
                unsaved(code, CONTENDED),
                NOT_SAVED,
                "{:?}",
                code.map(SqlState::code)
            );
        }
    }
}
