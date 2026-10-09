//! `/api/users` writes and `/api/me/password`: accounts as a superuser changes them, and a
//! password as its owner changes it.
//!
//! The same shape as `data_planes_api`, whose helpers these share: the caller first, then the
//! path, then the rule, then the body, then the store, which decides a write again inside its
//! transaction. Every account action is a superuser's, refused here before any transaction, since
//! the store's first step locks every superuser. Creating an account and resetting a password
//! answer 200 with the temporary password, the only time it is shown, and are never cached; the
//! other writes answer 204. Changing one's own password is the one write an account on a
//! temporary password may make, is throttled as a sign-in is, and answers 204 with a fresh
//! session, since it signs the account out everywhere. Kubernetes mode keeps no accounts in a
//! store, so there these answer 404.

use crate::access_api::CallerError;
use crate::accounts::{self, NewAccount, PasswordChange, CURRENT};
use crate::configuration_api::{body, caller_of, field_error};
use crate::grants::Refusal;
use crate::grants_api::{unsaved, NO_ACCOUNTS};
use crate::state::AppState;
use crate::store::{sqlstate, WriteError};
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

/// What the console shows when another write got in the way, after the store has already tried
/// again where that could settle it. `configuration_api`'s says "this workspace", which no
/// account write concerns.
const CONTENDED: &str =
    "Someone else was changing accounts at that moment, so this change was not saved. Try again.";

/// `configuration_api::early`, but a console with no store keeps no accounts, not "no
/// configuration".
fn early(error: CallerError) -> Response {
    match error {
        CallerError::Status(StatusCode::NOT_FOUND) => {
            crate::api::refuse(StatusCode::NOT_FOUND, NO_ACCOUNTS)
        }
        other => crate::configuration_api::early(other),
    }
}

/// `configuration_api::written`, with an account's words for a failure in the store, and its
/// own label in the log.
fn written(result: Result<(), WriteError>) -> Response {
    match result {
        Err(WriteError::Store(error)) => {
            let code = sqlstate(&error);
            tracing::warn!(
                error = format!("{error:#}"),
                sqlstate = code.map(SqlState::code),
                "an account write failed"
            );
            crate::api::refuse(StatusCode::SERVICE_UNAVAILABLE, unsaved(code, CONTENDED))
        }
        other => crate::configuration_api::written(other),
    }
}

/// What `PUT /api/users/{id}/status` sends.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusChange {
    disabled: bool,
}

/// What `PUT /api/users/{id}/superuser` sends.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuperuserChange {
    superuser: bool,
}

/// A new account, with the temporary password it signs in with first.
#[derive(Serialize)]
struct Created {
    id: Uuid,
    username: String,
    password: String,
}

/// A temporary password a reset handed out.
#[derive(Serialize)]
struct Reset {
    password: String,
}

/// An answer carrying a password: shown once, never cached.
fn once<T: Serialize>(value: T) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

/// The account a path names, if it can name one. Asked only once the caller is known to be a
/// superuser, so a refused caller learns nothing from the path.
fn account(id: Result<Path<String>, PathRejection>) -> Option<Uuid> {
    id.ok().and_then(|Path(id)| id.parse().ok())
}

/// A path that names no account, answered as an account that does not exist.
fn no_such_account() -> Response {
    Refusal::NotFound("There is no such account.".into()).into_response()
}

/// `POST /api/users`: create a local account, which answers with its temporary password.
pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = accounts::may_administer(&caller.me) {
        return r.into_response();
    }
    let input: NewAccount = match body(raw, "an account") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    let username = match accounts::username(&input) {
        Ok(name) => name,
        Err(e) => return field_error(e),
    };
    match store
        .create_account(caller.me.id, &username, input.superuser)
        .await
    {
        Ok((id, password)) => once(Created {
            id,
            username,
            password,
        }),
        Err(e) => written(Err(e)),
    }
}

/// `POST /api/users/{id}/password`: give a local account a new temporary password, which signs
/// it out everywhere, and answer with it.
pub async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = accounts::may_administer(&caller.me) {
        return r.into_response();
    }
    let Some(id) = account(id) else {
        return no_such_account();
    };
    match store.reset_password(caller.me.id, id).await {
        Ok(password) => once(Reset { password }),
        Err(e) => written(Err(e)),
    }
}

/// `PUT /api/users/{id}/status`: disable an account, which signs it out everywhere, or enable it.
pub async fn set_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    id: Result<Path<String>, PathRejection>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = accounts::may_administer(&caller.me) {
        return r.into_response();
    }
    let Some(id) = account(id) else {
        return no_such_account();
    };
    let input: StatusChange = match body(raw, "an account's status") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    written(store.set_disabled(caller.me.id, id, input.disabled).await)
}

/// `PUT /api/users/{id}/superuser`: make an account a superuser, or no longer one, which signs it
/// out everywhere.
pub async fn set_superuser(
    State(state): State<AppState>,
    headers: HeaderMap,
    id: Result<Path<String>, PathRejection>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = accounts::may_administer(&caller.me) {
        return r.into_response();
    }
    let Some(id) = account(id) else {
        return no_such_account();
    };
    let input: SuperuserChange = match body(raw, "a superuser change") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    written(store.set_superuser(caller.me.id, id, input.superuser).await)
}

/// `DELETE /api/users/{id}`: delete a local account.
pub async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let (store, caller) = match caller_of(&state, &headers).await {
        Ok(found) => found,
        Err(error) => return early(error),
    };
    if let Err(r) = accounts::may_administer(&caller.me) {
        return r.into_response();
    }
    let Some(id) = account(id) else {
        return no_such_account();
    };
    written(store.delete_account(caller.me.id, id).await)
}

/// A password change refused for its count of wrong current passwords, not for this one: 429,
/// with how long to wait, in the words the sign-in form uses.
fn throttled(wait: std::time::Duration) -> Response {
    let mut response = crate::api::refuse(
        StatusCode::TOO_MANY_REQUESTS,
        &crate::throttle::wait_message(wait),
    );
    if let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// `POST /api/me/password`: replace the caller's own password, given the current one.
///
/// Open to an account on a temporary password, which is what it is for. A wrong current password
/// is a failed sign-in to the throttle, counted against the account's name at this address as the
/// sign-in form counts it, so neither is a way around the other's limit. The change signs the
/// account out everywhere, this browser included, so the answer carries a fresh session, issued no
/// earlier than the cut-off the store set: the cut-off is the database's clock and the session the
/// console's, and a console running behind would otherwise sign the person out by their own
/// change.
pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    raw: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(store) = state.store.as_deref() else {
        return early(StatusCode::NOT_FOUND.into());
    };
    let caller = match crate::access_api::signed_in(store, &headers, &state.session_key).await {
        Ok(caller) => caller,
        Err(status) => return early(status.into()),
    };
    let input: PasswordChange = match body(raw, "a password change") {
        Ok(i) => i,
        Err(r) => return *r,
    };
    // Before the password is looked at: a locked pair or a busy address costs no hashing.
    let addr = crate::login::client_addr(&state, &headers, peer);
    let name = caller.me.name.as_str();
    let attempt = match state.sign_in.begin(Some(name), addr) {
        Ok(attempt) => attempt,
        Err(wait) => return throttled(wait),
    };
    let cut_off = match store
        .change_own_password(caller.me.id, &input.current, &input.new)
        .await
    {
        Ok(cut_off) => cut_off,
        Err(WriteError::Field(error)) if error.field == CURRENT => {
            attempt.failed();
            return field_error(error);
        }
        // Anything else said nothing about the current password; dropping the attempt gives
        // its reservation back.
        Err(e) => return written(Err(e)),
    };
    attempt.succeeded();
    tracing::info!(user = %caller.me.id, "changed their password");
    let issued_at = crate::login::now_millis().max(u64::try_from(cut_off).unwrap_or(0));
    let cookie =
        crate::login::session_cookie(&state, caller.me.id.to_string(), Vec::new(), issued_at);
    let Ok(value) = HeaderValue::from_str(&cookie) else {
        tracing::error!("a session cookie would not fit in a header");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    (
        StatusCode::NO_CONTENT,
        [
            (header::SET_COOKIE, value),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response()
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

    /// Nothing an account route says is about configuration or a workspace.
    fn about_accounts(sentence: &str) {
        for word in ["configuration", "workspace"] {
            assert!(!sentence.contains(word), "{sentence}");
        }
    }

    #[tokio::test]
    async fn without_a_store_there_are_no_accounts() {
        let (status, sentence) = sentence_of(early(StatusCode::NOT_FOUND.into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(sentence, NO_ACCOUNTS);
    }

    #[tokio::test]
    async fn a_hash_that_found_the_queue_full_is_busy_not_unsaved() {
        // Creating, resetting and changing a password hash through `password::hash_or_busy`,
        // which answers at once rather than waiting behind a full queue.
        let (status, sentence) = sentence_of(written(Err(WriteError::Busy))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            sentence,
            "The console is busy right now. Try again in a moment."
        );
    }

    #[tokio::test]
    async fn a_failed_account_write_is_worded_for_accounts() {
        let (status, sentence) =
            sentence_of(written(Err(WriteError::Store(anyhow::anyhow!("down"))))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        about_accounts(&sentence);
        assert_eq!(
            unsaved(Some(&SqlState::LOCK_NOT_AVAILABLE), CONTENDED),
            CONTENDED
        );
        about_accounts(CONTENDED);
    }
}
