//! Who is signed in, and the Users and Roles pages: store mode's view of `access`.
//!
//! Every handler here reads its caller back from the store on each request, so a grant takes
//! effect on the next one and a disabled account is signed out on the next one.

use crate::access::{Access, Method, Role, Rows, User};
use crate::accounts::session_current;
use crate::state::AppState;
use crate::store::{sqlstate, Store};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::collections::BTreeSet;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

/// The signed-in account in store mode, with the rows its access is computed from.
pub struct StoreCaller {
    pub rows: Rows,
    pub me: User,
}

/// What every store API route but `/api/me` and the password change says to an account still on
/// a temporary password.
pub const CHOOSE_A_NEW_PASSWORD: &str = "Choose a new password first.";

/// Why there is no caller to act for: a bare status, or an account that must replace its
/// temporary password, whose 403 has to say so, since it is the one refusal the console acts on
/// rather than shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerError {
    Status(StatusCode),
    MustChangePassword,
}

impl From<StatusCode> for CallerError {
    fn from(status: StatusCode) -> Self {
        CallerError::Status(status)
    }
}

impl IntoResponse for CallerError {
    fn into_response(self) -> Response {
        match self {
            CallerError::Status(status) => status.into_response(),
            CallerError::MustChangePassword => {
                crate::api::refuse(StatusCode::FORBIDDEN, CHOOSE_A_NEW_PASSWORD)
            }
        }
    }
}

/// The caller behind `headers`, read back from `store`, as every store API route but two reads
/// them: as `signed_in`, and refused while their account must replace a temporary password.
pub async fn store_caller(
    store: &Store,
    headers: &HeaderMap,
    key: &[u8],
) -> Result<StoreCaller, CallerError> {
    let caller = signed_in(store, headers, key).await?;
    if caller.me.must_change_password {
        return Err(CallerError::MustChangePassword);
    }
    Ok(caller)
}

/// The caller behind `headers`, read back from `store`, whether or not they must replace a
/// temporary password: for `/api/me`, which says they must, and the change that does it.
///
/// 401 when there is no session, when it names no account -- a session issued in Kubernetes
/// mode carries an email where store mode puts an id -- when the account is disabled, or when
/// the session was issued before the account's sessions were cut off. 503 when the store cannot
/// be read, which is not the caller's fault and must not look like it.
pub async fn signed_in(
    store: &Store,
    headers: &HeaderMap,
    key: &[u8],
) -> Result<StoreCaller, StatusCode> {
    let session = crate::api::session_from(headers, key).ok_or(StatusCode::UNAUTHORIZED)?;
    let id: Uuid = session
        .subject
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let rows = store.access_rows().await.map_err(|error| {
        // An `anyhow::Error` shown with `%` prints only its outermost error, and for a database
        // error that is just "db error": the chain and the SQLSTATE hold the reason.
        tracing::warn!(
            error = format!("{error:#}"),
            sqlstate = sqlstate(&error).map(SqlState::code),
            "reading accounts from the store failed"
        );
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    let me = rows
        .users
        .iter()
        .find(|u| {
            u.id == id && !u.disabled && session_current(session.issued_at, u.sessions_valid_after)
        })
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(StoreCaller { rows, me })
}

/// The store, the caller and the workspaces they administer, when they are a superuser or
/// administer at least one. A superuser keeps these pages even with no workspaces at all, the
/// state `waiting` already guards. Kubernetes mode has no accounts to list, so there these pages
/// do not exist. The writes in `grants_api` start here too, so they refuse exactly whom these
/// pages refuse, and they take the store from here rather than look for it a second time.
pub(crate) async fn admin_caller<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
) -> Result<(&'a Store, StoreCaller, BTreeSet<Uuid>), CallerError> {
    let store = state.store.as_deref().ok_or(StatusCode::NOT_FOUND)?;
    let caller = store_caller(store, headers, &state.session_key).await?;
    let within = caller.rows.grantable(&caller.me);
    if within.is_empty() && !caller.me.superuser {
        return Err(StatusCode::FORBIDDEN.into());
    }
    Ok((store, caller, within))
}

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Me {
    /// Enough for the console to leave out what only store mode has.
    Kubernetes,
    Store {
        /// The account's id, as `/api/users` names it, so the console can tell the reader's own
        /// row from everyone else's.
        id: Uuid,
        name: String,
        method: Method,
        superuser: bool,
        waiting: bool,
        /// Signed in with a temporary password: the console offers nothing but replacing it,
        /// which every other store API route insists on with a 403.
        must_change_password: bool,
        /// A local account, which has a password of its own to change; an OIDC one does not.
        local: bool,
        /// Every workspace where the caller holds a role, that role, and every grant that gives
        /// them one there, as `/api/users` lists them: what a change to one of those grants would
        /// leave the caller holding is the console's to say before it is made.
        roles: Vec<AccessView>,
        /// Where the caller is admin, and so may see and grant other people's roles. Named, so a
        /// form can list them without asking again, and in the order of their names.
        grantable: Vec<WorkspaceName>,
    },
}

/// A workspace, named the way `/api/users` and `/api/roles` name them, so the console reads one
/// shape.
#[derive(Serialize)]
pub struct WorkspaceName {
    workspace_id: Uuid,
    workspace: String,
}

/// `GET /api/me`: who this is and what they hold. A waiting account, and one that must replace a
/// temporary password, gets an answer here and a 403 everywhere else, so the console can say why
/// instead of showing empty pages.
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Me>, CallerError> {
    let Some(store) = &state.store else {
        crate::api::session_from(&headers, &state.session_key).ok_or(StatusCode::UNAUTHORIZED)?;
        return Ok(Json(Me::Kubernetes));
    };
    let caller = signed_in(store, &headers, &state.session_key).await?;
    let roles = caller
        .rows
        .workspaces
        .iter()
        .filter_map(|w| {
            caller
                .rows
                .effective(&caller.me, w.id)
                .map(|access| AccessView {
                    workspace_id: w.id,
                    workspace: w.name.clone(),
                    access,
                })
        })
        .collect();
    // Walked in the rows' order, which is by name, rather than in the set's, which is by id.
    let within = caller.rows.grantable(&caller.me);
    let grantable = caller
        .rows
        .workspaces
        .iter()
        .filter(|w| within.contains(&w.id))
        .map(|w| WorkspaceName {
            workspace_id: w.id,
            workspace: w.name.clone(),
        })
        .collect();
    Ok(Json(Me::Store {
        id: caller.me.id,
        name: caller.me.name.clone(),
        method: caller.me.method,
        superuser: caller.me.superuser,
        waiting: caller.rows.waiting(&caller.me),
        must_change_password: caller.me.must_change_password,
        local: caller.me.method == Method::Local,
        roles,
        grantable,
    }))
}

#[derive(Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Active,
    Waiting,
    Disabled,
}

#[derive(Serialize)]
pub struct UserView {
    id: Uuid,
    name: String,
    method: Method,
    superuser: bool,
    status: Status,
    /// Unix seconds.
    last_sign_in_at: Option<i64>,
    /// Only the workspaces the caller administers. An empty list says nothing about roles
    /// elsewhere, which is the point: whether they exist is not the caller's to know.
    access: Vec<AccessView>,
}

#[derive(Serialize)]
pub struct AccessView {
    workspace_id: Uuid,
    workspace: String,
    #[serde(flatten)]
    access: Access,
}

/// `GET /api/users`: every account, and its roles where the caller administers.
pub async fn users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserView>>, CallerError> {
    let (_, caller, within) = admin_caller(&state, &headers).await?;
    let mut views: Vec<UserView> = caller
        .rows
        .users
        .iter()
        .map(|u| {
            let access: Vec<AccessView> = caller
                .rows
                .access_in(u, &within)
                .into_iter()
                .map(|(w, access)| AccessView {
                    workspace_id: w.id,
                    workspace: w.name.clone(),
                    access,
                })
                .collect();
            // Waiting as the caller can see it: no role in the workspaces they administer. For a
            // superuser that is every workspace, so it is the account's own waiting state; for a
            // workspace admin it is the set they are here to act on, and a role somewhere they
            // cannot see does not show through as "active".
            let status = if u.disabled {
                Status::Disabled
            } else if !u.superuser && access.is_empty() {
                Status::Waiting
            } else {
                Status::Active
            };
            UserView {
                id: u.id,
                name: u.name.clone(),
                method: u.method,
                superuser: u.superuser,
                status,
                last_sign_in_at: u.last_sign_in,
                access,
            }
        })
        .collect();
    // Waiting accounts first: they are the ones someone is here to act on.
    views.sort_by_cached_key(|v| (v.status != Status::Waiting, v.name.to_lowercase()));
    Ok(Json(views))
}

#[derive(Serialize, Default)]
pub struct HeldBy {
    viewer: usize,
    editor: usize,
    admin: usize,
    superuser: usize,
}

#[derive(Serialize)]
pub struct MappingView {
    group: String,
    workspace_id: Uuid,
    workspace: String,
    role: Role,
    /// How many enabled accounts were in the group at their last sign-in. Zero beside a mapping
    /// just made is the quickest sign that its name does not match what the identity provider
    /// sends. Each one counted is listed in `/api/users` with this group as a source in this
    /// workspace, which the caller administers, so the number says nothing the caller could not
    /// already see.
    seen: usize,
}

#[derive(Serialize)]
pub struct RolesView {
    held_by: HeldBy,
    mappings: Vec<MappingView>,
}

/// `GET /api/roles`: how many accounts hold each role, and which groups map to which, within
/// the caller's workspaces.
pub async fn roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RolesView>, CallerError> {
    let (_, caller, within) = admin_caller(&state, &headers).await?;
    let mut held_by = HeldBy::default();
    for user in caller.rows.users.iter().filter(|u| !u.disabled) {
        // A superuser is counted as one, not again as the admin they are everywhere.
        if user.superuser {
            held_by.superuser += 1;
            continue;
        }
        let held: BTreeSet<Role> = caller
            .rows
            .access_in(user, &within)
            .into_iter()
            .map(|(_, access)| access.role)
            .collect();
        for role in held {
            match role {
                Role::Viewer => held_by.viewer += 1,
                Role::Editor => held_by.editor += 1,
                Role::Admin => held_by.admin += 1,
            }
        }
    }
    let mut mappings: Vec<MappingView> = caller
        .rows
        .group_grants
        .iter()
        .filter(|g| within.contains(&g.workspace))
        .filter_map(|g| {
            let workspace = caller
                .rows
                .workspaces
                .iter()
                .find(|w| w.id == g.workspace)?;
            Some(MappingView {
                group: g.group.clone(),
                workspace_id: g.workspace,
                workspace: workspace.name.clone(),
                role: g.role,
                seen: caller
                    .rows
                    .users
                    .iter()
                    .filter(|u| !u.disabled && u.groups.contains(&g.group))
                    .count(),
            })
        })
        .collect();
    mappings.sort_by(|a, b| (&a.workspace, &a.group).cmp(&(&b.workspace, &b.group)));
    Ok(Json(RolesView { held_by, mappings }))
}
