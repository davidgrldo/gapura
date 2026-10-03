//! Who is signed in, and the Users and Roles pages: store mode's view of `access`.
//!
//! Every handler here reads its caller back from the store on each request, so a grant takes
//! effect on the next one and a disabled account is signed out on the next one.

use crate::access::{Access, Method, Role, Rows, User};
use crate::state::AppState;
use crate::store::Store;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Serialize;
use std::collections::BTreeSet;
use uuid::Uuid;

/// The signed-in account in store mode, with the rows its access is computed from.
pub struct StoreCaller {
    pub rows: Rows,
    pub me: User,
}

/// The caller behind `headers`, read back from `store`.
///
/// 401 when there is no session, when it names no account -- a session issued in Kubernetes
/// mode carries an email where store mode puts an id -- or when the account is disabled. 503
/// when the store cannot be read, which is not the caller's fault and must not look like it.
pub async fn store_caller(
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
        tracing::warn!(%error, "reading accounts from the store failed");
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    let me = rows
        .users
        .iter()
        .find(|u| u.id == id && !u.disabled)
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(StoreCaller { rows, me })
}

/// The caller and the workspaces they administer, when they are a superuser or administer at
/// least one. A superuser keeps these pages even with no workspaces at all, the state `waiting`
/// already guards. Kubernetes mode has no accounts to list, so there these pages do not exist.
async fn admin_caller(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(StoreCaller, BTreeSet<Uuid>), StatusCode> {
    let store = state.store.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let caller = store_caller(store, headers, &state.session_key).await?;
    let within = caller.rows.grantable(&caller.me);
    if within.is_empty() && !caller.me.superuser {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((caller, within))
}

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Me {
    /// Enough for the console to leave out what only store mode has.
    Kubernetes,
    Store {
        name: String,
        method: Method,
        superuser: bool,
        waiting: bool,
        /// Every workspace where the caller holds a role, and that role.
        roles: Vec<WorkspaceRole>,
        /// Where the caller is admin: where they may see, and later grant, other people's roles.
        grantable: Vec<Uuid>,
    },
}

/// A workspace and a role in it, named the way `/api/users` and `/api/roles` name them, so the
/// console reads one shape.
#[derive(Serialize)]
pub struct WorkspaceRole {
    workspace_id: Uuid,
    workspace: String,
    role: Role,
}

/// `GET /api/me`: who this is and what they hold. A waiting account gets an answer here and a
/// 403 everywhere else, so the console can say why instead of showing empty pages.
pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Me>, StatusCode> {
    let Some(store) = &state.store else {
        crate::api::session_from(&headers, &state.session_key).ok_or(StatusCode::UNAUTHORIZED)?;
        return Ok(Json(Me::Kubernetes));
    };
    let caller = store_caller(store, &headers, &state.session_key).await?;
    let roles = caller
        .rows
        .workspaces
        .iter()
        .filter_map(|w| {
            caller
                .rows
                .effective(&caller.me, w.id)
                .map(|a| WorkspaceRole {
                    workspace_id: w.id,
                    workspace: w.name.clone(),
                    role: a.role,
                })
        })
        .collect();
    Ok(Json(Me::Store {
        name: caller.me.name.clone(),
        method: caller.me.method,
        superuser: caller.me.superuser,
        waiting: caller.rows.waiting(&caller.me),
        roles,
        grantable: caller.rows.grantable(&caller.me).into_iter().collect(),
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
) -> Result<Json<Vec<UserView>>, StatusCode> {
    let (caller, within) = admin_caller(&state, &headers).await?;
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
) -> Result<Json<RolesView>, StatusCode> {
    let (caller, within) = admin_caller(&state, &headers).await?;
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
            })
        })
        .collect();
    mappings.sort_by(|a, b| (&a.workspace, &a.group).cmp(&(&b.workspace, &b.group)));
    Ok(Json(RolesView { held_by, mappings }))
}
