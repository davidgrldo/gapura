//! The HTTP surface. Handlers stay thin: they resolve scope, call a reader, and serialise.

use crate::rows::Row;
use crate::scope;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{routing::get, Json, Router};
use std::collections::BTreeSet;

pub fn router_with(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/api/routes", get(routes))
        .with_state(state)
}

/// Pulls the signed session out of the `gapura_session` cookie. Any failure — no
/// cookie, no signature, a bad signature, an expired session — collapses to `None`;
/// the caller turns that into a uniform 401 rather than leaking which case it was.
fn session_from(headers: &HeaderMap, key: &[u8]) -> Option<crate::session::Session> {
    let cookies = headers.get("cookie")?.to_str().ok()?;
    let value = cookies
        .split(';')
        .filter_map(|c| c.trim().strip_prefix("gapura_session="))
        .next()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    crate::session::decode(value, key, now).ok()
}

async fn routes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Row>>, StatusCode> {
    let session = session_from(&headers, &state.session_key).ok_or(StatusCode::UNAUTHORIZED)?;
    let visible = scope::visible(&session.groups, &state.mapping);
    // Every row leaves through only_visible, so scoping is a property of this one path
    // rather than of whichever reader happens to have produced the rows.
    Ok(Json(only_visible(
        state.rows.as_ref().clone(),
        visible.as_ref(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn state() -> AppState {
        AppState {
            mapping: std::sync::Arc::new(crate::scope::Mapping::new()),
            session_key: std::sync::Arc::new(b"test key".to_vec()),
            rows: std::sync::Arc::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn healthz_answers_ok() {
        let response = router_with(state())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

/// Drop every row outside the caller's namespaces. `None` means every namespace.
pub fn only_visible(rows: Vec<Row>, visible: Option<&BTreeSet<String>>) -> Vec<Row> {
    match visible {
        None => rows,
        Some(allowed) => rows
            .into_iter()
            .filter(|r| allowed.contains(&r.namespace))
            .collect(),
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::rows::{ParentRow, State};

    fn row(id: &str) -> Row {
        Row {
            id: id.to_string(),
            namespace: id.split('/').next().unwrap().to_string(),
            state: State::Served,
            parents: vec![ParentRow {
                gateway: "infra/main".to_string(),
                section: None,
                state: State::Served,
                reason: None,
                message: None,
            }],
        }
    }

    #[test]
    fn a_namespace_outside_the_grant_is_not_returned_at_all() {
        let rows = vec![row("apps/checkout"), row("shop/catalog")];
        let visible = BTreeSet::from(["apps".to_string()]);
        let got = only_visible(rows, Some(&visible));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "apps/checkout");
    }

    #[test]
    fn granting_nothing_returns_nothing() {
        let rows = vec![row("apps/checkout")];
        assert!(only_visible(rows, Some(&BTreeSet::new())).is_empty());
    }

    #[test]
    fn a_grant_over_every_namespace_returns_every_row() {
        let rows = vec![row("apps/checkout"), row("shop/catalog")];
        assert_eq!(only_visible(rows, None).len(), 2);
    }
}

#[cfg(test)]
mod route_endpoint_tests {
    use super::*;
    use crate::session::{encode, Session};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    const KEY: &[u8] = b"test key";

    fn state() -> crate::state::AppState {
        crate::state::AppState {
            mapping: std::sync::Arc::new(
                [("team-a".to_string(), vec!["apps".to_string()])]
                    .into_iter()
                    .collect(),
            ),
            session_key: std::sync::Arc::new(KEY.to_vec()),
            // One row on each side of the grant above, so a handler that forgot to filter
            // would hand the caller the shop row it must never see.
            rows: std::sync::Arc::new(vec![row("apps/checkout"), row("shop/catalog")]),
        }
    }

    fn row(id: &str) -> Row {
        Row {
            id: id.to_string(),
            namespace: id.split('/').next().unwrap().to_string(),
            state: crate::rows::State::Served,
            parents: vec![crate::rows::ParentRow {
                gateway: "infra/main".to_string(),
                section: None,
                state: crate::rows::State::Served,
                reason: None,
                message: None,
            }],
        }
    }

    /// The `id` of every row in a response body, which must be an array of rows.
    fn ids(body: &str) -> Vec<String> {
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(body).unwrap_or_else(|e| panic!("an array of rows: {e}: {body}"));
        rows.into_iter()
            .map(|r| r["id"].as_str().expect("every row has an id").to_string())
            .collect()
    }

    fn signed_in_as(groups: &[&str]) -> String {
        let session = Session {
            subject: "alice".into(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
            expires_at: u64::MAX,
        };
        format!("gapura_session={}", encode(&session, KEY))
    }

    async fn get(cookie: Option<&str>) -> (StatusCode, String) {
        let mut request = Request::builder().uri("/api/routes");
        if let Some(c) = cookie {
            request = request.header("cookie", c);
        }
        let response = router_with(state())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn without_a_session_it_is_refused() {
        let (status, _) = get(None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_forged_cookie_is_refused() {
        let (status, _) = get(Some("gapura_session=forged.nonsense")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_signed_in_caller_gets_json() {
        let (status, body) = get(Some(&signed_in_as(&["team-a"]))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ids(&body), ["apps/checkout"]);
    }

    #[tokio::test]
    async fn a_row_outside_the_callers_namespaces_never_reaches_them() {
        // The filtering invariant, asserted over the path a request actually takes rather
        // than over only_visible in isolation: team-a is granted apps and nothing else, so
        // the shop row must not appear in the body however the handler is rearranged.
        let (status, body) = get(Some(&signed_in_as(&["team-a"]))).await;
        assert_eq!(status, StatusCode::OK);
        let ids = ids(&body);
        assert!(
            ids.contains(&"apps/checkout".to_string()),
            "the caller's own namespace must still be served, got {ids:?}"
        );
        assert!(
            !ids.contains(&"shop/catalog".to_string()),
            "a row outside the grant leaked to the caller, got {ids:?}"
        );
    }
}
