//! The HTTP surface. Handlers stay thin: they resolve scope, call a reader, and serialise.

use crate::rows::{self, Row};
use crate::scope;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{routing::get, Json, Router};
use std::collections::BTreeSet;

pub fn router_with(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/auth/login", get(crate::login::begin))
        .route("/auth/callback", get(crate::login::callback))
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
        .filter_map(|c| c.trim().strip_prefix(crate::login::COOKIE_NAME))
        .filter_map(|rest| rest.strip_prefix('='))
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
    let declared = state
        .source
        .routes(&state.controller_name)
        .await
        .map_err(|e| {
            // The caller is told a status and no more; the operator needs to know which of
            // the many ways of not reaching an API server this was, and here is the last
            // place that still knows.
            tracing::warn!(error = %e, "reading HTTPRoutes from the API server failed");
            StatusCode::BAD_GATEWAY
        })?;
    // A gateway that cannot be reached is not a failed request: the declared half is still
    // worth showing, and `join` renders the served side as unknown rather than absent. That
    // unknown is the console saying so on screen, so nothing is being swallowed here.
    let served = state.admin.served().await.ok();
    let rows = rows::join(declared, served.as_ref());
    // Every row leaves through only_visible, so scoping is a property of this one path
    // rather than of whichever reader happens to have produced the rows.
    Ok(Json(only_visible(rows, visible.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// An identity provider nobody is going to contact. These tests are about the API
    /// surface; nothing here reaches the network, the URLs only have to parse.
    pub fn test_oidc() -> crate::login::Oidc {
        crate::login::Oidc::new(
            "https://id.example.test",
            "console",
            "not a real secret",
            "https://console.example.test/auth/callback",
            "groups",
            &[],
        )
        .expect("literal URLs parse")
    }

    /// Readers pointed at nothing: this module's tests are about the surface in front of
    /// them, and a health check that needed a cluster to answer would not be one.
    fn state() -> AppState {
        AppState {
            mapping: std::sync::Arc::new(crate::scope::Mapping::new()),
            session_key: std::sync::Arc::new(b"test key".to_vec()),
            source: std::sync::Arc::new(crate::kube_source::Source::new(
                "http://127.0.0.1:1".to_string(),
            )),
            admin: std::sync::Arc::new(crate::served::Admin::new("http://127.0.0.1:1")),
            controller_name: std::sync::Arc::new("gapura.dev/controller".to_string()),
            oidc: std::sync::Arc::new(test_oidc()),
            pending: crate::login::PendingLogins::default(),
            session_lifetime: std::time::Duration::from_secs(3600),
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
    use crate::kube_source::tests::stub_api;
    use crate::served::tests::stub_admin;
    use crate::session::{encode, Session};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    const KEY: &[u8] = b"test key";

    /// What the API-server stub answers with, and what the parser is tested against: four
    /// routes in `apps` and two in `shop`, so a caller granted only `apps` has both rows to
    /// be given and rows to be kept from.
    const FIXTURE: &str = include_str!("../tests/fixtures/httproutes.json");

    /// Nothing is listening here, and nothing is meant to be.
    fn nothing_listening() -> String {
        "http://127.0.0.1:1".to_string()
    }

    /// A state that reads its two sides from the given base URLs, granting team-a the apps
    /// namespace and nothing else.
    fn state_reading(api_server: String, gateway_admin: String) -> AppState {
        AppState {
            mapping: Arc::new(
                [("team-a".to_string(), vec!["apps".to_string()])]
                    .into_iter()
                    .collect(),
            ),
            session_key: Arc::new(KEY.to_vec()),
            source: Arc::new(crate::kube_source::Source::new(api_server)),
            admin: Arc::new(crate::served::Admin::new(gateway_admin)),
            controller_name: Arc::new("gapura.dev/controller".to_string()),
            oidc: Arc::new(super::tests::test_oidc()),
            pending: crate::login::PendingLogins::default(),
            session_lifetime: std::time::Duration::from_secs(3600),
        }
    }

    /// An admin port serving a gateway that is up and serving nothing, which leaves the
    /// rows' served side answerable without any of these tests depending on its answer.
    async fn stub_empty_gateway() -> String {
        stub_admin(serde_json::json!({ "listeners": [] })).await
    }

    fn signed_in_as(groups: &[&str]) -> String {
        let session = Session {
            subject: "alice".into(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
            expires_at: u64::MAX,
        };
        format!("gapura_session={}", encode(&session, KEY))
    }

    /// The `id` of every row in a response body, which must be an array of rows.
    fn ids(body: &str) -> Vec<String> {
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(body).unwrap_or_else(|e| panic!("an array of rows: {e}: {body}"));
        rows.into_iter()
            .map(|r| r["id"].as_str().expect("every row has an id").to_string())
            .collect()
    }

    /// `GET /api/routes`: the status it answered with, and the ids of the rows it carried.
    /// Anything but an OK carries no rows at all, so there is nothing there to parse.
    async fn get_routes(state: &AppState, cookie: Option<&str>) -> (StatusCode, Vec<String>) {
        let mut request = Request::builder().uri("/api/routes");
        if let Some(c) = cookie {
            request = request.header("cookie", c);
        }
        let response = router_with(state.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        let ids = if status == StatusCode::OK {
            ids(&body)
        } else {
            Vec::new()
        };
        (status, ids)
    }

    #[tokio::test]
    async fn without_a_session_it_is_refused() {
        // Both readers are dead ends, so a 401 here also says the session is checked before
        // anything is read: an unauthenticated caller cannot make us go and ask the cluster.
        let state = state_reading(nothing_listening(), nothing_listening());
        let (status, _) = get_routes(&state, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_forged_cookie_is_refused() {
        let state = state_reading(nothing_listening(), nothing_listening());
        let (status, _) = get_routes(&state, Some("gapura_session=forged.nonsense")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_signed_in_caller_gets_json() {
        let state = state_reading(stub_api(FIXTURE).await, stub_empty_gateway().await);
        let (status, ids) = get_routes(&state, Some(&signed_in_as(&["team-a"]))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            ids.contains(&"apps/checkout".to_string()),
            "the fixture's apps routes must be in the body, got {ids:?}"
        );
    }

    #[tokio::test]
    async fn a_row_outside_the_callers_namespaces_never_reaches_them() {
        // Unchanged in intent from the version this replaces: the readers are stubbed rather
        // than the rows, so the filter is still exercised over the path a request takes.
        let state = state_reading(stub_api(FIXTURE).await, stub_empty_gateway().await);
        let (status, ids) = get_routes(&state, Some(&signed_in_as(&["team-a"]))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ids.iter().all(|id| id.starts_with("apps/")), "got {ids:?}");
        assert!(
            !ids.is_empty(),
            "the fixture has apps/ routes; an empty result proves nothing"
        );
    }

    #[tokio::test]
    async fn an_unreachable_gateway_still_answers_with_the_declared_side() {
        // The spec's rule: the Kubernetes half still renders, with served marked unknown.
        let state = state_reading(stub_api(FIXTURE).await, nothing_listening());
        let (status, ids) = get_routes(&state, Some(&signed_in_as(&["team-a"]))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a dead gateway is not a failed request"
        );
        assert!(!ids.is_empty(), "declared routes must still be listed");
    }

    #[tokio::test]
    async fn an_unreachable_api_server_is_an_error_the_caller_can_see() {
        // The other direction is not symmetrical: with no declared side there are no rows to
        // render at all, and pretending otherwise would show an empty, reassuring screen.
        let state = state_reading(nothing_listening(), stub_empty_gateway().await);
        let (status, _) = get_routes(&state, Some(&signed_in_as(&["team-a"]))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }
}
