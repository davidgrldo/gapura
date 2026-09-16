//! The HTTP surface. Handlers stay thin: they resolve scope, call a reader, and serialise.

use crate::rows::{self, Row};
use crate::scope::{self, Scope};
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{routing::get, Json, Router};

pub fn router_with(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/auth/login", get(crate::login::begin))
        .route("/auth/callback", get(crate::login::callback))
        .route("/api/routes", get(routes))
        .route("/api/overview", get(overview))
        .with_state(state)
}

/// Pulls the signed session out of the `gapura_session` cookie. Any failure — no
/// cookie, no signature, a bad signature, an expired session — collapses to `None`;
/// the caller turns that into a uniform 401 rather than leaking which case it was.
fn session_from(headers: &HeaderMap, key: &[u8]) -> Option<crate::session::Session> {
    // Every `cookie` field, not just the first: HTTP/2 lets a client or an intermediary
    // split the cookies across several of them (RFC 9113 section 8.2.3) and hyper leaves
    // them as it found them, so a session that landed in the second field would otherwise
    // be invisible and the caller refused while holding a valid one.
    let value = headers
        .get_all("cookie")
        .iter()
        .filter_map(|field| field.to_str().ok())
        .flat_map(|field| field.split(';'))
        .filter_map(|c| c.trim().strip_prefix(crate::login::COOKIE_NAME))
        .filter_map(|rest| rest.strip_prefix('='))
        .next()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    crate::session::decode(value, key, now).ok()
}

#[cfg(test)]
mod session_cookie_tests {
    use super::*;
    use crate::session::{encode, Session};

    const KEY: &[u8] = b"test key";

    /// A `gapura_session` cookie this key accepts, expiring far enough out that no test
    /// here is ever racing the clock.
    fn a_valid_session_cookie() -> String {
        let session = Session {
            subject: "alice".into(),
            groups: vec!["team-a".into()],
            expires_at: u64::MAX,
        };
        format!("{}={}", crate::login::COOKIE_NAME, encode(&session, KEY))
    }

    /// Headers carrying one `cookie` field per element. They are appended rather than
    /// inserted, because inserting would replace the previous field and the whole point of
    /// these tests is a request that arrives with more than one of them.
    fn headers_with(cookie_fields: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for field in cookie_fields {
            headers.append("cookie", field.parse().expect("a valid header value"));
        }
        headers
    }

    #[test]
    fn a_session_in_the_first_of_two_cookie_fields_is_found() {
        let ours = a_valid_session_cookie();
        let headers = headers_with(&[ours.as_str(), "theme=dark"]);
        assert_eq!(
            session_from(&headers, KEY).map(|s| s.subject),
            Some("alice".to_string())
        );
    }

    #[test]
    fn a_session_in_the_second_of_two_cookie_fields_is_found() {
        // HTTP/2 lets a client or an intermediary split the cookies over several `cookie`
        // fields (RFC 9113 section 8.2.3) and hyper hands them over as it found them, so
        // reading only the first field turned a perfectly valid session into a 401.
        let ours = a_valid_session_cookie();
        let headers = headers_with(&["theme=dark", ours.as_str()]);
        assert_eq!(
            session_from(&headers, KEY).map(|s| s.subject),
            Some("alice".to_string())
        );
    }

    #[test]
    fn a_session_among_several_cookies_on_one_line_is_found() {
        let line = format!("theme=dark; {}; tz=UTC", a_valid_session_cookie());
        let headers = headers_with(&[line.as_str()]);
        assert_eq!(
            session_from(&headers, KEY).map(|s| s.subject),
            Some("alice".to_string())
        );
    }

    #[test]
    fn no_cookie_header_at_all_is_no_session() {
        assert!(session_from(&headers_with(&[]), KEY).is_none());
    }

    #[test]
    fn a_cookie_header_holding_nothing_of_ours_is_no_session() {
        let headers = headers_with(&["theme=dark; tz=UTC"]);
        assert!(session_from(&headers, KEY).is_none());
    }
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
    Ok(Json(only_visible(rows, &visible)))
}

/// `/api/overview`'s body: which gapura this is and what it is doing. `listeners` is empty
/// exactly when `reachable` is false, never the other way around — the landing page has one
/// boolean to check before it draws either the list or the "could not be reached" message.
#[derive(serde::Serialize)]
struct Overview {
    reachable: bool,
    listeners: Vec<crate::served::ServedListener>,
}

async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Overview>, StatusCode> {
    session_from(&headers, &state.session_key).ok_or(StatusCode::UNAUTHORIZED)?;
    // Same rule as `/api/routes`: a gateway that cannot be reached is not a failed request,
    // it is the answer. Collapsing the error to `None` here, rather than propagating it,
    // is what keeps this handler from turning "the gateway is down" into a 5xx for a page
    // whose whole job is to say that in words instead.
    let served = state
        .admin
        .served()
        .await
        .map_err(|e| tracing::warn!(error = %e, "reading the gateway's admin port failed"))
        .ok();
    Ok(Json(Overview {
        reachable: served.is_some(),
        listeners: served.map(|s| s.listeners).unwrap_or_default(),
    }))
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

/// Drop every row outside the caller's namespaces.
pub fn only_visible(rows: Vec<Row>, visible: &Scope) -> Vec<Row> {
    match visible {
        // Handing back every row is the one branch that has to be spelled out, so that it
        // is reached by a group actually granted `*` and never by a value that fell out of
        // a default or a failure on the way here.
        Scope::AllNamespaces => rows,
        Scope::Only(allowed) => rows
            .into_iter()
            .filter(|r| allowed.contains(&r.namespace))
            .collect(),
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use crate::rows::{ParentRow, State};
    use std::collections::BTreeSet;

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
        let visible = Scope::Only(BTreeSet::from(["apps".to_string()]));
        let got = only_visible(rows, &visible);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "apps/checkout");
    }

    #[test]
    fn granting_nothing_returns_nothing() {
        let rows = vec![row("apps/checkout")];
        assert!(only_visible(rows, &Scope::Only(BTreeSet::new())).is_empty());
    }

    #[test]
    fn a_grant_over_every_namespace_returns_every_row() {
        let rows = vec![row("apps/checkout"), row("shop/catalog")];
        assert_eq!(only_visible(rows, &Scope::AllNamespaces).len(), 2);
    }
}

// Shared by `route_endpoint_tests` and `overview_tests`: both drive full HTTP requests
// through `router_with` against the same two stubbed backends, so the request plumbing and
// the fixtures live once here rather than once per endpoint.
#[cfg(test)]
use crate::kube_source::tests::stub_api;
#[cfg(test)]
use crate::served::tests::stub_admin;
#[cfg(test)]
use crate::session::{encode, Session};
#[cfg(test)]
use axum::body::Body;
#[cfg(test)]
use axum::http::Request;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use tower::ServiceExt;

#[cfg(test)]
const KEY: &[u8] = b"test key";

/// What the API-server stub answers with, and what the parser is tested against: four
/// routes in `apps` and two in `shop`, so a caller granted only `apps` has both rows to
/// be given and rows to be kept from.
#[cfg(test)]
const FIXTURE: &str = include_str!("../tests/fixtures/httproutes.json");

/// Nothing is listening here, and nothing is meant to be.
#[cfg(test)]
fn nothing_listening() -> String {
    "http://127.0.0.1:1".to_string()
}

/// A state that reads its two sides from the given base URLs, granting team-a the apps
/// namespace and nothing else.
#[cfg(test)]
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
        oidc: Arc::new(tests::test_oidc()),
        pending: crate::login::PendingLogins::default(),
        session_lifetime: std::time::Duration::from_secs(3600),
    }
}

/// An admin port serving a gateway that is up and serving nothing, which leaves the
/// served side answerable without any test depending on what it answers.
#[cfg(test)]
async fn stub_empty_gateway() -> String {
    stub_admin(serde_json::json!({ "listeners": [] })).await
}

#[cfg(test)]
fn signed_in_as(groups: &[&str]) -> String {
    let session = Session {
        subject: "alice".into(),
        groups: groups.iter().map(|s| s.to_string()).collect(),
        expires_at: u64::MAX,
    };
    format!("gapura_session={}", encode(&session, KEY))
}

/// The `id` of every row in a response body, which must be an array of rows.
#[cfg(test)]
fn ids(body: &str) -> Vec<String> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("an array of rows: {e}: {body}"));
    rows.into_iter()
        .map(|r| r["id"].as_str().expect("every row has an id").to_string())
        .collect()
}

/// `GET /api/routes`: the status it answered with, and the ids of the rows it carried.
/// Anything but an OK carries no rows at all, so there is nothing there to parse.
#[cfg(test)]
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

/// `GET <path>`, parsed as JSON: same shape as `get_routes`, generalised to any endpoint and
/// to a body that is not a list of rows — `/api/overview` answers with an object. A response
/// with no body (a 401 carries none) reads back as `Value::Null` rather than panicking, so a
/// caller asserting only on the status never has to special-case it.
#[cfg(test)]
async fn get_json(
    state: &AppState,
    path: &str,
    cookie: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder().uri(path);
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
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("expected JSON: {e}: {}", String::from_utf8_lossy(&bytes)))
    };
    (status, body)
}

#[cfg(test)]
mod route_endpoint_tests {
    use super::*;

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

#[cfg(test)]
mod overview_tests {
    use super::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn overview_reports_what_the_gateway_is_serving() {
        let state = state_reading(
            stub_api(include_str!("../tests/fixtures/httproutes.json")).await,
            stub_admin(serde_json::json!({
                "listeners": [
                    { "id": "infra/main/http",  "port": 80,  "rules": [] },
                    { "id": "infra/main/https", "port": 443, "rules": [] }
                ]
            }))
            .await,
        );
        let (status, body) =
            get_json(&state, "/api/overview", Some(&signed_in_as(&["team-a"]))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["listeners"].as_array().unwrap().len(), 2);
        assert_eq!(body["listeners"][0]["id"], "infra/main/http");
        assert_eq!(body["listeners"][0]["port"], 80);
        assert_eq!(body["reachable"], true);
    }

    #[tokio::test]
    async fn an_unreachable_gateway_is_reported_as_such_not_as_an_empty_one() {
        // A console that draws "0 listeners" for a gateway it could not reach is lying with a
        // number, which is worse than admitting it does not know.
        let state = state_reading(
            stub_api(include_str!("../tests/fixtures/httproutes.json")).await,
            "http://127.0.0.1:1".to_string(),
        );
        let (status, body) =
            get_json(&state, "/api/overview", Some(&signed_in_as(&["team-a"]))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["reachable"], false);
        assert!(body["listeners"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn overview_needs_a_session_like_everything_else() {
        let state = state_reading(
            stub_api(include_str!("../tests/fixtures/httproutes.json")).await,
            stub_admin(serde_json::json!({ "listeners": [] })).await,
        );
        let (status, _) = get_json(&state, "/api/overview", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
