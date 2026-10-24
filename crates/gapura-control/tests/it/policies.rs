//! Policies through `/api/workspaces/{ws}/policies/{kind}`, against Postgres: that an
//! ip_restriction reaches the compiled configuration, which applies where several do, what the
//! lists and the route and service rows show, who may do what, what the audit records, that every
//! refusal writes nothing, and that a stored row in a shape the API never writes fails the
//! snapshot.
//!
//! The helpers are copies of `rate_limit.rs`'s, so that each file reads on its own. Run with:
//!
//! ```text
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5434/postgres cargo test -p gapura-control --test it policies::
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
use gapura_core::config::{
    Config, HeaderEdits, IpRestrictionPolicy, Plugin, RequestSizeLimitPolicy,
    RequestTransformerPolicy,
};
use gapura_core::store::StoreSettings;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use crate::common::fresh_store;

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

fn console(store: Option<Arc<Store>>) -> axum::Router {
    gapura_control::api::router_with(AppState {
        mapping: Arc::new(Default::default()),
        session_key: Arc::from(KEY.to_vec()),
        source: Arc::new(gapura_control::kube_source::Source::new(
            "http://127.0.0.1:1".to_string(),
        )),
        admin: Arc::new(gapura_control::served::Admin::new("http://127.0.0.1:1")),
        controller_name: Arc::new("gapura.dev/controller".to_string()),
        oidc: Arc::new(gapura_control::login::Oidc::unused().unwrap()),
        auth_mode: gapura_control::login::AuthMode::Local,
        local_users: Default::default(),
        session_lifetime: Duration::from_secs(3600),
        store,
        sign_in: Default::default(),
        sign_up: Default::default(),
        store_settings: Default::default(),
    })
}

fn cookie(subject: &str) -> String {
    format!(
        "{}={}",
        gapura_control::login::COOKIE_NAME,
        encode(
            &Session {
                subject: subject.to_string(),
                groups: vec![],
                expires_at: u64::MAX,
                issued_at: 0,
            },
            KEY
        )
    )
}

/// Sends `method path` with `body`, as the console does, signed in as `as_` when one is given.
async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    as_: Option<Uuid>,
    body: &str,
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin");
    if let Some(id) = as_ {
        req = req.header("cookie", cookie(&id.to_string()));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

const SERVICE: &str = r#"{"name":"orders","protocol":"http","host":"orders.internal","port":8080}"#;
const ROUTE: &str = r#"{"name":"orders-api","service":"orders","hosts":["api.example.com"],"paths":[{"type":"prefix","value":"/orders"}]}"#;
const SERVICES: &str = "/api/workspaces/default/services";
const ROUTES: &str = "/api/workspaces/default/routes";
const IP: &str = "/api/workspaces/default/policies/ip_restriction";
const SIZE: &str = "/api/workspaces/default/policies/request_size_limit";
const TRANSFORM: &str = "/api/workspaces/default/policies/request_transformer";
/// The compiled name of the seeded route.
const COMPILED_ROUTE: &str = "default/orders-api";

/// - `root`: superuser, the only one who reaches the second workspace, `payments`.
/// - `ada`: admin of default. `ed`: editor of default. `vi`: viewer of default.
///
/// And in default, a service `orders` and a route `orders-api` for `api.example.com`.
struct Seed {
    ada: Uuid,
    ed: Uuid,
    vi: Uuid,
}

async fn seed(store: &Store, app: &axum::Router) -> Seed {
    let db = store.client().await.unwrap();
    let default: Uuid = db
        .query_one("select id from workspaces where name = 'default'", &[])
        .await
        .unwrap()
        .get(0);
    db.execute("insert into workspaces (name) values ('payments')", &[])
        .await
        .unwrap();
    let hash = gapura_control::password::hash("correct horse battery").unwrap();
    let mut ids = std::collections::HashMap::new();
    for (name, superuser) in [("root", true), ("ada", false), ("ed", false), ("vi", false)] {
        let id: Uuid = db
            .query_one(
                "insert into users (username, password_hash, superuser) values ($1, $2, $3) returning id",
                &[&name, &hash, &superuser],
            )
            .await
            .unwrap()
            .get(0);
        ids.insert(name, id);
    }
    for (name, role) in [("ada", "admin"), ("ed", "editor"), ("vi", "viewer")] {
        db.execute(
            "insert into role_bindings (user_id, workspace_id, role) values ($1, $2, $3::text::role_name)",
            &[&ids[name], &default, &role],
        )
        .await
        .unwrap();
    }
    let s = Seed {
        ada: ids["ada"],
        ed: ids["ed"],
        vi: ids["vi"],
    };
    ok(app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(app, "POST", ROUTES, s.ed, ROUTE).await;
    s
}

/// A setup write, which must succeed for the test to mean anything.
async fn ok(app: &axum::Router, method: &str, path: &str, as_: Uuid, body: &str) {
    let (status, answer) = send(app, method, path, Some(as_), body).await;
    assert_eq!(
        (status, answer.as_str()),
        (StatusCode::NO_CONTENT, ""),
        "{method} {path} {body}"
    );
}

/// The sentence a refusal carries.
fn sentence(body: &str) -> String {
    parse(body)["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no sentence: {body}"))
        .to_string()
}

/// A GET that must succeed, as JSON.
async fn read(app: &axum::Router, path: &str, as_: Uuid) -> serde_json::Value {
    let (status, body) = send(app, "GET", path, Some(as_), "").await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    parse(&body)
}

/// The row the list shows for `name`.
async fn row(app: &axum::Router, list: &str, name: &str, as_: Uuid) -> serde_json::Value {
    read(app, list, as_)
        .await
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not listed in {list}"))
        .clone()
}

/// Every row a policy write could change, the number of audit entries, and the version the data
/// planes poll. Equal before and after a refusal means the refusal wrote nothing.
async fn everything(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select jsonb_build_object(
                 'services', (select coalesce(jsonb_agg(to_jsonb(s) order by s.id), '[]') from services s),
                 'routes', (select coalesce(jsonb_agg(to_jsonb(r) order by r.id), '[]') from routes r),
                 'plugins', (select coalesce(jsonb_agg(to_jsonb(p) order by p.id), '[]') from plugins p),
                 'audit', (select count(*) from audit_log),
                 'version', (select version from config_state))",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// What the data planes would be served now.
async fn compiled(store: &Store) -> Config {
    let (_, snapshot) = store.snapshot().await.unwrap();
    gapura_core::store::compile(
        &snapshot,
        &StoreSettings {
            http_ports: vec![80],
        },
    )
}

/// The plugins the compiled `route` runs.
fn plugins_on(config: &Config, route: &str) -> Vec<Plugin> {
    config
        .listeners
        .iter()
        .flat_map(|l| &l.rules)
        .find(|r| r.route == route)
        .unwrap_or_else(|| panic!("{route} is not compiled"))
        .plugins
        .clone()
}

/// The policy writes in the audit log, oldest first: action, before, after.
async fn policy_audits(store: &Store) -> Vec<(String, serde_json::Value, serde_json::Value)> {
    store
        .client()
        .await
        .unwrap()
        .query(
            "select action, coalesce(before, 'null'), coalesce(after, 'null') from audit_log
              where object_kind = 'policy' order by id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}

/// A PUT body for `target`, with `seen` as the stamp it read when there is one.
fn put(target: &str, config: serde_json::Value, seen: Option<&str>) -> String {
    let mut body = json!({"target": target, "config": config});
    if let Some(seen) = seen {
        body["seen_updated_at"] = json!(seen);
    }
    body.to_string()
}

/// The `updated_at` the list shows for `target`'s policy, if it has one.
async fn stamp(app: &axum::Router, target: &str, as_: Uuid) -> Option<String> {
    read(app, IP, as_)
        .await
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["target"] == target)
        .map(|row| row["updated_at"].as_str().expect("a stamp").to_string())
}

/// A PUT the console makes: from a fresh read of the list, so with the stamp of the policy it
/// replaces when there is one. It must succeed.
async fn apply(app: &axum::Router, as_: Uuid, target: &str, config: serde_json::Value) {
    let read_at = stamp(app, target, as_).await;
    ok(
        app,
        "PUT",
        IP,
        as_,
        &put(target, config, read_at.as_deref()),
    )
    .await;
}

fn deny(nets: &[&str]) -> Plugin {
    Plugin::IpRestriction(IpRestrictionPolicy {
        allow: vec![],
        deny: nets.iter().map(|n| n.parse().unwrap()).collect(),
    })
}

/// A route's own policy compiles onto its rule, and the list shows it in the form the data plane
/// reads: a bare address as the network of one.
#[tokio::test]
async fn an_ip_restriction_reaches_the_compiled_rule() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    assert!(plugins_on(&compiled(&store).await, COMPILED_ROUTE).is_empty());

    apply(
        &app,
        s.ed,
        "route:orders-api",
        json!({"deny": ["203.0.113.7", "10.0.0.0/8"]}),
    )
    .await;
    assert_eq!(
        plugins_on(&compiled(&store).await, COMPILED_ROUTE),
        [deny(&["203.0.113.7/32", "10.0.0.0/8"])]
    );
    let list = read(&app, IP, s.vi).await;
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list[0]["target"], "route:orders-api");
    assert_eq!(
        list[0]["config"],
        json!({"deny": ["203.0.113.7/32", "10.0.0.0/8"]})
    );
}

/// The most specific policy applies, route over service over workspace, and each route and
/// service row says where its policy comes from. A row with none has no `policies` at all, so
/// rows read as they did before the field existed.
#[tokio::test]
async fn the_most_specific_applies_and_the_rows_say_where_from() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    assert!(row(&app, ROUTES, "orders-api", s.vi)
        .await
        .get("policies")
        .is_none());
    assert!(row(&app, SERVICES, "orders", s.vi)
        .await
        .get("policies")
        .is_none());

    apply(&app, s.ed, "workspace", json!({"deny": ["192.0.2.0/24"]})).await;
    let from = |row: serde_json::Value| row["policies"]["ip_restriction"]["from"].clone();
    assert_eq!(
        from(row(&app, ROUTES, "orders-api", s.vi).await),
        "workspace"
    );
    assert_eq!(from(row(&app, SERVICES, "orders", s.vi).await), "workspace");

    apply(
        &app,
        s.ed,
        "service:orders",
        json!({"deny": ["198.51.100.0/24"]}),
    )
    .await;
    assert_eq!(from(row(&app, ROUTES, "orders-api", s.vi).await), "service");
    assert_eq!(
        plugins_on(&compiled(&store).await, COMPILED_ROUTE),
        [deny(&["198.51.100.0/24"])]
    );

    apply(
        &app,
        s.ed,
        "route:orders-api",
        json!({"allow": ["10.0.0.0/8"]}),
    )
    .await;
    let route = row(&app, ROUTES, "orders-api", s.vi).await;
    assert_eq!(from(route.clone()), "route");
    assert_eq!(
        route["policies"]["ip_restriction"]["updated_at"],
        json!(stamp(&app, "route:orders-api", s.vi).await)
    );
    assert_eq!(from(row(&app, SERVICES, "orders", s.vi).await), "service");

    ok(
        &app,
        "DELETE",
        &format!("{IP}?target=service:orders"),
        s.ed,
        "",
    )
    .await;
    ok(
        &app,
        "DELETE",
        &format!("{IP}?target=route:orders-api"),
        s.ed,
        "",
    )
    .await;
    assert_eq!(
        from(row(&app, ROUTES, "orders-api", s.vi).await),
        "workspace"
    );
    assert_eq!(
        plugins_on(&compiled(&store).await, COMPILED_ROUTE),
        [deny(&["192.0.2.0/24"])]
    );
}

/// A create, an update and a delete each write one audit entry naming the target, the kind and
/// the policy; saving the same policy again writes nothing at all. A replace needs the stamp of
/// the policy it replaces, and a create sends none.
#[tokio::test]
async fn the_audit_records_each_change_and_a_replace_needs_a_fresh_read() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let first = json!({"deny": ["192.0.2.0/24"]});
    let second = json!({"deny": ["198.51.100.0/24"]});

    ok(
        &app,
        "PUT",
        IP,
        s.ed,
        &put("route:orders-api", first.clone(), None),
    )
    .await;
    let read_at = stamp(&app, "route:orders-api", s.ed).await;
    let before = everything(&store).await;
    ok(
        &app,
        "PUT",
        IP,
        s.ed,
        &put("route:orders-api", first.clone(), read_at.as_deref()),
    )
    .await;
    assert_eq!(
        everything(&store).await,
        before,
        "the same policy wrote nothing"
    );

    for stale in [None, Some("2001-01-01T00:00:00.000000Z")] {
        let (status, body) = send(
            &app,
            "PUT",
            IP,
            Some(s.ed),
            &put("route:orders-api", second.clone(), stale),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{stale:?}: {body}");
    }
    assert_eq!(
        everything(&store).await,
        before,
        "a stale write wrote nothing"
    );

    apply(&app, s.ed, "route:orders-api", second.clone()).await;
    ok(
        &app,
        "DELETE",
        &format!("{IP}?target=route:orders-api"),
        s.ed,
        "",
    )
    .await;
    let entry = |config: &serde_json::Value| json!({"target": "route:orders-api", "kind": "ip_restriction", "config": config});
    assert_eq!(
        policy_audits(&store).await,
        [
            ("create".to_string(), json!(null), entry(&first)),
            ("update".to_string(), entry(&first), entry(&second)),
            ("delete".to_string(), entry(&second), json!(null)),
        ]
    );
}

/// Each refusal names what is wrong, beside the field the console shows it at, and writes
/// nothing.
#[tokio::test]
async fn bad_input_is_named_and_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let before = everything(&store).await;

    for (body, status, field) in [
        (
            put("workspace", json!({}), None),
            StatusCode::BAD_REQUEST,
            "allow",
        ),
        (
            put("workspace", json!({"allow": ["10.0.0.0/33"]}), None),
            StatusCode::BAD_REQUEST,
            "allow",
        ),
        (
            put("workspace", json!({"deny": ["nope"]}), None),
            StatusCode::BAD_REQUEST,
            "deny",
        ),
        (
            put("workspace", json!({"deny": "10.0.0.0/8"}), None),
            StatusCode::BAD_REQUEST,
            "config",
        ),
        (
            put("everywhere", json!({"deny": ["10.0.0.0/8"]}), None),
            StatusCode::BAD_REQUEST,
            "target",
        ),
    ] {
        let (got, answer) = send(&app, "PUT", IP, Some(s.ed), &body).await;
        assert_eq!(got, status, "{body}: {answer}");
        assert_eq!(parse(&answer)["field"], field, "{body}: {answer}");
    }
    let many: Vec<String> = (0..=gapura_control::policies::MAX_NETWORKS)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
        .collect();
    let (status, answer) = send(
        &app,
        "PUT",
        IP,
        Some(s.ed),
        &put("workspace", json!({"deny": many}), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");

    // Not a policy at all, a target that does not exist, a kind that does not exist.
    let (status, _) = send(&app, "PUT", IP, Some(s.ed), "not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, answer) = send(
        &app,
        "PUT",
        IP,
        Some(s.ed),
        &put("route:nowhere", json!({"deny": ["10.0.0.0/8"]}), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    for method in ["GET", "PUT", "DELETE"] {
        let (status, answer) = send(
            &app,
            method,
            "/api/workspaces/default/policies/oauth2?target=workspace",
            Some(s.ed),
            &put("workspace", json!({}), None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}: {answer}");
        assert_eq!(sentence(&answer), "There is no such policy kind.");
    }
    let (status, answer) = send(
        &app,
        "DELETE",
        &format!("{IP}?target=workspace"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(sentence(&answer), "workspace has no ip_restriction policy.");
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );

    // The cap is set so that a full list of the longest networks still fits the body limit.
    let longest: Vec<String> = (0..gapura_control::policies::MAX_NETWORKS)
        .map(|i| format!("ffff:ffff:ffff:ffff:ffff:ffff:ffff:{i:04x}/128"))
        .collect();
    let (status, answer) = send(
        &app,
        "PUT",
        IP,
        Some(s.ed),
        &put("workspace", json!({"deny": longest}), None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
}

#[tokio::test]
async fn a_viewer_reads_an_editor_writes_and_no_role_is_refused() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let body = put("workspace", json!({"deny": ["192.0.2.0/24"]}), None);
    ok(&app, "PUT", IP, s.ed, &body).await;
    let off = format!("{IP}?target=workspace");

    assert_eq!(read(&app, IP, s.vi).await[0]["target"], "workspace");
    let before = everything(&store).await;
    for (method, path, body) in [
        (
            "PUT",
            IP,
            put("route:orders-api", json!({"deny": ["10.0.0.0/8"]}), None),
        ),
        ("DELETE", off.as_str(), String::new()),
    ] {
        let (status, answer) = send(&app, method, path, Some(s.vi), &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
        assert_eq!(
            sentence(&answer),
            "Making changes in this workspace needs the editor role."
        );
    }
    // Someone whose roles are all in default is refused alike in a workspace that exists and in
    // one that does not.
    for who in [s.ed, s.ada] {
        for (method, tail, body) in [
            ("GET", "/policies/ip_restriction", String::new()),
            ("PUT", "/policies/ip_restriction", body.clone()),
            (
                "DELETE",
                "/policies/ip_restriction?target=workspace",
                String::new(),
            ),
        ] {
            let mut answers = vec![];
            for ws in ["payments", "nowhere"] {
                let path = format!("/api/workspaces/{ws}{tail}");
                let (status, answer) = send(&app, method, &path, Some(who), &body).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
                answers.push(answer);
            }
            assert_eq!(answers[0], answers[1], "{method} {tail}");
        }
    }
    let (status, _) = send(&app, "GET", IP, None, "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );

    // A route with a policy of its own is not deleted from under it.
    ok(
        &app,
        "PUT",
        IP,
        s.ed,
        &put("route:orders-api", json!({"deny": ["10.0.0.0/8"]}), None),
    )
    .await;
    let (status, answer) = send(
        &app,
        "DELETE",
        &format!("{ROUTES}/orders-api"),
        Some(s.ada),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    ok(&app, "DELETE", &off, s.ed, "").await;
}

/// A row only SQL written by hand could store fails the snapshot, so the data planes keep the
/// configuration they have rather than lose the restriction, and the lists say they cannot read
/// it. The API then takes the row over, sending no stamp, since no read could show one.
#[tokio::test]
async fn a_stored_policy_in_another_shape_fails_the_snapshot() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let db = store.client().await.unwrap();
    for config in [
        json!({}),
        json!({"deny": ["nope"]}),
        json!({"deny": ["10.0.0.0/8"], "mode": "strict"}),
    ] {
        db.execute("delete from plugins", &[]).await.unwrap();
        db.execute(
            "insert into plugins (workspace_id, name, config, service_id)
             select workspace_id, 'ip_restriction', $1, id from services where name = 'orders'",
            &[&config],
        )
        .await
        .unwrap();
        assert!(store.snapshot().await.is_err(), "{config}");
        for path in [IP, ROUTES, SERVICES] {
            let (status, _) = send(&app, "GET", path, Some(s.vi), "").await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path} {config}");
        }
    }
    ok(
        &app,
        "PUT",
        IP,
        s.ed,
        &put("service:orders", json!({"deny": ["10.0.0.0/8"]}), None),
    )
    .await;
    assert_eq!(
        plugins_on(&compiled(&store).await, COMPILED_ROUTE),
        [deny(&["10.0.0.0/8"])]
    );
}

/// A request_size_limit goes through the same endpoint as every kind it keeps: it compiles onto
/// the rule, the route row says where it comes from, and a limit of nothing is refused at
/// `max_bytes`, writing nothing.
#[tokio::test]
async fn a_request_size_limit_reaches_the_compiled_rule() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;

    ok(
        &app,
        "PUT",
        SIZE,
        s.ed,
        &put("route:orders-api", json!({"max_bytes": 1024}), None),
    )
    .await;
    assert_eq!(
        plugins_on(&compiled(&store).await, COMPILED_ROUTE),
        [Plugin::RequestSizeLimit(RequestSizeLimitPolicy {
            max_bytes: 1024
        })]
    );
    assert_eq!(
        row(&app, ROUTES, "orders-api", s.vi).await["policies"]["request_size_limit"]["from"],
        "route"
    );

    let before = everything(&store).await;
    let (status, answer) = send(
        &app,
        "PUT",
        SIZE,
        Some(s.ed),
        &put("workspace", json!({"max_bytes": 0}), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(parse(&answer)["field"], "max_bytes", "{answer}");
    assert_eq!(
        everything(&store).await,
        before,
        "the refusal wrote nothing"
    );
}

/// A request_transformer goes through the same endpoint: it compiles onto the rule and the route
/// row says where it comes from. A credential it adds for the upstream is in the list, which the
/// console edits from, and never in the audit log, whose entries name the header and not its
/// value, for a create, an update and a delete alike. A header the gateway sets from the key it
/// checked is refused at the list that names it, writing nothing.
#[tokio::test]
async fn a_request_transformer_reaches_the_rule_and_its_audit_names_no_values() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let first = json!({"headers": {"add": [["authorization", "Bearer s3cret"]]}});

    ok(
        &app,
        "PUT",
        TRANSFORM,
        s.ed,
        &put("route:orders-api", first.clone(), None),
    )
    .await;
    assert_eq!(
        plugins_on(&compiled(&store).await, COMPILED_ROUTE),
        [Plugin::RequestTransformer(RequestTransformerPolicy {
            headers: HeaderEdits {
                add: vec![("authorization".into(), "Bearer s3cret".into())],
                ..HeaderEdits::default()
            },
            query: HeaderEdits::default(),
        })]
    );
    assert_eq!(
        row(&app, ROUTES, "orders-api", s.vi).await["policies"]["request_transformer"]["from"],
        "route"
    );
    let list = read(&app, TRANSFORM, s.vi).await;
    assert_eq!(list[0]["target"], "route:orders-api");
    assert_eq!(list[0]["config"], first);
    assert!(list.to_string().contains("s3cret"), "{list}");

    let (_, _, after) = &policy_audits(&store).await[0];
    assert!(!after.to_string().contains("s3cret"), "{after}");
    assert_eq!(
        after,
        &json!({
            "target": "route:orders-api",
            "kind": "request_transformer",
            "config": {"headers": {"add": ["authorization"]}},
        })
    );

    // An update and a delete record the replaced policy by its names too.
    let second = json!({
        "headers": {"replace": [["authorization", "Bearer t0ken"]]},
        "query": {"add": [["api_key", "k3y"]]},
    });
    let read_at = list[0]["updated_at"].as_str().unwrap().to_string();
    ok(
        &app,
        "PUT",
        TRANSFORM,
        s.ed,
        &put("route:orders-api", second, Some(&read_at)),
    )
    .await;
    ok(
        &app,
        "DELETE",
        &format!("{TRANSFORM}?target=route:orders-api"),
        s.ed,
        "",
    )
    .await;
    let audits = policy_audits(&store).await;
    let entry = |config: serde_json::Value| json!({"target": "route:orders-api", "kind": "request_transformer", "config": config});
    let first_names = entry(json!({"headers": {"add": ["authorization"]}}));
    let second_names = entry(json!({
        "headers": {"replace": ["authorization"]},
        "query": {"add": ["api_key"]},
    }));
    assert_eq!(
        audits,
        [
            ("create".to_string(), json!(null), first_names.clone()),
            ("update".to_string(), first_names, second_names.clone()),
            ("delete".to_string(), second_names, json!(null)),
        ]
    );

    let before = everything(&store).await;
    let consumer = json!({"headers": {"add": [["x-consumer-username", "alice"]]}});
    let (status, answer) = send(
        &app,
        "PUT",
        TRANSFORM,
        Some(s.ed),
        &put("route:orders-api", consumer, None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(parse(&answer)["field"], "headers.add", "{answer}");
    assert_eq!(
        everything(&store).await,
        before,
        "the refusal wrote nothing"
    );
}

#[tokio::test]
async fn kubernetes_mode_has_none_of_it() {
    let app = console(None);
    let (status, body) = send(&app, "GET", IP, None, "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(sentence(&body).contains("keeps no configuration"), "{body}");
}
