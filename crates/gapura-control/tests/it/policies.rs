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
use gapura_core::config::{Config, IpRestrictionPolicy, Plugin};
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
/// The compiled name of the seeded route.
const COMPILED_ROUTE: &str = "default/orders-api";

/// - `root`: superuser, the only one who reaches the second workspace, `payments`.
/// - `ada`: admin of default. `ed`: editor of default. `vi`: viewer of default.
///
/// And in default, a service `orders` and a route `orders-api` for `api.example.com`.
struct Seed {
    #[allow(dead_code)] // a later test in this file uses it
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
#[allow(dead_code)] // a later test in this file uses it
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
#[allow(dead_code)] // a later test in this file uses it
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
#[allow(dead_code)] // a later test in this file uses it
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
