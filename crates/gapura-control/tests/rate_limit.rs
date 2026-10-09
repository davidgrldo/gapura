//! Request limits through `/api/workspaces/{ws}/rate-limit`, against Postgres: that a limit
//! reaches the compiled configuration as the rule's `rate_limit`, which limit applies where
//! several do, what the lists show, who may do what, what the audit records, that every refusal
//! writes nothing, and that a stored row in a shape the API never writes fails the snapshot.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `consumers.rs`, whose helpers these are copies of so that each file reads on its own. Run
//! them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test rate_limit
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
use gapura_core::config::{Config, Plugin, RateLimit};
use gapura_core::store::StoreSettings;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

/// One database, so the tests take turns, as in `consumers.rs`.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn fresh_store() -> Option<(Arc<Store>, tokio::sync::MutexGuard<'static, ()>)> {
    let url = match std::env::var("GAPURA_TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "GAPURA_TEST_DATABASE_URL must be set in CI"
            );
            eprintln!("skipped: set GAPURA_TEST_DATABASE_URL to run this");
            return None;
        }
    };
    let guard = ONE_AT_A_TIME.lock().await;
    let store = Arc::new(Store::connect(&url).await.expect("connecting"));
    store
        .client()
        .await
        .expect("client")
        .batch_execute(
            "drop schema public cascade; create schema public;
             grant all on schema public to public;",
        )
        .await
        .expect("resetting the schema");
    store.migrate().await.expect("migrating");
    Some((store, guard))
}

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
const LIMITS: &str = "/api/workspaces/default/rate-limit";
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

/// The request limit the compiled `route` carries, if any.
fn limit_on(config: &Config, route: &str) -> Option<RateLimit> {
    let rule = config
        .listeners
        .iter()
        .flat_map(|l| &l.rules)
        .find(|r| r.route == route)
        .unwrap_or_else(|| panic!("{route} is not compiled"));
    rule.rate_limit.clone()
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

/// A PUT body for `target`.
fn put(target: &str, limit: u32, per: &str) -> String {
    json!({"target": target, "limit": limit, "per": per}).to_string()
}

fn per_minute(limit: u32) -> Option<RateLimit> {
    Some(RateLimit {
        limit,
        window_ms: 60_000,
    })
}

/// The point of the feature: a limit written through the API reaches the rule the data planes
/// are served, with the window its `per` names, and not the plugin list.
#[tokio::test]
async fn the_compiled_rule_carries_the_limit() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    assert_eq!(limit_on(&compiled(&store).await, COMPILED_ROUTE), None);

    for (per, window_ms) in [("second", 1_000), ("minute", 60_000), ("hour", 3_600_000)] {
        ok(&app, "PUT", LIMITS, s.ed, &put("route:orders-api", 20, per)).await;
        let config = compiled(&store).await;
        assert_eq!(
            limit_on(&config, COMPILED_ROUTE),
            Some(RateLimit {
                limit: 20,
                window_ms
            }),
            "{per}"
        );
        let rule = &config.listeners[0].rules[0];
        assert!(rule.plugins.is_empty(), "a limit is not a plugin");
    }
    // At the bound, not past it.
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("route:orders-api", 1_000_000, "hour"),
    )
    .await;
    assert_eq!(
        limit_on(&compiled(&store).await, COMPILED_ROUTE),
        Some(RateLimit {
            limit: 1_000_000,
            window_ms: 3_600_000
        })
    );
}

/// PUT on each kind of target; the list shows each with its limit and window.
#[tokio::test]
async fn each_target_kind_is_listed() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    assert_eq!(read(&app, LIMITS, s.vi).await, json!([]));
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("route:orders-api", 3, "second"),
    )
    .await;
    ok(&app, "PUT", LIMITS, s.ed, &put("workspace", 1000, "hour")).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("service:orders", 120, "minute"),
    )
    .await;
    assert_eq!(
        read(&app, LIMITS, s.vi).await,
        json!([
            {"target": "workspace", "limit": 1000, "per": "hour"},
            {"target": "service:orders", "limit": 120, "per": "minute"},
            {"target": "route:orders-api", "limit": 3, "per": "second"},
        ])
    );
    // What is stored is the data plane's shape, one row per target.
    let stored: Vec<serde_json::Value> = store
        .client()
        .await
        .unwrap()
        .query(
            "select config from plugins where name = 'rate_limit' order by config->>'limit'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        stored,
        vec![
            json!({"limit": 1000, "window_ms": 3_600_000}),
            json!({"limit": 120, "window_ms": 60_000}),
            json!({"limit": 3, "window_ms": 1_000}),
        ]
    );
}

/// Route over service over workspace in the compiled rule and in both lists, and beside a key
/// requirement, which is another kind and applies as well.
#[tokio::test]
async fn the_most_specific_limit_applies() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    for (target, limit) in [
        ("workspace", 10),
        ("service:orders", 20),
        ("route:orders-api", 30),
    ] {
        ok(&app, "PUT", LIMITS, s.ed, &put(target, limit, "minute")).await;
    }
    ok(
        &app,
        "PUT",
        "/api/workspaces/default/key-auth",
        s.ed,
        r#"{"target":"workspace"}"#,
    )
    .await;

    for (limit, from, then_delete) in [
        (30, "route", Some("route:orders-api")),
        (20, "service", Some("service:orders")),
        (10, "workspace", None),
    ] {
        let config = compiled(&store).await;
        assert_eq!(
            limit_on(&config, COMPILED_ROUTE),
            per_minute(limit),
            "{from}"
        );
        assert!(
            matches!(
                config.listeners[0].rules[0].plugins.as_slice(),
                [Plugin::KeyAuth(_)]
            ),
            "the key requirement still applies"
        );
        let route = row(&app, ROUTES, "orders-api", s.vi).await;
        assert_eq!(
            route["rate_limit"],
            json!({"limit": limit, "per": "minute", "from": from})
        );
        assert_eq!(
            route["key_auth"],
            json!({"header": "x-api-key", "from": "workspace"})
        );
        if let Some(target) = then_delete {
            ok(
                &app,
                "DELETE",
                &format!("{LIMITS}?target={target}"),
                s.ed,
                "",
            )
            .await;
        }
    }
    // The service shows its own limit or the workspace's, never a route's.
    assert_eq!(
        row(&app, SERVICES, "orders", s.vi).await["rate_limit"],
        json!({"limit": 10, "per": "minute", "from": "workspace"})
    );
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("route:orders-api", 5, "second"),
    )
    .await;
    assert_eq!(
        row(&app, SERVICES, "orders", s.vi).await["rate_limit"],
        json!({"limit": 10, "per": "minute", "from": "workspace"})
    );
    ok(&app, "PUT", LIMITS, s.ed, &put("service:orders", 7, "hour")).await;
    assert_eq!(
        row(&app, SERVICES, "orders", s.vi).await["rate_limit"],
        json!({"limit": 7, "per": "hour", "from": "service"})
    );

    for target in ["route:orders-api", "service:orders", "workspace"] {
        ok(
            &app,
            "DELETE",
            &format!("{LIMITS}?target={target}"),
            s.ed,
            "",
        )
        .await;
    }
    assert_eq!(limit_on(&compiled(&store).await, COMPILED_ROUTE), None);
    for (list, name) in [(ROUTES, "orders-api"), (SERVICES, "orders")] {
        assert_eq!(
            row(&app, list, name, s.vi).await["rate_limit"],
            serde_json::Value::Null,
            "{list}"
        );
    }
}

/// Create, the same limit again (nothing written), a change, and removal: each write is one
/// policy entry recording the target, the kind, the limit and its window.
#[tokio::test]
async fn the_audit_records_each_change_and_a_save_of_nothing_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let first = put("service:orders", 100, "minute");
    ok(&app, "PUT", LIMITS, s.ed, &first).await;

    let before = everything(&store).await;
    ok(&app, "PUT", LIMITS, s.ada, &first).await;
    assert_eq!(everything(&store).await, before, "a save of nothing");

    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("service:orders", 100, "second"),
    )
    .await;
    ok(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=service:orders"),
        s.ed,
        "",
    )
    .await;

    let minute =
        json!({"target": "service:orders", "kind": "rate_limit", "limit": 100, "per": "minute"});
    let second =
        json!({"target": "service:orders", "kind": "rate_limit", "limit": 100, "per": "second"});
    let null = serde_json::Value::Null;
    assert_eq!(
        policy_audits(&store).await,
        vec![
            ("create".to_string(), null.clone(), minute.clone()),
            ("update".to_string(), minute, second.clone()),
            ("delete".to_string(), second, null),
        ]
    );

    // Deleting what is no longer there is 404, and writes nothing.
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=service:orders"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(sentence(&body), "service:orders has no request limit.");
    assert_eq!(everything(&store).await, before);
}

#[tokio::test]
async fn bad_input_is_named_and_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let before = everything(&store).await;

    for (body, field) in [
        (put("consumer:x", 10, "minute"), "target"),
        (put("route:", 10, "minute"), "target"),
        (put("workspace", 0, "minute"), "limit"),
        (put("workspace", 1_000_001, "minute"), "limit"),
        (
            json!({"target": "workspace", "limit": -5, "per": "minute"}).to_string(),
            "limit",
        ),
        (
            json!({"target": "workspace", "limit": 1.5, "per": "minute"}).to_string(),
            "limit",
        ),
        (
            json!({"target": "workspace", "limit": "10", "per": "minute"}).to_string(),
            "limit",
        ),
        (
            json!({"target": "workspace", "per": "minute"}).to_string(),
            "limit",
        ),
        (put("workspace", 10, "min"), "per"),
        (put("workspace", 10, "day"), "per"),
        (
            json!({"target": "workspace", "limit": 10}).to_string(),
            "per",
        ),
    ] {
        let (status, answer) = send(&app, "PUT", LIMITS, Some(s.ed), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert_eq!(parse(&answer)["field"], field, "{body}: {answer}");
        assert!(!sentence(&answer).is_empty());
    }
    // A field this console does not know is not quietly dropped.
    let (status, answer) = send(
        &app,
        "PUT",
        LIMITS,
        Some(s.ed),
        &json!({"target": "workspace", "limit": 10, "per": "minute", "by": "consumer"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    let (status, answer) = send(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=consumer:x"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(parse(&answer)["field"], "target");
    let (status, answer) = send(&app, "DELETE", LIMITS, Some(s.ed), "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no target: {answer}");
    assert_eq!(parse(&answer)["field"], "target");

    for (method, path, body, said) in [
        (
            "PUT",
            LIMITS.to_string(),
            put("route:missing", 10, "minute"),
            "There is no route named missing in this workspace.",
        ),
        (
            "PUT",
            LIMITS.to_string(),
            put("service:missing", 10, "minute"),
            "There is no service named missing in this workspace.",
        ),
        (
            "DELETE",
            format!("{LIMITS}?target=route:orders-api"),
            String::new(),
            "route:orders-api has no request limit.",
        ),
        (
            "DELETE",
            format!("{LIMITS}?target=workspace"),
            String::new(),
            "workspace has no request limit.",
        ),
    ] {
        let (status, answer) = send(&app, method, &path, Some(s.ed), &body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
        assert_eq!(sentence(&answer), said);
    }
    assert_eq!(
        everything(&store).await,
        before,
        "none of it wrote anything"
    );
}

#[tokio::test]
async fn a_viewer_reads_an_editor_writes_and_no_role_is_refused() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "PUT", LIMITS, s.ed, &put("workspace", 60, "minute")).await;
    let off = format!("{LIMITS}?target=workspace");

    assert_eq!(read(&app, LIMITS, s.vi).await[0]["target"], "workspace");
    let before = everything(&store).await;
    for (method, path, body) in [
        ("PUT", LIMITS, put("route:orders-api", 1, "second")),
        ("DELETE", off.as_str(), String::new()),
    ] {
        let (status, answer) = send(&app, method, path, Some(s.vi), &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
        assert_eq!(
            sentence(&answer),
            "Making changes in this workspace needs the editor role."
        );
    }
    assert_eq!(everything(&store).await, before, "a viewer wrote nothing");

    // Someone whose roles are all in default is refused the same way in a workspace that exists
    // and one that does not.
    for who in [s.ed, s.ada] {
        for (method, tail, body) in [
            ("GET", "/rate-limit", String::new()),
            ("PUT", "/rate-limit", put("workspace", 60, "minute")),
            ("DELETE", "/rate-limit?target=workspace", String::new()),
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
    // And no one signed in at all.
    let (status, _) = send(&app, "GET", LIMITS, None, "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );

    // A service or route with a limit of its own is not deleted from under it.
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("route:orders-api", 1, "second"),
    )
    .await;
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("{ROUTES}/orders-api"),
        Some(s.ada),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        sentence(&body),
        "1 policy is attached to this route. Remove it first."
    );

    // An editor switches it off, as they switched it on.
    ok(&app, "DELETE", &off, s.ed, "").await;
    ok(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=route:orders-api"),
        s.ed,
        "",
    )
    .await;
    assert_eq!(read(&app, LIMITS, s.vi).await, json!([]));
}

/// A `rate_limit` row only SQL written by hand could store -- a window the API never writes, a
/// limit of zero, a field it does not know -- fails the snapshot, so the data planes keep the
/// configuration they have rather than lose the limit, and the lists say they cannot read it
/// rather than show no limit. The API then takes the row over with a limit it can read.
#[tokio::test]
async fn a_stored_limit_in_another_shape_fails_the_snapshot() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let db = store.client().await.unwrap();
    for config in [
        json!({"limit": 10, "window_ms": 5_000}),
        json!({"limit": 0, "window_ms": 1_000}),
        json!({"limit": 10, "window_ms": 1_000, "by": "consumer"}),
        json!({"limit": "ten", "window_ms": 1_000}),
    ] {
        db.execute("delete from plugins", &[]).await.unwrap();
        db.execute(
            "insert into plugins (workspace_id, name, config, service_id)
             select workspace_id, 'rate_limit', $1, id from services where name = 'orders'",
            &[&config],
        )
        .await
        .unwrap();
        assert!(store.snapshot().await.is_err(), "{config}");
        for path in [LIMITS, ROUTES, SERVICES] {
            let (status, _) = send(&app, "GET", path, Some(s.vi), "").await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path} {config}");
        }
    }
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("service:orders", 10, "second"),
    )
    .await;
    assert_eq!(
        limit_on(&compiled(&store).await, COMPILED_ROUTE),
        Some(RateLimit {
            limit: 10,
            window_ms: 1_000
        })
    );
    assert_eq!(policy_audits(&store).await.len(), 1);
}

#[tokio::test]
async fn kubernetes_mode_has_none_of_it() {
    let app = console(None);
    let (status, body) = send(&app, "GET", LIMITS, None, "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(sentence(&body).contains("keeps no configuration"), "{body}");
}
