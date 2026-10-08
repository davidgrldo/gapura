//! Services and routes through `/api/workspaces/{ws}/services` and `/routes`, against Postgres:
//! who may read, write and delete them, the conflicts a write can meet, which hosts a workspace
//! may route, the audit entries writes leave, and that what the console writes is what the data
//! planes are served.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `identity.rs` and `grants.rs`, and for the same reason: the alternative mocks the database and
//! proves the mock. CI sets it. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test configuration
//! ```
//!
//! The helpers are copies of `grants.rs`'s rather than a shared `tests/common` module, so that
//! each file reads on its own; the accounts each file seeds are its own.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
use tower::ServiceExt;
use uuid::Uuid;

/// One database, so the tests take turns: each starts by dropping the schema, and two doing
/// that at once would delete each other's tables mid-run. The guard is held for the whole test
/// rather than just the reset, because the race is between one test's reset and another's
/// queries. Cargo runs test binaries one after another, so the other test files that reset
/// this schema never use the database at the same time as this one. Two cargo runs against one
/// database still collide, and so does a runner that gives each test a process of its own.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn fresh_store() -> Option<(Arc<Store>, tokio::sync::MutexGuard<'static, ()>)> {
    let url = match std::env::var("GAPURA_TEST_DATABASE_URL") {
        Ok(url) => url,
        // Optional locally, mandatory in CI, so a typo in the workflow cannot turn these into a
        // green build that exercised nothing.
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

/// The console's router: in store mode over `store`, or in Kubernetes mode without one. Its
/// readers point at nothing, because these tests are about the store's configuration.
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
                expires_at: u64::MAX
            },
            KEY
        )
    )
}

/// Sends `method path` with `headers` and `body`, signed in as `as_` when one is given, and
/// returns the status and the body as text.
async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    as_: Option<Uuid>,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, String) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(id) = as_ {
        req = req.header("cookie", cookie(&id.to_string()));
    }
    for (name, value) in headers {
        req = req.header(*name, *value);
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

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

const JSON: (&str, &str) = ("content-type", "application/json");

/// What a browser sends with the console's own writes.
const FROM_THE_CONSOLE: &[(&str, &str)] = &[JSON, ("sec-fetch-site", "same-origin")];

/// - `root`: superuser.
/// - `ada`: admin of default. `ed`: editor of default. `vi`: viewer of default.
/// - `out`: holds nothing. A second workspace, `payments`, where only root reaches.
struct Seed {
    root: Uuid,
    ada: Uuid,
    ed: Uuid,
    vi: Uuid,
    out: Uuid,
    default: Uuid,
}

async fn seed(store: &Store) -> Seed {
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
    for (name, superuser) in [
        ("root", true),
        ("ada", false),
        ("ed", false),
        ("vi", false),
        ("out", false),
    ] {
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
    Seed {
        root: ids["root"],
        ada: ids["ada"],
        ed: ids["ed"],
        vi: ids["vi"],
        out: ids["out"],
        default,
    }
}

const SERVICE: &str = r#"{"name":"orders","protocol":"http","host":"orders.internal","port":8080,"read_timeout_ms":15000}"#;
/// Names a host, since only a superuser may route every host.
const ROUTE: &str = r#"{"name":"orders-api","service":"orders","hosts":["api.example.com"],"paths":[{"type":"prefix","value":"/orders"}],"methods":["GET"]}"#;
const SERVICES: &str = "/api/workspaces/default/services";
const ROUTES: &str = "/api/workspaces/default/routes";
const PAYMENTS_SERVICES: &str = "/api/workspaces/payments/services";
const PAYMENTS_ROUTES: &str = "/api/workspaces/payments/routes";

/// The row the list shows for `name`.
async fn row(app: &axum::Router, list: &str, name: &str, as_: Uuid) -> serde_json::Value {
    let (status, body) = send(app, "GET", list, Some(as_), &[], "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    json(&body)
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not listed: {body}"))
        .clone()
}

/// The `updated_at` the list shows for `name`.
async fn seen(app: &axum::Router, list: &str, name: &str, as_: Uuid) -> String {
    row(app, list, name, as_).await["updated_at"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn count(store: &Store, sql: &str) -> i64 {
    store
        .client()
        .await
        .unwrap()
        .query_one(sql, &[])
        .await
        .unwrap()
        .get(0)
}

/// Everything a write could change: every service and route row as stored (with its
/// `updated_at`), every policy, how many audit entries there are, and the version the data planes
/// poll. Equal before and after a refusal means the refusal wrote nothing.
async fn everything(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select jsonb_build_object(
                 'services', (select coalesce(jsonb_agg(to_jsonb(s) order by s.workspace_id, s.name), '[]')
                                from services s),
                 'routes', (select coalesce(jsonb_agg(to_jsonb(r) order by r.workspace_id, r.name), '[]')
                              from routes r),
                 'plugins', (select count(*) from plugins),
                 'audit', (select count(*) from audit_log),
                 'version', (select version from config_state))",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// A setup write, which must succeed for the test to mean anything.
async fn ok(app: &axum::Router, method: &str, path: &str, as_: Uuid, body: &str) {
    let (status, answer) = send(app, method, path, Some(as_), FROM_THE_CONSOLE, body).await;
    assert_eq!(
        (status, answer.as_str()),
        (StatusCode::NO_CONTENT, ""),
        "{method} {path} {body}"
    );
}

/// The sentence a refusal carries.
fn sentence(body: &str) -> String {
    json(body)["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no sentence: {body}"))
        .to_string()
}

/// The names a list shows.
async fn names(app: &axum::Router, list: &str, as_: Uuid) -> Vec<String> {
    let (status, body) = send(app, "GET", list, Some(as_), &[], "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    json(&body)
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_viewer_reads_an_editor_writes_and_an_admin_deletes() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let before = everything(&store).await;
    let (status, _) = send(
        &app,
        "POST",
        SERVICES,
        Some(s.vi),
        FROM_THE_CONSOLE,
        SERVICE,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(everything(&store).await, before, "a refusal writes nothing");
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    let (status, body) = send(&app, "GET", SERVICES, Some(s.vi), &[], "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)[0]["host"], "orders.internal");
    assert_eq!(json(&body)[0]["routes"], 0);
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("{SERVICES}/orders"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    ok(&app, "DELETE", &format!("{SERVICES}/orders"), s.ada, "").await;
    assert!(names(&app, SERVICES, s.vi).await.is_empty());
}

#[tokio::test]
async fn a_workspace_without_a_role_reads_as_forbidden_whether_or_not_it_exists() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store));
    for path in [PAYMENTS_SERVICES, "/api/workspaces/nowhere/services"] {
        let (status, body) = send(&app, "GET", path, Some(s.ada), &[], "").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(json(&body)["error"], "You hold no role in that workspace.");
    }
    let (status, _) = send(&app, "GET", SERVICES, Some(s.out), &[], "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&app, "GET", PAYMENTS_SERVICES, Some(s.root), &[], "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a superuser reaches every workspace"
    );
}

#[tokio::test]
async fn a_duplicate_a_stale_edit_and_a_service_in_use_are_conflicts() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    let before = everything(&store).await;
    let (status, _) = send(
        &app,
        "POST",
        SERVICES,
        Some(s.ed),
        FROM_THE_CONSOLE,
        SERVICE,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        everything(&store).await,
        before,
        "a duplicate writes nothing"
    );

    let at = seen(&app, SERVICES, "orders", s.ed).await;
    let edit = |port: u16, at: &str| {
        format!(
            r#"{{"name":"orders","protocol":"http","host":"orders.internal","port":{port},"updated_at":"{at}"}}"#
        )
    };
    ok(
        &app,
        "PUT",
        &format!("{SERVICES}/orders"),
        s.ed,
        &edit(8081, &at),
    )
    .await;
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "PUT",
        &format!("{SERVICES}/orders"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        &edit(8082, &at),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(sentence(&body).contains("Reload"));
    assert_eq!(
        everything(&store).await,
        before,
        "a stale edit writes nothing"
    );
    assert_eq!(row(&app, SERVICES, "orders", s.ed).await["port"], 8081);
    let updates = count(
        &store,
        "select count(*) from audit_log where object_kind = 'service' and action = 'update'",
    )
    .await;
    assert_eq!(updates, 1, "only the edit that was saved");

    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("{SERVICES}/orders"),
        Some(s.ada),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(sentence(&body).starts_with("1 route uses this service"));
    assert_eq!(everything(&store).await, before, "a service in use stays");
}

#[tokio::test]
async fn renaming_a_service_carries_its_routes() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    ok(
        &app,
        "POST",
        SERVICES,
        s.ed,
        r#"{"name":"billing","protocol":"http","host":"billing.internal","port":8080}"#,
    )
    .await;
    let at = seen(&app, SERVICES, "orders", s.ed).await;
    let rename = |to: &str| {
        format!(
            r#"{{"name":"{to}","protocol":"http","host":"orders.internal","port":8080,"updated_at":"{at}"}}"#
        )
    };

    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "PUT",
        &format!("{SERVICES}/orders"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        &rename("billing"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        sentence(&body),
        "A service named billing already exists in this workspace."
    );
    assert_eq!(everything(&store).await, before);

    ok(
        &app,
        "PUT",
        &format!("{SERVICES}/orders"),
        s.ed,
        &rename("orders-v2"),
    )
    .await;
    assert_eq!(names(&app, SERVICES, s.vi).await, ["billing", "orders-v2"]);
    let (_, body) = send(&app, "GET", ROUTES, Some(s.vi), &[], "").await;
    assert_eq!(json(&body)[0]["service"], "orders-v2");
}

#[tokio::test]
async fn editing_a_route_runs_its_checks_and_its_update() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    ok(
        &app,
        "POST",
        ROUTES,
        s.ed,
        &route_for("second", "orders", r#"["second.example.com"]"#),
    )
    .await;
    let edit = |name: &str, path: &str, priority: i32, at: &str| {
        format!(
            r#"{{"name":"{name}","service":"orders","hosts":["api.example.com"],"paths":[{{"type":"exact","value":"{path}"}}],"methods":["GET"],"priority":{priority},"updated_at":"{at}"}}"#
        )
    };

    // A real edit: the paths and the priority change, and the list shows them.
    let first = seen(&app, ROUTES, "orders-api", s.ed).await;
    ok(
        &app,
        "PUT",
        &format!("{ROUTES}/orders-api"),
        s.ed,
        &edit("orders-api", "/v2", 5, &first),
    )
    .await;
    let edited = row(&app, ROUTES, "orders-api", s.vi).await;
    assert_eq!(
        edited["paths"],
        serde_json::json!([{"type": "exact", "value": "/v2"}])
    );
    assert_eq!(edited["priority"], 5);
    assert_ne!(edited["updated_at"].as_str().unwrap(), first);

    // A save over what was read before that edit.
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "PUT",
        &format!("{ROUTES}/orders-api"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        &edit("orders-api", "/v3", 6, &first),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(sentence(&body).contains("Reload"));
    assert_eq!(everything(&store).await, before);

    // A rename into a name another route has.
    let at = seen(&app, ROUTES, "orders-api", s.ed).await;
    let (status, body) = send(
        &app,
        "PUT",
        &format!("{ROUTES}/orders-api"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        &edit("second", "/v2", 5, &at),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        sentence(&body),
        "A route named second already exists in this workspace."
    );
    assert_eq!(everything(&store).await, before);

    // A rename: the old name is gone.
    ok(
        &app,
        "PUT",
        &format!("{ROUTES}/orders-api"),
        s.ed,
        &edit("orders-api-v2", "/v2", 5, &at),
    )
    .await;
    assert_eq!(names(&app, ROUTES, s.vi).await, ["orders-api-v2", "second"]);

    // A route that is not there.
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "PUT",
        &format!("{ROUTES}/orders-api"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        &edit("orders-api", "/v2", 5, &at),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(everything(&store).await, before);

    // A superuser's catch-all, which an editor may not save as one.
    ok(
        &app,
        "POST",
        ROUTES,
        s.root,
        &route_for("catch-all", "orders", "[]"),
    )
    .await;
    let at = seen(&app, ROUTES, "catch-all", s.ed).await;
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "PUT",
        &format!("{ROUTES}/catch-all"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        &format!(
            r#"{{"name":"catch-all","service":"orders","hosts":[],"paths":[{{"type":"prefix","value":"/"}}],"priority":-1,"updated_at":"{at}"}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(sentence(&body).contains("Name at least one host"), "{body}");
    assert_eq!(everything(&store).await, before);
}

#[tokio::test]
async fn an_invalid_field_is_named_and_nothing_is_written() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let (status, body) = send(
        &app,
        "POST",
        SERVICES,
        Some(s.ed),
        FROM_THE_CONSOLE,
        r#"{"name":"orders","protocol":"http","host":"orders.internal","port":70000}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["field"], "port");
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    let (status, body) = send(
        &app,
        "POST",
        ROUTES,
        Some(s.ed),
        FROM_THE_CONSOLE,
        r#"{"name":"r","service":"orders","hosts":["api.example.com"],"paths":[{"type":"regex","value":"[unclosed"}]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["field"], "paths[0].value");
    let (status, body) = send(
        &app,
        "POST",
        ROUTES,
        Some(s.ed),
        FROM_THE_CONSOLE,
        r#"{"name":"r","service":"missing","hosts":["api.example.com"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(sentence(&body).contains("missing"));
    let audits = count(
        &store,
        "select count(*) from audit_log where object_kind in ('service', 'route')",
    )
    .await;
    assert_eq!(audits, 1, "only the one service that was created");
}

#[tokio::test]
async fn every_write_leaves_one_audit_entry_naming_its_actor() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    let at = seen(&app, SERVICES, "orders", s.ed).await;
    ok(
        &app,
        "PUT",
        &format!("{SERVICES}/orders"),
        s.ed,
        &format!(
            r#"{{"name":"orders","protocol":"http","host":"orders.internal","port":8081,"updated_at":"{at}"}}"#
        ),
    )
    .await;
    let at = seen(&app, ROUTES, "orders-api", s.ed).await;
    ok(
        &app,
        "PUT",
        &format!("{ROUTES}/orders-api"),
        s.ed,
        &format!(
            r#"{{"name":"orders-api","service":"orders","hosts":["api.example.com"],"priority":3,"updated_at":"{at}"}}"#
        ),
    )
    .await;
    ok(&app, "DELETE", &format!("{ROUTES}/orders-api"), s.ada, "").await;
    ok(&app, "DELETE", &format!("{SERVICES}/orders"), s.ada, "").await;
    let rows = store
        .client()
        .await
        .unwrap()
        .query(
            "select actor_name, action, object_kind, before is null as no_before, after is null as no_after
               from audit_log where object_kind in ('service', 'route') order by id",
            &[],
        )
        .await
        .unwrap();
    let got: Vec<(String, String, String, bool, bool)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect();
    assert_eq!(
        got,
        [
            ("ed".into(), "create".into(), "service".into(), true, false),
            ("ed".into(), "create".into(), "route".into(), true, false),
            ("ed".into(), "update".into(), "service".into(), false, false),
            ("ed".into(), "update".into(), "route".into(), false, false),
            ("ada".into(), "delete".into(), "route".into(), false, true),
            ("ada".into(), "delete".into(), "service".into(), false, true),
        ]
    );
}

#[tokio::test]
async fn a_route_made_in_the_console_is_served_to_data_planes() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    let (_, snapshot) = store.snapshot().await.unwrap();
    let config = gapura_core::store::compile(
        &snapshot,
        &gapura_core::store::StoreSettings {
            http_ports: vec![80],
        },
    );
    let hit = config
        .match_port_with(
            80,
            &gapura_core::matcher::RequestAttrs {
                host: "api.example.com",
                path: "/orders/7",
                method: "GET",
                headers: &[],
                query: &[],
            },
            &gapura_core::matcher::compile_regexes(&config).0,
        )
        .expect("the route matches");
    assert_eq!(hit.rule.route, "default/orders-api");
    assert_eq!(hit.rule.timeouts.backend_request_ms, Some(15000));
    assert!(config.clusters.contains_key("orders.internal:8080"));
}

#[tokio::test]
async fn kubernetes_mode_has_no_configuration_api() {
    let app = console(None);
    let (status, body) = send(&app, "GET", SERVICES, None, &[], "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(sentence(&body).contains("keeps no configuration"), "{body}");
}

/// Every configuration path and method, each as a request that would be valid from an editor
/// (or an admin, for a delete), and each malformed in some way: a body that is not JSON, one
/// longer than the console reads, and a workspace segment that is not UTF-8 once decoded.
#[tokio::test]
async fn a_request_is_judged_by_who_sent_it_before_it_is_judged_by_what_it_says() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    let service_at = seen(&app, SERVICES, "orders", s.ed).await;
    let route_at = seen(&app, ROUTES, "orders-api", s.ed).await;
    let service_edit = format!(
        r#"{{"name":"orders","protocol":"http","host":"orders.internal","port":8081,"updated_at":"{service_at}"}}"#
    );
    let route_edit = format!(
        r#"{{"name":"orders-api","service":"orders","hosts":["api.example.com"],"priority":2,"updated_at":"{route_at}"}}"#
    );
    let service = format!("{SERVICES}/orders");
    let route = format!("{ROUTES}/orders-api");
    let too_long = format!(
        r#"{{"name":"orders","protocol":"http","host":"{}","port":1}}"#,
        "a".repeat(100_000)
    );
    let before = everything(&store).await;

    let valid: Vec<(&str, &str, &str)> = vec![
        ("GET", SERVICES, ""),
        ("POST", SERVICES, SERVICE),
        ("PUT", service.as_str(), service_edit.as_str()),
        ("DELETE", service.as_str(), ""),
        ("GET", ROUTES, ""),
        ("POST", ROUTES, ROUTE),
        ("PUT", route.as_str(), route_edit.as_str()),
        ("DELETE", route.as_str(), ""),
    ];
    // Each with what an editor is told about it.
    let malformed: Vec<(&str, &str, &str, StatusCode)> = vec![
        ("POST", SERVICES, "{", StatusCode::BAD_REQUEST),
        ("PUT", service.as_str(), "{", StatusCode::BAD_REQUEST),
        ("POST", ROUTES, "{", StatusCode::BAD_REQUEST),
        ("PUT", route.as_str(), "{", StatusCode::BAD_REQUEST),
        (
            "POST",
            SERVICES,
            too_long.as_str(),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "PUT",
            route.as_str(),
            too_long.as_str(),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ];
    let unreadable_workspace: Vec<(&str, &str, &str)> = vec![
        ("GET", "/api/workspaces/%FF/services", ""),
        ("POST", "/api/workspaces/%FF/services", SERVICE),
        (
            "PUT",
            "/api/workspaces/%FF/services/orders",
            service_edit.as_str(),
        ),
        ("DELETE", "/api/workspaces/%FF/services/orders", ""),
        ("GET", "/api/workspaces/%FF/routes", ""),
        ("POST", "/api/workspaces/%FF/routes", ROUTE),
        (
            "PUT",
            "/api/workspaces/%FF/routes/orders-api",
            route_edit.as_str(),
        ),
        ("DELETE", "/api/workspaces/%FF/routes/orders-api", ""),
    ];

    // No session, and an id that names no account: not signed in, so nothing else is said.
    let every = valid
        .iter()
        .chain(&unreadable_workspace)
        .copied()
        .chain(malformed.iter().map(|&(m, p, r, _)| (m, p, r)));
    for (method, path, request) in every {
        for who in [None, Some(Uuid::new_v4())] {
            let (status, body) = send(&app, method, path, who, FROM_THE_CONSOLE, request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} {who:?}");
            assert_eq!(sentence(&body), "You are not signed in.");
        }
    }

    // Signed in, a workspace segment that cannot be a workspace's name reads as an unknown one.
    for (method, path, request) in &unreadable_workspace {
        let (status, body) = send(&app, method, path, Some(s.ada), FROM_THE_CONSOLE, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(sentence(&body), "You hold no role in that workspace.");
    }

    // An editor is told what is wrong with the body.
    for (method, path, request, expected) in &malformed {
        let (status, body) = send(&app, method, path, Some(s.ed), FROM_THE_CONSOLE, request).await;
        assert_eq!(status, *expected, "{method} {path}: {body}");
        assert!(!sentence(&body).is_empty());
    }

    // A viewer may not change anything, however well asked, nor an editor delete.
    for (method, path, request) in [
        ("PUT", &service, &service_edit),
        ("PUT", &route, &route_edit),
    ] {
        let (status, body) = send(&app, method, path, Some(s.vi), FROM_THE_CONSOLE, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(
            sentence(&body),
            "Changing services and routes needs the editor role in this workspace."
        );
    }
    let (status, body) = send(&app, "DELETE", &route, Some(s.ed), FROM_THE_CONSOLE, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        sentence(&body),
        "Deleting services and routes needs the admin role in this workspace."
    );

    assert_eq!(
        everything(&store).await,
        before,
        "none of it wrote anything"
    );
}

/// A route body for `service` named `name`, with `hosts` as a JSON array.
fn route_for(name: &str, service: &str, hosts: &str) -> String {
    format!(
        r#"{{"name":"{name}","service":"{service}","hosts":{hosts},"paths":[{{"type":"prefix","value":"/"}}]}}"#
    )
}

#[tokio::test]
async fn a_host_belongs_to_one_workspace_and_any_host_only_to_a_superuser() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", PAYMENTS_SERVICES, s.root, SERVICE).await;

    // An editor routes a named host, and a workspace's routes may share one, since their
    // priority settles which answers; a wildcard of two labels or more is an editor's too.
    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    ok(
        &app,
        "POST",
        ROUTES,
        s.ed,
        &route_for("same-host", "orders", r#"["api.example.com"]"#),
    )
    .await;
    ok(
        &app,
        "POST",
        ROUTES,
        s.ed,
        &route_for("wild", "orders", r#"["*.example.com"]"#),
    )
    .await;

    let before = everything(&store).await;
    // Even a superuser cannot take a host another workspace routes, here through a wildcard
    // that would cover it.
    let (status, body) = send(
        &app,
        "POST",
        PAYMENTS_ROUTES,
        Some(s.root),
        FROM_THE_CONSOLE,
        &route_for("wide", "orders", r#"["*.example.com"]"#),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        sentence(&body),
        "*.example.com is already routed by another workspace."
    );
    let (status, body) = send(
        &app,
        "POST",
        ROUTES,
        Some(s.ed),
        FROM_THE_CONSOLE,
        &route_for("everything", "orders", "[]"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an editor routes no host: {body}"
    );
    assert!(sentence(&body).contains("Name at least one host"), "{body}");
    let (status, body) = send(
        &app,
        "POST",
        ROUTES,
        Some(s.ed),
        FROM_THE_CONSOLE,
        &route_for("tld", "orders", r#"["*.com"]"#),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an editor routes *.com: {body}"
    );
    assert!(
        sentence(&body).contains("only a superuser may route it"),
        "{body}"
    );
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );

    // A superuser's catch-all neither claims a host nor keeps another workspace from naming one.
    ok(
        &app,
        "POST",
        PAYMENTS_ROUTES,
        s.root,
        &route_for("everything", "orders", "[]"),
    )
    .await;
    ok(
        &app,
        "POST",
        ROUTES,
        s.ed,
        &route_for("shop", "orders", r#"["shop.example.org"]"#),
    )
    .await;
}

/// Two workspaces claiming one host at the same moment: the advisory lock orders them, so the
/// second sees the first's route and is refused, rather than both committing. Several rounds,
/// each with a host of its own, so one lucky interleaving does not pass it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_workspaces_claiming_one_host_at_once_get_one_each_way() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", PAYMENTS_SERVICES, s.root, SERVICE).await;
    for round in 0..20 {
        let hosts = format!(r#"["race{round}.example.com"]"#);
        let start = Arc::new(tokio::sync::Barrier::new(2));
        let claim = |list: &'static str, who: Uuid| {
            let app = app.clone();
            let body = route_for(&format!("race{round}"), "orders", &hosts);
            let start = start.clone();
            tokio::spawn(async move {
                start.wait().await;
                send(&app, "POST", list, Some(who), FROM_THE_CONSOLE, &body).await
            })
        };
        let ours = claim(ROUTES, s.ed);
        let theirs = claim(PAYMENTS_ROUTES, s.root);
        let (ours, theirs) = (ours.await.unwrap(), theirs.await.unwrap());
        let mut statuses = [ours.0, theirs.0];
        statuses.sort();
        assert_eq!(
            statuses,
            [StatusCode::NO_CONTENT, StatusCode::CONFLICT],
            "round {round}: {ours:?} {theirs:?}"
        );
    }
    let claimed = count(
        &store,
        "select count(*) from routes where name like 'race%'",
    )
    .await;
    assert_eq!(claimed, 20, "one route per host");
}

#[tokio::test]
async fn a_route_or_service_with_a_policy_attached_is_not_deleted() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    ok(
        &app,
        "POST",
        SERVICES,
        s.ed,
        r#"{"name":"billing","protocol":"http","host":"billing.internal","port":8080}"#,
    )
    .await;
    let db = store.client().await.unwrap();
    db.execute(
        "insert into plugins (workspace_id, name, config, route_id)
         select $1, 'key_auth', '{\"header\":\"x-api-key\"}', id from routes where name = 'orders-api'",
        &[&s.default],
    )
    .await
    .unwrap();
    db.execute(
        "insert into plugins (workspace_id, name, config, service_id)
         select $1, 'key_auth', '{\"header\":\"x-api-key\"}', id from services where name = 'billing'",
        &[&s.default],
    )
    .await
    .unwrap();

    let before = everything(&store).await;
    for (path, kind) in [
        (format!("{ROUTES}/orders-api"), "route"),
        (format!("{SERVICES}/billing"), "service"),
    ] {
        let (status, body) = send(&app, "DELETE", &path, Some(s.ada), FROM_THE_CONSOLE, "").await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}: {body}");
        assert_eq!(
            sentence(&body),
            format!("1 policy is attached to this {kind}. Remove it first.")
        );
    }
    assert_eq!(everything(&store).await, before);
    assert_eq!(count(&store, "select count(*) from plugins").await, 2);
}

#[tokio::test]
async fn a_save_that_changes_nothing_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ed, ROUTE).await;
    let before = everything(&store).await;

    // The route exactly as the list shows it, and the service without the count the list adds.
    let route = row(&app, ROUTES, "orders-api", s.ed).await;
    let mut service = row(&app, SERVICES, "orders", s.ed).await;
    service.as_object_mut().unwrap().remove("routes");
    ok(
        &app,
        "PUT",
        &format!("{ROUTES}/orders-api"),
        s.ed,
        &route.to_string(),
    )
    .await;
    ok(
        &app,
        "PUT",
        &format!("{SERVICES}/orders"),
        s.ed,
        &service.to_string(),
    )
    .await;

    assert_eq!(
        everything(&store).await,
        before,
        "no audit entry, no new updated_at, nothing for the data planes to reload"
    );
    assert_eq!(
        seen(&app, ROUTES, "orders-api", s.ed).await,
        route["updated_at"].as_str().unwrap()
    );
    assert_eq!(
        seen(&app, SERVICES, "orders", s.ed).await,
        service["updated_at"].as_str().unwrap()
    );
}

#[tokio::test]
async fn a_prefix_is_kept_without_its_trailing_slash() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store));
    ok(&app, "POST", SERVICES, s.ed, SERVICE).await;
    ok(
        &app,
        "POST",
        ROUTES,
        s.ed,
        &ROUTE.replace(r#""/orders""#, r#""/orders/""#),
    )
    .await;
    let route = row(&app, ROUTES, "orders-api", s.vi).await;
    assert_eq!(
        route["paths"],
        serde_json::json!([{"type": "prefix", "value": "/orders"}])
    );
}
