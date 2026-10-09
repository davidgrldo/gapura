//! Workspaces through `/api/workspaces`, against Postgres: that only a superuser creates, renames
//! and deletes them, that a workspace admin lists only theirs, that a rename carries everything
//! with it and changes what `/v1/config` serves, that only an empty workspace and never the last
//! one is deleted, also when two writes meet, and that every refusal writes nothing.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `data_planes.rs`, and for the same reason: the alternative mocks the database and proves the
//! mock. CI sets it. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test workspaces
//! ```
//!
//! The helpers are copies of `data_planes.rs`'s rather than a shared `tests/common` module, so
//! that each file reads on its own; the accounts each file seeds are its own.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::configuration::{Protocol, Service};
use gapura_control::grants::Refusal;
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::{Store, WriteError};
use gapura_core::store::StoreSettings;
use tower::ServiceExt;
use uuid::Uuid;

/// One database, so the tests take turns: each starts by dropping the schema, and two doing
/// that at once would delete each other's tables mid-run. The guard is held for the whole test
/// rather than just the reset, because the race is between one test's reset and another's
/// queries. Cargo runs test binaries one after another, so the other test files that reset
/// this schema never use the database at the same time as this one.
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
/// readers point at nothing, because these tests are about the store.
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
        store_settings: StoreSettings::default(),
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

/// Sends `method path` with `body`, as the console sends its own writes, signed in as `as_` when
/// one is given, and returns the status and the body as text.
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

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

const WORKSPACES: &str = "/api/workspaces";
const SERVICE: &str = r#"{"name":"orders","protocol":"http","host":"orders.internal","port":8080}"#;
const ROUTE: &str = r#"{"name":"orders-api","service":"orders","hosts":["api.example.com"],"paths":[{"type":"prefix","value":"/orders"}]}"#;

/// The sentence every refused write by someone who is not a superuser carries.
const SUPERUSERS_ONLY: &str = "Workspaces are a superuser's to change.";

fn workspace(name: &str) -> String {
    format!("{WORKSPACES}/{name}")
}

fn named(name: &str) -> String {
    format!(r#"{{"name":"{name}"}}"#)
}

/// - `root`: superuser. `ada`: admin of default. `vi`: viewer of default.
/// - `nobody`: an account with no role anywhere.
struct Seed {
    root: Uuid,
    ada: Uuid,
    vi: Uuid,
    nobody: Uuid,
}

async fn seed(store: &Store) -> Seed {
    let db = store.client().await.unwrap();
    let default = id_of(store, "default").await;
    let hash = gapura_control::password::hash("correct horse battery").unwrap();
    let mut ids = std::collections::HashMap::new();
    for (name, superuser) in [
        ("root", true),
        ("ada", false),
        ("vi", false),
        ("nobody", false),
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
    for (name, role) in [("ada", "admin"), ("vi", "viewer")] {
        grant(store, ids[name], default, role).await;
    }
    Seed {
        root: ids["root"],
        ada: ids["ada"],
        vi: ids["vi"],
        nobody: ids["nobody"],
    }
}

async fn grant(store: &Store, user: Uuid, workspace: Uuid, role: &str) {
    store
        .client()
        .await
        .unwrap()
        .execute(
            "insert into role_bindings (user_id, workspace_id, role) values ($1, $2, $3::text::role_name)",
            &[&user, &workspace, &role],
        )
        .await
        .unwrap();
}

async fn map_group(store: &Store, group: &str, workspace: Uuid, role: &str) {
    store
        .client()
        .await
        .unwrap()
        .execute(
            "insert into group_bindings (group_name, workspace_id, role) values ($1, $2, $3::text::role_name)",
            &[&group, &workspace, &role],
        )
        .await
        .unwrap();
}

async fn id_of(store: &Store, name: &str) -> Uuid {
    store
        .client()
        .await
        .unwrap()
        .query_one("select id from workspaces where name = $1", &[&name])
        .await
        .unwrap()
        .get(0)
}

/// A write that answers 204, which must succeed for the test to mean anything.
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
    json(body)["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no sentence: {body}"))
        .to_string()
}

/// The list as `as_`, which must succeed.
async fn list(app: &axum::Router, as_: Uuid) -> serde_json::Value {
    let (status, body) = send(app, "GET", WORKSPACES, Some(as_), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    json(&body)
}

/// The names the list shows `as_`, in its order.
async fn names(app: &axum::Router, as_: Uuid) -> Vec<String> {
    list(app, as_)
        .await
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["name"].as_str().unwrap().to_string())
        .collect()
}

/// The workspaces `/api/me` says `as_` holds a role in.
async fn my_workspaces(app: &axum::Router, as_: Uuid) -> Vec<String> {
    let (status, body) = send(app, "GET", "/api/me", Some(as_), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    json(&body)["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["workspace"].as_str().unwrap().to_string())
        .collect()
}

/// Every row a workspace write could change, as stored, the configuration's version, and how
/// many audit entries there are. Equal before and after a refusal means the refusal wrote nothing.
async fn everything(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select jsonb_build_object(
                 'workspaces', (select coalesce(jsonb_agg(to_jsonb(w) order by w.id), '[]') from workspaces w),
                 'grants', (select coalesce(jsonb_agg(to_jsonb(b) order by b.user_id, b.workspace_id), '[]') from role_bindings b),
                 'mappings', (select coalesce(jsonb_agg(to_jsonb(g) order by g.group_name, g.workspace_id), '[]') from group_bindings g),
                 'services', (select count(*) from services),
                 'routes', (select count(*) from routes),
                 'consumers', (select count(*) from consumers),
                 'plugins', (select count(*) from plugins),
                 'certificates', (select count(*) from certificates),
                 'version', (select version from config_state),
                 'audit', (select count(*) from audit_log))",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// The newest audit entry about a workspace, as JSON.
async fn last_audit(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select to_jsonb(a) from audit_log a where object_kind = 'workspace'
              order by id desc limit 1",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

async fn audit_count(store: &Store) -> i64 {
    store
        .client()
        .await
        .unwrap()
        .query_one("select count(*) from audit_log", &[])
        .await
        .unwrap()
        .get(0)
}

/// What `/v1/config` serves now: the compiled configuration as text, and its tag.
async fn served(store: &Store) -> (String, String) {
    let (_, snapshot) = store.snapshot().await.unwrap();
    let (body, etag) =
        gapura_control::config_api::served(&snapshot, &StoreSettings::default()).unwrap();
    (String::from_utf8(body).unwrap(), etag)
}

/// Waits until `n` lock requests are queued in the database, so the writes a test started are
/// really held where it means them to be.
async fn queued(store: &Store, n: i64) {
    let probe = store.client().await.unwrap();
    let mut waited = Duration::ZERO;
    loop {
        let queued: i64 = probe
            .query_one("select count(*) from pg_locks where not granted", &[])
            .await
            .unwrap()
            .get(0);
        if queued == n {
            return;
        }
        assert!(
            waited < Duration::from_secs(5),
            "{queued} lock requests queued, not {n}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
        waited += Duration::from_millis(5);
    }
}

#[tokio::test]
async fn creating_a_workspace() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    let id = id_of(&store, "payments").await;
    let entry = last_audit(&store).await;
    assert_eq!(entry["action"], "create");
    assert_eq!(entry["object_id"], id.to_string());
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(entry["actor_name"], "root");
    assert_eq!(entry["before"], serde_json::Value::Null);
    assert_eq!(entry["after"], serde_json::json!({ "name": "payments" }));
    // A superuser holds a role in it at once; nobody else does.
    assert_eq!(my_workspaces(&app, s.root).await, ["default", "payments"]);
    assert_eq!(my_workspaces(&app, s.ada).await, ["default"]);
    let listed = list(&app, s.root).await;
    assert_eq!(listed[1]["name"], "payments");
    for count in [
        "services",
        "routes",
        "consumers",
        "policies",
        "certificates",
        "members",
    ] {
        assert_eq!(listed[1][count], 0, "{count}");
    }
    assert!(listed[1]["created_at"].as_str().unwrap().ends_with('Z'));

    // A name taken, case and all, an invalid one, and a body that is not a workspace: refused,
    // and nothing written.
    let before = everything(&store).await;
    let (status, answer) = send(&app, "POST", WORKSPACES, Some(s.root), &named("payments")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        sentence(&answer),
        "A workspace named payments already exists."
    );
    for bad in ["", "..", "pay ments", "-payments"] {
        let (status, answer) = send(&app, "POST", WORKSPACES, Some(s.root), &named(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}: {answer}");
        assert_eq!(json(&answer)["field"], "name", "{bad:?}");
    }
    let (status, _) = send(
        &app,
        "POST",
        WORKSPACES,
        Some(s.root),
        r#"{"name":"x","id":"y"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(everything(&store).await, before);
    // Case matters, as for services.
    ok(&app, "POST", WORKSPACES, s.root, &named("Payments")).await;
    assert_eq!(names(&app, s.root).await.len(), 3);
}

#[tokio::test]
async fn the_list_counts_what_each_workspace_holds() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    let default = id_of(&store, "default").await;
    ok(
        &app,
        "POST",
        "/api/workspaces/default/services",
        s.root,
        SERVICE,
    )
    .await;
    ok(
        &app,
        "POST",
        "/api/workspaces/default/routes",
        s.root,
        ROUTE,
    )
    .await;
    ok(
        &app,
        "POST",
        "/api/workspaces/default/consumers",
        s.root,
        r#"{"name":"shop"}"#,
    )
    .await;
    map_group(&store, "platform", default, "editor").await;
    let listed = list(&app, s.root).await;
    assert_eq!(
        listed,
        serde_json::json!([
            {
                "name": "default",
                "created_at": listed[0]["created_at"],
                "services": 1, "routes": 1, "consumers": 1, "policies": 0, "certificates": 0,
                // ada's and vi's grants, and the mapping.
                "members": 3,
            },
            {
                "name": "payments",
                "created_at": listed[1]["created_at"],
                "services": 0, "routes": 0, "consumers": 0, "policies": 0, "certificates": 0,
                "members": 0,
            },
        ])
    );
}

#[tokio::test]
async fn renaming_carries_everything_and_changes_what_is_served() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let default = id_of(&store, "default").await;
    for (path, body) in [
        ("/api/workspaces/default/services", SERVICE),
        ("/api/workspaces/default/routes", ROUTE),
    ] {
        ok(&app, "POST", path, s.ada, body).await;
    }
    let (config, tag) = served(&store).await;
    assert!(config.contains("default/orders-api"), "{config}");
    let version: i64 = everything(&store).await["version"].as_i64().unwrap();

    ok(&app, "PUT", &workspace("default"), s.root, &named("main")).await;
    assert_eq!(id_of(&store, "main").await, default, "the id stays");
    let entry = last_audit(&store).await;
    assert_eq!(entry["action"], "update");
    assert_eq!(entry["object_id"], default.to_string());
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(entry["before"], serde_json::json!({ "name": "default" }));
    assert_eq!(entry["after"], serde_json::json!({ "name": "main" }));

    // The data planes are served the new name, under a new tag, and the version moved.
    let (renamed, renamed_tag) = served(&store).await;
    assert!(renamed.contains("main/orders-api"), "{renamed}");
    assert!(!renamed.contains("default/"), "{renamed}");
    assert_ne!(renamed_tag, tag);
    assert_eq!(everything(&store).await["version"], version + 1);

    // The grants and the rows followed; the old name is gone.
    assert_eq!(my_workspaces(&app, s.ada).await, ["main"]);
    assert_eq!(my_workspaces(&app, s.vi).await, ["main"]);
    let (status, body) = send(
        &app,
        "GET",
        "/api/workspaces/main/services",
        Some(s.ada),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)[0]["name"], "orders");
    let (status, _) = send(
        &app,
        "GET",
        "/api/workspaces/default/services",
        Some(s.ada),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Refusals write nothing: a name taken, an invalid one, a workspace that does not exist, and
    // one whose name could be no workspace's.
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    let before = everything(&store).await;
    let (status, answer) = send(
        &app,
        "PUT",
        &workspace("main"),
        Some(s.root),
        &named("payments"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        sentence(&answer),
        "A workspace named payments already exists."
    );
    let (status, answer) = send(&app, "PUT", &workspace("main"), Some(s.root), &named("..")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(json(&answer)["field"], "name");
    for (path, refusal) in [
        (workspace("default"), "There is no workspace named default."),
        (workspace("%2E%2E"), "There is no workspace named ..."),
    ] {
        let (status, answer) = send(&app, "PUT", &path, Some(s.root), &named("other")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {answer}");
        assert_eq!(sentence(&answer), refusal);
    }
    // Its own name: nothing to write, and nothing to record.
    ok(&app, "PUT", &workspace("main"), s.root, &named("main")).await;
    assert_eq!(everything(&store).await, before);
}

#[tokio::test]
async fn deleting_an_empty_workspace_takes_its_grants_with_it() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    let payments = id_of(&store, "payments").await;
    grant(&store, s.ada, payments, "admin").await;
    grant(&store, s.vi, payments, "editor").await;
    map_group(&store, "platform", payments, "viewer").await;
    // A row that names the workspace in the audit log stays, with no workspace.
    store
        .client()
        .await
        .unwrap()
        .execute(
            "insert into audit_log (actor_name, action, object_kind, workspace_id)
             values ('root', 'update', 'user', $1)",
            &[&payments],
        )
        .await
        .unwrap();
    assert_eq!(list(&app, s.root).await[1]["members"], 3);

    ok(&app, "DELETE", &workspace("payments"), s.root, "").await;
    assert_eq!(names(&app, s.root).await, ["default"]);
    assert_eq!(my_workspaces(&app, s.ada).await, ["default"]);
    let left: i64 = store
        .client()
        .await
        .unwrap()
        .query_one(
            "select (select count(*) from role_bindings where workspace_id = $1)
                  + (select count(*) from group_bindings where workspace_id = $1)
                  + (select count(*) from audit_log where workspace_id = $1)",
            &[&payments],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, 0);
    let entry = last_audit(&store).await;
    assert_eq!(entry["action"], "delete");
    assert_eq!(entry["object_id"], payments.to_string());
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(
        entry["before"],
        serde_json::json!({ "name": "payments", "role_grants": 2, "group_mappings": 1 })
    );
    assert_eq!(entry["after"], serde_json::Value::Null);

    // Gone, so a second delete finds nothing, and writes nothing.
    let before = everything(&store).await;
    let (status, answer) = send(&app, "DELETE", &workspace("payments"), Some(s.root), "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(sentence(&answer), "There is no workspace named payments.");
    assert_eq!(everything(&store).await, before);
}

#[tokio::test]
async fn a_workspace_that_holds_anything_stays() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    let payments = id_of(&store, "payments").await;
    for (path, body) in [
        ("/api/workspaces/payments/services", SERVICE),
        ("/api/workspaces/payments/routes", ROUTE),
        ("/api/workspaces/payments/consumers", r#"{"name":"shop"}"#),
    ] {
        ok(&app, "POST", path, s.root, body).await;
    }
    let db = store.client().await.unwrap();
    db.execute(
        "insert into plugins (workspace_id, name) values ($1, 'cors')",
        &[&payments],
    )
    .await
    .unwrap();
    db.execute(
        "insert into certificates (workspace_id, name, cert_pem, key_pem) values ($1, 'c', '', '')",
        &[&payments],
    )
    .await
    .unwrap();
    let before = everything(&store).await;
    let (status, answer) = send(&app, "DELETE", &workspace("payments"), Some(s.root), "").await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        sentence(&answer),
        "payments still has 1 service, 1 route, 1 consumer, 1 policy and 1 certificate. \
         Remove them first."
    );
    assert_eq!(everything(&store).await, before);

    // Emptied of all but its service, it still stays, and says what is left.
    db.batch_execute(
        "delete from plugins; delete from certificates; delete from routes; delete from consumers;",
    )
    .await
    .unwrap();
    let (status, answer) = send(&app, "DELETE", &workspace("payments"), Some(s.root), "").await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        sentence(&answer),
        "payments still has 1 service. Remove it first."
    );
}

#[tokio::test]
async fn the_last_workspace_stays() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let before = everything(&store).await;
    let (status, answer) = send(&app, "DELETE", &workspace("default"), Some(s.root), "").await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        sentence(&answer),
        "default is the only workspace, and the console needs one. Create another first."
    );
    assert_eq!(everything(&store).await, before);
}

/// Two superusers deleting the last two workspaces at the same moment: both are held at a
/// workspace row behind a lock this test takes, and released together, so they really do
/// overlap. One wins; the other, once it may count, counts one workspace and is refused.
#[tokio::test]
async fn two_deletes_cannot_take_the_last_two() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    let audited = audit_count(&store).await;
    let mut holder = store.client().await.unwrap();
    let hold = holder.transaction().await.unwrap();
    hold.query("select id from workspaces for share", &[])
        .await
        .unwrap();
    let delete = |name: &'static str| {
        let app = app.clone();
        let root = s.root;
        tokio::spawn(async move { send(&app, "DELETE", &workspace(name), Some(root), "").await })
    };
    let first = delete("default");
    let second = delete("payments");
    queued(&store, 2).await;
    hold.rollback().await.unwrap();
    let answers = [first.await.unwrap(), second.await.unwrap()];
    let mut statuses: Vec<StatusCode> = answers.iter().map(|(status, _)| *status).collect();
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::NO_CONTENT, StatusCode::CONFLICT],
        "{answers:?}"
    );
    let (_, refusal) = answers
        .iter()
        .find(|(status, _)| *status == StatusCode::CONFLICT)
        .unwrap();
    assert!(
        sentence(refusal)
            .ends_with("is the only workspace, and the console needs one. Create another first."),
        "{refusal}"
    );
    assert_eq!(names(&app, s.root).await.len(), 1);
    assert_eq!(audit_count(&store).await, audited + 1);
}

/// A service written into a workspace while a delete waits for it: the delete counts it, under
/// its lock, and is refused. The test's transaction stands in for the service's write, holding
/// the workspace as `rights` holds it.
#[tokio::test]
async fn a_delete_counts_what_was_written_while_it_waited() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    let payments = id_of(&store, "payments").await;
    let mut holder = store.client().await.unwrap();
    let hold = holder.transaction().await.unwrap();
    hold.query(
        "select id from workspaces where id = $1 for share",
        &[&payments],
    )
    .await
    .unwrap();
    let deleting = {
        let app = app.clone();
        let root = s.root;
        tokio::spawn(
            async move { send(&app, "DELETE", &workspace("payments"), Some(root), "").await },
        )
    };
    queued(&store, 1).await;
    hold.execute(
        "insert into services (workspace_id, name, protocol, host, port)
         values ($1, 'orders', 'http', 'orders.internal', 8080)",
        &[&payments],
    )
    .await
    .unwrap();
    hold.commit().await.unwrap();
    let (status, answer) = deleting.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        sentence(&answer),
        "payments still has 1 service. Remove it first."
    );
    assert_eq!(names(&app, s.root).await, ["default", "payments"]);
}

/// A service written into a workspace that is deleted while the write waits for it: refused as
/// for a workspace that does not exist, even to a superuser, and nothing is written. The test's
/// transaction stands in for the delete, holding the workspace as it does.
#[tokio::test]
async fn a_write_that_waited_for_a_delete_finds_the_workspace_gone() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    let payments = id_of(&store, "payments").await;
    let mut holder = store.client().await.unwrap();
    let hold = holder.transaction().await.unwrap();
    hold.query(
        "select id from workspaces where id = $1 for update",
        &[&payments],
    )
    .await
    .unwrap();
    let writing = {
        let store = store.clone();
        let root = s.root;
        tokio::spawn(async move {
            let service = Service {
                name: "orders".into(),
                protocol: Protocol::Http,
                host: "orders.internal".into(),
                port: 8080,
                connect_timeout_ms: None,
                read_timeout_ms: None,
            };
            store.create_service(root, payments, &service).await
        })
    };
    queued(&store, 1).await;
    hold.execute("delete from workspaces where id = $1", &[&payments])
        .await
        .unwrap();
    hold.commit().await.unwrap();
    match writing.await.unwrap() {
        Err(WriteError::Refused(Refusal::Forbidden(sentence))) => {
            assert_eq!(sentence, "You hold no role in that workspace.")
        }
        other => panic!("not refused: {other:?}"),
    }
    assert_eq!(everything(&store).await["services"], 0);
}

#[tokio::test]
async fn a_workspace_admin_lists_theirs_and_changes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    ok(&app, "POST", WORKSPACES, s.root, &named("payments")).await;
    assert_eq!(names(&app, s.root).await, ["default", "payments"]);
    assert_eq!(names(&app, s.ada).await, ["default"]);

    // Writes are refused before the path or the body is looked at, so a workspace that does not
    // exist and one that does read alike.
    let before = everything(&store).await;
    for (method, path, body) in [
        ("POST", WORKSPACES.to_string(), named("mine")),
        ("PUT", workspace("default"), named("mine")),
        ("PUT", workspace("nope"), named("mine")),
        ("DELETE", workspace("payments"), String::new()),
        ("DELETE", workspace("nope"), String::new()),
    ] {
        for caller in [s.ada, s.vi, s.nobody] {
            let (status, answer) = send(&app, method, &path, Some(caller), &body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
            assert_eq!(sentence(&answer), SUPERUSERS_ONLY, "{method} {path}");
        }
    }
    assert_eq!(everything(&store).await, before);

    // Someone who administers nothing sees no list.
    for caller in [s.vi, s.nobody] {
        let (status, answer) = send(&app, "GET", WORKSPACES, Some(caller), "").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
        assert_eq!(sentence(&answer), "You do not administer any workspace.");
    }
    let (status, _) = send(&app, "GET", WORKSPACES, None, "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn kubernetes_mode_has_none_of_it() {
    let app = console(None);
    let id = Uuid::new_v4();
    for (method, path, body) in [
        ("GET", WORKSPACES.to_string(), String::new()),
        ("POST", WORKSPACES.to_string(), named("payments")),
        ("PUT", workspace("default"), named("main")),
        ("DELETE", workspace("default"), String::new()),
    ] {
        let (status, answer) = send(&app, method, &path, Some(id), &body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
        assert_eq!(
            sentence(&answer),
            "This console keeps no workspaces: it runs without a database.",
            "{method} {path}"
        );
    }
}
