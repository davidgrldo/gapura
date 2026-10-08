//! Consumers, their API keys and the key_auth requirement through `/api/workspaces/{ws}/consumers`
//! and `/key-auth`, against Postgres: that a key is shown once and kept only as its hash, that a
//! requirement admits its own workspace's keys and no other's, which requirement applies where
//! several do, who may do what, and that every refusal writes nothing.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `configuration.rs`, and for the same reason: the alternative mocks the database and proves the
//! mock. CI sets it. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test consumers
//! ```
//!
//! The helpers are copies of `configuration.rs`'s rather than a shared `tests/common` module, so
//! that each file reads on its own; the accounts each file seeds are its own.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
use gapura_core::config::{Config, KeyAuthPolicy, Plugin};
use gapura_core::credentials::{identify, Refusal};
use gapura_core::store::StoreSettings;
use sha2::{Digest, Sha256};
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
                expires_at: u64::MAX
            },
            KEY
        )
    )
}

/// Sends `method path` with `headers` and `body`, signed in as `as_` when one is given, and
/// returns the status, the response headers and the body as text.
async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    as_: Option<Uuid>,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, HeaderMap, String) {
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
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

/// `request` without the response headers.
async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    as_: Option<Uuid>,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, String) {
    let (status, _, body) = request(app, method, path, as_, headers, body).await;
    (status, body)
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

const JSON: (&str, &str) = ("content-type", "application/json");

/// What a browser sends with the console's own writes.
const FROM_THE_CONSOLE: &[(&str, &str)] = &[JSON, ("sec-fetch-site", "same-origin")];

const SERVICE: &str = r#"{"name":"orders","protocol":"http","host":"orders.internal","port":8080}"#;
const ROUTE: &str = r#"{"name":"orders-api","service":"orders","hosts":["api.example.com"],"paths":[{"type":"prefix","value":"/orders"}]}"#;
const SERVICES: &str = "/api/workspaces/default/services";
const ROUTES: &str = "/api/workspaces/default/routes";
const CONSUMERS: &str = "/api/workspaces/default/consumers";
const KEY_AUTH: &str = "/api/workspaces/default/key-auth";
const PAYMENTS_CONSUMERS: &str = "/api/workspaces/payments/consumers";
/// The compiled name of the seeded route.
const COMPILED_ROUTE: &str = "default/orders-api";

/// - `root`: superuser, the only one who reaches the second workspace, `payments`.
/// - `ada`: admin of default. `ed`: editor of default. `vi`: viewer of default.
///
/// And in default, a service `orders` and a route `orders-api` for `api.example.com`.
struct Seed {
    root: Uuid,
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
        root: ids["root"],
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

/// A key issued to `consumer` under `consumers` (a workspace's consumers path) as `as_`, which
/// must succeed: the key and its prefix.
async fn issue(
    app: &axum::Router,
    consumers: &str,
    consumer: &str,
    as_: Uuid,
    body: &str,
) -> (String, String) {
    let path = format!("{consumers}/{consumer}/keys");
    let (status, answer) = send(app, "POST", &path, Some(as_), FROM_THE_CONSOLE, body).await;
    assert_eq!(status, StatusCode::OK, "{path}: {answer}");
    let issued = json(&answer);
    (
        issued["key"].as_str().unwrap().to_string(),
        issued["prefix"].as_str().unwrap().to_string(),
    )
}

/// A GET that must succeed, as JSON.
async fn read(app: &axum::Router, path: &str, as_: Uuid) -> serde_json::Value {
    let (status, body) = send(app, "GET", path, Some(as_), &[], "").await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    json(&body)
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

/// Every row a consumers, keys or key_auth write could change, as stored, with the services and
/// routes, how many audit entries there are, and the version the data planes poll. Equal before
/// and after a refusal means the refusal wrote nothing.
async fn everything(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select jsonb_build_object(
                 'services', (select coalesce(jsonb_agg(to_jsonb(s) order by s.id), '[]') from services s),
                 'routes', (select coalesce(jsonb_agg(to_jsonb(r) order by r.id), '[]') from routes r),
                 'consumers', (select coalesce(jsonb_agg(to_jsonb(c) order by c.id), '[]') from consumers c),
                 'keys', (select coalesce(jsonb_agg(to_jsonb(k) order by k.id), '[]') from consumer_keys k),
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

/// The key requirement the compiled `route` carries, if any.
fn key_auth_on(config: &Config, route: &str) -> Option<KeyAuthPolicy> {
    let rule = config
        .listeners
        .iter()
        .flat_map(|l| &l.rules)
        .find(|r| r.route == route)
        .unwrap_or_else(|| panic!("{route} is not compiled"));
    rule.plugins.iter().find_map(|p| match p {
        Plugin::KeyAuth(policy) => Some(policy.clone()),
        _ => None,
    })
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The audit rows as text, every column of each.
async fn audit_text(store: &Store) -> Vec<String> {
    store
        .client()
        .await
        .unwrap()
        .query("select a::text from audit_log a order by id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

#[tokio::test]
async fn a_key_is_shown_once_and_stored_as_its_hash_only() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let (status, headers, body) = request(
        &app,
        "POST",
        &format!("{CONSUMERS}/mobile/keys"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "the one answer that carries a key is never cached"
    );
    let issued = json(&body);
    let key = issued["key"].as_str().unwrap().to_string();
    let prefix = issued["prefix"].as_str().unwrap();
    let secret = key.strip_prefix("gpak_").expect("a gpak_ key");
    assert_eq!(secret.len(), 64, "{key}");
    assert!(
        secret
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "{key}"
    );
    assert_eq!(prefix, &key[..13]);
    assert_eq!(issued["expires_at"], serde_json::Value::Null);
    let digest = sha256_hex(&key);

    // Stored: the prefix and the hash, and nowhere the key or its secret part.
    let db = store.client().await.unwrap();
    let stored = db
        .query(
            "select k::text, k.key_prefix, k.key_hash from consumer_keys k",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    let (as_text, stored_prefix, stored_hash): (String, String, String) =
        (stored[0].get(0), stored[0].get(1), stored[0].get(2));
    assert_eq!(stored_prefix, prefix);
    assert_eq!(stored_hash, digest);
    assert!(!as_text.contains(secret), "consumer_keys holds the key");

    // Audited: by prefix, never the key.
    let audit = audit_text(&store).await;
    assert!(audit.iter().any(|row| row.contains(prefix)));
    for row in &audit {
        assert!(!row.contains(secret), "an audit row holds the key: {row}");
    }

    // Listed: by prefix, never the key.
    let (status, list) = send(&app, "GET", CONSUMERS, Some(s.vi), &[], "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!list.contains(secret), "the list shows the key: {list}");
    assert_eq!(json(&list)[0]["keys"][0]["prefix"], prefix);

    // Served: the hash, never the key, both as compiled and as `/v1/config` sends it.
    let config = compiled(&store).await;
    assert_eq!(
        config.credentials.get(&digest).map(String::as_str),
        Some("mobile")
    );
    let serialised = serde_json::to_string(&config).unwrap();
    assert!(!serialised.contains(secret));
    let token = store.issue_token("edge-1").await.unwrap();
    let served =
        gapura_control::config_api::router(Arc::new(gapura_control::config_api::ConfigApi {
            store: store.clone(),
            settings: StoreSettings {
                http_ports: vec![80],
            },
        }));
    let (status, served) = send(
        &served,
        "GET",
        "/v1/config",
        None,
        &[("authorization", &format!("Bearer {token}"))],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!served.contains(secret), "/v1/config serves the key");
    assert!(served.contains(&digest), "/v1/config serves the hash");
}

#[tokio::test]
async fn key_auth_on_a_route_admits_its_workspaces_keys_only() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let (key, prefix) = issue(&app, CONSUMERS, "mobile", s.ed, "").await;
    // The same consumer name in another workspace, with a key of its own.
    ok(
        &app,
        "POST",
        PAYMENTS_CONSUMERS,
        s.root,
        r#"{"name":"mobile"}"#,
    )
    .await;
    let (theirs, _) = issue(&app, PAYMENTS_CONSUMERS, "mobile", s.root, "").await;
    ok(
        &app,
        "PUT",
        KEY_AUTH,
        s.ed,
        r#"{"target":"route:orders-api"}"#,
    )
    .await;
    assert_eq!(
        read(&app, KEY_AUTH, s.vi).await,
        serde_json::json!([{"target": "route:orders-api", "header": "x-api-key"}])
    );

    let config = compiled(&store).await;
    let policy = key_auth_on(&config, COMPILED_ROUTE).expect("the route requires a key");
    assert_eq!(policy.header, "x-api-key");
    assert_eq!(policy.workspace.as_deref(), Some("default"));
    let workspace = policy.workspace.as_deref();
    assert_eq!(identify(&config, Some(&key), workspace), Ok("mobile"));
    assert_eq!(
        identify(&config, Some(&theirs), workspace),
        Err(Refusal::Unknown),
        "a key of another workspace's consumer"
    );
    assert_eq!(
        identify(&config, Some(&theirs), Some("payments")),
        Ok("mobile"),
        "it is refused for its workspace, not because it is missing"
    );
    assert_eq!(identify(&config, None, workspace), Err(Refusal::Missing));

    ok(
        &app,
        "DELETE",
        &format!("{CONSUMERS}/mobile/keys/{prefix}"),
        s.ada,
        "",
    )
    .await;
    assert!(read(&app, CONSUMERS, s.vi).await[0]["keys"]
        .as_array()
        .unwrap()
        .is_empty());
    let config = compiled(&store).await;
    assert_eq!(
        identify(&config, Some(&key), workspace),
        Err(Refusal::Unknown),
        "a revoked key"
    );
    let revoked = count(
        &store,
        "select count(*) from audit_log
          where object_kind = 'consumer_key' and action = 'delete' and actor_name = 'ada'",
    )
    .await;
    assert_eq!(revoked, 1);
}

#[tokio::test]
async fn an_expired_key_is_not_served() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let soon = (chrono::Utc::now() + chrono::Duration::minutes(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (key, _) = issue(
        &app,
        CONSUMERS,
        "mobile",
        s.ed,
        &format!(r#"{{"expires_at":"{soon}"}}"#),
    )
    .await;
    let digest = sha256_hex(&key);
    let listed = &read(&app, CONSUMERS, s.vi).await[0]["keys"][0];
    assert_eq!(listed["expired"], false);
    assert!(listed["expires_at"].is_string(), "{listed}");
    assert!(compiled(&store).await.credentials.contains_key(&digest));

    store
        .client()
        .await
        .unwrap()
        .execute(
            "update consumer_keys set expires_at = now() - interval '1 second'",
            &[],
        )
        .await
        .unwrap();
    let config = compiled(&store).await;
    assert!(!config.credentials.contains_key(&digest));
    assert!(!config.credential_workspaces.contains_key(&digest));
    assert_eq!(
        read(&app, CONSUMERS, s.vi).await[0]["keys"][0]["expired"],
        true
    );
}

#[tokio::test]
async fn an_expiry_with_an_offset_is_stored_in_utc() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let (_, _) = issue(
        &app,
        CONSUMERS,
        "mobile",
        s.ed,
        r#"{"expires_at":"2030-01-01T07:00:00+07:00"}"#,
    )
    .await;
    assert_eq!(
        read(&app, CONSUMERS, s.vi).await[0]["keys"][0]["expires_at"],
        "2030-01-01T00:00:00.000000Z"
    );
}

#[tokio::test]
async fn the_most_specific_requirement_applies() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(
        &app,
        "PUT",
        KEY_AUTH,
        s.ed,
        r#"{"target":"workspace","header":"x-ws"}"#,
    )
    .await;
    ok(
        &app,
        "PUT",
        KEY_AUTH,
        s.ed,
        r#"{"target":"service:orders","header":"x-svc"}"#,
    )
    .await;
    ok(
        &app,
        "PUT",
        KEY_AUTH,
        s.ed,
        r#"{"target":"route:orders-api","header":"x-route"}"#,
    )
    .await;
    assert_eq!(
        read(&app, KEY_AUTH, s.vi).await,
        serde_json::json!([
            {"target": "workspace", "header": "x-ws"},
            {"target": "service:orders", "header": "x-svc"},
            {"target": "route:orders-api", "header": "x-route"},
        ])
    );

    for (header, from, then_delete) in [
        ("x-route", "route", Some("route:orders-api")),
        ("x-svc", "service", Some("service:orders")),
        ("x-ws", "workspace", None),
    ] {
        let policy = key_auth_on(&compiled(&store).await, COMPILED_ROUTE).unwrap();
        assert_eq!(policy.header, header);
        assert_eq!(
            row(&app, ROUTES, "orders-api", s.vi).await["key_auth"],
            serde_json::json!({"header": header, "from": from})
        );
        if let Some(target) = then_delete {
            ok(
                &app,
                "DELETE",
                &format!("{KEY_AUTH}?target={target}"),
                s.ed,
                "",
            )
            .await;
        }
    }
    // The service shows its own requirement or the workspace's, never a route's.
    assert_eq!(
        row(&app, SERVICES, "orders", s.vi).await["key_auth"],
        serde_json::json!({"header": "x-ws", "from": "workspace"})
    );
    ok(
        &app,
        "DELETE",
        &format!("{KEY_AUTH}?target=workspace"),
        s.ed,
        "",
    )
    .await;
    assert_eq!(key_auth_on(&compiled(&store).await, COMPILED_ROUTE), None);
    assert_eq!(
        row(&app, ROUTES, "orders-api", s.vi).await["key_auth"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn switching_key_auth_off_lets_the_route_be_deleted() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(
        &app,
        "PUT",
        KEY_AUTH,
        s.ed,
        r#"{"target":"route:orders-api"}"#,
    )
    .await;
    let route = format!("{ROUTES}/orders-api");
    let before = everything(&store).await;
    let (status, body) = send(&app, "DELETE", &route, Some(s.ada), FROM_THE_CONSOLE, "").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        sentence(&body),
        "1 policy is attached to this route. Remove it first."
    );
    assert_eq!(everything(&store).await, before, "the route stays");

    ok(
        &app,
        "DELETE",
        &format!("{KEY_AUTH}?target=route:orders-api"),
        s.ed,
        "",
    )
    .await;
    assert_eq!(count(&store, "select count(*) from plugins").await, 0);
    ok(&app, "DELETE", &route, s.ada, "").await;
    assert_eq!(count(&store, "select count(*) from routes").await, 0);
}

#[tokio::test]
async fn deleting_a_consumer_takes_its_keys_and_says_which() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let (_, first) = issue(&app, CONSUMERS, "mobile", s.ed, "").await;
    let (_, second) = issue(&app, CONSUMERS, "mobile", s.ed, "").await;
    assert_ne!(first, second);
    assert_eq!(count(&store, "select count(*) from consumer_keys").await, 2);

    ok(&app, "DELETE", &format!("{CONSUMERS}/mobile"), s.ada, "").await;
    assert_eq!(count(&store, "select count(*) from consumer_keys").await, 0);
    assert_eq!(count(&store, "select count(*) from consumers").await, 0);
    assert_eq!(read(&app, CONSUMERS, s.vi).await, serde_json::json!([]));
    let row = store
        .client()
        .await
        .unwrap()
        .query_one(
            "select actor_name, before, after is null from audit_log
              where object_kind = 'consumer' and action = 'delete'",
            &[],
        )
        .await
        .unwrap();
    let (actor, before, no_after): (String, serde_json::Value, bool) =
        (row.get(0), row.get(1), row.get(2));
    assert_eq!(actor, "ada");
    assert!(no_after);
    assert_eq!(before["name"], "mobile");
    let mut keys: Vec<String> = serde_json::from_value(before["keys"].clone()).unwrap();
    keys.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(keys, expected, "the audit entry names both keys");

    // A consumer that is gone is not there to delete again.
    let before = everything(&store).await;
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("{CONSUMERS}/mobile"),
        Some(s.ada),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(everything(&store).await, before);
}

#[tokio::test]
async fn roles() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let (_, prefix) = issue(&app, CONSUMERS, "mobile", s.ed, "").await;
    ok(&app, "PUT", KEY_AUTH, s.ed, r#"{"target":"workspace"}"#).await;
    let keys = format!("{CONSUMERS}/mobile/keys");
    let off = format!("{KEY_AUTH}?target=workspace");
    let editor = "Making changes in this workspace needs the editor role.";
    let admin = "Deleting things in this workspace needs the admin role.";

    // A viewer reads, and changes nothing however well asked.
    assert_eq!(read(&app, CONSUMERS, s.vi).await[0]["name"], "mobile");
    assert_eq!(read(&app, KEY_AUTH, s.vi).await[0]["target"], "workspace");
    let before = everything(&store).await;
    for (method, path, body) in [
        ("POST", CONSUMERS, r#"{"name":"web"}"#),
        ("POST", keys.as_str(), ""),
        ("PUT", KEY_AUTH, r#"{"target":"route:orders-api"}"#),
        ("DELETE", off.as_str(), ""),
    ] {
        let (status, answer) = send(&app, method, path, Some(s.vi), FROM_THE_CONSOLE, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
        assert_eq!(sentence(&answer), editor);
    }
    // An editor neither revokes a key nor deletes a consumer.
    for path in [format!("{keys}/{prefix}"), format!("{CONSUMERS}/mobile")] {
        let (status, answer) = send(&app, "DELETE", &path, Some(s.ed), FROM_THE_CONSOLE, "").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {answer}");
        assert_eq!(sentence(&answer), admin);
    }
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );

    // An editor switches key_auth off, as they switched it on.
    ok(&app, "DELETE", &off, s.ed, "").await;
    assert_eq!(read(&app, KEY_AUTH, s.vi).await, serde_json::json!([]));
}

/// A user whose only role is in `default` is refused the same way in a workspace that exists and
/// one that does not, on every endpoint, so a refusal never says which workspaces exist, and
/// nothing is written.
#[tokio::test]
async fn no_role_is_403_everywhere() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let before = everything(&store).await;
    for (who, name) in [(s.ed, "ed"), (s.ada, "ada")] {
        for (method, tail, body) in [
            ("GET", "/consumers", ""),
            ("POST", "/consumers", r#"{"name":"web"}"#),
            ("DELETE", "/consumers/web", ""),
            ("POST", "/consumers/web/keys", ""),
            ("DELETE", "/consumers/web/keys/gpak_00000000", ""),
            ("GET", "/key-auth", ""),
            ("PUT", "/key-auth", r#"{"target":"workspace"}"#),
            ("DELETE", "/key-auth?target=workspace", ""),
        ] {
            let mut answers = vec![];
            for ws in ["payments", "nowhere"] {
                let path = format!("/api/workspaces/{ws}{tail}");
                let (status, answer) =
                    send(&app, method, &path, Some(who), FROM_THE_CONSOLE, body).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{name} {method} {path}: {answer}"
                );
                answers.push(answer);
            }
            assert_eq!(answers[0], answers[1], "{name} {method} {tail}");
        }
    }
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );
}

/// A key's prefix names it within one consumer of one workspace: another workspace's key with a
/// consumer of the same name is not found, and keeps working.
#[tokio::test]
async fn a_prefix_names_a_key_in_its_own_workspace_only() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    for consumers in [CONSUMERS, PAYMENTS_CONSUMERS] {
        ok(&app, "POST", consumers, s.root, r#"{"name":"mobile"}"#).await;
    }
    let (_, ours) = issue(&app, CONSUMERS, "mobile", s.root, "").await;
    let (theirs, prefix) = issue(&app, PAYMENTS_CONSUMERS, "mobile", s.root, "").await;
    assert_ne!(ours, prefix);

    let before = everything(&store).await;
    let (status, answer) = send(
        &app,
        "DELETE",
        &format!("{CONSUMERS}/mobile/keys/{prefix}"),
        Some(s.ada),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(everything(&store).await, before, "nothing was written");
    let listed = read(&app, PAYMENTS_CONSUMERS, s.root).await;
    assert_eq!(listed[0]["keys"][0]["prefix"], prefix.as_str());
    assert_eq!(
        identify(&compiled(&store).await, Some(&theirs), Some("payments")),
        Ok("mobile"),
        "the payments key is still served"
    );
}

/// Two editors switching key_auth on for one target at the same moment, with different headers:
/// the unique index lets one insert, and the other, retried, finds that row and changes its
/// header. Once per kind of target, each from nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_policy_per_target_even_at_once() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    for (target, column) in [
        ("workspace", "route_id is null and service_id is null"),
        ("service:orders", "service_id is not null"),
        ("route:orders-api", "route_id is not null"),
    ] {
        let put = |header: &str| format!(r#"{{"target":"{target}","header":"{header}"}}"#);
        let (one, two) = (put("x-one"), put("x-two"));
        let (a, b) = tokio::join!(
            send(&app, "PUT", KEY_AUTH, Some(s.ed), FROM_THE_CONSOLE, &one),
            send(&app, "PUT", KEY_AUTH, Some(s.ada), FROM_THE_CONSOLE, &two),
        );
        assert_eq!(
            (a.0, b.0),
            (StatusCode::NO_CONTENT, StatusCode::NO_CONTENT),
            "{target}: {a:?} {b:?}"
        );
        let db = store.client().await.unwrap();
        let rows = db
            .query(
                &format!(
                    "select config->>'header' from plugins where name = 'key_auth' and {column}"
                ),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "{target}: one policy");
        let header: String = rows[0].get(0);
        assert!(["x-one", "x-two"].contains(&header.as_str()), "{header}");

        // One created it and the other changed it, and the change is what is stored.
        let audits = db
            .query(
                "select action, after->>'header' from audit_log
                  where object_kind = 'policy' and after->>'target' = $1 order by id",
                &[&target],
            )
            .await
            .unwrap();
        let audits: Vec<(String, String)> = audits.iter().map(|r| (r.get(0), r.get(1))).collect();
        assert_eq!(audits.len(), 2, "{target}: {audits:?}");
        assert_eq!(
            (audits[0].0.as_str(), audits[1].0.as_str()),
            ("create", "update")
        );
        assert_eq!(audits[1].1, header, "{target}");

        // The header it already reads, again: nothing to write.
        let before = everything(&store).await;
        ok(&app, "PUT", KEY_AUTH, s.ed, &put(&header)).await;
        assert_eq!(
            everything(&store).await,
            before,
            "{target}: a save of nothing"
        );
    }
}

#[tokio::test]
async fn bad_input_is_named() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let keys = format!("{CONSUMERS}/mobile/keys");
    let before = everything(&store).await;

    for (method, path, body, field) in [
        ("POST", CONSUMERS, r#"{"name":".."}"#, "name"),
        (
            "POST",
            keys.as_str(),
            r#"{"expires_at":"2020-01-01T00:00:00Z"}"#,
            "expires_at",
        ),
        (
            "POST",
            keys.as_str(),
            r#"{"expires_at":"tomorrow"}"#,
            "expires_at",
        ),
        ("PUT", KEY_AUTH, r#"{"target":"consumer:x"}"#, "target"),
        (
            "PUT",
            KEY_AUTH,
            r#"{"target":"workspace","header":"x y"}"#,
            "header",
        ),
        (
            "PUT",
            KEY_AUTH,
            r#"{"target":"workspace","header":"X-Consumer-Username"}"#,
            "header",
        ),
        (
            "PUT",
            KEY_AUTH,
            r#"{"target":"workspace","header":"Host"}"#,
            "header",
        ),
    ] {
        let (status, answer) = send(&app, method, path, Some(s.ed), FROM_THE_CONSOLE, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert_eq!(json(&answer)["field"], field, "{body}");
        assert!(!sentence(&answer).is_empty());
    }
    let (status, answer) = send(
        &app,
        "DELETE",
        &format!("{KEY_AUTH}?target=consumer:x"),
        Some(s.ed),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&answer)["field"], "target");

    for (method, path, body, as_, said) in [
        (
            "POST",
            format!("{CONSUMERS}/missing/keys"),
            "",
            s.ed,
            "There is no consumer named missing in this workspace.",
        ),
        (
            "PUT",
            KEY_AUTH.to_string(),
            r#"{"target":"route:missing"}"#,
            s.ed,
            "There is no route named missing in this workspace.",
        ),
        (
            "PUT",
            KEY_AUTH.to_string(),
            r#"{"target":"service:missing"}"#,
            s.ed,
            "There is no service named missing in this workspace.",
        ),
        (
            "DELETE",
            format!("{KEY_AUTH}?target=route:orders-api"),
            "",
            s.ed,
            "route:orders-api has no key requirement.",
        ),
        (
            "DELETE",
            format!("{keys}/gpak_00000000"),
            "",
            s.ada,
            "There is no key gpak_00000000 for mobile.",
        ),
    ] {
        let (status, answer) = send(&app, method, &path, Some(as_), FROM_THE_CONSOLE, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
        assert_eq!(sentence(&answer), said);
    }

    let (status, answer) = send(
        &app,
        "POST",
        CONSUMERS,
        Some(s.ed),
        FROM_THE_CONSOLE,
        r#"{"name":"mobile"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        sentence(&answer),
        "A consumer named mobile already exists in this workspace."
    );
    assert_eq!(
        everything(&store).await,
        before,
        "none of it wrote anything"
    );
}

#[tokio::test]
async fn kubernetes_mode_has_none_of_it() {
    let app = console(None);
    for path in [CONSUMERS, KEY_AUTH] {
        let (status, body) = send(&app, "GET", path, None, &[], "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(sentence(&body).contains("keeps no configuration"), "{body}");
    }
}
