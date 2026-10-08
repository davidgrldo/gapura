//! Data planes and their tokens through `/api/data-planes`, against Postgres, with the
//! `/v1/config` calls that report their health: that a token is shown once and kept only as its
//! hash, that only a superuser writes, that a rotation and a delete take effect at the next call,
//! that the list reads health from the calls, and that every refusal writes nothing.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `consumers.rs`, and for the same reason: the alternative mocks the database and proves the
//! mock. CI sets it. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test data_planes
//! ```
//!
//! The helpers are copies of `consumers.rs`'s rather than a shared `tests/common` module, so
//! that each file reads on its own; the accounts each file seeds are its own.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Extension;
use gapura_control::config_api::ConfigApi;
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
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
/// readers point at nothing, because these tests are about the store. Its settings are the
/// default, as are `served`'s, so the tag the list compares with is the one `/v1/config` sends.
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

/// `/v1/config` over `store`, with the peer address both listeners in main put on each request.
fn served(store: &Arc<Store>) -> axum::Router {
    gapura_control::config_api::router(Arc::new(ConfigApi {
        store: store.clone(),
        settings: StoreSettings::default(),
    }))
    .layer(Extension(ConnectInfo(
        "10.0.3.7:5000".parse::<SocketAddr>().unwrap(),
    )))
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

const DATA_PLANES: &str = "/api/data-planes";
const SERVICE: &str = r#"{"name":"orders","protocol":"http","host":"orders.internal","port":8080}"#;
const ROUTE: &str = r#"{"name":"orders-api","service":"orders","hosts":["api.example.com"],"paths":[{"type":"prefix","value":"/orders"}]}"#;
const SERVICES: &str = "/api/workspaces/default/services";
const ROUTES: &str = "/api/workspaces/default/routes";

/// The sentence every refused data plane write by someone who is not a superuser carries.
const SUPERUSERS_ONLY: &str = "Data planes are a superuser's: each one fetches every workspace's \
                               configuration, private keys included.";

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
    let default: Uuid = db
        .query_one("select id from workspaces where name = 'default'", &[])
        .await
        .unwrap()
        .get(0);
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
        vi: ids["vi"],
        nobody: ids["nobody"],
    }
}

/// A setup write that answers 204, which must succeed for the test to mean anything.
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

/// A token answered by `POST path` as `as_`, which must succeed: the token and its prefix.
async fn token_from(app: &axum::Router, path: &str, as_: Uuid, body: &str) -> (String, String) {
    let (status, answer) = send(app, "POST", path, Some(as_), FROM_THE_CONSOLE, body).await;
    assert_eq!(status, StatusCode::OK, "{path}: {answer}");
    let issued = json(&answer);
    (
        issued["token"].as_str().unwrap().to_string(),
        issued["prefix"].as_str().unwrap().to_string(),
    )
}

/// Registers the data plane `name` as `as_`: its first token and that token's prefix.
async fn register(app: &axum::Router, name: &str, as_: Uuid) -> (String, String) {
    token_from(app, DATA_PLANES, as_, &format!(r#"{{"name":"{name}"}}"#)).await
}

/// Issues another token to the data plane `name` as `as_`.
async fn issue(app: &axum::Router, name: &str, as_: Uuid) -> (String, String) {
    token_from(app, &format!("{DATA_PLANES}/{name}/tokens"), as_, "").await
}

/// The list as `as_`, which must succeed.
async fn list(app: &axum::Router, as_: Uuid) -> serde_json::Value {
    let (status, body) = send(app, "GET", DATA_PLANES, Some(as_), &[], "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    json(&body)
}

/// The row the list shows for `name`.
async fn row(app: &axum::Router, name: &str, as_: Uuid) -> serde_json::Value {
    list(app, as_)
        .await
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not listed"))
        .clone()
}

/// The prefixes the list shows for `name`, in its order.
fn prefixes(row: &serde_json::Value) -> Vec<String> {
    row["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["prefix"].as_str().unwrap().to_string())
        .collect()
}

/// `/v1/config` with `token` and, when given, `If-None-Match`: the status and the ETag.
async fn call(app: &axum::Router, token: &str, tag: Option<&str>) -> (StatusCode, Option<String>) {
    let mut req = Request::builder()
        .uri("/v1/config")
        .header("authorization", format!("Bearer {token}"));
    if let Some(tag) = tag {
        req = req.header("if-none-match", tag);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let etag = res
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (res.status(), etag)
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

/// Every row a data plane write could change, as stored, and how many audit entries there are.
/// Equal before and after a refusal means the refusal wrote nothing.
async fn everything(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select jsonb_build_object(
                 'data_planes', (select coalesce(jsonb_agg(to_jsonb(d) order by d.id), '[]') from data_planes d),
                 'tokens', (select coalesce(jsonb_agg(to_jsonb(t) order by t.id), '[]') from data_plane_tokens t),
                 'audit', (select count(*) from audit_log))",
            &[],
        )
        .await
        .unwrap()
        .get(0)
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

/// The newest audit entry about a `kind`, as JSON.
async fn last_audit(store: &Store, kind: &str) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select to_jsonb(a) from audit_log a where object_kind = $1 order by id desc limit 1",
            &[&kind],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn registering_shows_the_token_once_and_stores_its_hash() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let (status, headers, body) = request(
        &app,
        "POST",
        DATA_PLANES,
        Some(s.root),
        FROM_THE_CONSOLE,
        r#"{"name":"edge-1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "the one answer that carries a token is never cached"
    );
    let issued = json(&body);
    assert_eq!(issued["name"], "edge-1");
    let token = issued["token"].as_str().unwrap().to_string();
    let prefix = issued["prefix"].as_str().unwrap();
    let secret = token.strip_prefix("gpdp_").expect("a gpdp_ token");
    assert_eq!(secret.len(), 64, "{token}");
    assert!(
        secret
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "{token}"
    );
    assert_eq!(prefix, &token[..13]);

    // Stored: the prefix and the hash, and in no column the token or its secret part.
    let db = store.client().await.unwrap();
    let stored = db
        .query(
            "select t::text, t.token_prefix, t.token_hash from data_plane_tokens t",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    let (as_text, stored_prefix, stored_hash): (String, String, String) =
        (stored[0].get(0), stored[0].get(1), stored[0].get(2));
    assert_eq!(stored_prefix, prefix);
    assert_eq!(stored_hash, sha256_hex(&token));
    assert!(
        !as_text.contains(secret),
        "data_plane_tokens holds the token"
    );
    let plane: String = db
        .query_one("select d::text from data_planes d", &[])
        .await
        .unwrap()
        .get(0);
    assert!(!plane.contains(secret), "data_planes holds the token");

    // Audited: once, by prefix, concerning no workspace, and never the token.
    let audit = audit_text(&store).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert!(!audit[0].contains(secret), "the audit row holds the token");
    let entry = last_audit(&store, "data_plane").await;
    assert_eq!(entry["action"], "create");
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(entry["actor_name"], "root");
    assert_eq!(
        entry["after"],
        serde_json::json!({ "name": "edge-1", "tokens": [prefix] })
    );

    // Listed: by prefix, never the token, and to a viewer too.
    let (status, listed) = send(&app, "GET", DATA_PLANES, Some(s.vi), &[], "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !listed.contains(secret),
        "the list shows the token: {listed}"
    );
    let listed = json(&listed);
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["name"], "edge-1");
    assert_eq!(prefixes(&listed[0]), [prefix]);
    assert_eq!(
        listed[0]["tokens"][0]["last_used_at"],
        serde_json::Value::Null
    );

    // And it opens `/v1/config`.
    let (status, _) = call(&served(&store), &token, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn only_a_superuser_writes() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let (token, prefix) = register(&app, "edge-1", s.root).await;

    // Anyone with a role somewhere reads the list.
    for as_ in [s.ada, s.vi, s.root] {
        assert_eq!(list(&app, as_).await[0]["name"], "edge-1");
    }
    // Someone with no role anywhere does not.
    let (status, body) = send(&app, "GET", DATA_PLANES, Some(s.nobody), &[], "").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains("edge-1"), "{body}");

    let before = everything(&store).await;
    let writes = [
        ("POST", DATA_PLANES.to_string(), r#"{"name":"edge-2"}"#),
        ("POST", format!("{DATA_PLANES}/edge-1/tokens"), ""),
        (
            "DELETE",
            format!("{DATA_PLANES}/edge-1/tokens/{prefix}"),
            "",
        ),
        ("DELETE", format!("{DATA_PLANES}/edge-1"), ""),
    ];
    for as_ in [s.ada, s.vi, s.nobody] {
        for (method, path, body) in &writes {
            let (status, answer) =
                send(&app, method, path, Some(as_), FROM_THE_CONSOLE, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
            assert_eq!(sentence(&answer), SUPERUSERS_ONLY, "{method} {path}");
            assert!(!answer.contains("gpdp_"), "a refusal carries a token");
        }
    }
    assert_eq!(
        everything(&store).await,
        before,
        "none of it wrote anything"
    );
    // The token still works: nothing was revoked or deleted.
    let (status, _) = call(&served(&store), &token, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_disabled_superuser_registers_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let (_, prefix) = register(&app, "edge-1", s.root).await;
    // The session was signed before this; it is the account that is disabled.
    store
        .client()
        .await
        .unwrap()
        .execute(
            "update users set disabled_at = now() where id = $1",
            &[&s.root],
        )
        .await
        .unwrap();
    let before = everything(&store).await;
    for (method, path, body) in [
        ("POST", DATA_PLANES.to_string(), r#"{"name":"edge-2"}"#),
        ("POST", format!("{DATA_PLANES}/edge-1/tokens"), ""),
        (
            "DELETE",
            format!("{DATA_PLANES}/edge-1/tokens/{prefix}"),
            "",
        ),
        ("DELETE", format!("{DATA_PLANES}/edge-1"), ""),
    ] {
        let (status, answer) =
            send(&app, method, &path, Some(s.root), FROM_THE_CONSOLE, body).await;
        // A disabled account is no caller at all: the stack reads it as signed out.
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path}: {answer}"
        );
        assert!(!answer.contains("gpdp_"), "a refusal carries a token");
    }
    assert_eq!(
        everything(&store).await,
        before,
        "a disabled superuser wrote something"
    );
}

#[tokio::test]
async fn rotation() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let config = served(&store);
    let s = seed(&store).await;
    let (first, first_prefix) = register(&app, "edge-1", s.root).await;
    let (second, second_prefix) = issue(&app, "edge-1", s.root).await;
    assert_ne!(first, second);
    assert_ne!(first_prefix, second_prefix);

    // The issue is audited by prefix, concerning no workspace.
    let entry = last_audit(&store, "data_plane_token").await;
    assert_eq!(entry["action"], "create");
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(
        entry["after"],
        serde_json::json!({ "data_plane": "edge-1", "prefix": second_prefix })
    );
    for row in audit_text(&store).await {
        assert!(!row.contains(&first[5..]) && !row.contains(&second[5..]));
    }

    // Newest first, neither used yet.
    let listed = row(&app, "edge-1", s.vi).await;
    assert_eq!(
        prefixes(&listed),
        [second_prefix.as_str(), first_prefix.as_str()]
    );
    assert_eq!(listed["tokens"][0]["last_used_at"], serde_json::Value::Null);
    assert_eq!(listed["tokens"][1]["last_used_at"], serde_json::Value::Null);

    // The first calls: only it is marked used, so the second is plainly the one not yet rolled
    // out.
    assert_eq!(call(&config, &first, None).await.0, StatusCode::OK);
    let listed = row(&app, "edge-1", s.vi).await;
    assert_eq!(listed["tokens"][0]["last_used_at"], serde_json::Value::Null);
    assert!(listed["tokens"][1]["last_used_at"].is_string(), "{listed}");

    // Both open `/v1/config` during the rotation.
    assert_eq!(call(&config, &second, None).await.0, StatusCode::OK);
    let listed = row(&app, "edge-1", s.vi).await;
    assert!(listed["tokens"][0]["last_used_at"].is_string(), "{listed}");

    // Revoking the first refuses it from its next call, and leaves the second working.
    ok(
        &app,
        "DELETE",
        &format!("{DATA_PLANES}/edge-1/tokens/{first_prefix}"),
        s.root,
        "",
    )
    .await;
    assert_eq!(
        call(&config, &first, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(call(&config, &second, None).await.0, StatusCode::OK);
    assert_eq!(
        prefixes(&row(&app, "edge-1", s.vi).await),
        [second_prefix.as_str()]
    );

    let entry = last_audit(&store, "data_plane_token").await;
    assert_eq!(entry["action"], "delete");
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(
        entry["before"],
        serde_json::json!({ "data_plane": "edge-1", "prefix": first_prefix })
    );
}

#[tokio::test]
async fn deleting_takes_the_tokens_and_says_which() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let config = served(&store);
    let s = seed(&store).await;
    let (first, first_prefix) = register(&app, "edge-1", s.root).await;
    let (second, second_prefix) = issue(&app, "edge-1", s.root).await;
    // Another data plane, which the delete must leave alone.
    let (other, _) = register(&app, "edge-2", s.root).await;
    assert_eq!(call(&config, &first, None).await.0, StatusCode::OK);

    ok(&app, "DELETE", &format!("{DATA_PLANES}/edge-1"), s.root, "").await;

    assert_eq!(
        count(
            &store,
            "select count(*) from data_planes where name = 'edge-1'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &store,
            "select count(*) from data_plane_tokens t join data_planes d on d.id = t.data_plane_id
              where d.name = 'edge-2'"
        )
        .await,
        count(&store, "select count(*) from data_plane_tokens").await,
        "a token of edge-1 outlived it"
    );
    let names: Vec<_> = list(&app, s.vi)
        .await
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["edge-2"]);

    let entry = last_audit(&store, "data_plane").await;
    assert_eq!(entry["action"], "delete");
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(entry["before"]["name"], "edge-1");
    let mut said: Vec<String> = entry["before"]["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap().to_string())
        .collect();
    said.sort();
    let mut expected = vec![first_prefix, second_prefix];
    expected.sort();
    assert_eq!(said, expected);
    for row in audit_text(&store).await {
        assert!(!row.contains(&first[5..]) && !row.contains(&second[5..]));
    }

    for token in [&first, &second] {
        assert_eq!(call(&config, token, None).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(call(&config, &other, None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn health_reads_from_the_calls() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let config = served(&store);
    let s = seed(&store).await;
    let (token, _) = register(&app, "edge-1", s.root).await;

    let plane = row(&app, "edge-1", s.vi).await;
    assert_eq!(plane["status"], "never");
    assert_eq!(plane["in_sync"], serde_json::Value::Null);
    assert_eq!(plane["last_seen_at"], serde_json::Value::Null);
    assert_eq!(plane["last_seen_address"], serde_json::Value::Null);

    // A first call holds nothing yet, so whether it is in sync is unknown.
    let (status, etag) = call(&config, &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let etag = etag.expect("an ETag");
    let plane = row(&app, "edge-1", s.vi).await;
    assert_eq!(plane["status"], "connected");
    assert_eq!(plane["last_seen_address"], "10.0.3.7");
    assert!(plane["last_seen_at"].is_string(), "{plane}");
    assert_eq!(plane["in_sync"], serde_json::Value::Null);

    // Holding what it was served.
    assert_eq!(
        call(&config, &token, Some(&etag)).await.0,
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(row(&app, "edge-1", s.vi).await["in_sync"], true);

    // The configuration changes under it.
    ok(&app, "POST", SERVICES, s.ada, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ada, ROUTE).await;
    assert_eq!(row(&app, "edge-1", s.vi).await["in_sync"], false);

    // It is sent the new one, and is in sync once it calls holding it.
    let (status, new_etag) = call(&config, &token, Some(&etag)).await;
    assert_eq!(status, StatusCode::OK);
    let new_etag = new_etag.expect("an ETag");
    assert_ne!(new_etag, etag);
    assert_eq!(row(&app, "edge-1", s.vi).await["in_sync"], false);
    assert_eq!(
        call(&config, &token, Some(&new_etag)).await.0,
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(row(&app, "edge-1", s.vi).await["in_sync"], true);

    // Silent for longer than the window.
    store
        .client()
        .await
        .unwrap()
        .execute(
            "update data_planes set last_seen_at = now() - interval '3 minutes'",
            &[],
        )
        .await
        .unwrap();
    let plane = row(&app, "edge-1", s.vi).await;
    assert_eq!(plane["status"], "not_seen");
    assert_eq!(plane["in_sync"], true, "what it holds has not changed");
}

#[tokio::test]
async fn the_list_tag_is_the_served_tag() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let config = served(&store);
    let s = seed(&store).await;
    // Something to serve, so the tag is over a real configuration rather than an empty one.
    ok(&app, "POST", SERVICES, s.ada, SERVICE).await;
    ok(&app, "POST", ROUTES, s.ada, ROUTE).await;
    let (token, _) = register(&app, "edge-1", s.root).await;

    let (status, served_tag) = call(&config, &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let served_tag = served_tag.expect("an ETag");

    // Holding exactly the tag `/v1/config` answered with is what the list calls in sync, and
    // holding any other is not.
    assert_eq!(
        call(&config, &token, Some(&served_tag)).await.0,
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(row(&app, "edge-1", s.vi).await["in_sync"], true);
    assert_eq!(
        call(&config, &token, Some("\"abc\"")).await.0,
        StatusCode::OK
    );
    assert_eq!(row(&app, "edge-1", s.vi).await["in_sync"], false);
    let held: Option<String> = store
        .client()
        .await
        .unwrap()
        .query_one(
            "select last_seen_etag from data_planes where name = 'edge-1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(held.as_deref(), Some("\"abc\""));
}

#[tokio::test]
async fn bad_input_is_named() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    register(&app, "edge-1", s.root).await;
    let before = everything(&store).await;

    let (status, answer) = send(
        &app,
        "POST",
        DATA_PLANES,
        Some(s.root),
        FROM_THE_CONSOLE,
        r#"{"name":".."}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(json(&answer)["field"], "name", "{answer}");

    let (status, answer) = send(
        &app,
        "POST",
        DATA_PLANES,
        Some(s.root),
        FROM_THE_CONSOLE,
        r#"{"name":"edge-1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(
        sentence(&answer),
        "A data plane named edge-1 already exists."
    );
    assert!(!answer.contains("gpdp_"), "a refusal carries a token");

    for (method, path, said) in [
        (
            "POST",
            format!("{DATA_PLANES}/edge-9/tokens"),
            "There is no data plane named edge-9.",
        ),
        (
            "DELETE",
            format!("{DATA_PLANES}/edge-9"),
            "There is no data plane named edge-9.",
        ),
        (
            "DELETE",
            format!("{DATA_PLANES}/edge-1/tokens/gpdp_00000000"),
            "There is no token gpdp_00000000 for edge-1.",
        ),
        // Answered before the store, which would reject a NUL byte in a text value.
        (
            "POST",
            format!("{DATA_PLANES}/a%00b/tokens"),
            "There is no data plane named a\0b.",
        ),
        (
            "DELETE",
            format!("{DATA_PLANES}/a%00b"),
            "There is no data plane named a\0b.",
        ),
        (
            "DELETE",
            format!("{DATA_PLANES}/edge-1/tokens/gpd"),
            "There is no token gpd for edge-1.",
        ),
    ] {
        let (status, answer) = send(&app, method, &path, Some(s.root), FROM_THE_CONSOLE, "").await;
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
async fn kubernetes_mode_has_none_of_it() {
    let app = console(None);
    for (method, path) in [
        ("GET", DATA_PLANES.to_string()),
        ("POST", DATA_PLANES.to_string()),
        ("POST", format!("{DATA_PLANES}/edge-1/tokens")),
        (
            "DELETE",
            format!("{DATA_PLANES}/edge-1/tokens/gpdp_00000000"),
        ),
        ("DELETE", format!("{DATA_PLANES}/edge-1")),
    ] {
        let (status, body) = send(&app, method, &path, None, FROM_THE_CONSOLE, "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {body}");
        assert!(sentence(&body).contains("keeps no configuration"), "{body}");
    }
}
