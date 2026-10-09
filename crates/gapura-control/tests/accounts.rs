//! Accounts through `/api/users` and `/api/me/password`, against Postgres: that a temporary
//! password is shown once and kept only as its hash, that it opens nothing but the screen that
//! replaces it, that a reset, a disable, a demotion and a change of one's own password sign the
//! account out, that the guards keep at least one superuser and keep everyone from locking
//! themselves out, that only a superuser administers accounts, and that every refusal writes
//! nothing.
//!
//! Where a test is about a password working or not, it signs in for real through `/auth/login`;
//! elsewhere it builds the session cookie itself.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `data_planes.rs`, and for the same reason: the alternative mocks the database and proves the
//! mock. CI sets it. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test accounts
//! ```
//!
//! The helpers are copies of `data_planes.rs`'s and `identity.rs`'s rather than a shared
//! `tests/common` module, so that each file reads on its own; the accounts each file seeds are
//! its own.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
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
/// readers point at nothing, because these tests are about accounts.
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
        store_settings: StoreSettings::default(),
    })
}

/// A session for `id` issued at `issued_at`, in Unix milliseconds.
fn cookie_issued_at(id: Uuid, issued_at: u64) -> String {
    format!(
        "{}={}",
        gapura_control::login::COOKIE_NAME,
        encode(
            &Session {
                subject: id.to_string(),
                groups: vec![],
                expires_at: u64::MAX,
                issued_at,
            },
            KEY
        )
    )
}

/// A session for `id` issued at the start of time, which stands until its account's first
/// cut-off.
fn cookie(id: Uuid) -> String {
    cookie_issued_at(id, 0)
}

/// The database's clock, in Unix milliseconds: a session issued at this stands against every
/// cut-off set before it, whatever the difference between that clock and this process's.
async fn db_now(store: &Store) -> u64 {
    let now: i64 = store
        .client()
        .await
        .unwrap()
        .query_one(
            "select floor(extract(epoch from clock_timestamp()) * 1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    u64::try_from(now).unwrap()
}

/// A session for `id` issued now, by the database's clock.
async fn fresh_cookie(store: &Store, id: Uuid) -> String {
    cookie_issued_at(id, db_now(store).await)
}

/// A pause before a write that cuts sessions off, so the cut-off falls in a later millisecond
/// than the sign-in it must cut, which a fast machine could otherwise share.
async fn later() {
    tokio::time::sleep(Duration::from_millis(10)).await;
}

/// Sends `method path` with `body` as the console sends its own requests, with `cookie` when
/// one is given, and returns the status, the response headers and the body as text.
async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
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
    cookie: &str,
    body: &str,
) -> (StatusCode, String) {
    let (status, _, body) = request(app, method, path, Some(cookie), body).await;
    (status, body)
}

/// `GET path` with `cookie`: just the status.
async fn status_of(app: &axum::Router, path: &str, cookie: &str) -> StatusCode {
    send(app, "GET", path, cookie, "").await.0
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

/// The sentence a refusal carries.
fn sentence(body: &str) -> String {
    json(body)["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no sentence: {body}"))
        .to_string()
}

/// A setup write that answers 204, which must succeed for the test to mean anything.
async fn ok(app: &axum::Router, method: &str, path: &str, cookie: &str, body: &str) {
    let (status, answer) = send(app, method, path, cookie, body).await;
    assert_eq!(
        (status, answer.as_str()),
        (StatusCode::NO_CONTENT, ""),
        "{method} {path} {body}"
    );
}

/// The cookie a `Set-Cookie` header sets, as a request sends it back.
fn set_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
}

fn form_value(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker).expect("field present") + marker.len();
    let end = start + html[start..].find('"').expect("closing quote");
    html[start..end].to_string()
}

/// Opens the sign-in form, posts `username` and `password` with the state it carried, and
/// returns the answer's status and the session it set, if any.
async fn sign_in(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> (StatusCode, Option<String>) {
    let (_, _, page) = request(app, "GET", "/auth/login", None, "").await;
    let state = form_value(&page, "state");
    let body = format!(
        "state={state}&username={}&password={}",
        username,
        password.replace(' ', "+")
    );
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    (res.status(), set_cookie(res.headers()))
}

/// A sign-in that must succeed: the session it set.
async fn signed_in(app: &axum::Router, username: &str, password: &str) -> String {
    let (status, cookie) = sign_in(app, username, password).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "{username} could not sign in"
    );
    cookie.expect("a session cookie")
}

/// A sign-in that must be refused.
async fn refused(app: &axum::Router, username: &str, password: &str) {
    let (status, cookie) = sign_in(app, username, password).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{username} signed in");
    assert!(cookie.is_none(), "{username} was given a cookie");
}

const PASSWORD: &str = "correct horse battery";
const USERS: &str = "/api/users";
const ME: &str = "/api/me";
const MY_PASSWORD: &str = "/api/me/password";
const SERVICES: &str = "/api/workspaces/default/services";
const SERVICE: &str = r#"{"name":"orders","protocol":"http","host":"orders.internal","port":8080}"#;

const SUPERUSERS_ONLY: &str = "Accounts are a superuser's to change.";
const YOURSELF: &str = "You cannot disable, delete or demote yourself; another superuser can.";
const CHOOSE: &str = "Choose a new password first.";
const NO_SUCH_ACCOUNT: &str = "There is no such account.";

fn user_path(id: Uuid, rest: &str) -> String {
    format!("{USERS}/{id}{rest}")
}

/// - `root` and `sam`: superusers, local.
/// - `ada`: admin of default. `vi`: viewer of default.
/// - `oidc`: an account that signs in through the identity provider, shown as `oidc-user`.
struct Seed {
    root: Uuid,
    sam: Uuid,
    ada: Uuid,
    vi: Uuid,
    oidc: Uuid,
}

async fn seed(store: &Store) -> Seed {
    let db = store.client().await.unwrap();
    let default: Uuid = db
        .query_one("select id from workspaces where name = 'default'", &[])
        .await
        .unwrap()
        .get(0);
    let hash = gapura_control::password::hash(PASSWORD).unwrap();
    let mut ids = std::collections::HashMap::new();
    for (name, superuser) in [("root", true), ("sam", true), ("ada", false), ("vi", false)] {
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
    let oidc: Uuid = db
        .query_one(
            "insert into users (oidc_issuer, oidc_subject, display_name)
             values ('https://id.example', 's-oidc', 'oidc-user') returning id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
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
        sam: ids["sam"],
        ada: ids["ada"],
        vi: ids["vi"],
        oidc,
    }
}

/// Every row an account write could change, as stored but for the last sign-in, which a refused
/// sign-in leaves alone and a good one is meant to change, and how many audit entries there are.
/// Equal before and after a refusal means the refusal wrote nothing.
async fn everything(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select jsonb_build_object(
                 'users', (select coalesce(jsonb_agg(to_jsonb(u) - 'last_sign_in_at' order by u.id), '[]') from users u),
                 'role_bindings', (select coalesce(jsonb_agg(to_jsonb(r) order by r.user_id, r.workspace_id), '[]') from role_bindings r),
                 'audit', (select count(*) from audit_log))",
            &[],
        )
        .await
        .unwrap()
        .get(0)
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

/// No audit row holds a password hash, whatever it records.
async fn no_hash_audited(store: &Store) {
    for row in audit_text(store).await {
        assert!(!row.contains("$argon2"), "an audit row holds a hash: {row}");
    }
}

/// The newest audit entry about an account, as JSON.
async fn last_audit(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select to_jsonb(a) from audit_log a where object_kind = 'user' order by id desc limit 1",
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

async fn enabled_superusers(store: &Store) -> Vec<Uuid> {
    store
        .client()
        .await
        .unwrap()
        .query(
            "select id from users where superuser and disabled_at is null order by id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

/// The temporary password `POST path` answers, as `cookie`, which must succeed and must never be
/// cached.
async fn temporary(app: &axum::Router, path: &str, cookie: &str, body: &str) -> serde_json::Value {
    let (status, headers, answer) = request(app, "POST", path, Some(cookie), body).await;
    assert_eq!(status, StatusCode::OK, "{path}: {answer}");
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "an answer that carries a password is never cached"
    );
    let answer = json(&answer);
    let password = answer["password"].as_str().unwrap();
    assert_eq!(password.chars().count(), 20, "{password}");
    assert!(
        password
            .bytes()
            .all(|b| gapura_control::accounts::TEMPORARY_ALPHABET.contains(&b)),
        "{password} has a character outside the alphabet"
    );
    answer
}

#[tokio::test]
async fn creating_shows_a_temporary_password_once() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let root = cookie(s.root);

    let created = temporary(&app, USERS, &root, r#"{"username":"maya"}"#).await;
    assert_eq!(created["username"], "maya");
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let password = created["password"].as_str().unwrap().to_string();

    // Stored: its hash, which that password matches, and in no column the password itself.
    let db = store.client().await.unwrap();
    let row = db
        .query_one(
            "select password_hash, superuser, must_change_password, sessions_valid_after is null
               from users where id = $1",
            &[&id],
        )
        .await
        .unwrap();
    let hash: String = row.get(0);
    assert!(gapura_control::password::verify(&password, &hash));
    assert!(!row.get::<_, bool>(1), "not asked to be a superuser");
    assert!(row.get::<_, bool>(2), "it must change its password");
    assert!(row.get::<_, bool>(3));
    for row in db.query("select u::text from users u", &[]).await.unwrap() {
        let text: String = row.get(0);
        assert!(
            !text.contains(&password),
            "users holds the password: {text}"
        );
    }

    // Audited: once, concerning no workspace, and never the password or its hash.
    let audit = audit_text(&store).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert!(
        !audit[0].contains(&password),
        "the audit row holds the password"
    );
    no_hash_audited(&store).await;
    let entry = last_audit(&store).await;
    assert_eq!(entry["action"], "create");
    assert_eq!(entry["object_id"], serde_json::json!(id));
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(entry["actor_name"], "root");
    assert_eq!(
        entry["after"],
        serde_json::json!({"username": "maya", "superuser": false})
    );

    // Listed as waiting, on a temporary password, and local.
    let (status, list) = send(&app, "GET", USERS, &root, "").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let list = json(&list);
    let maya = list
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "maya")
        .expect("maya is listed");
    assert_eq!(maya["id"], serde_json::json!(id));
    assert_eq!(maya["status"], "waiting");
    assert_eq!(maya["must_change_password"], true);
    assert_eq!(maya["local"], true);
    assert!(!list.to_string().contains(&password));

    // A name that differs only in case from one that exists, and a name that is no username,
    // are refused and write nothing.
    let before = everything(&store).await;
    let (status, body) = send(&app, "POST", USERS, &root, r#"{"username":"Ada"}"#).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(sentence(&body), "An account named Ada already exists.");
    let (status, body) = send(&app, "POST", USERS, &root, r#"{"username":"-ada"}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["field"], "username");
    assert_eq!(everything(&store).await, before);

    // Asked to be one, it is a superuser.
    let boss = temporary(
        &app,
        USERS,
        &root,
        r#"{"username":"boss","superuser":true}"#,
    )
    .await;
    let boss: Uuid = boss["id"].as_str().unwrap().parse().unwrap();
    assert!(enabled_superusers(&store).await.contains(&boss));
}

#[tokio::test]
async fn a_temporary_password_opens_only_the_change_screen() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let created = temporary(&app, USERS, &cookie(s.root), r#"{"username":"maya"}"#).await;
    let temporary_password = created["password"].as_str().unwrap().to_string();

    let maya = signed_in(&app, "maya", &temporary_password).await;
    let (status, me) = send(&app, "GET", ME, &maya, "").await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(json(&me)["must_change_password"], true);
    assert_eq!(json(&me)["local"], true);
    for path in [USERS, SERVICES] {
        let (status, body) = send(&app, "GET", path, &maya, "").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        assert_eq!(json(&body), serde_json::json!({"error": CHOOSE}), "{path}");
    }

    later().await;
    let change =
        serde_json::json!({"current": temporary_password, "new": "a much better passphrase"})
            .to_string();
    let (status, headers, body) = request(&app, "POST", MY_PASSWORD, Some(&maya), &change).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let fresh = set_cookie(&headers).expect("a fresh session");
    let (status, me) = send(&app, "GET", ME, &fresh, "").await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(json(&me)["must_change_password"], false);
    assert_eq!(
        status_of(&app, SERVICES, &fresh).await,
        StatusCode::FORBIDDEN,
        "no longer gated, and still holding no role"
    );
    assert_eq!(
        sentence(&send(&app, "GET", SERVICES, &fresh, "").await.1),
        "You hold no role in that workspace."
    );
    assert_eq!(status_of(&app, ME, &maya).await, StatusCode::UNAUTHORIZED);

    // The new password signs in, the temporary one no longer does.
    refused(&app, "maya", &temporary_password).await;
    signed_in(&app, "maya", "a much better passphrase").await;
    let entry = last_audit(&store).await;
    assert_eq!(entry["actor_name"], "maya");
    assert_eq!(entry["after"], serde_json::json!({"password": "changed"}));
    no_hash_audited(&store).await;
}

#[tokio::test]
async fn a_reset_signs_out_open_sessions() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let ada = signed_in(&app, "ada", PASSWORD).await;
    let (status, me) = send(&app, "GET", ME, &ada, "").await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(json(&me)["roles"].as_array().unwrap().len(), 1, "{me}");
    assert_eq!(json(&me)["grantable"].as_array().unwrap().len(), 1, "{me}");

    later().await;
    let reset = temporary(&app, &user_path(s.ada, "/password"), &cookie(s.root), "").await;
    let temporary_password = reset["password"].as_str().unwrap();
    assert_eq!(status_of(&app, ME, &ada).await, StatusCode::UNAUTHORIZED);
    refused(&app, "ada", PASSWORD).await;

    let again = signed_in(&app, "ada", temporary_password).await;
    let (status, me) = send(&app, "GET", ME, &again, "").await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(json(&me)["must_change_password"], true);
    // Still admin of default in the store, but shown holding nothing until she has a password
    // of her own.
    assert_eq!(json(&me)["roles"], serde_json::json!([]), "{me}");
    assert_eq!(json(&me)["grantable"], serde_json::json!([]), "{me}");
    let (status, body) = send(&app, "GET", SERVICES, &again, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(sentence(&body), CHOOSE);

    let entry = last_audit(&store).await;
    assert_eq!(entry["action"], "update");
    assert_eq!(entry["object_id"], serde_json::json!(s.ada));
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(entry["after"], serde_json::json!({"password": "reset"}));
    for row in audit_text(&store).await {
        assert!(!row.contains(temporary_password), "{row}");
    }
    no_hash_audited(&store).await;
}

#[tokio::test]
async fn changing_ones_own_password() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    seed(&store).await;
    let ada = signed_in(&app, "ada", PASSWORD).await;
    let elsewhere = signed_in(&app, "ada", PASSWORD).await;
    let change =
        |current: &str, new: &str| serde_json::json!({"current": current, "new": new}).to_string();
    const NEW: &str = "staple battery horse";

    let before = everything(&store).await;
    let (status, body) = send(&app, "POST", MY_PASSWORD, &ada, &change("not it", NEW)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["field"], "current");
    let (status, body) = send(&app, "POST", MY_PASSWORD, &ada, &change(PASSWORD, "short")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["field"], "new");
    assert_eq!(sentence(&body), "A password needs at least 12 characters.");
    let (status, body) = send(&app, "POST", MY_PASSWORD, &ada, &change(PASSWORD, PASSWORD)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["field"], "new");
    assert_eq!(
        sentence(&body),
        "Choose a password different from the current one."
    );
    assert_eq!(everything(&store).await, before);

    later().await;
    let (status, headers, body) = request(
        &app,
        "POST",
        MY_PASSWORD,
        Some(&ada),
        &change(PASSWORD, NEW),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let answered = set_cookie(&headers).expect("a fresh session");
    assert_eq!(
        status_of(&app, ME, &elsewhere).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(status_of(&app, ME, &ada).await, StatusCode::UNAUTHORIZED);
    assert_eq!(status_of(&app, ME, &answered).await, StatusCode::OK);
    refused(&app, "ada", PASSWORD).await;
    signed_in(&app, "ada", NEW).await;

    // Wrong current passwords count as failed sign-ins: five, and the sixth try is refused for
    // the count, the right password included, writing nothing.
    let before = everything(&store).await;
    for _ in 0..5 {
        let (status, body) = send(
            &app,
            "POST",
            MY_PASSWORD,
            &answered,
            &change("not it", PASSWORD),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(json(&body)["field"], "current");
    }
    for current in ["not it", NEW] {
        let (status, headers, body) = request(
            &app,
            "POST",
            MY_PASSWORD,
            Some(&answered),
            &change(current, "yet another passphrase"),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        let wait: u64 = headers
            .get("retry-after")
            .expect("a Retry-After")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(wait > 0);
    }
    assert_eq!(everything(&store).await, before);
    no_hash_audited(&store).await;
}

#[tokio::test]
async fn disable_and_enable() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let root = cookie(s.root);
    let status = user_path(s.ada, "/status");
    let ada = signed_in(&app, "ada", PASSWORD).await;

    later().await;
    ok(&app, "PUT", &status, &root, r#"{"disabled":true}"#).await;
    assert_eq!(status_of(&app, ME, &ada).await, StatusCode::UNAUTHORIZED);
    refused(&app, "ada", PASSWORD).await;
    let entry = last_audit(&store).await;
    assert_eq!(entry["object_id"], serde_json::json!(s.ada));
    assert_eq!(entry["before"], serde_json::json!({"disabled": false}));
    assert_eq!(entry["after"], serde_json::json!({"disabled": true}));

    ok(&app, "PUT", &status, &root, r#"{"disabled":false}"#).await;
    assert_eq!(
        last_audit(&store).await["after"],
        serde_json::json!({"disabled": false})
    );
    let back = signed_in(&app, "ada", PASSWORD).await;
    assert_eq!(status_of(&app, ME, &back).await, StatusCode::OK);
    assert_eq!(
        status_of(&app, ME, &ada).await,
        StatusCode::UNAUTHORIZED,
        "enabling does not bring back the sessions disabling cut"
    );

    // A session issued after the disable's cut-off, as a sign-in that verified just before the
    // disable could issue one, is cut off by enabling too.
    later().await;
    ok(&app, "PUT", &status, &root, r#"{"disabled":true}"#).await;
    let raced = fresh_cookie(&store, s.ada).await;
    later().await;
    ok(&app, "PUT", &status, &root, r#"{"disabled":false}"#).await;
    assert_eq!(
        status_of(&app, ME, &raced).await,
        StatusCode::UNAUTHORIZED,
        "enabling cuts off a session from before it"
    );
    signed_in(&app, "ada", PASSWORD).await;

    // Enabling an enabled account changes nothing and records nothing.
    let audited = audit_count(&store).await;
    ok(&app, "PUT", &status, &root, r#"{"disabled":false}"#).await;
    assert_eq!(audit_count(&store).await, audited);
    no_hash_audited(&store).await;
}

/// A sign-in just after a cut-off, with the database's clock two seconds ahead of the console's:
/// the session is issued by that clock too, so it stands. The skew is made, not found, so the
/// test does not depend on how far apart this host's clocks happen to be: the console's store
/// connects with a `search_path` that finds a `clock_timestamp()` two seconds fast before
/// `pg_catalog`'s.
#[tokio::test]
async fn a_sign_in_after_a_cut_off_stands_when_the_database_clock_runs_ahead() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .client()
        .await
        .unwrap()
        .batch_execute(
            "create schema if not exists skew;
             create or replace function skew.clock_timestamp() returns timestamptz
                 language sql as $$ select pg_catalog.clock_timestamp() + interval '2 seconds' $$;",
        )
        .await
        .unwrap();
    let url = std::env::var("GAPURA_TEST_DATABASE_URL").unwrap();
    let joiner = if url.contains('?') { '&' } else { '?' };
    let ahead = Arc::new(
        Store::connect(&format!(
            "{url}{joiner}options=-c%20search_path%3Dpublic%2Cskew%2Cpg_catalog"
        ))
        .await
        .expect("connecting"),
    );
    let app = console(Some(ahead));
    let root = cookie(s.root);
    let status = user_path(s.ada, "/status");
    ok(&app, "PUT", &status, &root, r#"{"disabled":true}"#).await;
    ok(&app, "PUT", &status, &root, r#"{"disabled":false}"#).await;
    let ada = signed_in(&app, "ada", PASSWORD).await;
    assert_eq!(
        status_of(&app, ME, &ada).await,
        StatusCode::OK,
        "a session issued just after the cut-off is refused"
    );
}

#[tokio::test]
async fn the_guards() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let root = cookie(s.root);

    // An account that is not there, or a path that cannot name one.
    let before = everything(&store).await;
    for id in ["not-an-id".to_string(), Uuid::new_v4().to_string()] {
        for (method, path, body) in [
            ("POST", format!("{USERS}/{id}/password"), ""),
            (
                "PUT",
                format!("{USERS}/{id}/status"),
                r#"{"disabled":true}"#,
            ),
            (
                "PUT",
                format!("{USERS}/{id}/superuser"),
                r#"{"superuser":true}"#,
            ),
            ("DELETE", format!("{USERS}/{id}"), ""),
        ] {
            let (status, answer) = send(&app, method, &path, &root, body).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
            assert_eq!(sentence(&answer), NO_SUCH_ACCOUNT, "{method} {path}");
        }
    }
    assert_eq!(everything(&store).await, before);

    // Nobody locks themselves out.
    let own = |rest: &str| user_path(s.root, rest);
    for (method, path, body) in [
        ("PUT", own("/status"), r#"{"disabled":true}"#),
        ("PUT", own("/superuser"), r#"{"superuser":false}"#),
        ("DELETE", own(""), ""),
    ] {
        let (status, answer) = send(&app, method, &path, &root, body).await;
        assert_eq!(status, StatusCode::CONFLICT, "{method} {path}: {answer}");
        assert_eq!(sentence(&answer), YOURSELF, "{method} {path}");
    }
    assert_eq!(everything(&store).await, before);

    // Demoted, sam signs out, and from a new session is no longer one to administer accounts.
    later().await;
    ok(
        &app,
        "PUT",
        &user_path(s.sam, "/superuser"),
        &root,
        r#"{"superuser":false}"#,
    )
    .await;
    assert_eq!(
        status_of(&app, ME, &cookie(s.sam)).await,
        StatusCode::UNAUTHORIZED
    );
    let sam = fresh_cookie(&store, s.sam).await;
    assert_eq!(status_of(&app, ME, &sam).await, StatusCode::OK);
    let before = everything(&store).await;
    for (method, path, body) in [
        ("POST", USERS.to_string(), r#"{"username":"maya"}"#),
        ("POST", user_path(s.ada, "/password"), ""),
        ("PUT", user_path(s.ada, "/status"), r#"{"disabled":true}"#),
        (
            "PUT",
            user_path(s.sam, "/superuser"),
            r#"{"superuser":true}"#,
        ),
        ("DELETE", user_path(s.ada, ""), ""),
    ] {
        let (status, answer) = send(&app, method, &path, &sam, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
        assert_eq!(sentence(&answer), SUPERUSERS_ONLY, "{method} {path}");
    }
    assert_eq!(everything(&store).await, before);

    // A superuser again, which keeps sam's session; sam disables root, and is then the only
    // enabled superuser, who still cannot lock themselves out.
    ok(
        &app,
        "PUT",
        &user_path(s.sam, "/superuser"),
        &root,
        r#"{"superuser":true}"#,
    )
    .await;
    later().await;
    ok(
        &app,
        "PUT",
        &user_path(s.root, "/status"),
        &sam,
        r#"{"disabled":true}"#,
    )
    .await;
    assert_eq!(enabled_superusers(&store).await, [s.sam]);
    assert_eq!(status_of(&app, ME, &root).await, StatusCode::UNAUTHORIZED);
    let before = everything(&store).await;
    let own = |rest: &str| user_path(s.sam, rest);
    for (method, path, body) in [
        ("PUT", own("/status"), r#"{"disabled":true}"#),
        ("PUT", own("/superuser"), r#"{"superuser":false}"#),
        ("DELETE", own(""), ""),
    ] {
        let (status, answer) = send(&app, method, &path, &sam, body).await;
        assert_eq!(status, StatusCode::CONFLICT, "{method} {path}: {answer}");
        assert_eq!(sentence(&answer), YOURSELF, "{method} {path}");
    }
    assert_eq!(everything(&store).await, before);

    // Two superusers demoting each other at once: both are held at the superusers' rows behind
    // a lock this test takes, and released together, so they really do overlap. One wins; by
    // the time the other decides, its caller is no superuser, so it is refused as one.
    ok(
        &app,
        "PUT",
        &user_path(s.root, "/status"),
        &sam,
        r#"{"disabled":false}"#,
    )
    .await;
    let root = fresh_cookie(&store, s.root).await;
    assert_eq!(enabled_superusers(&store).await.len(), 2);
    let audited = audit_count(&store).await;
    let mut holder = store.client().await.unwrap();
    let hold = holder.transaction().await.unwrap();
    hold.query(
        "select id from users where superuser and disabled_at is null for update",
        &[],
    )
    .await
    .unwrap();
    let demote = |cookie: String, target: Uuid| {
        let app = app.clone();
        tokio::spawn(async move {
            send(
                &app,
                "PUT",
                &user_path(target, "/superuser"),
                &cookie,
                r#"{"superuser":false}"#,
            )
            .await
        })
    };
    let by_root = demote(root, s.sam);
    let by_sam = demote(sam, s.root);
    let probe = store.client().await.unwrap();
    let mut waited = Duration::ZERO;
    loop {
        let queued: i64 = probe
            .query_one("select count(*) from pg_locks where not granted", &[])
            .await
            .unwrap()
            .get(0);
        if queued == 2 {
            break;
        }
        assert!(
            waited < Duration::from_secs(5),
            "the demotions never queued"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
        waited += Duration::from_millis(5);
    }
    hold.rollback().await.unwrap();
    let answers = [by_root.await.unwrap(), by_sam.await.unwrap()];
    let mut statuses: Vec<StatusCode> = answers.iter().map(|(status, _)| *status).collect();
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::NO_CONTENT, StatusCode::FORBIDDEN],
        "{answers:?}"
    );
    let (_, refusal) = answers
        .iter()
        .find(|(status, _)| *status == StatusCode::FORBIDDEN)
        .unwrap();
    assert_eq!(sentence(refusal), SUPERUSERS_ONLY);
    assert_eq!(enabled_superusers(&store).await.len(), 1);
    assert_eq!(audit_count(&store).await, audited + 1);
    no_hash_audited(&store).await;
}

#[tokio::test]
async fn delete_keeps_the_audit_name() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let root = cookie(s.root);
    ok(&app, "POST", SERVICES, &cookie(s.ada), SERVICE).await;
    let db = store.client().await.unwrap();
    let by_ada = "select actor_user_id, actor_name from audit_log where object_kind = 'service'";
    let row = db.query_one(by_ada, &[]).await.unwrap();
    assert_eq!(row.get::<_, Option<Uuid>>(0), Some(s.ada));

    ok(&app, "DELETE", &user_path(s.ada, ""), &root, "").await;
    let bindings: i64 = db
        .query_one(
            "select count(*) from role_bindings where user_id = $1",
            &[&s.ada],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(bindings, 0, "her role went with her");
    let row = db.query_one(by_ada, &[]).await.unwrap();
    assert_eq!(row.get::<_, Option<Uuid>>(0), None);
    assert_eq!(row.get::<_, String>(1), "ada", "who did it is kept");
    let entry = last_audit(&store).await;
    assert_eq!(entry["action"], "delete");
    assert_eq!(entry["object_id"], serde_json::json!(s.ada));
    assert_eq!(entry["workspace_id"], serde_json::Value::Null);
    assert_eq!(entry["before"], serde_json::json!({"username": "ada"}));
    refused(&app, "ada", PASSWORD).await;

    // An account from the identity provider has no password here, and deleting it would last
    // only until its next sign-in; disabling it is the way.
    let before = everything(&store).await;
    let (status, body) = send(&app, "DELETE", &user_path(s.oidc, ""), &root, "").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        sentence(&body),
        "oidc-user signs in through the identity provider and would be back at their next \
         sign-in. Disable the account instead."
    );
    let (status, body) = send(&app, "POST", &user_path(s.oidc, "/password"), &root, "").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        sentence(&body),
        "oidc-user signs in through the identity provider, so there is no password here to \
         reset."
    );
    assert_eq!(everything(&store).await, before);
    ok(
        &app,
        "PUT",
        &user_path(s.oidc, "/status"),
        &root,
        r#"{"disabled":true}"#,
    )
    .await;
    assert_eq!(
        status_of(&app, ME, &cookie(s.oidc)).await,
        StatusCode::UNAUTHORIZED
    );
    no_hash_audited(&store).await;
}

#[tokio::test]
async fn only_a_superuser_administers() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let before = everything(&store).await;
    for who in [s.ada, s.vi] {
        let as_ = cookie(who);
        for target in [
            s.vi.to_string(),
            s.root.to_string(),
            "not-an-id".to_string(),
        ] {
            for (method, path, body) in [
                ("POST", USERS.to_string(), r#"{"username":"maya"}"#),
                // Refused before the body is read, so this is not a 400.
                ("POST", USERS.to_string(), "not json"),
                ("POST", format!("{USERS}/{target}/password"), ""),
                (
                    "PUT",
                    format!("{USERS}/{target}/status"),
                    r#"{"disabled":true}"#,
                ),
                (
                    "PUT",
                    format!("{USERS}/{target}/superuser"),
                    r#"{"superuser":true}"#,
                ),
                ("PUT", format!("{USERS}/{target}/superuser"), "{}"),
                ("DELETE", format!("{USERS}/{target}"), ""),
            ] {
                let (status, answer) = send(&app, method, &path, &as_, body).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
                assert_eq!(sentence(&answer), SUPERUSERS_ONLY, "{method} {path}");
            }
        }
    }
    assert_eq!(everything(&store).await, before);
}

#[tokio::test]
async fn a_cookie_without_issued_at_works_until_a_cut_off() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    let ada = cookie_issued_at(s.ada, 0);
    assert_eq!(status_of(&app, ME, &ada).await, StatusCode::OK);
    assert_eq!(status_of(&app, SERVICES, &ada).await, StatusCode::OK);
    temporary(&app, &user_path(s.ada, "/password"), &cookie(s.root), "").await;
    assert_eq!(status_of(&app, ME, &ada).await, StatusCode::UNAUTHORIZED);
    // Only the account that was reset is signed out.
    assert_eq!(status_of(&app, ME, &cookie(s.vi)).await, StatusCode::OK);
}

#[tokio::test]
async fn a_sign_in_that_raced_a_reset_is_not_recorded() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store).await;
    // What the sign-in form read and verified, before a reset replaced it.
    let verified = store
        .local_user("ada")
        .await
        .unwrap()
        .unwrap()
        .password_hash;
    temporary(&app, &user_path(s.ada, "/password"), &cookie(s.root), "").await;
    let before = everything(&store).await;
    assert!(
        store
            .record_sign_in(s.ada, &verified)
            .await
            .unwrap()
            .is_none(),
        "a sign-in against the replaced hash is recorded"
    );
    let unstamped: bool = store
        .client()
        .await
        .unwrap()
        .query_one(
            "select last_sign_in_at is null from users where id = $1",
            &[&s.ada],
        )
        .await
        .unwrap()
        .get(0);
    assert!(unstamped);
    assert_eq!(everything(&store).await, before);
    // Against the hash the account has now, it is.
    let current = store
        .local_user("ada")
        .await
        .unwrap()
        .unwrap()
        .password_hash;
    let signed_in_at = store.record_sign_in(s.ada, &current).await.unwrap();
    assert!(signed_in_at.is_some_and(|t| t > 0));
}

#[tokio::test]
async fn kubernetes_mode_has_none_of_it() {
    let app = console(None);
    let id = Uuid::new_v4();
    for (method, path, body) in [
        ("POST", USERS.to_string(), r#"{"username":"maya"}"#),
        ("POST", user_path(id, "/password"), ""),
        ("PUT", user_path(id, "/status"), r#"{"disabled":true}"#),
        ("PUT", user_path(id, "/superuser"), r#"{"superuser":true}"#),
        ("DELETE", user_path(id, ""), ""),
        (
            "POST",
            MY_PASSWORD.to_string(),
            r#"{"current":"correct horse battery","new":"staple battery horse"}"#,
        ),
    ] {
        let (status, _, answer) = request(&app, method, &path, Some(&cookie(id)), body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
        assert_eq!(
            sentence(&answer),
            "This console keeps no accounts: it runs without a database.",
            "{method} {path}"
        );
    }
}
