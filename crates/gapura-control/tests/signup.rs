//! Sign-up through `/auth/signup` and the switch at `/api/settings`, against Postgres: that
//! nothing is created while sign-up is closed, that an account made while it is open holds no
//! role and is signed in, that every refusal of the form writes nothing and keeps what was typed
//! but the passwords, that the form is limited per address, that only a superuser opens or closes
//! it, and that closing races no sign-up.
//!
//! Every sign-up drives the real form: the page is fetched, its state taken, and the form posted.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like `accounts.rs`,
//! and for the same reason. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test signup
//! ```
//!
//! The helpers are copies of `accounts.rs`'s, so that this file reads on its own.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::{SignUp, Store, MAX_WAITING_SIGN_UPS};
use tower::ServiceExt;
use uuid::Uuid;

/// One database, so the tests take turns: see `accounts.rs`.
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

/// The console's router, in store mode over `store` or in Kubernetes mode without one. Each call
/// makes a new one, with limits that have counted nothing yet.
fn console(store: Option<Arc<Store>>, auth_mode: gapura_control::login::AuthMode) -> axum::Router {
    gapura_control::api::router_with(AppState {
        mapping: Arc::new(Default::default()),
        session_key: Arc::from(KEY.to_vec()),
        source: Arc::new(gapura_control::kube_source::Source::new(
            "http://127.0.0.1:1".to_string(),
        )),
        admin: Arc::new(gapura_control::served::Admin::new("http://127.0.0.1:1")),
        controller_name: Arc::new("gapura.dev/controller".to_string()),
        oidc: Arc::new(gapura_control::login::Oidc::unused().unwrap()),
        auth_mode,
        local_users: Default::default(),
        session_lifetime: Duration::from_secs(3600),
        store,
        sign_in: Default::default(),
        sign_up: Default::default(),
        store_settings: Default::default(),
    })
}

fn local(store: &Arc<Store>) -> axum::Router {
    console(Some(store.clone()), gapura_control::login::AuthMode::Local)
}

/// A session for `id` issued at the start of time.
fn cookie(id: Uuid) -> String {
    format!(
        "{}={}",
        gapura_control::login::COOKIE_NAME,
        encode(
            &Session {
                subject: id.to_string(),
                groups: vec![],
                expires_at: u64::MAX,
                issued_at: 0,
            },
            KEY
        )
    )
}

/// Sends `method path` as the console's own pages do, with `cookie` when one is given and
/// `content_type` for the body, and returns the status, the headers and the body as text.
async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    content_type: &str,
    body: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", content_type)
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

/// A JSON request with `cookie`: the status and the body.
async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: &str,
) -> (StatusCode, String) {
    let (status, _, body) = request(app, method, path, cookie, "application/json", body).await;
    (status, body)
}

/// `GET path`, as a browser opens a page: the status and the page.
async fn get(app: &axum::Router, path: &str) -> (StatusCode, String) {
    let (status, _, body) = request(app, "GET", path, None, "text/plain", "").await;
    (status, body)
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

fn sentence(body: &str) -> String {
    json(body)["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no sentence: {body}"))
        .to_string()
}

/// The value of the form field `name` on `html`.
fn form_value(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no field {name}: {html}"))
        + marker.len();
    let end = start + html[start..].find('"').expect("closing quote");
    html[start..end].to_string()
}

/// `value` percent-encoded for a form body.
fn encoded(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// What a sign-up form posts.
struct Form<'a> {
    username: &'a str,
    password: &'a str,
    again: &'a str,
    note: &'a str,
}

const PASSWORD: &str = "correct horse battery";

fn form<'a>(username: &'a str, note: &'a str) -> Form<'a> {
    Form {
        username,
        password: PASSWORD,
        again: PASSWORD,
        note,
    }
}

/// Posts `fields` with `state`, as the form would: the status, the headers and the page.
async fn post_with_state(
    app: &axum::Router,
    state: Option<&str>,
    fields: &Form<'_>,
) -> (StatusCode, HeaderMap, String) {
    let mut body = format!(
        "username={}&password={}&password_again={}&note={}",
        encoded(fields.username),
        encoded(fields.password),
        encoded(fields.again),
        encoded(fields.note)
    );
    if let Some(state) = state {
        body = format!("state={}&{body}", encoded(state));
    }
    request(
        app,
        "POST",
        "/auth/signup",
        None,
        "application/x-www-form-urlencoded",
        &body,
    )
    .await
}

/// Opens the sign-up page, takes the form's state, and posts `fields` with it.
async fn sign_up(app: &axum::Router, fields: &Form<'_>) -> (StatusCode, HeaderMap, String) {
    let (status, page) = get(app, "/auth/signup").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let state = form_value(&page, "state");
    post_with_state(app, Some(&state), fields).await
}

/// A state the sign-in page issued, for posting where the sign-up page offers none.
async fn a_state(app: &axum::Router) -> String {
    form_value(&get(app, "/auth/login").await.1, "state")
}

/// The session a `Set-Cookie` header sets, as a request sends it back.
fn session_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
        .find(|c| c.starts_with(gapura_control::login::COOKIE_NAME))
}

/// Every row a sign-up could write, and how many audit entries there are. Equal before and after
/// a refusal means the refusal wrote nothing.
async fn everything(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select jsonb_build_object(
                 'users', (select coalesce(jsonb_agg(to_jsonb(u) - 'last_sign_in_at' order by u.id), '[]') from users u),
                 'role_bindings', (select count(*) from role_bindings),
                 'settings', (select jsonb_agg(to_jsonb(s)) from console_settings s),
                 'audit', (select count(*) from audit_log))",
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

async fn last_audit(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select to_jsonb(a) from audit_log a order by id desc limit 1",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// - `root`: superuser. `ada`: admin of default. `vi`: viewer of default.
struct Seed {
    root: Uuid,
    ada: Uuid,
    vi: Uuid,
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
    for (name, superuser) in [("root", true), ("ada", false), ("vi", false)] {
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
    }
}

const SETTINGS: &str = "/api/settings";
const OPEN: &str = r#"{"sign_up_open":true}"#;
const CLOSE: &str = r#"{"sign_up_open":false}"#;
const CLOSED: &str = "Sign-up is closed";
const LINK: &str = r#"href="/auth/signup""#;

/// Opens sign-up as `root`, which must succeed.
async fn open(app: &axum::Router, root: Uuid) {
    let (status, body) = send(app, "PUT", SETTINGS, Some(&cookie(root)), OPEN).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

fn alert(page: &str) -> &str {
    let start = page
        .find(r#"<p class="alert" role="alert">"#)
        .unwrap_or_else(|| panic!("no alert: {page}"));
    let rest = &page[start..];
    &rest[..rest.find("</p>").unwrap()]
}

#[tokio::test]
async fn while_closed_the_page_says_so_and_a_post_creates_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = local(&store);

    let (status, page) = get(&app, "/auth/signup").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(CLOSED), "{page}");
    assert!(page.contains("Ask a superuser"), "{page}");
    assert!(!page.contains(r#"name="password""#), "no form: {page}");
    assert!(
        !page.contains("Sign in with SSO"),
        "no identity provider to point at: {page}"
    );
    let (_, login) = get(&app, "/auth/login").await;
    assert!(
        !login.contains(LINK),
        "the sign-in page links nowhere: {login}"
    );

    let before = everything(&store).await;
    let state = a_state(&app).await;
    let (status, headers, page) = post_with_state(&app, Some(&state), &form("maya", "hi")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(page.contains(CLOSED), "the same words: {page}");
    assert!(session_of(&headers).is_none());
    assert_eq!(everything(&store).await, before, "nothing written");

    // With an identity provider configured, the closed page points at it too.
    let oidc = console(Some(store.clone()), gapura_control::login::AuthMode::Oidc);
    let (_, page) = get(&oidc, "/auth/signup").await;
    assert!(page.contains(CLOSED), "{page}");
    assert!(page.contains(r#"href="/auth/login?sso=1""#), "{page}");

    // The store itself refuses while closed, whatever reaches it.
    let refused = store.sign_up("maya", "x", None).await.unwrap();
    assert!(matches!(refused, SignUp::Closed), "{refused:?}");
    assert_eq!(everything(&store).await, before, "nothing written");
    let _ = s;
}

#[tokio::test]
async fn while_open_a_sign_up_creates_a_waiting_account_and_signs_it_in() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = local(&store);
    open(&app, s.root).await;

    let (_, login) = get(&app, "/auth/login").await;
    assert!(
        login.contains(LINK),
        "the sign-in page links to sign-up: {login}"
    );

    let note = "Maya from payments.\nI need to see the payments routes.";
    let (status, headers, body) = sign_up(&app, &form("maya", note)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_eq!(headers.get("location").unwrap(), "/");
    let session = session_of(&headers).expect("a session");

    let (status, body) = send(&app, "GET", "/api/me", Some(&session), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let me = json(&body);
    assert_eq!(me["name"], "maya");
    assert_eq!(me["waiting"], true);
    assert_eq!(me["superuser"], false);
    assert_eq!(me["must_change_password"], false);
    assert_eq!(me["local"], true);
    assert_eq!(me["roles"], serde_json::json!([]));
    assert!(me.get("signup_note").is_none(), "{me}");
    let maya: Uuid = me["id"].as_str().unwrap().parse().unwrap();

    let db = store.client().await.unwrap();
    let row = db
        .query_one(
            "select signup_note, superuser, must_change_password, last_sign_in_at is not null,
                    password_hash like '$argon2id$%',
                    (select count(*) from role_bindings where user_id = users.id)
               from users where id = $1",
            &[&maya],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Option<String>>(0).as_deref(), Some(note));
    assert!(!row.get::<_, bool>(1));
    assert!(!row.get::<_, bool>(2));
    assert!(row.get::<_, bool>(3), "signed in as it was made");
    assert!(row.get::<_, bool>(4), "hashed with argon2id");
    assert_eq!(row.get::<_, i64>(5), 0, "no role");

    let audit = last_audit(&store).await;
    assert_eq!(audit["actor_user_id"], serde_json::json!(maya));
    assert_eq!(audit["actor_name"], "maya");
    assert_eq!(audit["actor_method"], "local");
    assert_eq!(audit["action"], "create");
    assert_eq!(audit["object_kind"], "user");
    assert_eq!(audit["object_id"], serde_json::json!(maya));
    assert_eq!(audit["workspace_id"], serde_json::Value::Null);
    assert_eq!(audit["before"], serde_json::Value::Null);
    assert_eq!(
        audit["after"],
        serde_json::json!({"username": "maya", "signed_up": true, "note": true})
    );
    assert!(!audit.to_string().contains("argon2"), "{audit}");

    // The note, for a superuser and for a workspace admin; nobody else lists accounts.
    for caller in [s.root, s.ada] {
        let (status, body) = send(&app, "GET", "/api/users", Some(&cookie(caller)), "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let users = json(&body);
        let row = users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["id"] == serde_json::json!(maya))
            .unwrap()
            .clone();
        assert_eq!(row["signup_note"], note);
        assert_eq!(row["status"], "waiting");
        let root = users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["name"] == "root")
            .unwrap();
        assert_eq!(root["signup_note"], serde_json::Value::Null);
    }
    let (status, _) = send(&app, "GET", "/api/users", Some(&cookie(s.vi)), "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&app, "GET", "/api/users", Some(&session), "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a waiting account lists nobody"
    );

    // It signs in again with its password, and without a note nothing is stored.
    let (status, _, _) = sign_up(&app, &form("ivan", "   ")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let ivan: Option<String> = db
        .query_one("select signup_note from users where username = 'ivan'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(ivan, None);
    assert_eq!(last_audit(&store).await["after"]["note"], false);
}

#[tokio::test]
async fn every_refusal_of_the_form_writes_nothing_and_keeps_what_was_typed() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let first = local(&store);
    open(&first, s.root).await;
    let (status, _, _) = sign_up(&first, &form("maya", "")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    // A console that has counted nothing from this address yet.
    let app = local(&store);

    let long = "n".repeat(501);
    let cases: [(Form, StatusCode, &str); 5] = [
        (
            form("MAYA", "a <b>note</b> & more"),
            StatusCode::CONFLICT,
            "That username is taken.",
        ),
        (
            Form {
                password: "short",
                again: "short",
                ..form("ivan", "a <b>note</b> & more")
            },
            StatusCode::BAD_REQUEST,
            "A password needs at least 12 characters.",
        ),
        (
            Form {
                again: "correct horse batterY",
                ..form("ivan", "a <b>note</b> & more")
            },
            StatusCode::BAD_REQUEST,
            "The two passwords do not match.",
        ),
        (
            form("ivan", &long),
            StatusCode::BAD_REQUEST,
            "A note has at most 500 characters.",
        ),
        (
            form("<ivan>", "a <b>note</b> & more"),
            StatusCode::BAD_REQUEST,
            "A username must start with a letter or a digit.",
        ),
    ];
    // Five posts, which the limit allows from one address; each counts, so the next waits.
    let before = everything(&store).await;
    for (fields, expected, words) in &cases {
        let (status, headers, page) = sign_up(&app, fields).await;
        assert_eq!(status, *expected, "{words}: {page}");
        assert!(alert(&page).contains(words), "{words}: {page}");
        assert!(session_of(&headers).is_none(), "{words}");
        assert!(!page.contains(PASSWORD), "a password echoed: {page}");
        assert!(!page.contains("short"), "a password echoed: {page}");
        assert_eq!(
            form_value(&page, "username"),
            fields.username.replace('<', "&lt;").replace('>', "&gt;"),
            "the username kept, escaped"
        );
        if fields.note.len() < 500 {
            assert!(
                page.contains("a &lt;b&gt;note&lt;/b&gt; &amp; more</textarea>"),
                "the note kept, escaped: {page}"
            );
        }
        assert!(page.contains(r#"name="state" value=""#), "a fresh form");
        assert_eq!(everything(&store).await, before, "{words}: nothing written");
    }
}

#[tokio::test]
async fn the_form_state_is_required() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = local(&store);
    open(&app, s.root).await;
    let before = everything(&store).await;

    let state = a_state(&app).await;
    let (payload, signature) = state.split_once('.').unwrap();
    let forged = format!("{payload}x.{signature}");
    let another_key = {
        let other = form_value(&get(&app, "/auth/signup").await.1, "state");
        format!("{}.{}", other.split_once('.').unwrap().0, "AAAA")
    };
    for state in [None, Some(""), Some(forged.as_str()), Some(&another_key)] {
        let (status, headers, page) = post_with_state(&app, state, &form("maya", "hello")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{state:?}: {page}");
        assert!(
            alert(&page).contains("This sign-up form is no longer valid."),
            "{page}"
        );
        assert_eq!(form_value(&page, "username"), "maya");
        assert!(session_of(&headers).is_none());
    }
    assert_eq!(everything(&store).await, before, "nothing written");
    // And none of those counted: five real ones still go through.
    for name in ["a1", "a2", "a3", "a4", "a5"] {
        let (status, _, page) = sign_up(&app, &form(name, "")).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{name}: {page}");
    }
}

#[tokio::test]
async fn an_address_gets_five_sign_ups_in_ten_minutes() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = local(&store);
    open(&app, s.root).await;
    // Successes count as much as refusals: three made, two refused.
    for name in ["u1", "u2", "u3"] {
        assert_eq!(
            sign_up(&app, &form(name, "")).await.0,
            StatusCode::SEE_OTHER
        );
    }
    for _ in 0..2 {
        assert_eq!(sign_up(&app, &form("u1", "")).await.0, StatusCode::CONFLICT);
    }
    let before = everything(&store).await;
    let (status, headers, page) = sign_up(&app, &form("u6", "still typed")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{page}");
    assert_eq!(
        alert(&page),
        r#"<p class="alert" role="alert">Too many sign-ups from this address. Try again in 10 minutes."#
    );
    let retry: u64 = headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((590..=600).contains(&retry), "{retry}");
    assert_eq!(form_value(&page, "username"), "u6");
    assert!(page.contains("still typed</textarea>"));
    assert_eq!(everything(&store).await, before, "nothing written");
    // Signing in is limited apart, and is not refused for it.
    let (_, login) = get(&app, "/auth/login").await;
    let state = form_value(&login, "state");
    let (status, _, _) = request(
        &app,
        "POST",
        "/auth/login",
        None,
        "application/x-www-form-urlencoded",
        &format!(
            "state={}&username=u1&password={}",
            encoded(&state),
            encoded(PASSWORD)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn only_a_superuser_reads_or_changes_the_switch_and_each_change_is_audited_once() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = local(&store);
    let root = cookie(s.root);

    let (status, body) = send(&app, "GET", SETTINGS, Some(&root), "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body), serde_json::json!({"sign_up_open": false}));

    // Nobody else, an admin included, and nothing written by the attempt.
    let before = everything(&store).await;
    for caller in [s.ada, s.vi] {
        for (method, body) in [("GET", ""), ("PUT", OPEN)] {
            let (status, answer) = send(&app, method, SETTINGS, Some(&cookie(caller)), body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method}");
            assert_eq!(sentence(&answer), "Settings are a superuser's to change.");
        }
    }
    let (status, _) = send(&app, "PUT", SETTINGS, None, OPEN).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for bad in [
        r#"{"sign_up_open":"yes"}"#,
        r#"{"sign_up_open":true,"x":1}"#,
        "{}",
    ] {
        let (status, _) = send(&app, "PUT", SETTINGS, Some(&root), bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _) = send(&app, "PUT", SETTINGS, Some(&root), CLOSE).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "unchanged");
    assert_eq!(everything(&store).await, before, "nothing written");

    let count = audit_count(&store).await;
    open(&app, s.root).await;
    assert_eq!(audit_count(&store).await, count + 1);
    let audit = last_audit(&store).await;
    assert_eq!(audit["actor_user_id"], serde_json::json!(s.root));
    assert_eq!(audit["actor_method"], "local");
    assert_eq!(audit["action"], "update");
    assert_eq!(audit["object_kind"], "setting");
    assert_eq!(audit["object_id"], serde_json::Value::Null);
    assert_eq!(audit["workspace_id"], serde_json::Value::Null);
    assert_eq!(audit["before"], serde_json::json!({"sign_up_open": false}));
    assert_eq!(audit["after"], serde_json::json!({"sign_up_open": true}));
    open(&app, s.root).await;
    assert_eq!(audit_count(&store).await, count + 1, "unchanged: no audit");
    let (_, body) = send(&app, "GET", SETTINGS, Some(&root), "").await;
    assert_eq!(json(&body), serde_json::json!({"sign_up_open": true}));

    // A disabled superuser is no superuser.
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
    let (status, _) = send(&app, "PUT", SETTINGS, Some(&root), CLOSE).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn closing_leaves_accounts_and_a_waiting_account_can_be_declined() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = local(&store);
    let root = cookie(s.root);
    open(&app, s.root).await;
    let (_, headers, _) = sign_up(&app, &form("maya", "hello")).await;
    let maya_session = session_of(&headers).unwrap();
    let (_, headers, _) = sign_up(&app, &form("ivan", "")).await;
    assert!(session_of(&headers).is_some());

    let (status, _) = send(&app, "PUT", SETTINGS, Some(&root), CLOSE).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = send(&app, "GET", "/api/me", Some(&maya_session), "").await;
    assert_eq!(status, StatusCode::OK, "still signed in: {body}");
    assert_eq!(json(&body)["waiting"], true);
    let (_, login) = get(&app, "/auth/login").await;
    assert!(!login.contains(LINK));
    let state = a_state(&app).await;
    let (status, _, page) = post_with_state(&app, Some(&state), &form("zed", "")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(page.contains(CLOSED));

    // Declined: a local account is deleted, and its session is good for nothing after.
    let users = json(&send(&app, "GET", "/api/users", Some(&root), "").await.1);
    let maya = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "maya")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("/api/users/{maya}"),
        Some(&root),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _) = send(&app, "GET", "/api/me", Some(&maya_session), "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // An identity-provider account is disabled instead.
    let oli = store
        .upsert_oidc_user("https://id.example", "s-oli", "oli", &[])
        .await
        .unwrap()
        .id;
    let (status, body) = send(
        &app,
        "PUT",
        &format!("/api/users/{oli}/status"),
        Some(&root),
        r#"{"disabled":true}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let users = json(&send(&app, "GET", "/api/users", Some(&root), "").await.1);
    let names: Vec<_> = users
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            (
                u["name"].as_str().unwrap().to_string(),
                u["status"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        names.contains(&("ivan".into(), "waiting".into())),
        "{names:?}"
    );
    assert!(
        names.contains(&("oli".into(), "disabled".into())),
        "{names:?}"
    );
    assert!(!names.iter().any(|(n, _)| n == "maya"), "{names:?}");
}

#[tokio::test]
async fn a_sign_up_waiting_on_a_close_in_flight_is_refused() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store.set_sign_up_open(s.root, true).await.unwrap();
    // Another transaction closing sign-up, not yet committed.
    let closer = store.client().await.unwrap();
    closer
        .batch_execute("begin; update console_settings set sign_up_open = false")
        .await
        .unwrap();
    let signing_up = {
        let store = store.clone();
        tokio::spawn(async move { store.sign_up("maya", "x", None).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!signing_up.is_finished(), "the sign-up waits for the close");
    closer.batch_execute("commit").await.unwrap();
    let refused = signing_up.await.unwrap().unwrap();
    assert!(matches!(refused, SignUp::Closed), "{refused:?}");
    let made: i64 = store
        .client()
        .await
        .unwrap()
        .query_one("select count(*) from users where username = 'maya'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(made, 0);

    // And the other way round: a close waits for a sign-up in flight, which is made.
    store.set_sign_up_open(s.root, true).await.unwrap();
    let signer = store.client().await.unwrap();
    signer
        .batch_execute("begin; select sign_up_open from console_settings for share")
        .await
        .unwrap();
    let closing = {
        let store = store.clone();
        tokio::spawn(async move { store.set_sign_up_open(s.root, false).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!closing.is_finished(), "the close waits for the sign-up");
    signer.batch_execute("commit").await.unwrap();
    closing.await.unwrap().unwrap();
    assert!(!store.sign_up_open().await.unwrap());
}

#[tokio::test]
async fn kubernetes_mode_has_no_settings_and_no_sign_up() {
    let app = console(None, gapura_control::login::AuthMode::Local);
    for method in ["GET", "PUT"] {
        let (status, body) = send(&app, method, SETTINGS, None, OPEN).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
        assert_eq!(
            sentence(&body),
            "This console keeps no settings: it runs without a database."
        );
    }
    let (status, page) = get(&app, "/auth/signup").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(page.contains("There is no sign-up here"), "{page}");
    let (status, _, page) = post_with_state(&app, Some("x"), &form("maya", "")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(page.contains("There is no sign-up here"), "{page}");
    let (_, login) = get(&app, "/auth/login").await;
    assert!(!login.contains(LINK), "{login}");
}

const FULL: &str = "Sign-up is full: too many accounts are waiting for access. Ask a superuser.";

#[tokio::test]
async fn sign_up_is_full_while_too_many_of_its_accounts_wait() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = local(&store);
    open(&app, s.root).await;
    let db = store.client().await.unwrap();
    db.execute(
        "insert into users (username, password_hash, signed_up_at)
         select 'w' || g, 'x', now() from generate_series(1, $1::bigint) g",
        &[&MAX_WAITING_SIGN_UPS],
    )
    .await
    .unwrap();
    // Not counted: signed up but disabled, signed up and holding a role, and made by a superuser.
    // Without them this would be full just the same; with them it is still exactly full.
    db.batch_execute(
        "insert into users (username, password_hash, signed_up_at, disabled_at)
              values ('gone', 'x', now(), now());
         insert into users (username, password_hash, signed_up_at) values ('kept', 'x', now());
         insert into role_bindings (user_id, workspace_id, role)
              select u.id, w.id, 'viewer' from users u, workspaces w
               where u.username = 'kept' and w.name = 'default';
         insert into users (username, password_hash) values ('made', 'x');",
    )
    .await
    .unwrap();

    let before = everything(&store).await;
    let (status, headers, page) = sign_up(&app, &form("maya", "hello")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{page}");
    assert!(page.contains(FULL), "{page}");
    assert!(session_of(&headers).is_none());
    assert_eq!(everything(&store).await, before, "nothing written");

    // A role granted to one of them makes room for one.
    db.execute(
        "insert into role_bindings (user_id, workspace_id, role)
         select u.id, w.id, 'viewer' from users u, workspaces w
          where u.username = 'w1' and w.name = 'default'",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        sign_up(&app, &form("maya", "")).await.0,
        StatusCode::SEE_OTHER
    );
    let (status, _, page) = sign_up(&app, &form("ivan", "")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(page.contains(FULL), "full again: {page}");
    // And so does disabling one.
    db.execute(
        "update users set disabled_at = now() where username = 'w2'",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        sign_up(&app, &form("ivan", "")).await.0,
        StatusCode::SEE_OTHER
    );
    let signed_up: i64 = db
        .query_one(
            "select count(*) from users where username in ('maya', 'ivan') and signed_up_at is not null",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(signed_up, 2, "sign-up stamps when");
}

#[tokio::test]
async fn a_note_that_hides_or_reorders_text_is_refused() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = local(&store);
    open(&app, s.root).await;
    let before = everything(&store).await;
    for note in [
        "please grant \u{202E}nimda",
        "zero\u{200B}width",
        "line\u{2028}separator",
    ] {
        let (status, _, page) = sign_up(&app, &form("maya", note)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{note:?}: {page}");
        assert!(
            alert(&page).contains("A note can hold only plain text."),
            "{page}"
        );
    }
    assert_eq!(everything(&store).await, before, "nothing written");
    // A text box's line breaks are kept, as `\n`.
    let (status, _, _) = sign_up(&app, &form("maya", "first line\r\nsecond line")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let note: String = store
        .client()
        .await
        .unwrap()
        .query_one("select signup_note from users where username = 'maya'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(note, "first line\nsecond line");
}

#[tokio::test]
async fn a_note_longer_than_500_characters_is_refused_by_the_table_too() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let error = store
        .client()
        .await
        .unwrap()
        .execute(
            "insert into users (username, password_hash, signup_note) values ('x', 'x', repeat('n', 501))",
            &[],
        )
        .await
        .expect_err("a note of 501 characters");
    assert_eq!(
        error.as_db_error().and_then(|d| d.constraint()),
        Some("users_signup_note_length")
    );
}
