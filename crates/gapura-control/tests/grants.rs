//! Granting and removing roles and group mappings, the audit entries they leave, and the
//! cross-site rules in front of every write.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `identity.rs`, and for the same reason: the alternative mocks the database and proves the
//! mock. CI sets it. The cross-site tests need no store and always run. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test grants
//! ```
//!
//! The helpers are copies of `identity.rs`'s rather than a shared `tests/common` module, so that
//! each file reads on its own; the accounts each file seeds are its own.

use std::sync::Arc;

use gapura_control::store::Store;

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

/// The constraint a failed statement broke, by name, so a test can tell the rule it meant to
/// exercise from any other way the insert might have failed.
fn violated(error: tokio_postgres::Error) -> Option<String> {
    error
        .as_db_error()
        .and_then(|d| d.constraint())
        .map(str::to_string)
}

#[tokio::test]
async fn an_audit_entry_records_how_its_actor_signed_in_or_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    let insert = "insert into audit_log (actor_name, actor_method, action, object_kind)
                  values ('pat', $1, 'update', 'user')";
    // Local, single sign-on, and an entry no person made.
    for method in [Some("local"), Some("oidc"), None] {
        db.execute(insert, &[&method])
            .await
            .unwrap_or_else(|e| panic!("{method:?} was refused: {e}"));
    }
    let refused = db
        .execute(insert, &[&Some("saml")])
        .await
        .expect_err("a third way in is not one this console has");
    assert_eq!(
        violated(refused),
        Some("audit_log_actor_method".to_string())
    );
}

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

/// The console's router: in store mode over `store`, or in Kubernetes mode without one. Its
/// readers point at nothing, because these tests are about writes.
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
        pending: Default::default(),
        session_lifetime: Duration::from_secs(3600),
        store,
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

/// A test request has no `Host` unless it is given one, and an `Origin` is compared with it.
const HOST: (&str, &str) = ("host", "console.example.test");
const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

#[tokio::test]
async fn signing_out_from_another_site_is_refused_and_from_this_one_is_not() {
    // A page elsewhere posting to /auth/logout signs the reader out without asking them.
    let app = console(None);
    let refused: [&[(&str, &str)]; 4] = [
        &[("sec-fetch-site", "cross-site")],
        &[("sec-fetch-site", "same-site")],
        &[("origin", "https://evil.example"), HOST],
        &[("origin", "null"), HOST],
    ];
    for headers in refused {
        let (status, body) = send(&app, "POST", "/auth/logout", None, headers, "").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{headers:?}");
        assert!(json(&body)["error"].is_string(), "{body}");
    }
    let passed: [&[(&str, &str)]; 3] = [
        &[("sec-fetch-site", "same-origin")],
        &[("origin", "https://console.example.test"), HOST],
        // Neither header: not a browser, and so no cookie it did not mean to send.
        &[],
    ];
    for headers in passed {
        let (status, page) = send(&app, "POST", "/auth/logout", None, headers, "").await;
        assert_eq!(status, StatusCode::OK, "{headers:?}");
        assert!(page.contains("You are signed out"), "{page}");
    }
}

#[tokio::test]
async fn another_site_cannot_sign_a_browser_in() {
    // Login CSRF: a page elsewhere posts the sign-in form with an account of its choosing, and
    // the browser comes away signed in as that account. Refused before the form is read.
    let app = console(None);
    let body = "state=x&username=mallory&password=correct+horse+battery";
    let refused: [&[(&str, &str)]; 3] = [
        &[FORM, ("sec-fetch-site", "cross-site")],
        &[FORM, ("sec-fetch-site", "same-site")],
        &[FORM, ("origin", "https://evil.example"), HOST],
    ];
    for headers in refused {
        let (status, _) = send(&app, "POST", "/auth/login", None, headers, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{headers:?}");
    }
    // From this origin, or from no browser at all, the form is read. Its state was never
    // issued, so it is refused as a sign-in, not as a request from elsewhere.
    let read: [&[(&str, &str)]; 2] = [&[FORM, ("sec-fetch-site", "same-origin")], &[FORM]];
    for headers in read {
        let (status, page) = send(&app, "POST", "/auth/login", None, headers, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{headers:?}");
        assert!(page.contains("no longer valid"), "{page}");
    }
}

#[tokio::test]
async fn a_path_no_route_owns_is_judged_before_it_is_answered() {
    // The layer wraps the fallback too, so a write from another site learns nothing, not even
    // that the path does not exist.
    let app = console(None);
    let (status, _) = send(
        &app,
        "POST",
        "/api/nope",
        None,
        &[("sec-fetch-site", "cross-site")],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_link_from_another_site_still_reaches_the_sign_in_page() {
    let app = console(None);
    let (status, page) = send(
        &app,
        "GET",
        "/auth/login",
        None,
        &[("sec-fetch-site", "cross-site")],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(r#"action="/auth/login""#), "{page}");
}
