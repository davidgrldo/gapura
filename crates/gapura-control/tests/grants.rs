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
use std::time::{Duration, Instant};
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

use gapura_control::access::Role;
use gapura_control::grants::Refusal;
use gapura_control::store::WriteError;
use std::collections::BTreeMap;

const PASSWORD: &str = "correct horse battery";

/// - `root`: superuser.
/// - `pat`: admin of payments.
/// - `vic`: viewer of payments.
/// - `wes`: no grants, so waiting.
/// - `dee`: viewer of default, but disabled.
/// - Group mappings: `payments-dev` is editor of payments, `default-readers` is viewer of
///   default.
struct Seed {
    root: Uuid,
    pat: Uuid,
    vic: Uuid,
    wes: Uuid,
    dee: Uuid,
    default: Uuid,
    payments: Uuid,
}

async fn seed(store: &Store) -> Seed {
    let db = store.client().await.unwrap();
    let hash = gapura_control::password::hash(PASSWORD).unwrap();
    let default: Uuid = db
        .query_one("select id from workspaces where name = 'default'", &[])
        .await
        .unwrap()
        .get(0);
    let payments: Uuid = db
        .query_one(
            "insert into workspaces (name) values ('payments') returning id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let mut local = std::collections::HashMap::new();
    for (name, superuser, disabled) in [
        ("root", true, false),
        ("pat", false, false),
        ("vic", false, false),
        ("wes", false, false),
        ("dee", false, true),
    ] {
        let id: Uuid = db
            .query_one(
                "insert into users (username, password_hash, superuser, disabled_at)
                 values ($1, $2, $3, case when $4 then now() end) returning id",
                &[&name, &hash, &superuser, &disabled],
            )
            .await
            .unwrap()
            .get(0);
        local.insert(name, id);
    }
    for (user, workspace, role) in [
        (local["pat"], payments, "admin"),
        (local["vic"], payments, "viewer"),
        (local["dee"], default, "viewer"),
    ] {
        db.execute(
            "insert into role_bindings (user_id, workspace_id, role) values ($1, $2, $3::text::role_name)",
            &[&user, &workspace, &role],
        )
        .await
        .unwrap();
    }
    for (group, workspace, role) in [
        ("payments-dev", payments, "editor"),
        ("default-readers", default, "viewer"),
    ] {
        db.execute(
            "insert into group_bindings (group_name, workspace_id, role) values ($1, $2, $3::text::role_name)",
            &[&group, &workspace, &role],
        )
        .await
        .unwrap();
    }
    Seed {
        root: local["root"],
        pat: local["pat"],
        vic: local["vic"],
        wes: local["wes"],
        dee: local["dee"],
        default,
        payments,
    }
}

/// A change to an account's direct grants, as `set_direct_roles` takes it.
fn roles(changes: &[(Uuid, Option<Role>)]) -> BTreeMap<Uuid, Option<Role>> {
    changes.iter().copied().collect()
}

/// `user`'s direct grants as (workspace, role), in workspace order.
async fn grants_of(store: &Store, user: Uuid) -> Vec<(Uuid, String)> {
    store
        .client()
        .await
        .unwrap()
        .query(
            "select workspace_id, role::text from role_bindings where user_id = $1
              order by workspace_id",
            &[&user],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}

/// Every group mapping as (group, workspace, role).
async fn mappings(store: &Store) -> Vec<(String, Uuid, String)> {
    store
        .client()
        .await
        .unwrap()
        .query(
            "select group_name, workspace_id, role::text from group_bindings
              order by group_name, workspace_id",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}

/// Every audit entry, oldest first, as one JSON object each, so a test can compare an entry
/// whole.
///
/// `before_is_null` and `after_is_null` say whether the column holds SQL NULL, which `before` and
/// `after` cannot: read as JSON, a missing value and a stored JSON `null` look alike, and a side
/// of an entry that has nothing on it must be the first, not the second.
async fn audit(store: &Store) -> Vec<serde_json::Value> {
    store
        .client()
        .await
        .unwrap()
        .query(
            "select actor_user_id, actor_name, actor_method, action, object_kind, object_id,
                    workspace_id, before, after,
                    before is null as before_is_null, after is null as after_is_null
               from audit_log order by id",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "actor_user_id": r.get::<_, Option<Uuid>>("actor_user_id"),
                "actor_name": r.get::<_, String>("actor_name"),
                "actor_method": r.get::<_, Option<String>>("actor_method"),
                "action": r.get::<_, String>("action"),
                "object_kind": r.get::<_, String>("object_kind"),
                "object_id": r.get::<_, Option<Uuid>>("object_id"),
                "workspace_id": r.get::<_, Option<Uuid>>("workspace_id"),
                "before": r.get::<_, Option<serde_json::Value>>("before"),
                "after": r.get::<_, Option<serde_json::Value>>("after"),
                "before_is_null": r.get::<_, bool>("before_is_null"),
                "after_is_null": r.get::<_, bool>("after_is_null"),
            })
        })
        .collect()
}

/// The backend pid of `client`'s session, which `wait_for_lock_waiters` is given to name the
/// session a test holds a lock with.
async fn backend_pid(client: &tokio_postgres::Client) -> i32 {
    client
        .query_one("select pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0)
}

/// Waits until `n` sessions are blocked by the session with backend pid `blocker`, so a test
/// knows a write has reached the row it is meant to wait on before it lets that row go. It counts
/// only sessions that `blocker` blocks, so a session waiting on some other lock cannot satisfy it.
///
/// It asks over a connection of its own rather than one from the store's pool: the writes under
/// test and the sessions holding their locks already take pooled connections, and a probe that
/// took one more would leave a runner with few CPUs, and so a small pool, waiting for itself.
/// Bounded at five seconds by the clock, so a write that never waits fails the test instead of
/// hanging it.
async fn wait_for_lock_waiters(blocker: i32, n: i64) {
    let url = std::env::var("GAPURA_TEST_DATABASE_URL")
        .expect("a test that holds a lock only runs once the store it uses is set");
    let (probe, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connecting the probe");
    tokio::spawn(connection);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let waiting: i64 = probe
            .query_one(
                "select count(*) from pg_stat_activity where $1 = any(pg_blocking_pids(pid))",
                &[&blocker],
            )
            .await
            .unwrap()
            .get(0);
        if waiting >= n {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{n} sessions never queued behind the lock pid {blocker} holds; {waiting} did"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn giving_changing_and_removing_a_direct_grant_each_leave_one_audit_entry() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let entry = |before: Option<&str>, after: Option<&str>| {
        serde_json::json!({
            "actor_user_id": s.pat, "actor_name": "pat", "actor_method": "local",
            "action": "update", "object_kind": "user", "object_id": s.wes,
            "workspace_id": s.payments,
            // A direct grant's entry always holds an object on both sides, with `role` null on
            // the side that has no grant, so neither column is ever SQL NULL.
            "before": {"workspace": "payments", "role": before},
            "after": {"workspace": "payments", "role": after},
            "before_is_null": false, "after_is_null": false,
        })
    };
    store
        .set_direct_roles(s.pat, s.wes, &roles(&[(s.payments, Some(Role::Viewer))]))
        .await
        .unwrap();
    assert_eq!(
        grants_of(&store, s.wes).await,
        [(s.payments, "viewer".to_string())]
    );
    store
        .set_direct_roles(s.pat, s.wes, &roles(&[(s.payments, Some(Role::Editor))]))
        .await
        .unwrap();
    assert_eq!(
        grants_of(&store, s.wes).await,
        [(s.payments, "editor".to_string())]
    );
    store
        .set_direct_roles(s.pat, s.wes, &roles(&[(s.payments, None)]))
        .await
        .unwrap();
    assert!(grants_of(&store, s.wes).await.is_empty());
    assert_eq!(
        audit(&store).await,
        [
            entry(None, Some("viewer")),
            entry(Some("viewer"), Some("editor")),
            entry(Some("editor"), None),
        ]
    );
}

#[tokio::test]
async fn asking_for_the_grant_already_held_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .set_direct_roles(s.pat, s.vic, &roles(&[(s.payments, Some(Role::Viewer))]))
        .await
        .unwrap();
    store
        .set_direct_roles(s.pat, s.vic, &BTreeMap::new())
        .await
        .unwrap();
    assert_eq!(
        grants_of(&store, s.vic).await,
        [(s.payments, "viewer".to_string())]
    );
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn a_superuser_grants_in_every_workspace_in_one_change() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .set_direct_roles(
            s.root,
            s.wes,
            &roles(&[
                (s.default, Some(Role::Viewer)),
                (s.payments, Some(Role::Admin)),
            ]),
        )
        .await
        .unwrap();
    let mut changed = [
        (s.default, "default", "viewer"),
        (s.payments, "payments", "admin"),
    ];
    // The order the write takes the bindings in, and so the order of its entries.
    changed.sort();
    let expected_grants: Vec<(Uuid, String)> = changed
        .iter()
        .map(|(workspace, _, role)| (*workspace, role.to_string()))
        .collect();
    assert_eq!(grants_of(&store, s.wes).await, expected_grants);
    let expected_entries: Vec<serde_json::Value> = changed
        .iter()
        .map(|(workspace, name, role)| {
            serde_json::json!({
                "actor_user_id": s.root, "actor_name": "root", "actor_method": "local",
                "action": "update", "object_kind": "user", "object_id": s.wes,
                "workspace_id": workspace,
                "before": {"workspace": name, "role": null},
                "after": {"workspace": name, "role": role},
                "before_is_null": false, "after_is_null": false,
            })
        })
        .collect();
    assert_eq!(
        audit(&store).await,
        expected_entries,
        "one whole entry per binding that changed, in workspace order"
    );
}

#[tokio::test]
async fn any_account_may_be_given_a_grant_a_disabled_one_and_a_superuser_included() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .set_direct_roles(s.pat, s.dee, &roles(&[(s.payments, Some(Role::Editor))]))
        .await
        .unwrap();
    store
        .set_direct_roles(s.pat, s.root, &roles(&[(s.payments, Some(Role::Viewer))]))
        .await
        .unwrap();
    assert!(
        grants_of(&store, s.dee)
            .await
            .contains(&(s.payments, "editor".to_string())),
        "a disabled account's grants apply once it is enabled again"
    );
    assert_eq!(
        grants_of(&store, s.root).await,
        [(s.payments, "viewer".to_string())]
    );
}

#[tokio::test]
async fn one_workspace_the_caller_does_not_administer_refuses_the_whole_change() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let outside = store
        .set_direct_roles(
            s.pat,
            s.wes,
            &roles(&[
                (s.payments, Some(Role::Viewer)),
                (s.default, Some(Role::Viewer)),
            ]),
        )
        .await;
    let unknown = store
        .set_direct_roles(
            s.pat,
            s.wes,
            &roles(&[
                (s.payments, Some(Role::Viewer)),
                (Uuid::new_v4(), Some(Role::Viewer)),
            ]),
        )
        .await;
    match (outside, unknown) {
        (Err(WriteError::Refused(outside)), Err(WriteError::Refused(unknown))) => {
            assert!(matches!(outside, Refusal::Forbidden(_)), "{outside:?}");
            assert_eq!(
                outside, unknown,
                "a workspace that does not exist reads like one that is not pat's"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(
        grants_of(&store, s.wes).await.is_empty(),
        "not even payments, which pat administers, was granted"
    );
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn a_missing_account_is_reported_only_to_someone_who_administers_the_workspace() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let nobody = Uuid::new_v4();
    let in_payments = store
        .set_direct_roles(s.pat, nobody, &roles(&[(s.payments, Some(Role::Viewer))]))
        .await;
    assert!(
        matches!(in_payments, Err(WriteError::Refused(Refusal::NotFound(_)))),
        "{in_payments:?}"
    );
    let in_default = store
        .set_direct_roles(s.pat, nobody, &roles(&[(s.default, Some(Role::Viewer))]))
        .await;
    assert!(
        matches!(in_default, Err(WriteError::Refused(Refusal::Forbidden(_)))),
        "{in_default:?}"
    );
}

#[tokio::test]
async fn an_admin_through_a_group_grants_and_is_recorded_as_signing_in_with_sso() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .client()
        .await
        .unwrap()
        .execute(
            "insert into group_bindings (group_name, workspace_id, role)
             values ('/payments admins', $1, 'admin')",
            &[&s.payments],
        )
        .await
        .unwrap();
    let ada = store
        .upsert_oidc_user(
            "https://id.example",
            "s-ada",
            "ada",
            &["/payments admins".to_string()],
        )
        .await
        .unwrap()
        .id;
    store
        .set_direct_roles(ada, s.wes, &roles(&[(s.payments, Some(Role::Viewer))]))
        .await
        .unwrap();
    let entries = audit(&store).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["actor_user_id"], serde_json::json!(ada));
    assert_eq!(entries[0]["actor_name"], "ada");
    assert_eq!(entries[0]["actor_method"], "oidc");
}

#[tokio::test]
async fn a_caller_disabled_since_their_session_was_read_is_refused() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .client()
        .await
        .unwrap()
        .execute(
            "update users set disabled_at = now() where id = $1",
            &[&s.pat],
        )
        .await
        .unwrap();
    let refused = store
        .set_direct_roles(s.pat, s.wes, &roles(&[(s.payments, Some(Role::Viewer))]))
        .await;
    assert!(
        matches!(refused, Err(WriteError::Refused(Refusal::Forbidden(_)))),
        "{refused:?}"
    );
    assert!(grants_of(&store, s.wes).await.is_empty());
}

#[tokio::test]
async fn an_admin_may_lower_their_own_role_and_then_cannot_raise_it_again() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    // Another admin, so lowering the caller's own role leaves the workspace one.
    store
        .set_direct_roles(s.pat, s.vic, &roles(&[(s.payments, Some(Role::Admin))]))
        .await
        .unwrap();
    store
        .set_direct_roles(s.pat, s.pat, &roles(&[(s.payments, Some(Role::Viewer))]))
        .await
        .unwrap();
    assert_eq!(
        grants_of(&store, s.pat).await,
        [(s.payments, "viewer".to_string())]
    );
    let refused = store
        .set_direct_roles(s.pat, s.pat, &roles(&[(s.payments, Some(Role::Admin))]))
        .await;
    assert!(
        matches!(refused, Err(WriteError::Refused(Refusal::Forbidden(_)))),
        "with the role went the right to change it back: {refused:?}"
    );
}

#[tokio::test]
async fn a_mapping_is_created_changed_and_removed_with_an_audit_entry_each() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let group = "/platform team";
    store
        .put_group_mapping(s.pat, s.payments, group, Role::Viewer)
        .await
        .unwrap();
    store
        .put_group_mapping(s.pat, s.payments, group, Role::Editor)
        .await
        .unwrap();
    // The same role again: nothing to write, and nothing to record.
    store
        .put_group_mapping(s.pat, s.payments, group, Role::Editor)
        .await
        .unwrap();
    assert!(mappings(&store).await.contains(&(
        group.to_string(),
        s.payments,
        "editor".to_string()
    )));
    store
        .delete_group_mapping(s.pat, s.payments, group)
        .await
        .unwrap();
    assert!(!mappings(&store).await.iter().any(|(g, _, _)| g == group));
    let again = store.delete_group_mapping(s.pat, s.payments, group).await;
    assert!(
        matches!(again, Err(WriteError::Refused(Refusal::NotFound(_)))),
        "{again:?}"
    );
    let shape =
        |role: &str| serde_json::json!({"group": group, "workspace": "payments", "role": role});
    // A side with no mapping on it is `None`, and must be SQL NULL in the column, not a stored
    // JSON `null`, which `before_is_null` and `after_is_null` tell apart.
    let entry =
        |action: &str, before: Option<serde_json::Value>, after: Option<serde_json::Value>| {
            serde_json::json!({
                "actor_user_id": s.pat, "actor_name": "pat", "actor_method": "local",
                "action": action, "object_kind": "group_mapping", "object_id": null,
                "workspace_id": s.payments,
                "before_is_null": before.is_none(), "after_is_null": after.is_none(),
                "before": before, "after": after,
            })
        };
    assert_eq!(
        audit(&store).await,
        [
            entry("create", None, Some(shape("viewer"))),
            entry("update", Some(shape("viewer")), Some(shape("editor"))),
            entry("delete", Some(shape("editor")), None),
        ]
    );
}

#[tokio::test]
async fn a_mapping_outside_the_callers_workspaces_is_refused_before_it_is_looked_for() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let exists = store
        .delete_group_mapping(s.pat, s.default, "default-readers")
        .await;
    let missing = store
        .delete_group_mapping(s.pat, s.default, "no-such-group")
        .await;
    match (exists, missing) {
        (Err(WriteError::Refused(exists)), Err(WriteError::Refused(missing))) => {
            assert!(matches!(exists, Refusal::Forbidden(_)), "{exists:?}");
            assert_eq!(
                exists, missing,
                "whether the mapping exists is not pat's to learn"
            );
        }
        other => panic!("{other:?}"),
    }
    let put = store
        .put_group_mapping(s.pat, s.default, "anyone", Role::Admin)
        .await;
    assert!(
        matches!(put, Err(WriteError::Refused(Refusal::Forbidden(_)))),
        "{put:?}"
    );
    assert!(mappings(&store)
        .await
        .iter()
        .any(|(g, _, _)| g == "default-readers"));
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn a_demotion_racing_the_callers_write_is_ordered_and_the_write_changes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    // 1. Another session removes pat's admin grant and holds the change uncommitted.
    let mut demoter = store.client().await.unwrap();
    let demoter_pid = backend_pid(&demoter).await;
    let demotion = demoter.transaction().await.unwrap();
    demotion
        .execute(
            "delete from role_bindings where user_id = $1 and workspace_id = $2",
            &[&s.pat, &s.payments],
        )
        .await
        .unwrap();
    // 2. pat's write reaches pat's grant, which the demotion holds, and waits for it.
    let write = tokio::spawn({
        let store = store.clone();
        let (pat, wes, payments) = (s.pat, s.wes, s.payments);
        async move {
            store
                .set_direct_roles(pat, wes, &roles(&[(payments, Some(Role::Viewer))]))
                .await
        }
    });
    wait_for_lock_waiters(demoter_pid, 1).await;
    // 3. The demotion commits.
    demotion.commit().await.unwrap();
    // 4. The write reads pat as no longer admin, and is refused with nothing changed.
    let outcome = write.await.unwrap();
    assert!(
        matches!(outcome, Err(WriteError::Refused(Refusal::Forbidden(_)))),
        "{outcome:?}"
    );
    assert!(grants_of(&store, s.wes).await.is_empty());
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn a_mapping_removed_racing_the_write_of_someone_admin_through_it_is_ordered() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    // ada administers payments only through her group's mapping: she holds no grant of her own,
    // so the group path is the one the write has to read again, locked, to know she still can.
    store
        .client()
        .await
        .unwrap()
        .execute(
            "insert into group_bindings (group_name, workspace_id, role)
             values ('/payments admins', $1, 'admin')",
            &[&s.payments],
        )
        .await
        .unwrap();
    let ada = store
        .upsert_oidc_user(
            "https://id.example",
            "s-ada",
            "ada",
            &["/payments admins".to_string()],
        )
        .await
        .unwrap()
        .id;
    // 1. Another session removes that mapping and holds the change uncommitted.
    let mut remover = store.client().await.unwrap();
    let remover_pid = backend_pid(&remover).await;
    let removal = remover.transaction().await.unwrap();
    removal
        .execute(
            "delete from group_bindings where group_name = '/payments admins' and workspace_id = $1",
            &[&s.payments],
        )
        .await
        .unwrap();
    // 2. ada's write reaches the mapping, which the removal holds, and waits for it.
    let write = tokio::spawn({
        let store = store.clone();
        let (wes, payments) = (s.wes, s.payments);
        async move {
            store
                .set_direct_roles(ada, wes, &roles(&[(payments, Some(Role::Viewer))]))
                .await
        }
    });
    wait_for_lock_waiters(remover_pid, 1).await;
    // 3. The removal commits.
    removal.commit().await.unwrap();
    // 4. The write reads ada's group as mapped to nothing, and is refused with nothing changed.
    match write.await.unwrap() {
        Err(WriteError::Refused(refusal)) => {
            assert_eq!(refusal, Refusal::outside_your_workspaces())
        }
        other => panic!("{other:?}"),
    }
    assert!(grants_of(&store, s.wes).await.is_empty());
    assert!(grants_of(&store, ada).await.is_empty());
    assert_eq!(
        mappings(&store).await,
        [
            (
                "default-readers".to_string(),
                s.default,
                "viewer".to_string()
            ),
            ("payments-dev".to_string(), s.payments, "editor".to_string()),
        ],
        "only the removal changed a mapping"
    );
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn two_admins_demoting_each_other_at_once_are_ordered_rather_than_failed() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let db = store.client().await.unwrap();
    db.execute(
        "update role_bindings set role = 'admin' where user_id = $1 and workspace_id = $2",
        &[&s.vic, &s.payments],
    )
    .await
    .unwrap();
    // A third session share-locks both grants. Each write takes the share lock on its own grant
    // and then queues behind this session for the other's. Once this one lets go, each waits for
    // the other, a deadlock every time, rather than only when the timing happens to make one.
    let mut holder = store.client().await.unwrap();
    let holder_pid = backend_pid(&holder).await;
    let hold = holder.transaction().await.unwrap();
    hold.query(
        "select 1 from role_bindings where workspace_id = $1 and user_id = any($2) for share",
        &[&s.payments, &vec![s.pat, s.vic]],
    )
    .await
    .unwrap();
    let demote = |caller: Uuid, target: Uuid| {
        let store = store.clone();
        let payments = s.payments;
        tokio::spawn(async move {
            store
                .set_direct_roles(caller, target, &roles(&[(payments, None)]))
                .await
        })
    };
    let pat_demotes_vic = demote(s.pat, s.vic);
    let vic_demotes_pat = demote(s.vic, s.pat);
    wait_for_lock_waiters(holder_pid, 2).await;
    hold.rollback().await.unwrap();
    let outcomes = [
        pat_demotes_vic.await.unwrap(),
        vic_demotes_pat.await.unwrap(),
    ];
    // Postgres aborted one. Run again, it read the other's demotion of its own caller and was
    // refused: an ordering, not an outage.
    assert_eq!(
        outcomes.iter().filter(|o| o.is_ok()).count(),
        1,
        "{outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Err(WriteError::Refused(Refusal::Forbidden(_)))))
            .count(),
        1,
        "{outcomes:?}"
    );
    let admins: i64 = db
        .query_one(
            "select count(*) from role_bindings where workspace_id = $1 and role = 'admin'",
            &[&s.payments],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(admins, 1, "exactly one of the two is still admin");
    assert_eq!(audit(&store).await.len(), 1);
}

#[tokio::test]
async fn a_grant_made_meanwhile_is_what_the_write_replaces() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let mut other = store.client().await.unwrap();
    let other_pid = backend_pid(&other).await;
    let meanwhile = other.transaction().await.unwrap();
    meanwhile
        .execute(
            "insert into role_bindings (user_id, workspace_id, role) values ($1, $2, 'editor')",
            &[&s.wes, &s.payments],
        )
        .await
        .unwrap();
    let write = tokio::spawn({
        let store = store.clone();
        let (pat, wes, payments) = (s.pat, s.wes, s.payments);
        async move {
            store
                .set_direct_roles(pat, wes, &roles(&[(payments, Some(Role::Viewer))]))
                .await
        }
    });
    // The write saw no grant, so it inserts one, and that insert waits on the uncommitted one.
    wait_for_lock_waiters(other_pid, 1).await;
    meanwhile.commit().await.unwrap();
    write
        .await
        .unwrap()
        .expect("run again, the write changes the grant it now sees");
    assert_eq!(
        grants_of(&store, s.wes).await,
        [(s.payments, "viewer".to_string())]
    );
    let entries = audit(&store).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["before"],
        serde_json::json!({"workspace": "payments", "role": "editor"}),
        "the entry names what it replaced, not an empty slot"
    );
}

const JSON: (&str, &str) = ("content-type", "application/json");

/// What a browser sends with the console's own writes.
const FROM_THE_CONSOLE: &[(&str, &str)] = &[JSON, ("sec-fetch-site", "same-origin")];

/// The sentence a refusal carries, which every refusal must.
fn sentence(body: &str) -> String {
    json(body)["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no error sentence in {body}"))
        .to_string()
}

#[tokio::test]
async fn a_write_from_the_console_is_made_and_answered_with_no_content() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let (status, body) = send(
        &app,
        "PATCH",
        &format!("/api/users/{}/roles", s.wes),
        Some(s.pat),
        FROM_THE_CONSOLE,
        &format!(r#"{{"{}": "viewer"}}"#, s.payments),
    )
    .await;
    assert_eq!((status, body.as_str()), (StatusCode::NO_CONTENT, ""));
    let (_, users) = send(&app, "GET", "/api/users", Some(s.pat), &[], "").await;
    let wes = json(&users)
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "wes")
        .unwrap()
        .clone();
    assert_eq!(
        wes["access"][0]["sources"],
        serde_json::json!([{"kind": "direct", "role": "viewer"}]),
        "the list fetched after a save shows the grant"
    );
    let (status, _) = send(
        &app,
        "PUT",
        "/api/group-mappings",
        Some(s.pat),
        FROM_THE_CONSOLE,
        &format!(
            r#"{{"workspace_id": "{}", "group": "/platform-team", "role": "editor"}}"#,
            s.payments
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Percent-encoded, as the console sends it: the name has a slash of its own.
    let (status, _) = send(
        &app,
        "DELETE",
        &format!(
            "/api/group-mappings?workspace_id={}&group=%2Fplatform-team",
            s.payments
        ),
        Some(s.pat),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let actions: Vec<serde_json::Value> = audit(&store)
        .await
        .iter()
        .map(|e| e["action"].clone())
        .collect();
    assert_eq!(actions, ["update", "create", "delete"]);
}

#[tokio::test]
async fn a_malformed_request_is_400_and_says_why() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let roles_of_wes = format!("/api/users/{}/roles", s.wes);
    let payments = s.payments;
    let malformed = [
        ("PATCH", roles_of_wes.clone(), "{".to_string()),
        (
            "PATCH",
            roles_of_wes.clone(),
            format!(r#"{{"{payments}": "owner"}}"#),
        ),
        (
            "PATCH",
            roles_of_wes.clone(),
            r#"{"payments": "viewer"}"#.to_string(),
        ),
        (
            "PATCH",
            "/api/users/not-an-id/roles".to_string(),
            "{}".to_string(),
        ),
        (
            "PUT",
            "/api/group-mappings".to_string(),
            format!(r#"{{"workspace_id": "{payments}", "group": "lead ", "role": "viewer"}}"#),
        ),
        (
            "PUT",
            "/api/group-mappings".to_string(),
            format!(r#"{{"workspace_id": "{payments}", "group": "lead"}}"#),
        ),
        (
            "DELETE",
            "/api/group-mappings?group=lead".to_string(),
            String::new(),
        ),
        (
            "DELETE",
            "/api/group-mappings?workspace_id=payments&group=lead".to_string(),
            String::new(),
        ),
        // NUL cannot be stored in text; without the check it would reach Postgres and come
        // back as a 503 that reads like an outage.
        (
            "DELETE",
            format!("/api/group-mappings?workspace_id={payments}&group=lead%00"),
            String::new(),
        ),
        // A body is held to its fields, and so is the query: a misspelt one is not ignored.
        (
            "DELETE",
            format!("/api/group-mappings?workspace_id={payments}&group=lead&gruop=lead"),
            String::new(),
        ),
        // A path segment that is not UTF-8 once decoded never reaches the handler as a string.
        (
            "PATCH",
            "/api/users/%ff/roles".to_string(),
            "{}".to_string(),
        ),
    ];
    for (method, path, request) in &malformed {
        let (status, body) = send(&app, method, path, Some(s.pat), FROM_THE_CONSOLE, request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{method} {path} {request}: {body}"
        );
        assert!(!sentence(&body).is_empty());
    }
    let (_, body) = send(
        &app,
        "PUT",
        "/api/group-mappings",
        Some(s.pat),
        FROM_THE_CONSOLE,
        &malformed[4].2,
    )
    .await;
    assert!(
        sentence(&body).contains("start or end with a space"),
        "the reason is given: {body}"
    );
    assert!(grants_of(&store, s.wes).await.is_empty());
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn a_write_without_a_live_session_is_401() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let path = format!("/api/users/{}/roles", s.wes);
    let body = format!(r#"{{"{}": "viewer"}}"#, s.payments);
    // No session; a disabled account; an id that names no account.
    for who in [None, Some(s.dee), Some(Uuid::new_v4())] {
        let (status, answer) = send(&app, "PATCH", &path, who, FROM_THE_CONSOLE, &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{who:?}");
        assert_eq!(sentence(&answer), "You are not signed in.");
    }
    // The request was a valid one, so what keeps it from being made is the 401 alone.
    assert!(grants_of(&store, s.wes).await.is_empty());
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn a_request_is_judged_by_who_sent_it_before_it_is_judged_by_what_it_says() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let roles_of_wes = format!("/api/users/{}/roles", s.wes);
    // Longer than the console reads of a body, whatever it says.
    let too_long = format!(r#"{{"{}": "{}"}}"#, s.payments, "a".repeat(100_000));
    // Each is malformed in a different way, and the last is not a body at all but a query.
    let malformed = [
        ("PATCH", roles_of_wes.clone(), "{".to_string(), 400),
        ("PATCH", roles_of_wes, too_long.clone(), 413),
        (
            "PATCH",
            "/api/users/not-an-id/roles".to_string(),
            "{}".to_string(),
            400,
        ),
        (
            "PATCH",
            "/api/users/%ff/roles".to_string(),
            "{}".to_string(),
            400,
        ),
        (
            "PUT",
            "/api/group-mappings".to_string(),
            "{".to_string(),
            400,
        ),
        ("PUT", "/api/group-mappings".to_string(), too_long, 413),
        (
            "DELETE",
            "/api/group-mappings?group=lead".to_string(),
            String::new(),
            400,
        ),
    ];
    for (method, path, request, status_for_an_admin) in &malformed {
        // No session, and a disabled account: not signed in, so nothing else is said.
        for who in [None, Some(s.dee)] {
            let (status, body) = send(&app, method, path, who, FROM_THE_CONSOLE, request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} {who:?}");
            assert_eq!(sentence(&body), "You are not signed in.");
        }
        // Waiting, and holding a role while administering nothing: signed in, but not allowed
        // to ask for anything, however it is asked.
        for who in [s.wes, s.vic] {
            let (status, body) =
                send(&app, method, path, Some(who), FROM_THE_CONSOLE, request).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path} {who}");
            assert_eq!(sentence(&body), "You do not administer any workspace.");
        }
        // Only an administrator is told what is wrong with it.
        let (status, body) = send(&app, method, path, Some(s.pat), FROM_THE_CONSOLE, request).await;
        assert_eq!(
            status.as_u16(),
            *status_for_an_admin,
            "{method} {path}: {body}"
        );
        assert!(!sentence(&body).is_empty());
    }
    assert!(grants_of(&store, s.wes).await.is_empty());
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn a_caller_who_may_not_make_the_change_is_403_and_nothing_changes() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let to_vic = format!("/api/users/{}/roles", s.vic);
    let editor_in = |workspace: Uuid| format!(r#"{{"{workspace}": "editor"}}"#);
    // Waiting, and holding a role while administering nothing.
    for who in [s.wes, s.vic] {
        let (status, body) = send(
            &app,
            "PATCH",
            &to_vic,
            Some(who),
            FROM_THE_CONSOLE,
            &editor_in(s.payments),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who}");
        assert_eq!(sentence(&body), "You do not administer any workspace.");
    }
    // A workspace pat does not administer, and one that does not exist, get one answer.
    let outside = send(
        &app,
        "PATCH",
        &to_vic,
        Some(s.pat),
        FROM_THE_CONSOLE,
        &editor_in(s.default),
    )
    .await;
    let unknown = send(
        &app,
        "PATCH",
        &to_vic,
        Some(s.pat),
        FROM_THE_CONSOLE,
        &editor_in(Uuid::new_v4()),
    )
    .await;
    assert_eq!(outside.0, StatusCode::FORBIDDEN);
    assert_eq!(outside, unknown);
    // The sentence the rules give, not one the handler worded for itself.
    let outside_yours = Refusal::outside_your_workspaces().sentence().to_string();
    assert_eq!(sentence(&outside.1), outside_yours);
    // A new mapping there gets it too, whether the workspace exists or not.
    let put_in = |workspace: Uuid| {
        format!(r#"{{"workspace_id": "{workspace}", "group": "new-group", "role": "viewer"}}"#)
    };
    let put_outside = send(
        &app,
        "PUT",
        "/api/group-mappings",
        Some(s.pat),
        FROM_THE_CONSOLE,
        &put_in(s.default),
    )
    .await;
    let put_unknown = send(
        &app,
        "PUT",
        "/api/group-mappings",
        Some(s.pat),
        FROM_THE_CONSOLE,
        &put_in(Uuid::new_v4()),
    )
    .await;
    assert_eq!(put_outside.0, StatusCode::FORBIDDEN);
    assert_eq!(put_outside, put_unknown);
    assert_eq!(sentence(&put_outside.1), outside_yours);
    // So does removing one, whether it exists or not.
    let mapping = |group: &str| {
        format!(
            "/api/group-mappings?workspace_id={}&group={group}",
            s.default
        )
    };
    let exists = send(
        &app,
        "DELETE",
        &mapping("default-readers"),
        Some(s.pat),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    let missing = send(
        &app,
        "DELETE",
        &mapping("nobody"),
        Some(s.pat),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(exists.0, StatusCode::FORBIDDEN);
    assert_eq!(exists, missing);
    assert_eq!(sentence(&exists.1), outside_yours);
    assert_eq!(
        grants_of(&store, s.vic).await,
        [(s.payments, "viewer".to_string())]
    );
    assert_eq!(
        mappings(&store).await,
        [
            (
                "default-readers".to_string(),
                s.default,
                "viewer".to_string()
            ),
            ("payments-dev".to_string(), s.payments, "editor".to_string()),
        ],
        "the mappings are as they were seeded"
    );
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn a_missing_account_or_mapping_is_404_once_the_workspace_is_the_callers() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store));
    let (status, body) = send(
        &app,
        "PATCH",
        &format!("/api/users/{}/roles", Uuid::new_v4()),
        Some(s.pat),
        FROM_THE_CONSOLE,
        &format!(r#"{{"{}": "viewer"}}"#, s.payments),
    )
    .await;
    assert_eq!(
        (status, sentence(&body)),
        (
            StatusCode::NOT_FOUND,
            "There is no such account.".to_string()
        )
    );
    // Asking for nothing is still asking about an account, and the answer for one that does not
    // exist does not depend on there being anything to change.
    let (status, body) = send(
        &app,
        "PATCH",
        &format!("/api/users/{}/roles", Uuid::new_v4()),
        Some(s.pat),
        FROM_THE_CONSOLE,
        "{}",
    )
    .await;
    assert_eq!(
        (status, sentence(&body)),
        (
            StatusCode::NOT_FOUND,
            "There is no such account.".to_string()
        )
    );
    let (status, body) = send(
        &app,
        "DELETE",
        &format!(
            "/api/group-mappings?workspace_id={}&group=nobody",
            s.payments
        ),
        Some(s.pat),
        FROM_THE_CONSOLE,
        "",
    )
    .await;
    assert_eq!(
        (status, sentence(&body)),
        (
            StatusCode::NOT_FOUND,
            "There is no such group mapping.".to_string()
        )
    );
}

#[tokio::test]
async fn a_group_with_a_space_or_a_plus_is_removed_as_the_console_encodes_it() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let seeded = mappings(&store).await;
    // `%20` and `%2B` are what `encodeURIComponent` makes of a space and a plus; `+` is what a
    // form encoder makes of a space, and a query reads it back as one.
    let removed = [
        ("front end", "front%20end"),
        ("front end", "front+end"),
        ("c++", "c%2B%2B"),
    ];
    for (group, encoded) in removed {
        let (status, body) = send(
            &app,
            "PUT",
            "/api/group-mappings",
            Some(s.pat),
            FROM_THE_CONSOLE,
            &format!(
                r#"{{"workspace_id": "{}", "group": "{group}", "role": "editor"}}"#,
                s.payments
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{group}: {body}");
        assert_eq!(mappings(&store).await.len(), seeded.len() + 1, "{group}");
        let (status, body) = send(
            &app,
            "DELETE",
            &format!(
                "/api/group-mappings?workspace_id={}&group={encoded}",
                s.payments
            ),
            Some(s.pat),
            FROM_THE_CONSOLE,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{encoded}: {body}");
        assert_eq!(mappings(&store).await, seeded, "{encoded} removed {group}");
    }
    let removed_groups: Vec<serde_json::Value> = audit(&store)
        .await
        .iter()
        .filter(|entry| entry["action"] == "delete")
        .map(|entry| entry["before"]["group"].clone())
        .collect();
    assert_eq!(removed_groups, ["front end", "front end", "c++"]);
}

#[tokio::test]
async fn a_store_that_cannot_be_read_or_written_is_503_and_nothing_is_half_written() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));
    let path = format!("/api/users/{}/roles", s.wes);
    let body = format!(r#"{{"{}": "viewer"}}"#, s.payments);
    let db = store.client().await.unwrap();
    // The write fails at its audit entry, after the grant, and the grant must go with it.
    db.batch_execute("alter table audit_log rename to audit_log_gone")
        .await
        .unwrap();
    let (status, answer) = send(&app, "PATCH", &path, Some(s.pat), FROM_THE_CONSOLE, &body).await;
    // It does not say the database cannot be reached, because it can: a table is gone.
    let could_not_save = "The console could not save this change. Try again in a moment.";
    assert_eq!(
        (status, sentence(&answer)),
        (StatusCode::SERVICE_UNAVAILABLE, could_not_save.to_string())
    );
    assert!(
        grants_of(&store, s.wes).await.is_empty(),
        "the grant went in without its audit entry"
    );
    // And when the caller cannot be read at all.
    db.batch_execute("alter table group_bindings rename to group_bindings_gone")
        .await
        .unwrap();
    let (status, answer) = send(&app, "PATCH", &path, Some(s.pat), FROM_THE_CONSOLE, &body).await;
    assert_eq!(
        (status, sentence(&answer)),
        (StatusCode::SERVICE_UNAVAILABLE, could_not_save.to_string())
    );
}

#[tokio::test]
async fn in_kubernetes_mode_a_write_is_refused_from_another_site_415_without_json_and_404_otherwise(
) {
    let app = console(None);
    let path = "/api/users/00000000-0000-4000-8000-000000000001/roles";
    let cross_site: [&[(&str, &str)]; 3] = [
        &[JSON, ("sec-fetch-site", "cross-site")],
        &[JSON, ("sec-fetch-site", "same-site")],
        &[JSON, ("origin", "https://evil.example"), HOST],
    ];
    for headers in cross_site {
        let (status, body) = send(&app, "PATCH", path, None, headers, "{}").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{headers:?}");
        assert_eq!(
            sentence(&body),
            "This request came from another site, so it was refused."
        );
    }
    let not_json: [&[(&str, &str)]; 3] = [
        &[("sec-fetch-site", "same-origin")],
        &[
            ("content-type", "text/plain"),
            ("sec-fetch-site", "same-origin"),
        ],
        &[FORM, ("origin", "https://console.example.test"), HOST],
    ];
    for headers in not_json {
        let (status, body) = send(&app, "PATCH", path, None, headers, "{}").await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{headers:?}");
        assert!(sentence(&body).contains("JSON"), "{body}");
    }
    // Past both, Kubernetes mode keeps no accounts to change, signed in or not. A session
    // signed with the console's key still names no account there.
    for (method, path) in [
        ("PATCH", path),
        ("PUT", "/api/group-mappings"),
        ("DELETE", "/api/group-mappings?workspace_id=x&group=y"),
    ] {
        for who in [None, Some(Uuid::new_v4())] {
            let (status, body) = send(&app, method, path, who, FROM_THE_CONSOLE, "{}").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path} {who:?}");
            assert_eq!(
                sentence(&body),
                "This console keeps no accounts: it runs without a database."
            );
        }
    }
}

#[tokio::test]
async fn the_last_admin_cannot_lower_or_remove_their_own_role() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    for change in [Some(Role::Editor), None] {
        let refused = store
            .set_direct_roles(s.pat, s.pat, &roles(&[(s.payments, change)]))
            .await;
        assert!(
            matches!(refused, Err(WriteError::Refused(Refusal::Conflict(_)))),
            "{refused:?}"
        );
    }
    assert_eq!(
        grants_of(&store, s.pat).await,
        [(s.payments, "admin".to_string())],
        "nothing was written"
    );
    assert!(audit(&store).await.is_empty());
}

#[tokio::test]
async fn an_admin_through_a_group_counts_and_the_last_one_keeps_the_mapping() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let db = store.client().await.unwrap();
    db.execute(
        "insert into group_bindings (group_name, workspace_id, role) values ('payments-admins', $1, 'admin')",
        &[&s.payments],
    )
    .await
    .unwrap();
    let oli: Uuid = db
        .query_one(
            "insert into users (oidc_issuer, oidc_subject, display_name, oidc_groups)
             values ('https://idp.example', 'oli', 'Oli', '{payments-admins}') returning id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    // Oli is an admin through the group, so Pat may step down.
    store
        .set_direct_roles(s.pat, s.pat, &roles(&[(s.payments, None)]))
        .await
        .unwrap();
    // Now the mapping is the workspace's only way to an admin, and Oli's only way in.
    let refused = store
        .delete_group_mapping(oli, s.payments, "payments-admins")
        .await;
    assert!(
        matches!(refused, Err(WriteError::Refused(Refusal::Conflict(_)))),
        "{refused:?}"
    );
    let refused = store
        .put_group_mapping(oli, s.payments, "payments-admins", Role::Editor)
        .await;
    assert!(
        matches!(refused, Err(WriteError::Refused(Refusal::Conflict(_)))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_superuser_may_leave_a_workspace_to_superusers() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .set_direct_roles(s.root, s.pat, &roles(&[(s.payments, None)]))
        .await
        .unwrap();
    assert!(grants_of(&store, s.pat).await.is_empty());
}

#[tokio::test]
async fn two_last_admins_stepping_down_at_once_leave_one() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .set_direct_roles(s.pat, s.vic, &roles(&[(s.payments, Some(Role::Admin))]))
        .await
        .unwrap();
    let step_down = |who: Uuid| {
        let store = store.clone();
        let payments = s.payments;
        tokio::spawn(async move {
            store
                .set_direct_roles(who, who, &roles(&[(payments, Some(Role::Viewer))]))
                .await
        })
    };
    let (pat, vic) = (step_down(s.pat), step_down(s.vic));
    let outcomes = [pat.await.unwrap(), vic.await.unwrap()];
    // Each alone would leave the other. Together they would leave nobody, so the second to
    // reach the count sees the first's commit and is refused, whichever order they ran in.
    assert_eq!(
        outcomes.iter().filter(|o| o.is_ok()).count(),
        1,
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Err(WriteError::Refused(Refusal::Conflict(_))))),
        "{outcomes:?}"
    );
}
