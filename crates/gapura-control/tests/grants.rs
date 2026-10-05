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
