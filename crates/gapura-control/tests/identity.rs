//! The console's accounts and access in the store, and the API over them, against a real
//! Postgres.
//!
//! Skipped unless `GAPURA_TEST_DATABASE_URL` is set, like `config_endpoint.rs` and for the same
//! reason: the alternative mocks the database and proves the mock. CI sets it. Run it with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test identity
//! ```

use std::sync::Arc;

use gapura_control::store::Store;

/// One database, so the tests take turns: each starts by dropping the schema, and two doing
/// that at once would delete each other's tables mid-run. The guard is held for the whole test
/// rather than just the reset, because the race is between one test's reset and another's
/// queries.
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
async fn an_account_is_exactly_local_or_exactly_oidc() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    // Every combination of the four identity columns, set or not. Each value is unique to its
    // combination, so no uniqueness rule can be what refuses one; exactly two shapes are accounts.
    let mut accepted = Vec::new();
    for mask in 0u8..16 {
        let [username, hash, issuer, subject] = [0, 1, 2, 3].map(|bit| mask & (1 << bit) != 0);
        let value = |set: bool| set.then(|| format!("v{mask}"));
        let result = db
            .execute(
                "insert into users (username, password_hash, oidc_issuer, oidc_subject)
                 values ($1, $2, $3, $4)",
                &[
                    &value(username),
                    &value(hash),
                    &value(issuer),
                    &value(subject),
                ],
            )
            .await;
        match result {
            Ok(_) => accepted.push((username, hash, issuer, subject)),
            Err(error) => assert_eq!(
                violated(error),
                Some("users_local_or_oidc".to_string()),
                "shape {mask:04b} was refused by something other than the shape rule"
            ),
        }
    }
    assert_eq!(
        accepted,
        [(true, true, false, false), (false, false, true, true)],
        "only (username, password) and (issuer, subject) are accounts"
    );
}

#[tokio::test]
async fn usernames_are_unique_ignoring_case_and_subjects_per_issuer() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    let local = "insert into users (username, password_hash) values ($1, 'x')";
    let oidc = "insert into users (oidc_issuer, oidc_subject) values ($1, $2)";
    db.execute(local, &[&"maya"]).await.unwrap();
    let same_name = db
        .execute(local, &[&"MAYA"])
        .await
        .expect_err("maya and MAYA would be two accounts that sign in as each other");
    assert_eq!(
        violated(same_name),
        Some("users_username_lower".to_string())
    );

    db.execute(oidc, &[&"https://id.example", &"s1"])
        .await
        .unwrap();
    let same_subject = db
        .execute(oidc, &[&"https://id.example", &"s1"])
        .await
        .expect_err("one subject from one issuer is one person");
    assert_eq!(
        violated(same_subject),
        Some("users_oidc_identity".to_string())
    );
    db.execute(oidc, &[&"https://other.example", &"s1"])
        .await
        .expect("the same subject from another issuer is another person");
}

use gapura_control::access::{Grant, Method, Role, Source};

#[tokio::test]
async fn access_rows_reads_accounts_grants_and_mappings_in_one_go() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let db = store.client().await.unwrap();
    let payments: uuid::Uuid = db
        .query_one(
            "insert into workspaces (name) values ('payments') returning id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(store.bootstrap_superuser("root", "x").await.unwrap());
    let oli = store
        .upsert_oidc_user(
            "https://id.example",
            "s-oli",
            "oli",
            &["payments-dev".to_string()],
        )
        .await
        .unwrap();
    db.execute(
        "insert into group_bindings (group_name, workspace_id, role) values ('payments-dev', $1, 'editor')",
        &[&payments],
    )
    .await
    .unwrap();
    let root_id: uuid::Uuid = db
        .query_one("select id from users where username = 'root'", &[])
        .await
        .unwrap()
        .get(0);
    db.execute(
        "insert into role_bindings (user_id, workspace_id, role) values ($1, $2, 'viewer')",
        &[&root_id, &payments],
    )
    .await
    .unwrap();

    let rows = store.access_rows().await.unwrap();
    assert_eq!(
        rows.grants,
        [Grant {
            user: root_id,
            workspace: payments,
            role: Role::Viewer,
        }],
        "a direct grant reads back with its user and workspace the right way round"
    );
    assert_eq!(rows.workspaces.len(), 2, "default and payments");
    let oli_row = rows.users.iter().find(|u| u.id == oli.id).unwrap();
    assert_eq!(oli_row.method, Method::Oidc);
    assert_eq!(oli_row.name, "oli");
    assert_eq!(
        rows.effective(oli_row, payments)
            .map(|a| (a.role, a.sources)),
        Some((
            Role::Editor,
            vec![Source::Group {
                name: "payments-dev".into(),
                role: Role::Editor
            }]
        ))
    );
    let root = rows.users.iter().find(|u| u.name == "root").unwrap();
    assert!(root.superuser && root.method == Method::Local);
}

#[tokio::test]
async fn an_oidc_account_is_one_row_per_subject_and_follows_its_latest_sign_in() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let first = store
        .upsert_oidc_user("https://id.example", "s1", "rini", &["a".to_string()])
        .await
        .unwrap();
    // Cleared, so the next sign-in has to stamp it rather than leave the first one standing.
    store
        .client()
        .await
        .unwrap()
        .execute(
            "update users set last_sign_in_at = null where id = $1",
            &[&first.id],
        )
        .await
        .unwrap();
    let again = store
        .upsert_oidc_user(
            "https://id.example",
            "s1",
            "rini.wulandari",
            &["b".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(first.id, again.id);
    let rows = store.access_rows().await.unwrap();
    assert_eq!(rows.users.len(), 1);
    assert_eq!(rows.users[0].name, "rini.wulandari");
    assert_eq!(rows.users[0].groups, ["b"]);
    assert!(rows.users[0].last_sign_in.is_some());
}

#[tokio::test]
async fn a_disabled_oidc_account_stays_disabled_and_its_refused_sign_in_is_not_recorded() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let account = store
        .upsert_oidc_user("https://id.example", "s1", "rini", &[])
        .await
        .unwrap();
    store
        .client()
        .await
        .unwrap()
        .execute(
            "update users set disabled_at = now(), last_sign_in_at = null where id = $1",
            &[&account.id],
        )
        .await
        .unwrap();
    let refused = store
        .upsert_oidc_user("https://id.example", "s1", "rini", &[])
        .await
        .unwrap();
    assert!(refused.disabled);
    let rows = store.access_rows().await.unwrap();
    assert_eq!(rows.users[0].last_sign_in, None);
}

#[tokio::test]
async fn an_oidc_account_with_no_name_is_shown_by_its_subject() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    store
        .upsert_oidc_user("https://id.example", "s-quiet", "", &[])
        .await
        .unwrap();
    let rows = store.access_rows().await.unwrap();
    assert_eq!(rows.users[0].name, "s-quiet");
}

#[tokio::test]
async fn bootstrap_creates_one_superuser_and_only_into_an_empty_table() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    // Both bootstraps are made to queue behind a lock this test holds, and released together,
    // so they really do overlap instead of depending on how fast a connection opens.
    let mut holder = store.client().await.unwrap();
    let hold = holder.transaction().await.unwrap();
    hold.batch_execute("lock table users in access exclusive mode")
        .await
        .unwrap();
    let a = tokio::spawn({
        let store = store.clone();
        async move { store.bootstrap_superuser("root", "x").await }
    });
    let b = tokio::spawn({
        let store = store.clone();
        async move { store.bootstrap_superuser("admin", "y").await }
    });
    let probe = store.client().await.unwrap();
    loop {
        let queued: i64 = probe
            .query_one(
                "select count(*) from pg_locks where relation = 'users'::regclass and not granted",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        if queued == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    hold.rollback().await.unwrap();
    let created = [a.await.unwrap().unwrap(), b.await.unwrap().unwrap()]
        .iter()
        .filter(|created| **created)
        .count();
    assert_eq!(
        created, 1,
        "two replicas starting at once create one superuser"
    );
    assert_eq!(store.user_count().await.unwrap(), 1);
    assert!(!store.bootstrap_superuser("third", "z").await.unwrap());
}

#[tokio::test]
async fn a_local_account_is_found_ignoring_case_and_its_sign_in_is_recorded() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    store.bootstrap_superuser("Root", "the-hash").await.unwrap();
    let found = store
        .local_user("rOOt")
        .await
        .unwrap()
        .expect("found ignoring case");
    assert_eq!(found.password_hash, "the-hash");
    assert!(!found.disabled);
    assert!(store.local_user("nobody").await.unwrap().is_none());
    store.record_sign_in(found.id).await.unwrap();
    let rows = store.access_rows().await.unwrap();
    assert!(rows.users[0].last_sign_in.is_some());
}

#[tokio::test]
async fn bootstrap_stores_a_hash_and_never_replaces_the_first_superuser() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let pair = |password: &str| (Some("root".to_string()), Some(password.to_string()));
    let (u, p) = pair("correct horse battery");
    gapura_control::bootstrap::apply(&store, u, p)
        .await
        .unwrap();
    let first = store.local_user("root").await.unwrap().expect("created");
    assert_ne!(first.password_hash, "correct horse battery");
    assert!(gapura_control::password::verify(
        "correct horse battery",
        &first.password_hash
    ));
    let (u, p) = pair("another long password");
    gapura_control::bootstrap::apply(&store, u, p)
        .await
        .unwrap();
    let still = store.local_user("root").await.unwrap().expect("kept");
    assert!(
        gapura_control::password::verify("correct horse battery", &still.password_hash),
        "a second start with another password changed nothing"
    );
}

#[tokio::test]
async fn once_accounts_exist_an_invalid_or_half_pair_is_ignored_rather_than_fatal() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    store.bootstrap_superuser("root", "x").await.unwrap();
    for (username, password) in [
        (Some("root"), Some("short")),
        (Some("root"), None),
        (None, Some("correct horse battery")),
    ] {
        gapura_control::bootstrap::apply(
            &store,
            username.map(String::from),
            password.map(String::from),
        )
        .await
        .expect("ignored once an account exists");
    }
}

#[tokio::test]
async fn into_an_empty_table_an_invalid_pair_stops_the_start() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let refused = gapura_control::bootstrap::apply(
        &store,
        Some("root".to_string()),
        Some("correct horse battery\n".to_string()),
    )
    .await;
    assert!(refused.is_err(), "a password the sign-in form cannot send");
    assert_eq!(store.user_count().await.unwrap(), 0);
}

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

/// The console's router over `store`, with readers pointed at nothing: these tests are about
/// accounts, and Overview answering "unreachable" is all they need from the gateway.
fn console(store: Arc<Store>, auth_mode: gapura_control::login::AuthMode) -> axum::Router {
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
        pending: Default::default(),
        session_lifetime: Duration::from_secs(3600),
        store: Some(store),
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

async fn call(app: &axum::Router, path: &str, as_: Option<Uuid>) -> (StatusCode, String) {
    let mut req = Request::builder().uri(path);
    if let Some(id) = as_ {
        req = req.header("cookie", cookie(&id.to_string()));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

const PASSWORD: &str = "correct horse battery";

/// - `root`: superuser.
/// - `pat`: admin of payments.
/// - `vic`: viewer of payments.
/// - `wes`: no grants, so waiting.
/// - `dee`: viewer of default, but disabled.
/// - `oli`: OIDC, a direct viewer of payments and in `payments-dev`, who are editors of payments.
/// - Group mappings: `payments-dev` is editor of payments, `default-readers` is viewer of default.
struct Seed {
    root: Uuid,
    pat: Uuid,
    vic: Uuid,
    wes: Uuid,
    dee: Uuid,
    oli: Uuid,
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
    let oli = store
        .upsert_oidc_user(
            "https://id.example",
            "s-oli",
            "oli",
            &["payments-dev".to_string()],
        )
        .await
        .unwrap()
        .id;
    for (user, workspace, role) in [
        (local["pat"], payments, "admin"),
        (local["vic"], payments, "viewer"),
        (local["dee"], default, "viewer"),
        (oli, payments, "viewer"),
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
        oli,
        default,
        payments,
    }
}

#[tokio::test]
async fn me_tells_each_account_what_it_holds() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(store, gapura_control::login::AuthMode::Local);

    let root = json(&call(&app, "/api/me", Some(s.root)).await.1);
    assert_eq!(root["mode"], "store");
    assert_eq!(root["superuser"], true);
    assert_eq!(root["roles"].as_array().unwrap().len(), 2);
    assert_eq!(root["grantable"].as_array().unwrap().len(), 2);

    let pat = json(&call(&app, "/api/me", Some(s.pat)).await.1);
    assert_eq!(pat["grantable"], serde_json::json!([s.payments]));
    assert_eq!(pat["roles"][0]["role"], "admin");

    let vic = json(&call(&app, "/api/me", Some(s.vic)).await.1);
    assert_eq!(vic["grantable"], serde_json::json!([]));
    assert_eq!(vic["waiting"], false);
    assert_eq!(vic["roles"][0]["role"], "viewer");

    let wes = json(&call(&app, "/api/me", Some(s.wes)).await.1);
    assert_eq!(wes["waiting"], true);
    assert_eq!(wes["roles"], serde_json::json!([]));
}

#[tokio::test]
async fn a_disabled_unknown_or_foreign_session_is_signed_out() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(store, gapura_control::login::AuthMode::Local);
    assert_eq!(
        call(&app, "/api/me", Some(s.dee)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "/api/me", Some(Uuid::new_v4())).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "/api/me", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    // A Kubernetes-mode session names an email, not an account id.
    let foreign = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("cookie", cookie("a@example.test"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_workspace_admin_sees_every_account_but_roles_only_in_their_workspace() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(store, gapura_control::login::AuthMode::Local);
    let (status, body) = call(&app, "/api/users", Some(s.pat)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(&s.default.to_string()),
        "the default workspace leaked to an admin of payments only: {body}"
    );
    let users = json(&body);
    let users = users.as_array().unwrap();
    assert_eq!(users.len(), 6, "every account is listed");
    assert_eq!(users[0]["name"], "wes", "waiting accounts come first");
    assert_eq!(users[0]["status"], "waiting");
    let by_name = |name: &str| users.iter().find(|u| u["name"] == name).unwrap().clone();
    assert_eq!(by_name("dee")["status"], "disabled");
    let root = by_name("root");
    assert_eq!(root["access"].as_array().unwrap().len(), 1);
    assert_eq!(
        root["access"][0]["sources"],
        serde_json::json!([{"kind": "superuser", "role": "admin"}])
    );
    let oli = by_name("oli");
    assert_eq!(oli["method"], "oidc");
    assert_eq!(oli["access"][0]["role"], "editor");
    assert_eq!(
        oli["access"][0]["sources"],
        serde_json::json!([
            {"kind": "direct", "role": "viewer"},
            {"kind": "group", "name": "payments-dev", "role": "editor"}
        ])
    );

    // The superuser sees the default workspace too.
    let all = json(&call(&app, "/api/users", Some(s.root)).await.1);
    let root_seen_by_root = all
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "root")
        .unwrap()
        .clone();
    assert_eq!(root_seen_by_root["access"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn roles_are_counted_and_mapped_within_the_callers_workspaces() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(store, gapura_control::login::AuthMode::Local);
    let pat = json(&call(&app, "/api/roles", Some(s.pat)).await.1);
    assert_eq!(
        pat["mappings"],
        serde_json::json!([{
            "group": "payments-dev", "workspace_id": s.payments, "workspace": "payments", "role": "editor"
        }])
    );
    assert_eq!(
        pat["held_by"],
        serde_json::json!({"viewer": 1, "editor": 1, "admin": 1, "superuser": 1})
    );
    let root = json(&call(&app, "/api/roles", Some(s.root)).await.1);
    assert_eq!(root["mappings"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn the_access_pages_are_refused_to_anyone_who_administers_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(store, gapura_control::login::AuthMode::Local);
    for who in [s.vic, s.wes, s.oli] {
        for path in ["/api/users", "/api/roles"] {
            assert_eq!(
                call(&app, path, Some(who)).await.0,
                StatusCode::FORBIDDEN,
                "{path}"
            );
        }
    }
}

#[tokio::test]
async fn the_gateway_screens_are_for_superusers_in_store_mode() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(store, gapura_control::login::AuthMode::Local);
    let (status, body) = call(&app, "/api/overview", Some(s.root)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["reachable"], false);
    for who in [s.pat, s.vic, s.wes] {
        assert_eq!(
            call(&app, "/api/overview", Some(who)).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, "/api/routes", Some(who)).await.0,
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn an_account_whose_roles_are_all_elsewhere_looks_to_an_admin_like_one_with_none() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let db = store.client().await.unwrap();
    let hash = gapura_control::password::hash(PASSWORD).unwrap();
    let zed: Uuid = db
        .query_one(
            "insert into users (username, password_hash) values ('zed', $1) returning id",
            &[&hash],
        )
        .await
        .unwrap()
        .get(0);
    // zed holds a role only in default, which pat does not administer; vic now holds a second
    // role there too, so the superuser sees one account counted under two roles.
    for user in [zed, s.vic] {
        db.execute(
            "insert into role_bindings (user_id, workspace_id, role) values ($1, $2, 'editor')",
            &[&user, &s.default],
        )
        .await
        .unwrap();
    }
    let app = console(store, gapura_control::login::AuthMode::Local);

    let seen = json(&call(&app, "/api/users", Some(s.pat)).await.1);
    let by_name = |name: &str| {
        seen.as_array()
            .unwrap()
            .iter()
            .find(|u| u["name"] == name)
            .unwrap()
            .clone()
    };
    assert_eq!(by_name("zed")["access"], serde_json::json!([]));
    assert_eq!(
        by_name("zed")["status"],
        by_name("wes")["status"],
        "a role somewhere pat cannot see must not show through the status"
    );
    let held_by_pat = json(&call(&app, "/api/roles", Some(s.pat)).await.1)["held_by"].clone();
    assert_eq!(
        held_by_pat,
        serde_json::json!({"viewer": 1, "editor": 1, "admin": 1, "superuser": 1}),
        "zed's and vic's editor roles are in default, which pat does not administer"
    );
    let held_by_root = json(&call(&app, "/api/roles", Some(s.root)).await.1)["held_by"].clone();
    assert_eq!(
        held_by_root,
        serde_json::json!({"viewer": 1, "editor": 3, "admin": 1, "superuser": 1}),
        "vic is a viewer of payments and an editor of default, and counted under both"
    );
}

#[tokio::test]
async fn an_unreadable_store_is_unavailable_to_a_session_and_unauthorized_to_anyone_else() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .client()
        .await
        .unwrap()
        .batch_execute("alter table group_bindings rename to group_bindings_gone")
        .await
        .unwrap();
    let app = console(store, gapura_control::login::AuthMode::Local);
    assert_eq!(
        call(&app, "/api/me", Some(s.root)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        call(&app, "/api/me", None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_superuser_keeps_the_access_pages_with_no_workspaces() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    store
        .client()
        .await
        .unwrap()
        .batch_execute("delete from workspaces")
        .await
        .unwrap();
    let app = console(store, gapura_control::login::AuthMode::Local);
    for path in ["/api/users", "/api/roles"] {
        assert_eq!(
            call(&app, path, Some(s.root)).await.0,
            StatusCode::OK,
            "{path}"
        );
    }
}

fn form_value(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker).expect("field present") + marker.len();
    let end = start + html[start..].find('"').expect("closing quote");
    html[start..end].to_string()
}

/// Opens the sign-in form, posts `username` and `password` with the state it carried, and
/// returns the answer's status, `Set-Cookie` and body.
async fn sign_in(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> (StatusCode, Option<String>, String) {
    let (_, page) = call(app, "/auth/login", None).await;
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
    let status = res.status();
    let cookie = res
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, cookie, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn a_local_account_signs_in_by_username_in_any_case() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    seed(&store).await;
    let app = console(store.clone(), gapura_control::login::AuthMode::Local);
    let (_, page) = call(&app, "/auth/login", None).await;
    assert!(
        page.contains(r#"name="username""#),
        "store mode asks for a username"
    );
    assert!(
        !page.contains("Sign in with SSO"),
        "local mode offers no provider"
    );

    let (status, cookie, _) = sign_in(&app, "PAT", PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let me = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("cookie", cookie.expect("a session cookie"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(me.into_body(), 1 << 16).await.unwrap();
    assert_eq!(json(std::str::from_utf8(&body).unwrap())["name"], "pat");
    let rows = store.access_rows().await.unwrap();
    assert!(rows
        .users
        .iter()
        .find(|u| u.name == "pat")
        .unwrap()
        .last_sign_in
        .is_some());
}

#[tokio::test]
async fn a_wrong_password_an_unknown_name_and_a_disabled_account_get_the_same_answer() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    seed(&store).await;
    let app = console(store, gapura_control::login::AuthMode::Local);
    let wrong = sign_in(&app, "pat", "not the password").await;
    let unknown = sign_in(&app, "nobody", PASSWORD).await;
    let disabled = sign_in(&app, "dee", PASSWORD).await;
    // A NUL is refused by Postgres itself; it must still read as an unknown name, not an outage.
    let impossible = sign_in(&app, "pat%00x", PASSWORD).await;
    for (what, answer) in [
        ("wrong", &wrong),
        ("unknown", &unknown),
        ("disabled", &disabled),
        ("impossible", &impossible),
    ] {
        assert_eq!(answer.0, StatusCode::UNAUTHORIZED, "{what}");
        assert!(answer.1.is_none(), "{what} was given a cookie");
    }
    assert_eq!(wrong.2, unknown.2);
    assert_eq!(wrong.2, impossible.2);
    assert_eq!(wrong.2, disabled.2);
}

#[tokio::test]
async fn with_an_identity_provider_the_form_offers_it_and_stays_for_break_glass() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(store, gapura_control::login::AuthMode::Oidc);
    let (status, page) = call(&app, "/auth/login?return_to=%2Fusers", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(r#"href="/auth/login?sso=1&amp;return_to=/users""#),
        "{page}"
    );
    assert!(page.contains(r#"name="username""#));
}
