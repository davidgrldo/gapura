//! The audit log through `/api/audit`, against Postgres: that it reads newest first a page at a
//! time with no entry missed or repeated between pages, that a reader sees the entries of the
//! workspaces they hold a role in and a superuser every entry, those with no workspace among them,
//! that each filter narrows what the reader may see and never widens it, and that a request it
//! cannot read is refused beside the field at fault.
//!
//! The entries are real ones, written by the store's own writes as different accounts, so what
//! is read is what the writes record.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `workspaces.rs`, and for the same reason: the alternative mocks the database and proves the
//! mock. CI sets it. Run them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test audit
//! ```
//!
//! The helpers are copies of `workspaces.rs`'s rather than a shared `tests/common` module, so
//! that each file reads on its own; the accounts each file seeds are its own.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::configuration::{Protocol, Service};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
use gapura_core::store::StoreSettings;
use serde_json::Value;
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
        sign_up: Default::default(),
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

/// `GET path`, as the console sends it, signed in as `as_` when one is given; the status and the
/// body as text.
async fn get(app: &axum::Router, path: &str, as_: Option<Uuid>) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method("GET")
        .uri(path)
        .header("sec-fetch-site", "same-origin");
    if let Some(id) = as_ {
        req = req.header("cookie", cookie(&id.to_string()));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 22)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn json(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

/// One page as `as_`, which must be answered.
async fn page(app: &axum::Router, as_: Uuid, query: &str) -> Value {
    let (status, body) = get(app, &format!("/api/audit{query}"), Some(as_)).await;
    assert_eq!(status, StatusCode::OK, "{query}: {body}");
    json(&body)
}

fn entries(page: &Value) -> &Vec<Value> {
    page["entries"].as_array().unwrap()
}

fn ids(page: &Value) -> Vec<i64> {
    entries(page)
        .iter()
        .map(|e| e["id"].as_i64().unwrap())
        .collect()
}

/// Every entry `as_` may read under `filter` (`&workspace=…`, or empty), by following `next`
/// from the newest, `limit` at a time. Each page but the last is full, and each `next` is the
/// last id of its page.
async fn walk(app: &axum::Router, as_: Uuid, limit: i64, filter: &str) -> Vec<Value> {
    let mut all = Vec::new();
    let mut before: Option<i64> = None;
    loop {
        let query = match before {
            Some(id) => format!("?limit={limit}&before={id}{filter}"),
            None => format!("?limit={limit}{filter}"),
        };
        let p = page(app, as_, &query).await;
        let got = entries(&p).clone();
        match p["next"].as_i64() {
            Some(next) => {
                assert_eq!(got.len() as i64, limit, "a page before the last is full");
                assert_eq!(Some(next), got.last().and_then(|e| e["id"].as_i64()));
                before = Some(next);
                all.extend(got);
            }
            None => {
                assert!(p["next"].is_null(), "{p}");
                assert!(got.len() as i64 <= limit);
                all.extend(got);
                return all;
            }
        }
    }
}

/// The sentence and field a refusal carries.
fn refusal(body: &str) -> (String, Option<String>) {
    let v = json(body);
    (
        v["error"].as_str().unwrap().to_string(),
        v["field"].as_str().map(str::to_string),
    )
}

async fn db_ids(store: &Store, filter: &str) -> Vec<i64> {
    store
        .client()
        .await
        .unwrap()
        .query(
            &format!("select id from audit_log a where {filter} order by id desc"),
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
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

fn service(name: &str) -> Service {
    Service {
        name: name.into(),
        protocol: Protocol::Http,
        host: format!("{name}.internal"),
        port: 8080,
        connect_timeout_ms: None,
        read_timeout_ms: None,
    }
}

/// How many consumers `ada` creates in `default`, so the log runs to more than one default page.
const MANY: usize = 55;

/// - `root`: superuser. `ada`: admin of default. `vi`: viewer of default and of `gone`.
/// - `pat`: admin of payments. `oli`: an editor of default who signs in through the identity
///   provider. `nobody`: no role anywhere.
///
/// And the entries they write:
/// - root: the workspaces `payments` and `gone`, an account, a data plane (no workspace);
///   a consumer in `gone`, deleted, then `gone` itself, so its two entries lose their workspace;
/// - ada: a service and `MANY` consumers in default;
/// - pat: a service and a consumer in payments;
/// - oli: a consumer in default.
struct Seed {
    root: Uuid,
    vi: Uuid,
    pat: Uuid,
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
        ("pat", false),
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
    let oli: Uuid = db
        .query_one(
            "insert into users (oidc_issuer, oidc_subject, display_name)
             values ('https://id.example', 's-oli', 'oli') returning id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let root = ids["root"];
    grant(store, ids["ada"], default, "admin").await;
    grant(store, ids["vi"], default, "viewer").await;
    grant(store, oli, default, "editor").await;

    store.create_workspace(root, "payments").await.unwrap();
    store.create_workspace(root, "gone").await.unwrap();
    let payments = id_of(store, "payments").await;
    let gone = id_of(store, "gone").await;
    grant(store, ids["pat"], payments, "admin").await;
    grant(store, ids["vi"], gone, "viewer").await;
    store.create_account(root, "acct", false).await.unwrap();
    store.register_data_plane(root, "edge").await.unwrap();

    store
        .create_service(ids["ada"], default, &service("orders"))
        .await
        .unwrap();
    store
        .create_service(ids["pat"], payments, &service("billing"))
        .await
        .unwrap();
    store
        .create_consumer(ids["pat"], payments, "payer")
        .await
        .unwrap();
    store
        .create_consumer(oli, default, "oli-app")
        .await
        .unwrap();
    for n in 0..MANY {
        store
            .create_consumer(ids["ada"], default, &format!("app-{n}"))
            .await
            .unwrap();
    }

    store.create_consumer(root, gone, "doomed").await.unwrap();
    store.delete_consumer(root, gone, "doomed").await.unwrap();
    store.delete_workspace(root, "gone").await.unwrap();

    Seed {
        root,
        vi: ids["vi"],
        pat: ids["pat"],
        nobody: ids["nobody"],
    }
}

#[tokio::test]
async fn pages_run_newest_first_with_nothing_missed_or_repeated() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));

    let every = db_ids(&store, "true").await;
    assert!(every.len() > 60, "{}", every.len());
    for limit in [1, 7, 50, 200] {
        let walked: Vec<i64> = walk(&app, s.root, limit, "")
            .await
            .iter()
            .map(|e| e["id"].as_i64().unwrap())
            .collect();
        assert_eq!(walked, every, "limit {limit}");
    }
    // A viewer's pages are of their own entries, and as whole.
    let theirs: Vec<i64> = walk(&app, s.vi, 7, "")
        .await
        .iter()
        .map(|e| e["id"].as_i64().unwrap())
        .collect();
    assert_eq!(
        theirs,
        db_ids(
            &store,
            "workspace_id = (select id from workspaces where name = 'default')"
        )
        .await
    );

    // Nothing asked is the newest fifty.
    let first = page(&app, s.root, "").await;
    assert_eq!(ids(&first), every[..50].to_vec());
    assert_eq!(first["next"], every[49]);
    // An entry written while someone reads older pages does not shift them.
    let second = page(&app, s.root, &format!("?before={}", every[49])).await;
    store
        .create_workspace(s.root, "later")
        .await
        .expect("a write between pages");
    let again = page(&app, s.root, &format!("?before={}", every[49])).await;
    assert_eq!(second, again);
    let newest = page(&app, s.root, "?limit=1").await;
    assert!(ids(&newest)[0] > every[0]);
    assert_eq!(newest["next"], ids(&newest)[0]);
}

#[tokio::test]
async fn an_entry_reads_as_it_was_recorded() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));

    let all = walk(&app, s.root, 200, "").await;
    let by_oli = all
        .iter()
        .find(|e| e["actor"] == "oli")
        .expect("oli's consumer");
    let at = by_oli["at"].as_str().unwrap().to_string();
    let id = by_oli["id"].clone();
    assert_eq!(
        *by_oli,
        serde_json::json!({
            "id": id,
            "at": at,
            "actor": "oli",
            "actor_method": "oidc",
            "action": "create",
            "object_kind": "consumer",
            "workspace": "default",
            "before": null,
            "after": by_oli["after"].clone(),
        }),
        "no object_id, and nothing else"
    );
    assert_eq!(by_oli["after"]["name"], "oli-app");
    // UTC to the microsecond, as `updated_at` is elsewhere: 2026-10-10T12:34:56.123456Z.
    assert_eq!(at.len(), 27, "{at}");
    assert!(at.ends_with('Z') && at.as_bytes()[10] == b'T', "{at}");
    let recorded: String = store
        .client()
        .await
        .unwrap()
        .query_one(
            r#"select to_char(at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
                 from audit_log where id = $1"#,
            &[&id.as_i64().unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(at, recorded);

    let by_pat = all.iter().find(|e| e["actor"] == "pat").unwrap();
    assert_eq!(by_pat["actor_method"], "local");
    assert_eq!(by_pat["workspace"], "payments");
}

#[tokio::test]
async fn a_viewer_sees_their_workspaces_entries_and_nothing_else() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));

    let seen = walk(&app, s.vi, 200, "").await;
    assert_eq!(
        seen.len(),
        1 + 1 + MANY,
        "orders, oli-app and ada's consumers"
    );
    for e in &seen {
        assert_eq!(e["workspace"], "default", "{e}");
    }
    // `gone` was theirs, but its workspace is deleted: its entries now have none, and are a
    // superuser's alone.
    assert!(!seen.iter().any(|e| e["after"]["name"] == "doomed"));

    let pats = walk(&app, s.pat, 200, "").await;
    let kinds: BTreeSet<&str> = pats
        .iter()
        .map(|e| e["object_kind"].as_str().unwrap())
        .collect();
    assert_eq!(pats.len(), 2);
    assert_eq!(kinds, BTreeSet::from(["service", "consumer"]));
    assert!(pats.iter().all(|e| e["workspace"] == "payments"));
}

#[tokio::test]
async fn a_superuser_sees_every_entry_those_with_no_workspace_among_them() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));

    let seen = walk(&app, s.root, 200, "").await;
    assert_eq!(seen.len(), db_ids(&store, "true").await.len());
    let without: Vec<&Value> = seen.iter().filter(|e| e["workspace"].is_null()).collect();
    let kinds: BTreeSet<&str> = without
        .iter()
        .map(|e| e["object_kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        BTreeSet::from(["workspace", "user", "data_plane", "consumer"]),
        "the workspaces, the account, the data plane, and the consumer of the deleted workspace"
    );
    let doomed: Vec<&str> = without
        .iter()
        .filter(|e| e["object_kind"] == "consumer")
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(doomed, ["delete", "create"]);
}

#[tokio::test]
async fn the_workspace_filter_narrows_and_never_widens() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));

    let payments = walk(&app, s.root, 200, "&workspace=payments").await;
    assert_eq!(payments.len(), 2);
    assert!(payments.iter().all(|e| e["workspace"] == "payments"));
    let none = walk(&app, s.root, 7, "&workspace=-").await;
    assert_eq!(
        none.iter()
            .map(|e| e["id"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        db_ids(&store, "workspace_id is null").await
    );
    let all_default = walk(&app, s.root, 200, "").await;
    let in_default = walk(&app, s.root, 200, "&workspace=default").await;
    assert_eq!(
        in_default,
        all_default
            .into_iter()
            .filter(|e| e["workspace"] == "default")
            .collect::<Vec<_>>()
    );

    // A workspace that does not exist, one the caller holds no role in, a name that can be no
    // workspace's, and, to anyone but a superuser, the entries with none: all an empty page,
    // so the filter tells nothing about which names exist.
    for (who, filter) in [
        (s.root, "nosuch"),
        (s.root, "gone"),
        (s.root, "a%00b"),
        (s.vi, "payments"),
        (s.vi, "nosuch"),
        (s.vi, "gone"),
        (s.vi, "-"),
        (s.pat, "default"),
        (s.pat, "-"),
    ] {
        let p = page(&app, who, &format!("?workspace={filter}")).await;
        assert_eq!(
            p,
            serde_json::json!({"entries": [], "next": null}),
            "{filter}"
        );
    }
    // An empty filter is every workspace the caller may see.
    let p = page(&app, s.vi, "?workspace=&kind=").await;
    assert_eq!(entries(&p).len(), 50);
}

#[tokio::test]
async fn the_kind_filter_takes_only_the_kinds_the_log_uses() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));

    let services = walk(&app, s.root, 200, "&kind=service").await;
    assert_eq!(services.len(), 2);
    assert!(services.iter().all(|e| e["object_kind"] == "service"));
    let consumers = walk(&app, s.vi, 10, "&kind=consumer&workspace=default").await;
    assert_eq!(consumers.len(), 1 + MANY);
    let p = page(&app, s.vi, "?kind=workspace").await;
    assert!(entries(&p).is_empty(), "a viewer sees no workspace entries");
    let p = page(&app, s.root, "?kind=data_plane").await;
    assert_eq!(entries(&p).len(), 1);

    let (status, body) = get(&app, "/api/audit?kind=nope", Some(s.root)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (sentence, field) = refusal(&body);
    assert_eq!(field.as_deref(), Some("kind"));
    assert!(sentence.contains("data_plane_token"), "{sentence}");
}

#[tokio::test]
async fn a_query_it_cannot_read_is_refused_beside_its_field() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));

    for (query, at) in [
        ("limit=0", "limit"),
        ("limit=201", "limit"),
        ("limit=-5", "limit"),
        ("limit=many", "limit"),
        ("before=0", "before"),
        ("before=x", "before"),
        ("kind=Service", "kind"),
    ] {
        let (status, body) = get(&app, &format!("/api/audit?{query}"), Some(s.root)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert_eq!(refusal(&body).1.as_deref(), Some(at), "{query}");
    }
    let (status, body) = get(&app, "/api/audit?limit=1&limit=2", Some(s.root)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(json(&body)["error"].is_string(), "JSON, not axum's text");

    let p = page(&app, s.root, "?limit=1").await;
    assert_eq!(entries(&p).len(), 1);
    let p = page(&app, s.root, "?limit=200").await;
    assert_eq!(
        entries(&p).len(),
        db_ids(&store, "true").await.len().min(200)
    );
    // Unknown keys are ignored, as the console may grow a filter before the server does.
    let p = page(&app, s.root, "?limit=3&color=blue").await;
    assert_eq!(entries(&p).len(), 3);
}

#[tokio::test]
async fn no_role_anywhere_reads_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let s = seed(&store).await;
    let app = console(Some(store.clone()));

    let (status, body) = get(&app, "/api/audit", Some(s.nobody)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(refusal(&body).1.is_none());
    // Refused before the query is looked at, so a bad one tells them nothing either.
    let (status, _) = get(&app, "/api/audit?kind=nope", Some(s.nobody)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = get(&app, "/api/audit", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = get(&app, "/api/audit", Some(Uuid::new_v4())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn kubernetes_mode_keeps_no_audit_log() {
    let app = console(None);
    let (status, body) = get(&app, "/api/audit", Some(Uuid::new_v4())).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        refusal(&body).0,
        "This console keeps no audit log: it runs without a database."
    );
}
