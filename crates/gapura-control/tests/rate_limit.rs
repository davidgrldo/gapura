//! Request limits through `/api/workspaces/{ws}/rate-limit`, against Postgres: that a limit
//! reaches the compiled configuration as the rule's `rate_limit`, which limit applies where
//! several do, what the lists show, who may do what, what the audit records, that every refusal
//! writes nothing, and that a stored row in a shape the API never writes fails the snapshot.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `consumers.rs`, whose helpers these are copies of so that each file reads on its own. Run
//! them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test rate_limit
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
use gapura_core::config::{Config, LimitBy, Plugin, RateLimit};
use gapura_core::store::StoreSettings;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

/// One database, so the tests take turns, as in `consumers.rs`.
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
                expires_at: u64::MAX,
                issued_at: 0,
            },
            KEY
        )
    )
}

/// Sends `method path` with `body`, as the console does, signed in as `as_` when one is given.
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

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

const SERVICE: &str = r#"{"name":"orders","protocol":"http","host":"orders.internal","port":8080}"#;
const ROUTE: &str = r#"{"name":"orders-api","service":"orders","hosts":["api.example.com"],"paths":[{"type":"prefix","value":"/orders"}]}"#;
const SERVICES: &str = "/api/workspaces/default/services";
const ROUTES: &str = "/api/workspaces/default/routes";
const CONSUMERS: &str = "/api/workspaces/default/consumers";
const LIMITS: &str = "/api/workspaces/default/rate-limit";
/// The compiled name of the seeded route.
const COMPILED_ROUTE: &str = "default/orders-api";

/// - `root`: superuser, the only one who reaches the second workspace, `payments`.
/// - `ada`: admin of default. `ed`: editor of default. `vi`: viewer of default.
///
/// And in default, a service `orders` and a route `orders-api` for `api.example.com`.
struct Seed {
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
    let (status, answer) = send(app, method, path, Some(as_), body).await;
    assert_eq!(
        (status, answer.as_str()),
        (StatusCode::NO_CONTENT, ""),
        "{method} {path} {body}"
    );
}

/// The sentence a refusal carries.
fn sentence(body: &str) -> String {
    parse(body)["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no sentence: {body}"))
        .to_string()
}

/// A GET that must succeed, as JSON.
async fn read(app: &axum::Router, path: &str, as_: Uuid) -> serde_json::Value {
    let (status, body) = send(app, "GET", path, Some(as_), "").await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    parse(&body)
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

/// Every row a policy write could change, the number of audit entries, and the version the data
/// planes poll. Equal before and after a refusal means the refusal wrote nothing.
async fn everything(store: &Store) -> serde_json::Value {
    store
        .client()
        .await
        .unwrap()
        .query_one(
            "select jsonb_build_object(
                 'services', (select coalesce(jsonb_agg(to_jsonb(s) order by s.id), '[]') from services s),
                 'routes', (select coalesce(jsonb_agg(to_jsonb(r) order by r.id), '[]') from routes r),
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

/// The request limit the compiled `route` carries, if any.
fn limit_on(config: &Config, route: &str) -> Option<RateLimit> {
    let rule = config
        .listeners
        .iter()
        .flat_map(|l| &l.rules)
        .find(|r| r.route == route)
        .unwrap_or_else(|| panic!("{route} is not compiled"));
    rule.rate_limit.clone()
}

/// The policy writes in the audit log, oldest first: action, before, after.
async fn policy_audits(store: &Store) -> Vec<(String, serde_json::Value, serde_json::Value)> {
    store
        .client()
        .await
        .unwrap()
        .query(
            "select action, coalesce(before, 'null'), coalesce(after, 'null') from audit_log
              where object_kind = 'policy' order by id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}

/// A PUT body for `target`.
fn put(target: &str, limit: u32, per: &str) -> String {
    json!({"target": target, "limit": limit, "per": per}).to_string()
}

/// The `updated_at` the list shows for `target`'s own limit on everyone, if it has one. A
/// consumer's own limit on the same target is another row with a stamp of its own, which this
/// never picks.
async fn stamp(app: &axum::Router, target: &str, as_: Uuid) -> Option<String> {
    stamp_for(app, target, None, as_).await
}

/// The `updated_at` the list shows for the limit on `target` that is `consumer`'s own, or, for
/// `None`, the one on everyone there, if there is one.
async fn stamp_for(
    app: &axum::Router,
    target: &str,
    consumer: Option<&str>,
    as_: Uuid,
) -> Option<String> {
    read(app, LIMITS, as_)
        .await
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["target"] == target && row["consumer"].as_str() == consumer)
        .map(|row| row["updated_at"].as_str().expect("a stamp").to_string())
}

/// `body`, a PUT, sending `seen` as the stamp it read, when there is one.
fn seen(body: &str, seen: Option<&str>) -> String {
    let mut body = parse(body);
    if let Some(seen) = seen {
        body["seen_updated_at"] = json!(seen);
    }
    body.to_string()
}

/// A PUT the console makes: from a fresh read of the list, so with the stamp of the limit it
/// replaces when there is one (#223) -- the consumer's own when the body names a consumer, else
/// the one on everyone. It must succeed.
async fn apply(app: &axum::Router, as_: Uuid, body: &str) {
    let sent = parse(body);
    let target = sent["target"].as_str().unwrap();
    let read_at = stamp_for(app, target, sent["consumer"].as_str(), as_).await;
    ok(app, "PUT", LIMITS, as_, &seen(body, read_at.as_deref())).await;
}

/// `value` with the `updated_at` of each row, or of the one object, taken out once it is checked
/// to be a stamp in the API's format: what the rows say, compared without when it was said.
fn unstamped(mut value: serde_json::Value) -> serde_json::Value {
    fn take(row: &mut serde_json::Value) {
        let shown = row.to_string();
        let stamp = row.as_object_mut().and_then(|o| o.remove("updated_at"));
        let stamp = stamp
            .as_ref()
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| panic!("no updated_at in {shown}"));
        assert!(stamp.len() == 27 && stamp.ends_with('Z'), "{stamp}");
    }
    match &mut value {
        serde_json::Value::Array(rows) => rows.iter_mut().for_each(take),
        one => take(one),
    }
    value
}

fn per_minute(limit: u32) -> Option<RateLimit> {
    Some(RateLimit {
        limit,
        window_ms: 60_000,
        by: LimitBy::Ip,
    })
}

/// The point of the feature: a limit written through the API reaches the rule the data planes
/// are served, with the window its `per` names, and not the plugin list.
#[tokio::test]
async fn the_compiled_rule_carries_the_limit() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    assert_eq!(limit_on(&compiled(&store).await, COMPILED_ROUTE), None);

    for (per, window_ms) in [("second", 1_000), ("minute", 60_000), ("hour", 3_600_000)] {
        apply(&app, s.ed, &put("route:orders-api", 20, per)).await;
        let config = compiled(&store).await;
        assert_eq!(
            limit_on(&config, COMPILED_ROUTE),
            Some(RateLimit {
                limit: 20,
                window_ms,
                by: LimitBy::Ip,
            }),
            "{per}"
        );
        let rule = &config.listeners[0].rules[0];
        assert!(rule.plugins.is_empty(), "a limit is not a plugin");
    }
    // At the bound, not past it.
    apply(&app, s.ed, &put("route:orders-api", 1_000_000, "hour")).await;
    assert_eq!(
        limit_on(&compiled(&store).await, COMPILED_ROUTE),
        Some(RateLimit {
            limit: 1_000_000,
            window_ms: 3_600_000,
            by: LimitBy::Ip,
        })
    );
}

/// PUT on each kind of target; the list shows each with its limit and window.
#[tokio::test]
async fn each_target_kind_is_listed() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    assert_eq!(read(&app, LIMITS, s.vi).await, json!([]));
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("route:orders-api", 3, "second"),
    )
    .await;
    ok(&app, "PUT", LIMITS, s.ed, &put("workspace", 1000, "hour")).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("service:orders", 120, "minute"),
    )
    .await;
    assert_eq!(
        unstamped(read(&app, LIMITS, s.vi).await),
        json!([
            {"target": "workspace", "limit": 1000, "per": "hour"},
            {"target": "service:orders", "limit": 120, "per": "minute"},
            {"target": "route:orders-api", "limit": 3, "per": "second"},
        ])
    );
    // What is stored is the data plane's shape, one row per target.
    let stored: Vec<serde_json::Value> = store
        .client()
        .await
        .unwrap()
        .query(
            "select config from plugins where name = 'rate_limit' order by config->>'limit'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        stored,
        vec![
            json!({"limit": 1000, "window_ms": 3_600_000}),
            json!({"limit": 120, "window_ms": 60_000}),
            json!({"limit": 3, "window_ms": 1_000}),
        ]
    );
}

/// Route over service over workspace in the compiled rule and in both lists, and beside a key
/// requirement, which is another kind and applies as well.
#[tokio::test]
async fn the_most_specific_limit_applies() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    for (target, limit) in [
        ("workspace", 10),
        ("service:orders", 20),
        ("route:orders-api", 30),
    ] {
        ok(&app, "PUT", LIMITS, s.ed, &put(target, limit, "minute")).await;
    }
    ok(
        &app,
        "PUT",
        "/api/workspaces/default/key-auth",
        s.ed,
        r#"{"target":"workspace"}"#,
    )
    .await;

    for (limit, from, then_delete) in [
        (30, "route", Some("route:orders-api")),
        (20, "service", Some("service:orders")),
        (10, "workspace", None),
    ] {
        let config = compiled(&store).await;
        assert_eq!(
            limit_on(&config, COMPILED_ROUTE),
            per_minute(limit),
            "{from}"
        );
        assert!(
            matches!(
                config.listeners[0].rules[0].plugins.as_slice(),
                [Plugin::KeyAuth(_)]
            ),
            "the key requirement still applies"
        );
        let route = row(&app, ROUTES, "orders-api", s.vi).await;
        // The stamp is that of the limit that applies, wherever it is set.
        let set_on = match from {
            "route" => "route:orders-api",
            "service" => "service:orders",
            _ => "workspace",
        };
        assert_eq!(
            route["rate_limit"]["updated_at"].as_str(),
            stamp(&app, set_on, s.vi).await.as_deref()
        );
        assert_eq!(
            unstamped(route["rate_limit"].clone()),
            json!({"limit": limit, "per": "minute", "from": from})
        );
        assert_eq!(
            unstamped(route["key_auth"].clone()),
            json!({"header": "x-api-key", "from": "workspace"})
        );
        if let Some(target) = then_delete {
            ok(
                &app,
                "DELETE",
                &format!("{LIMITS}?target={target}"),
                s.ed,
                "",
            )
            .await;
        }
    }
    // The service shows its own limit or the workspace's, never a route's.
    let service_limit =
        || async { unstamped(row(&app, SERVICES, "orders", s.vi).await["rate_limit"].clone()) };
    assert_eq!(
        service_limit().await,
        json!({"limit": 10, "per": "minute", "from": "workspace"})
    );
    apply(&app, s.ed, &put("route:orders-api", 5, "second")).await;
    assert_eq!(
        service_limit().await,
        json!({"limit": 10, "per": "minute", "from": "workspace"})
    );
    apply(&app, s.ed, &put("service:orders", 7, "hour")).await;
    assert_eq!(
        service_limit().await,
        json!({"limit": 7, "per": "hour", "from": "service"})
    );

    for target in ["route:orders-api", "service:orders", "workspace"] {
        ok(
            &app,
            "DELETE",
            &format!("{LIMITS}?target={target}"),
            s.ed,
            "",
        )
        .await;
    }
    assert_eq!(limit_on(&compiled(&store).await, COMPILED_ROUTE), None);
    for (list, name) in [(ROUTES, "orders-api"), (SERVICES, "orders")] {
        assert_eq!(
            row(&app, list, name, s.vi).await["rate_limit"],
            serde_json::Value::Null,
            "{list}"
        );
    }
}

/// Create, the same limit again (nothing written), a change, and removal: each write is one
/// policy entry recording the target, the kind, the limit and its window.
#[tokio::test]
async fn the_audit_records_each_change_and_a_save_of_nothing_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let first = put("service:orders", 100, "minute");
    ok(&app, "PUT", LIMITS, s.ed, &first).await;

    let before = everything(&store).await;
    apply(&app, s.ada, &first).await;
    assert_eq!(everything(&store).await, before, "a save of nothing");

    apply(&app, s.ed, &put("service:orders", 100, "second")).await;
    ok(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=service:orders"),
        s.ed,
        "",
    )
    .await;

    let minute =
        json!({"target": "service:orders", "kind": "rate_limit", "limit": 100, "per": "minute"});
    let second =
        json!({"target": "service:orders", "kind": "rate_limit", "limit": 100, "per": "second"});
    let null = serde_json::Value::Null;
    assert_eq!(
        policy_audits(&store).await,
        vec![
            ("create".to_string(), null.clone(), minute.clone()),
            ("update".to_string(), minute, second.clone()),
            ("delete".to_string(), second, null),
        ]
    );

    // Deleting what is no longer there is 404, and writes nothing.
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=service:orders"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(sentence(&body), "service:orders has no request limit.");
    assert_eq!(everything(&store).await, before);
}

/// #223: a PUT replaces a limit only with the stamp the list showed for it. Without one (the
/// caller saw none), with an older one, or with one for a limit removed since: 409, and nothing
/// is written.
#[tokio::test]
async fn a_limit_is_replaced_only_from_a_fresh_read() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let target = "route:orders-api";
    let old = "2026-01-01T00:00:00.000000Z";
    let stale = |body: String| {
        let app = &app;
        async move {
            let (status, answer) = send(app, "PUT", LIMITS, Some(s.ed), &body).await;
            assert_eq!(status, StatusCode::CONFLICT, "{body}: {answer}");
            assert_eq!(
                sentence(&answer),
                "Someone else changed this policy. Reload it and apply your change again."
            );
        }
    };

    let before = everything(&store).await;
    stale(seen(&put(target, 10, "minute"), Some(old))).await;
    assert_eq!(
        everything(&store).await,
        before,
        "none set: a stamp is stale"
    );
    ok(&app, "PUT", LIMITS, s.ed, &put(target, 10, "minute")).await;
    let first = stamp(&app, target, s.vi).await;
    assert_eq!(
        row(&app, ROUTES, "orders-api", s.vi).await["rate_limit"]["updated_at"].as_str(),
        first.as_deref()
    );

    let before = everything(&store).await;
    stale(put(target, 20, "minute")).await;
    stale(seen(&put(target, 20, "minute"), Some(old))).await;
    assert_eq!(everything(&store).await, before);
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ada,
        &seen(&put(target, 20, "minute"), first.as_deref()),
    )
    .await;
    // A sheet opened before that change cannot undo it.
    stale(seen(&put(target, 10, "second"), first.as_deref())).await;
    assert_eq!(
        limit_on(&compiled(&store).await, COMPILED_ROUTE),
        per_minute(20)
    );

    let last = stamp(&app, target, s.vi).await;
    ok(
        &app,
        "DELETE",
        &format!("{LIMITS}?target={target}"),
        s.ada,
        "",
    )
    .await;
    let before = everything(&store).await;
    stale(seen(&put(target, 10, "minute"), last.as_deref())).await;
    assert_eq!(everything(&store).await, before, "removed since: stale");
}

#[tokio::test]
async fn bad_input_is_named_and_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let before = everything(&store).await;

    for (body, field) in [
        (put("consumer:x", 10, "minute"), "target"),
        (put("route:", 10, "minute"), "target"),
        (put("workspace", 0, "minute"), "limit"),
        (put("workspace", 1_000_001, "minute"), "limit"),
        (
            json!({"target": "workspace", "limit": -5, "per": "minute"}).to_string(),
            "limit",
        ),
        (
            json!({"target": "workspace", "limit": 1.5, "per": "minute"}).to_string(),
            "limit",
        ),
        (
            json!({"target": "workspace", "limit": "10", "per": "minute"}).to_string(),
            "limit",
        ),
        (
            json!({"target": "workspace", "per": "minute"}).to_string(),
            "limit",
        ),
        (put("workspace", 10, "min"), "per"),
        (put("workspace", 10, "day"), "per"),
        (
            json!({"target": "workspace", "limit": 10}).to_string(),
            "per",
        ),
    ] {
        let (status, answer) = send(&app, "PUT", LIMITS, Some(s.ed), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert_eq!(parse(&answer)["field"], field, "{body}: {answer}");
        assert!(!sentence(&answer).is_empty());
    }
    // A field this console does not know is not quietly dropped.
    let (status, answer) = send(
        &app,
        "PUT",
        LIMITS,
        Some(s.ed),
        &json!({"target": "workspace", "limit": 10, "per": "minute", "tier": "gold"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    let (status, answer) = send(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=consumer:x"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(parse(&answer)["field"], "target");
    let (status, answer) = send(&app, "DELETE", LIMITS, Some(s.ed), "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no target: {answer}");
    assert_eq!(parse(&answer)["field"], "target");

    for (method, path, body, said) in [
        (
            "PUT",
            LIMITS.to_string(),
            put("route:missing", 10, "minute"),
            "There is no route named missing in this workspace.",
        ),
        (
            "PUT",
            LIMITS.to_string(),
            put("service:missing", 10, "minute"),
            "There is no service named missing in this workspace.",
        ),
        (
            "DELETE",
            format!("{LIMITS}?target=route:orders-api"),
            String::new(),
            "route:orders-api has no request limit.",
        ),
        (
            "DELETE",
            format!("{LIMITS}?target=workspace"),
            String::new(),
            "workspace has no request limit.",
        ),
    ] {
        let (status, answer) = send(&app, method, &path, Some(s.ed), &body).await;
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
async fn a_viewer_reads_an_editor_writes_and_no_role_is_refused() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "PUT", LIMITS, s.ed, &put("workspace", 60, "minute")).await;
    let off = format!("{LIMITS}?target=workspace");

    assert_eq!(read(&app, LIMITS, s.vi).await[0]["target"], "workspace");
    let before = everything(&store).await;
    for (method, path, body) in [
        ("PUT", LIMITS, put("route:orders-api", 1, "second")),
        ("DELETE", off.as_str(), String::new()),
    ] {
        let (status, answer) = send(&app, method, path, Some(s.vi), &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
        assert_eq!(
            sentence(&answer),
            "Making changes in this workspace needs the editor role."
        );
    }
    assert_eq!(everything(&store).await, before, "a viewer wrote nothing");

    // Someone whose roles are all in default is refused the same way in a workspace that exists
    // and one that does not.
    for who in [s.ed, s.ada] {
        for (method, tail, body) in [
            ("GET", "/rate-limit", String::new()),
            ("PUT", "/rate-limit", put("workspace", 60, "minute")),
            ("DELETE", "/rate-limit?target=workspace", String::new()),
        ] {
            let mut answers = vec![];
            for ws in ["payments", "nowhere"] {
                let path = format!("/api/workspaces/{ws}{tail}");
                let (status, answer) = send(&app, method, &path, Some(who), &body).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
                answers.push(answer);
            }
            assert_eq!(answers[0], answers[1], "{method} {tail}");
        }
    }
    // And no one signed in at all.
    let (status, _) = send(&app, "GET", LIMITS, None, "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );

    // A service or route with a limit of its own is not deleted from under it.
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("route:orders-api", 1, "second"),
    )
    .await;
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("{ROUTES}/orders-api"),
        Some(s.ada),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        sentence(&body),
        "1 policy is attached to this route. Remove it first."
    );

    // An editor switches it off, as they switched it on.
    ok(&app, "DELETE", &off, s.ed, "").await;
    ok(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=route:orders-api"),
        s.ed,
        "",
    )
    .await;
    assert_eq!(read(&app, LIMITS, s.vi).await, json!([]));
}

/// A `rate_limit` row only SQL written by hand could store -- a window the API never writes, a
/// limit of zero, a field it does not know -- fails the snapshot, so the data planes keep the
/// configuration they have rather than lose the limit, and the lists say they cannot read it
/// rather than show no limit. The API then takes the row over with a limit it can read, sending no
/// stamp, since no read could show one (#223).
#[tokio::test]
async fn a_stored_limit_in_another_shape_fails_the_snapshot() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let db = store.client().await.unwrap();
    for config in [
        json!({"limit": 10, "window_ms": 5_000}),
        json!({"limit": 0, "window_ms": 1_000}),
        json!({"limit": 10, "window_ms": 1_000, "by": "everyone"}),
        json!({"limit": 10, "window_ms": 1_000, "by": {"header": "Host"}}),
        json!({"limit": "ten", "window_ms": 1_000}),
    ] {
        db.execute("delete from plugins", &[]).await.unwrap();
        db.execute(
            "insert into plugins (workspace_id, name, config, service_id)
             select workspace_id, 'rate_limit', $1, id from services where name = 'orders'",
            &[&config],
        )
        .await
        .unwrap();
        assert!(store.snapshot().await.is_err(), "{config}");
        for path in [LIMITS, ROUTES, SERVICES] {
            let (status, _) = send(&app, "GET", path, Some(s.vi), "").await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path} {config}");
        }
    }
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("service:orders", 10, "second"),
    )
    .await;
    assert_eq!(
        limit_on(&compiled(&store).await, COMPILED_ROUTE),
        Some(RateLimit {
            limit: 10,
            window_ms: 1_000,
            by: LimitBy::Ip,
        })
    );
    assert_eq!(policy_audits(&store).await.len(), 1);
}

#[tokio::test]
async fn kubernetes_mode_has_none_of_it() {
    let app = console(None);
    let (status, body) = send(&app, "GET", LIMITS, None, "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(sentence(&body).contains("keeps no configuration"), "{body}");
}

/// One policy of a name per target and consumer: a limit on everyone and a consumer's own on
/// the same route are two rows, and a second of either is refused by the database itself.
#[tokio::test]
async fn a_route_holds_one_limit_on_everyone_and_one_per_consumer() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let db = store.client().await.unwrap();
    let insert = |consumer: bool| {
        let db = &db;
        async move {
            db.execute(
                "insert into plugins (workspace_id, name, config, route_id, consumer_id)
                 select r.workspace_id, 'rate_limit', '{\"limit\": 5, \"window_ms\": 1000}',
                        r.id, case when $1 then c.id end
                   from routes r, consumers c where r.name = 'orders-api' and c.username = 'mobile'",
                &[&consumer],
            )
            .await
        }
    };
    insert(false).await.expect("the limit on everyone");
    insert(true).await.expect("the consumer's own, beside it");
    assert!(insert(false).await.is_err(), "a second on everyone");
    assert!(insert(true).await.is_err(), "a second for the consumer");
    // A route and a service still exclude each other, consumer or not.
    let both = db
        .execute(
            "insert into plugins (workspace_id, name, route_id, service_id, consumer_id)
             select r.workspace_id, 'rate_limit', r.id, r.service_id, c.id
               from routes r, consumers c where r.name = 'orders-api' and c.username = 'mobile'",
            &[],
        )
        .await;
    assert!(both.is_err(), "a route and a service at once");
}

/// A body for a consumer's own limit.
fn put_for(target: &str, consumer: &str, limit: u32, per: &str, by: &str) -> String {
    json!({"target": target, "consumer": consumer, "limit": limit, "per": per, "by": by})
        .to_string()
}

/// The point of the feature on the control side: a consumer's own limit, on a route and on
/// nothing, reaches the compiled table under `workspace/username`, counted by what it says,
/// lists after the limits on everyone, and leaves the rule's own limit alone.
#[tokio::test]
async fn a_consumer_s_own_limit_reaches_the_compiled_table() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("route:orders-api", 3, "second"),
    )
    .await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for("route:orders-api", "mobile", 7, "minute", "consumer"),
    )
    .await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for("workspace", "mobile", 50, "hour", "header:x-tenant"),
    )
    .await;

    let config = compiled(&store).await;
    assert_eq!(
        limit_on(&config, COMPILED_ROUTE),
        Some(RateLimit {
            limit: 3,
            window_ms: 1_000,
            by: LimitBy::Ip
        })
    );
    let mobile = &config.consumer_rate_limits["default/mobile"];
    assert_eq!(
        mobile.routes[COMPILED_ROUTE],
        RateLimit {
            limit: 7,
            window_ms: 60_000,
            by: LimitBy::Consumer
        }
    );
    assert_eq!(
        mobile.any,
        Some(RateLimit {
            limit: 50,
            window_ms: 3_600_000,
            by: LimitBy::Header("x-tenant".into())
        })
    );
    assert_eq!(
        unstamped(read(&app, LIMITS, s.vi).await),
        json!([
            {"target": "route:orders-api", "limit": 3, "per": "second"},
            {"target": "workspace", "consumer": "mobile", "limit": 50, "per": "hour", "by": "header:x-tenant"},
            {"target": "route:orders-api", "consumer": "mobile", "limit": 7, "per": "minute", "by": "consumer"},
        ])
    );
    // The route list shows the limit on everyone, never a consumer's.
    let route = row(&app, ROUTES, "orders-api", s.vi).await;
    assert_eq!(route["rate_limit"]["limit"], 3);
    assert!(route["rate_limit"].get("by").is_none(), "{route}");
}

/// The consumer's limit and the one on everyone on one target are written, replaced and removed
/// apart; removing one leaves the other, and a key requirement on the same route reads its own
/// row, not a consumer's limit.
#[tokio::test]
async fn a_consumer_s_limit_and_the_limit_on_everyone_are_written_apart() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for("route:orders-api", "mobile", 7, "minute", "ip"),
    )
    .await;
    // No stamp: the target has no limit on everyone yet, whatever the consumer has.
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("route:orders-api", 3, "second"),
    )
    .await;
    ok(
        &app,
        "PUT",
        "/api/workspaces/default/key-auth",
        s.ed,
        r#"{"target":"route:orders-api"}"#,
    )
    .await;
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=route:orders-api&consumer=mobile"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=route:orders-api&consumer=mobile"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        sentence(&body),
        "route:orders-api has no request limit for mobile."
    );
    assert_eq!(
        limit_on(&compiled(&store).await, COMPILED_ROUTE).map(|l| l.limit),
        Some(3),
        "the limit on everyone is still there"
    );
    assert!(compiled(&store).await.consumer_rate_limits.is_empty());
}

/// A consumer that is not there, a consumer name no consumer could have, and anything to count
/// by that is not ip, consumer or a header the gateway may read are refused, and write nothing.
#[tokio::test]
async fn an_unknown_consumer_or_count_is_refused_and_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "PUT",
        LIMITS,
        Some(s.ed),
        &put_for("workspace", "ghost", 5, "minute", "ip"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(
        sentence(&body),
        "There is no consumer named ghost in this workspace."
    );
    for (body, field) in [
        (put_for("workspace", "a b", 5, "minute", "ip"), "consumer"),
        (
            put_for("workspace", "mobile", 5, "minute", "everyone"),
            "by",
        ),
        (put_for("workspace", "mobile", 5, "minute", "header:"), "by"),
        (
            put_for("workspace", "mobile", 5, "minute", "header:host"),
            "by",
        ),
    ] {
        let (status, answer) = send(&app, "PUT", LIMITS, Some(s.ed), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert_eq!(parse(&answer)["field"], field, "{body}");
    }
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("{LIMITS}?target=workspace&consumer=a%20b"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(everything(&store).await, before);
}

/// The audit row names the consumer and what the limit counts by.
#[tokio::test]
async fn the_audit_names_the_consumer_and_the_count() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for("service:orders", "mobile", 9, "minute", "consumer"),
    )
    .await;
    let audits = policy_audits(&store).await;
    let (action, before, after) = audits.last().expect("an audit row");
    assert_eq!(action, "create");
    assert_eq!(before, &json!(null));
    assert_eq!(
        after,
        &json!({"target": "service:orders", "kind": "rate_limit", "consumer": "mobile",
                "limit": 9, "per": "minute", "by": "consumer"})
    );
}

/// A consumer of another workspace attached to this workspace's policy -- which only SQL written
/// by hand can make -- fails the snapshot rather than attach to a same-named consumer here, and
/// fails the list rather than show as a limit on everyone. Deleting a route with a consumer's
/// limit on it is refused and says where to remove it, and deleting the consumer takes its limits
/// with it, which the audit entry for the consumer lists.
#[tokio::test]
async fn a_consumer_s_limit_is_bound_to_its_workspace_and_its_consumer() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for("route:orders-api", "mobile", 7, "minute", "ip"),
    )
    .await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for("workspace", "mobile", 50, "hour", "consumer"),
    )
    .await;

    // Deletes need the admin role.
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("{ROUTES}/orders-api"),
        Some(s.ada),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        sentence(&body).contains("removed from that consumer"),
        "{body}"
    );

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("{CONSUMERS}/mobile"),
        Some(s.ada),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(read(&app, LIMITS, s.vi).await, json!([]));
    // The limits that went with the consumer are in its audit entry, in the order the list
    // showed them, since no policy entry records their going.
    let db = store.client().await.unwrap();
    let before: serde_json::Value = db
        .query_one(
            "select before from audit_log where object_kind = 'consumer' and action = 'delete'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        before,
        json!({"name": "mobile", "keys": [], "limits": [
            {"target": "workspace", "limit": 50, "per": "hour", "by": "consumer"},
            {"target": "route:orders-api", "limit": 7, "per": "minute"},
        ]})
    );

    db.execute(
        "insert into consumers (workspace_id, username)
         select id, 'stranger' from workspaces where name = 'payments'",
        &[],
    )
    .await
    .unwrap();
    db.execute(
        "insert into plugins (workspace_id, name, config, consumer_id)
         select w.id, 'rate_limit', '{\"limit\": 5, \"window_ms\": 1000}', c.id
           from workspaces w, consumers c where w.name = 'default' and c.username = 'stranger'",
        &[],
    )
    .await
    .unwrap();
    let err = store.snapshot().await.expect_err("a foreign consumer");
    assert!(format!("{err:#}").contains("another workspace"), "{err:#}");
    let (status, body) = send(&app, "GET", LIMITS, Some(s.vi), "").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

/// A consumer of another workspace is not one of this workspace's: naming it here, to set a limit
/// or to remove one, is answered as naming a consumer that is not there, and writes nothing.
#[tokio::test]
async fn a_consumer_of_another_workspace_is_not_found_here() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let root: Uuid = store
        .client()
        .await
        .unwrap()
        .query_one("select id from users where username = 'root'", &[])
        .await
        .unwrap()
        .get(0);
    ok(
        &app,
        "POST",
        "/api/workspaces/payments/consumers",
        root,
        r#"{"name":"stranger"}"#,
    )
    .await;
    let before = everything(&store).await;
    for (method, path, body) in [
        (
            "PUT",
            LIMITS.to_string(),
            put_for("workspace", "stranger", 5, "minute", "ip"),
        ),
        (
            "PUT",
            LIMITS.to_string(),
            put_for("route:orders-api", "stranger", 5, "minute", "consumer"),
        ),
        (
            "DELETE",
            format!("{LIMITS}?target=workspace&consumer=stranger"),
            String::new(),
        ),
    ] {
        // The superuser, who reaches both workspaces, is answered no differently.
        for who in [s.ed, root] {
            let (status, answer) = send(&app, method, &path, Some(who), &body).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
            assert_eq!(
                sentence(&answer),
                "There is no consumer named stranger in this workspace."
            );
        }
    }
    assert_eq!(
        everything(&store).await,
        before,
        "none of it wrote anything"
    );
}

/// #223 for a consumer's own limit: it has a stamp of its own, apart from the limit on everyone on
/// the same target, and only that stamp replaces it. The other row's stamp, or none when it has
/// one, is stale, both ways round, and writes nothing.
#[tokio::test]
async fn a_consumer_s_limit_is_replaced_only_with_its_own_stamp() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let target = "route:orders-api";
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    ok(&app, "PUT", LIMITS, s.ed, &put(target, 3, "second")).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for(target, "mobile", 7, "minute", "ip"),
    )
    .await;
    let everyone = stamp(&app, target, s.vi).await;
    let own = stamp_for(&app, target, Some("mobile"), s.vi).await;
    assert!(everyone.is_some() && own.is_some(), "both are listed");
    assert_ne!(everyone, own, "each row has a stamp of its own");
    let stale = |body: String| {
        let app = &app;
        async move {
            let (status, answer) = send(app, "PUT", LIMITS, Some(s.ed), &body).await;
            assert_eq!(status, StatusCode::CONFLICT, "{body}: {answer}");
            assert_eq!(
                sentence(&answer),
                "Someone else changed this policy. Reload it and apply your change again."
            );
        }
    };

    let before = everything(&store).await;
    let changed = put_for(target, "mobile", 8, "minute", "ip");
    stale(seen(&changed, everyone.as_deref())).await;
    stale(changed.clone()).await;
    stale(seen(&put(target, 4, "second"), own.as_deref())).await;
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );

    ok(&app, "PUT", LIMITS, s.ed, &seen(&changed, own.as_deref())).await;
    let config = compiled(&store).await;
    assert_eq!(
        config.consumer_rate_limits["default/mobile"].routes[COMPILED_ROUTE].limit,
        8
    );
    assert_eq!(
        limit_on(&config, COMPILED_ROUTE).map(|l| l.limit),
        Some(3),
        "the limit on everyone is as it was"
    );
}

/// Saving a consumer's limit as it already is, from a fresh read, writes nothing: no row, no audit
/// entry and no new version for the data planes.
#[tokio::test]
async fn saving_a_consumer_s_limit_unchanged_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    let body = put_for("workspace", "mobile", 50, "hour", "header:x-tenant");
    ok(&app, "PUT", LIMITS, s.ed, &body).await;
    let before = everything(&store).await;
    apply(&app, s.ed, &body).await;
    assert_eq!(everything(&store).await, before, "a save of nothing");
}

/// A consumer's limit on a service reaches the compiled table under each of the service's routes,
/// and holds the service as a limit on everyone does: deleting the service is refused with a
/// sentence that names each consumer whose limit is there.
#[tokio::test]
async fn a_consumer_s_limit_on_a_service_reaches_its_routes_and_holds_the_service() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"mobile"}"#).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for("service:orders", "mobile", 9, "minute", "consumer"),
    )
    .await;
    let config = compiled(&store).await;
    let mobile = &config.consumer_rate_limits["default/mobile"];
    assert_eq!(
        mobile.routes[COMPILED_ROUTE],
        RateLimit {
            limit: 9,
            window_ms: 60_000,
            by: LimitBy::Consumer
        }
    );
    assert_eq!(mobile.any, None);
    assert_eq!(limit_on(&config, COMPILED_ROUTE), None, "none on everyone");

    // The route goes first: a service no route uses is the one whose policies are counted.
    ok(&app, "DELETE", &format!("{ROUTES}/orders-api"), s.ada, "").await;
    let refused = |said: &'static str| {
        let (app, store) = (&app, &store);
        async move {
            let before = everything(store).await;
            let (status, body) = send(
                app,
                "DELETE",
                &format!("{SERVICES}/orders"),
                Some(s.ada),
                "",
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{body}");
            assert_eq!(sentence(&body), said);
            assert_eq!(everything(store).await, before);
        }
    };
    refused(
        "1 policy is attached to this service. Remove it first. mobile has a limit of its own \
         here, which is removed from that consumer, not from the service.",
    )
    .await;

    ok(&app, "POST", CONSUMERS, s.ed, r#"{"name":"partner"}"#).await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put_for("service:orders", "partner", 5, "second", "ip"),
    )
    .await;
    ok(
        &app,
        "PUT",
        LIMITS,
        s.ed,
        &put("service:orders", 100, "minute"),
    )
    .await;
    refused(
        "3 policies are attached to this service. Remove them first. mobile, partner have limits \
         of their own here, which are removed from those consumers, not from the service.",
    )
    .await;
}
