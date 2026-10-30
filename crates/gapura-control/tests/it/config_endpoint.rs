//! The configuration endpoint against a real Postgres.
//!
//! Skipped unless `GAPURA_TEST_DATABASE_URL` is set, because the alternative is a test that
//! mocks the database and therefore proves the mock. Run it with:
//!
//! ```text
//! docker run -d --rm --name pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test it config_endpoint::
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Extension;
use gapura_control::config_api::{router, ConfigApi};
use gapura_control::store::Store;
use gapura_core::config::Config;
use gapura_core::features::FEATURES;
use gapura_core::matcher::{RegexMap, RequestAttrs};
use gapura_core::store::StoreSettings;
use tower::ServiceExt;

use crate::common::fresh_store;

/// A fresh store, as `common::fresh_store` makes one, and the endpoint over it.
async fn fixture() -> Option<(
    Arc<Store>,
    axum::Router,
    tokio::sync::MutexGuard<'static, ()>,
)> {
    let (store, guard) = fresh_store().await?;
    let api = Arc::new(ConfigApi {
        store: store.clone(),
        settings: StoreSettings {
            http_ports: vec![80],
        },
    });
    Some((store, router(api), guard))
}

/// A poll as a data plane of this build makes it: naming every feature it reads.
async fn get(
    app: &axum::Router,
    token: &str,
    if_none_match: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    get_as(app, token, if_none_match, Some(&FEATURES.join(","))).await
}

/// A poll naming `features`, or none at all, as rc.17 and older do.
async fn get_as(
    app: &axum::Router,
    token: &str,
    if_none_match: Option<&str>,
    features: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let mut req = Request::builder()
        .uri("/v1/config")
        .header("authorization", format!("Bearer {token}"));
    if let Some(v) = if_none_match {
        req = req.header("if-none-match", v);
    }
    if let Some(f) = features {
        req = req.header("x-gapura-features", f);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let etag = res
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, etag, body.to_vec())
}

/// A configuration a data plane cannot read is refused to it, naming what it lacks, rather than
/// sent for it to fail on; one that reads it is sent it; one that names nothing is taken to read
/// the legacy baseline; and one already holding it is told nothing changed.
#[tokio::test]
async fn a_data_plane_is_refused_what_it_cannot_read_and_told_why() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.seed_token("edge-1").await.expect("issuing a token");
    store
        .client()
        .await
        .unwrap()
        .batch_execute(
            "insert into services (workspace_id, name, protocol, host, port)
               select id, 'orders', 'http', 'orders.internal', 8080 from workspaces limit 1;
             insert into routes (workspace_id, service_id, name, paths)
               select w.id, s.id, 'orders-api', '[{\"type\":\"prefix\",\"value\":\"/\"}]'
                 from workspaces w, services s limit 1;
             insert into plugins (workspace_id, name, config)
               select id, 'ip_restriction', '{\"deny\":[\"203.0.113.7/32\"]}'
                 from workspaces limit 1;",
        )
        .await
        .expect("seeding");

    let without: Vec<&str> = FEATURES
        .iter()
        .copied()
        .filter(|f| *f != "ip_restriction")
        .collect();
    let (status, _, body) = get_as(&app, &token, None, Some(&without.join(","))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"error": "incompatible", "missing": ["ip_restriction"]})
    );

    let (status, _, _) = get_as(&app, &token, None, None).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "naming nothing is rc.17 and older, taken to read no ip_restriction"
    );

    // A header no data plane writes is read as saying nothing too: the legacy baseline, not
    // "reads everything" and not "reads nothing".
    let (status, _, body) = get_as(&app, &token, None, Some("JWT")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["missing"], serde_json::json!(["ip_restriction"]));
    let (status, _, _) = get_as(&app, &token, None, Some(&vec!["jwt"; 65].join(","))).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "more names than any data plane has is no data plane's header"
    );

    let (status, etag, _) = get(&app, &token, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = get_as(&app, &token, etag.as_deref(), Some("jwt")).await;
    assert_eq!(
        status,
        StatusCode::NOT_MODIFIED,
        "it already holds what would be refused"
    );
}

#[tokio::test]
async fn a_data_plane_fetches_a_routable_configuration_and_is_told_when_nothing_changed() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.seed_token("edge-1").await.expect("issuing a token");

    // A service and a route, written the way the console will write them.
    let client = store.client().await.unwrap();
    client
        .batch_execute(
            "insert into services (workspace_id, name, protocol, host, port)
               select id, 'orders', 'http', 'orders.internal', 8080 from workspaces limit 1;
             insert into routes (workspace_id, service_id, name, paths, priority)
               select w.id, s.id, 'orders-api', '[{\"type\":\"prefix\",\"value\":\"/orders\"}]', 0
                 from workspaces w, services s limit 1;",
        )
        .await
        .expect("seeding");

    let (status, etag, body) = get(&app, &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let etag = etag.expect("an ETag is what the next request sends back");

    // Not "the JSON has the right shape": the configuration has to route.
    let config: Config = serde_json::from_slice(&body).expect("a Config");
    let headers: Vec<(String, String)> = Vec::new();
    let query: Vec<(String, String)> = Vec::new();
    let hit = config.match_port_with(
        80,
        &RequestAttrs {
            host: "anything",
            path: "/orders/42",
            method: "GET",
            headers: &headers,
            query: &query,
        },
        &RegexMap::default(),
    );
    assert_eq!(hit.expect("a match").rule.route, "default/orders-api");
    // The data plane resolves this itself; the control plane could not.
    let cluster = &config.clusters["orders.internal:8080"];
    assert!(cluster.endpoints.is_empty());
    assert_eq!(cluster.resolve.as_ref().unwrap().host, "orders.internal");

    // Nothing changed, so nothing is sent.
    let (status, _, body) = get(&app, &token, Some(&etag)).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());

    // A write that changes what is served moves the tag, and the same conditional request now
    // gets the replacement.
    client
        .execute("update services set port = 8081 where name = 'orders'", &[])
        .await
        .unwrap();
    let (status, new_etag, _) = get(&app, &token, Some(&etag)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        new_etag.unwrap(),
        etag,
        "the tag has to move with what is served"
    );

    // A write that changes nothing served does not: priority only orders rules, and there is
    // one. The tag is the content, so the data plane is not sent the same configuration again.
    let (_, current, _) = get(&app, &token, None).await;
    let current = current.unwrap();
    client
        .execute(
            "update routes set priority = 5 where name = 'orders-api'",
            &[],
        )
        .await
        .unwrap();
    let (status, _, _) = get(&app, &token, Some(&current)).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn a_service_s_timeouts_and_https_reach_the_served_configuration() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.seed_token("edge-1").await.expect("issuing a token");
    let client = store.client().await.unwrap();
    client
        .batch_execute(
            "insert into services (workspace_id, name, protocol, host, port,
                                   connect_timeout_ms, read_timeout_ms)
               select id, 'secure', 'https', 'api.internal', 8443, 2000, 15000
                 from workspaces limit 1;
             insert into routes (workspace_id, service_id, name, paths, priority)
               select w.id, s.id, 'secure-api', '[{\"type\":\"prefix\",\"value\":\"/s\"}]', 0
                 from workspaces w, services s limit 1;",
        )
        .await
        .expect("seeding");

    let (status, _, body) = get(&app, &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let config: Config = serde_json::from_slice(&body).expect("a Config");

    let rules = &config.listeners[0].rules;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].timeouts.connect_ms, Some(2000));
    assert_eq!(rules[0].timeouts.backend_request_ms, Some(15000));
    assert_eq!(
        rules[0]
            .filters
            .rewrite
            .as_ref()
            .and_then(|r| r.hostname.as_deref()),
        Some("api.internal:8443")
    );
    let tls = config.clusters["https://api.internal:8443"]
        .tls
        .as_ref()
        .expect("an https service is reached over TLS");
    assert_eq!(tls.sni, "api.internal");
    assert!(!tls.insecure);
}

#[tokio::test]
async fn a_token_that_was_never_issued_gets_nothing() {
    let Some((_store, app, _guard)) = fixture().await else {
        return;
    };
    let (status, _, _) = get(&app, "gpdp_0000000000000000", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let res = app
        .oneshot(
            Request::builder()
                .uri("/v1/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "and neither does no token at all"
    );
}

/// The credential seam, end to end: the console issues a key, the store keeps only its hash, the
/// configuration carries that hash, and the data plane turns a presented key into a consumer.
/// It was built separately from JWT precisely so a failure anywhere along it is unambiguous.
#[tokio::test]
async fn a_key_the_console_issued_identifies_its_consumer_at_the_data_plane() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.seed_token("edge-1").await.expect("issuing a token");

    let client = store.client().await.unwrap();
    client
        .batch_execute(
            "insert into services (workspace_id, name, protocol, host, port)
               select id, 'orders', 'http', 'orders.internal', 8080 from workspaces limit 1;
             insert into routes (workspace_id, service_id, name, paths)
               select w.id, s.id, 'orders-api', '[{\"type\":\"prefix\",\"value\":\"/\"}]'
                 from workspaces w, services s limit 1;
             insert into consumers (workspace_id, username)
               select id, 'team-orders' from workspaces limit 1;
             insert into plugins (workspace_id, name, config)
               select id, 'key_auth', '{\"header\":\"x-api-key\"}' from workspaces limit 1;
             insert into workspaces (name) values ('payments');
             insert into consumers (workspace_id, username)
               select id, 'team-payments' from workspaces where name = 'payments';",
        )
        .await
        .expect("seeding");

    let key = store.seed_key("team-orders").await.expect("issuing a key");
    let elsewhere = store
        .seed_key("team-payments")
        .await
        .expect("issuing a key in another workspace");

    let (status, _, body) = get(&app, &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let config: gapura_core::config::Config = serde_json::from_slice(&body).unwrap();

    // The key itself must not be anywhere in what the data plane receives and caches to disk.
    assert!(
        !String::from_utf8_lossy(&body).contains(&key),
        "a configuration must never carry a presentable credential"
    );

    // The policy reached the rule that needs it, carrying its workspace.
    let plugins = &config.listeners[0].rules[0].plugins;
    let [gapura_core::config::Plugin::KeyAuth(policy)] = plugins.as_slice() else {
        panic!("one key_auth policy, got {plugins:?}");
    };
    assert_eq!(policy.workspace.as_deref(), Some("default"));

    // And the data plane, given the real key, names the consumer.
    let scope = policy.workspace.as_deref();
    assert_eq!(
        gapura_core::credentials::identify(&config, Some(&key), scope),
        Ok("team-orders")
    );
    assert!(gapura_core::credentials::identify(&config, Some("gpak_wrong"), scope).is_err());
    // A key issued in another workspace is real, and still does not open this route.
    assert!(
        gapura_core::credentials::identify(&config, Some(&elsewhere), scope).is_err(),
        "a key opens its own workspace's routes only"
    );
}

#[tokio::test]
async fn replicas_migrating_at_once_all_start() {
    let Some((store, _, _guard)) = fixture().await else {
        return;
    };
    store
        .client()
        .await
        .unwrap()
        .batch_execute(
            "drop schema public cascade; create schema public;
             grant all on schema public to public;",
        )
        .await
        .unwrap();
    let url = std::env::var("GAPURA_TEST_DATABASE_URL").unwrap();
    let (a, b, c) = tokio::join!(
        Store::connect(&url),
        Store::connect(&url),
        Store::connect(&url)
    );
    let (a, b, c) = (a.unwrap(), b.unwrap(), c.unwrap());
    // Without the migration lock, more than one finds 0001 unapplied and the losers fail on a
    // duplicate: a replica that cannot start.
    let (ra, rb, rc) = tokio::join!(a.migrate(), b.migrate(), c.migrate());
    ra.expect("first replica");
    rb.expect("second replica");
    rc.expect("third replica");
}

#[tokio::test]
async fn a_changed_setting_moves_the_tag_though_no_row_changed() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.seed_token("edge-1").await.unwrap();
    let (_, etag, _) = get(&app, &token, None).await;
    let etag = etag.unwrap();
    // Same rows, same store version, a control plane started with other flags: what it compiles
    // is different, and a data plane holding the old tag must be sent it, not told 304.
    let other = router(Arc::new(ConfigApi {
        store: store.clone(),
        settings: StoreSettings {
            http_ports: vec![8080],
        },
    }));
    let (status, new_etag, _) = get(&other, &token, Some(&etag)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(new_etag.unwrap(), etag);
}

#[tokio::test]
async fn a_call_records_the_address_the_tag_sent_and_the_token_used() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    // What both listeners in main put on each request: the connection's peer.
    let app = app.layer(Extension(ConnectInfo(
        "10.0.3.7:5000".parse::<SocketAddr>().unwrap(),
    )));
    // Two live tokens for one data plane, as in the middle of a rotation.
    let first = store.seed_token("edge-1").await.unwrap();
    let second = store.seed_token("edge-1").await.unwrap();

    let (status, _, _) = get(&app, &first, Some("\"abc\"")).await;
    assert_eq!(status, StatusCode::OK, "a stale tag is answered in full");

    let client = store.client().await.unwrap();
    let plane = client
        .query_one(
            "select host(last_seen_address), last_seen_etag, last_seen_at is not null
               from data_planes where name = 'edge-1'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        plane.get::<_, Option<String>>(0).as_deref(),
        Some("10.0.3.7")
    );
    // The tag it sent, not the one it was answered with: what it holds, not what it was offered.
    assert_eq!(
        plane.get::<_, Option<String>>(1).as_deref(),
        Some("\"abc\"")
    );
    assert!(plane.get::<_, bool>(2));

    // Which token authenticated, so the one a rotation left unused is the one safe to revoke.
    let used = |prefix: &str| {
        if first.starts_with(prefix) {
            "first"
        } else {
            assert!(second.starts_with(prefix), "a token nobody seeded");
            "second"
        }
    };
    let mut tokens: Vec<(&str, bool)> = client
        .query(
            "select token_prefix, last_used_at is not null from data_plane_tokens",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (used(row.get(0)), row.get(1)))
        .collect();
    tokens.sort();
    assert_eq!(tokens, [("first", true), ("second", false)]);

    // A call that sends no tag holds no configuration yet, and the record says so rather than
    // keeping the tag from before.
    let (status, _, _) = get(&app, &first, None).await;
    assert_eq!(status, StatusCode::OK);
    let etag: Option<String> = client
        .query_one(
            "select last_seen_etag from data_planes where name = 'edge-1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(etag, None);
}

#[tokio::test]
async fn a_tag_too_long_to_be_one_is_answered_but_not_stored() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.seed_token("edge-1").await.unwrap();

    let (status, _, _) = get(&app, &token, Some(&"a".repeat(10 * 1024))).await;
    assert_eq!(status, StatusCode::OK);

    let etag: Option<String> = store
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
    assert_eq!(etag, None);
}

/// The schema's foreign key allows a route to name another workspace's service, which only SQL
/// written by hand can make. Sent on, the route would compile into whichever same-named service
/// its own workspace has -- the wrong upstream, silently -- or be dropped; like a foreign
/// policy row, it fails the snapshot instead of guessing.
#[tokio::test]
async fn a_route_pointing_at_another_workspace_s_service_fails_the_snapshot() {
    let Some((store, _, _guard)) = fixture().await else {
        return;
    };
    store
        .client()
        .await
        .unwrap()
        .batch_execute(
            "insert into workspaces (name) values ('payments');
             insert into services (workspace_id, name, protocol, host, port)
               select id, 'orders', 'http', 'orders.internal', 8080
                 from workspaces where name = 'default';
             insert into services (workspace_id, name, protocol, host, port)
               select id, 'orders', 'http', 'impostor.internal', 9090
                 from workspaces where name = 'payments';
             insert into routes (workspace_id, service_id, name, paths, priority)
               select w.id, s.id, 'orders-api', '[{\"type\":\"prefix\",\"value\":\"/orders\"}]', 0
                 from workspaces w, services s
                where w.name = 'default' and s.workspace_id <> w.id;",
        )
        .await
        .unwrap();

    let error = store
        .snapshot()
        .await
        .expect_err("a foreign service must fail the snapshot");
    let text = format!("{error:#}");
    assert!(text.contains("orders-api"), "{text}");
    assert!(text.contains("default"), "{text}");
    assert!(text.contains("another workspace"), "{text}");
}

/// The start order the comment in `main` promises: a flag that cannot be honoured stops the
/// process before the store is touched. The certificate and the listener of the configuration
/// endpoint are settled only after `migrate` today, so an upgrade carrying a bad path migrates
/// the schema and then exits -- leaving the new schema for the old image's rollback. The
/// ordering lives in `main`, so this runs the real binary.
#[tokio::test]
async fn a_bad_configuration_certificate_stops_the_start_before_any_migration() {
    let Some((store, _, _guard)) = fixture().await else {
        return;
    };
    // `fixture` migrates; this test is about a start that must not.
    store
        .client()
        .await
        .unwrap()
        .batch_execute(
            "drop schema public cascade; create schema public;
             grant all on schema public to public;",
        )
        .await
        .unwrap();

    // A kubeconfig pointing nowhere, so the Kubernetes client builds without a cluster and the
    // start gets as far as the flags under test.
    let kubeconfig = std::env::temp_dir().join(format!("gapura-kubeconfig-{}", std::process::id()));
    std::fs::write(
        &kubeconfig,
        "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: http://127.0.0.1:1\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\ncurrent-context: c\nusers:\n- name: u\n  user: {}\n",
    )
    .unwrap();

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_gapura-control"))
            .args([
                "--gateway-admin",
                "http://127.0.0.1:1",
                "--auth-mode",
                "local",
                "--listen",
                "127.0.0.1:0",
                "--listen-config",
                "127.0.0.1:0",
                "--config-tls-cert",
                "/nonexistent/cert.pem",
                "--config-tls-key",
                "/nonexistent/key.pem",
            ])
            .env(
                "DATABASE_URL",
                std::env::var("GAPURA_TEST_DATABASE_URL").unwrap(),
            )
            .env("KUBECONFIG", &kubeconfig)
            .output(),
    )
    .await
    .expect("the start must stop on its own, not serve")
    .unwrap();
    let _ = std::fs::remove_file(&kubeconfig);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("reading /nonexistent"),
        "the certificate is what stopped it: {stderr}"
    );
    let migrated = store
        .client()
        .await
        .unwrap()
        .query_one(
            "select to_regclass('public._migrations') is not null as ran",
            &[],
        )
        .await
        .unwrap()
        .get::<_, bool>("ran");
    assert!(!migrated, "the schema must still be untouched: {stderr}");
}

/// Waits for the store's change listener to have connected. It counts once on connecting, for
/// whatever it could have missed before then, and a poll held before that count would be woken by
/// it and answered early, as though something had changed. Locally it has always connected by the
/// time the first poll is answered, but nothing orders the two.
async fn listening(store: &Store) {
    let mut changes = store.config_changes();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        changes.wait_for(|n| *n > 0),
    )
    .await
    .expect("listening within 5 s")
    .expect("the listener runs");
}

/// A poll holding the current tag that asks to wait is answered when a write changes what is
/// served, well inside the wait, rather than at its end.
#[tokio::test]
async fn a_held_poll_is_woken_by_a_change() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.seed_token("edge-1").await.expect("issuing a token");
    let (_, etag, _) = get(&app, &token, None).await;
    let etag = etag.unwrap();
    listening(&store).await;

    let held = {
        let (app, token, etag) = (app.clone(), token.clone(), etag.clone());
        tokio::spawn(async move {
            let res = app
                .oneshot(
                    Request::builder()
                        .uri("/v1/config")
                        .header("authorization", format!("Bearer {token}"))
                        .header("if-none-match", etag)
                        .header("x-gapura-features", FEATURES.join(","))
                        .header("prefer", "wait=30")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            res.status()
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    store
        .client()
        .await
        .unwrap()
        .batch_execute(
            "insert into services (workspace_id, name, protocol, host, port)
               select id, 'orders', 'http', 'orders.internal', 8080 from workspaces limit 1;
             insert into routes (workspace_id, service_id, name, paths)
               select w.id, s.id, 'orders-api', '[{\"type\":\"prefix\",\"value\":\"/\"}]'
                 from workspaces w, services s limit 1;",
        )
        .await
        .unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(2), held)
        .await
        .expect("woken within 2 s, not at the end of its 30 s wait")
        .unwrap();
    assert_eq!(status, StatusCode::OK);
}

/// With nothing changing, a held poll is answered 304 once its wait is up.
#[tokio::test]
async fn a_held_poll_with_nothing_new_is_told_so_after_its_wait() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.seed_token("edge-1").await.expect("issuing a token");
    let (_, etag, _) = get(&app, &token, None).await;
    listening(&store).await;
    let started = std::time::Instant::now();
    let res = app
        .oneshot(
            Request::builder()
                .uri("/v1/config")
                .header("authorization", format!("Bearer {token}"))
                .header("if-none-match", etag.unwrap())
                .header("x-gapura-features", FEATURES.join(","))
                .header("prefer", "wait=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));
}
