//! The configuration endpoint against a real Postgres.
//!
//! Skipped unless `GAPURA_TEST_DATABASE_URL` is set, because the alternative is a test that
//! mocks the database and therefore proves the mock. Run it with:
//!
//! ```text
//! docker run -d --rm --name pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test config_endpoint
//! ```

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gapura_control::config_api::{router, ConfigApi};
use gapura_control::store::Store;
use gapura_core::config::Config;
use gapura_core::matcher::{RegexMap, RequestAttrs};
use gapura_core::store::StoreSettings;
use tower::ServiceExt;

/// One database, so the tests take turns. Each starts by dropping the schema, and two doing
/// that at once delete each other's tables mid-run. The guard is held for the whole test rather
/// than just the reset, because the race is between one test's reset and another's queries.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn fixture() -> Option<(
    Arc<Store>,
    axum::Router,
    tokio::sync::MutexGuard<'static, ()>,
)> {
    let url = match std::env::var("GAPURA_TEST_DATABASE_URL") {
        Ok(url) => url,
        // Optional locally, mandatory in CI. Without this, a typo in the workflow's variable
        // name would skip these tests and report a green build that proved nothing -- which is
        // the exact failure they exist to catch, reproduced one level up.
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
    // Each run starts from nothing, so a failure is never yesterday's rows.
    {
        let pool_client = store.client().await.expect("client");
        pool_client
            .batch_execute(
                "drop schema public cascade; create schema public;
                 grant all on schema public to public;",
            )
            .await
            .expect("resetting the schema");
    }
    store.migrate().await.expect("migrating");
    let api = Arc::new(ConfigApi {
        store: store.clone(),
        settings: StoreSettings {
            http_ports: vec![80],
        },
    });
    Some((store, router(api), guard))
}

async fn get(
    app: &axum::Router,
    token: &str,
    if_none_match: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let mut req = Request::builder()
        .uri("/v1/config")
        .header("authorization", format!("Bearer {token}"));
    if let Some(v) = if_none_match {
        req = req.header("if-none-match", v);
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

#[tokio::test]
async fn a_data_plane_fetches_a_routable_configuration_and_is_told_when_nothing_changed() {
    let Some((store, app, _guard)) = fixture().await else {
        return;
    };
    let token = store.issue_token("edge-1").await.expect("issuing a token");

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
    assert_eq!(hit.expect("a match").rule.route, "orders-api");
    // The data plane resolves this itself; the control plane could not.
    let cluster = &config.clusters["orders.internal:8080"];
    assert!(cluster.endpoints.is_empty());
    assert_eq!(cluster.resolve.as_ref().unwrap().host, "orders.internal");

    // Nothing changed, so nothing is sent.
    let (status, _, body) = get(&app, &token, Some(&etag)).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());

    // A write moves the version, and the same conditional request now gets the replacement.
    client
        .execute(
            "update routes set priority = 5 where name = 'orders-api'",
            &[],
        )
        .await
        .unwrap();
    let (status, new_etag, _) = get(&app, &token, Some(&etag)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        new_etag.unwrap(),
        etag,
        "the version has to move with the rows"
    );
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
    let token = store.issue_token("edge-1").await.expect("issuing a token");

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
               select id, 'key_auth', '{\"header\":\"x-api-key\"}' from workspaces limit 1;",
        )
        .await
        .expect("seeding");

    let key = store.issue_key("team-orders").await.expect("issuing a key");

    let (status, _, body) = get(&app, &token, None).await;
    assert_eq!(status, StatusCode::OK);
    let config: gapura_core::config::Config = serde_json::from_slice(&body).unwrap();

    // The key itself must not be anywhere in what the data plane receives and caches to disk.
    assert!(
        !String::from_utf8_lossy(&body).contains(&key),
        "a configuration must never carry a presentable credential"
    );

    // And the data plane, given the real key, names the consumer.
    assert_eq!(
        gapura_core::credentials::identify(&config, Some(&key)),
        Ok("team-orders")
    );
    assert!(gapura_core::credentials::identify(&config, Some("gpak_wrong")).is_err());

    // The policy reached the rule that needs it.
    let plugins = &config.listeners[0].rules[0].plugins;
    assert!(matches!(
        plugins.as_slice(),
        [gapura_core::config::Plugin::KeyAuth(_)]
    ));
}
