//! JWT requirements through `/api/workspaces/{ws}/jwt`, against Postgres: that a requirement
//! reaches the compiled configuration and the verifier the data plane runs accepts a token signed
//! by a key in its JWKS and no other, that a JWKS the verifier finds no usable key in is refused
//! when it is written, which requirement applies where several do, who may do what, what the
//! audit records, and that every refusal writes nothing.
//!
//! The tests that need a store skip unless `GAPURA_TEST_DATABASE_URL` is set, like
//! `consumers.rs`, whose helpers these are copies of so that each file reads on its own. Run
//! them with:
//!
//! ```text
//! docker run -d --rm --name gapura-pg -e POSTGRES_PASSWORD=x -p 5433:5432 postgres:17-alpine
//! GAPURA_TEST_DATABASE_URL=postgres://postgres:x@localhost:5433/postgres cargo test -p gapura-control --test jwt
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use gapura_control::session::{encode, Session};
use gapura_control::state::AppState;
use gapura_control::store::Store;
use gapura_core::config::{Config, JwtPolicy, Plugin};
use gapura_core::jwt::Refusal;
use gapura_core::store::StoreSettings;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
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
const JWT: &str = "/api/workspaces/default/jwt";
/// The compiled name of the seeded route.
const COMPILED_ROUTE: &str = "default/orders-api";
const ISSUER: &str = "https://id.example";

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

/// The JWT requirement the compiled `route` carries, if any.
fn jwt_on(config: &Config, route: &str) -> Option<JwtPolicy> {
    let rule = config
        .listeners
        .iter()
        .flat_map(|l| &l.rules)
        .find(|r| r.route == route)
        .unwrap_or_else(|| panic!("{route} is not compiled"));
    rule.plugins.iter().find_map(|p| match p {
        Plugin::Jwt(policy) => Some(policy.clone()),
        _ => None,
    })
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

/// A P-256 key pair: the PKCS#8 document a token is signed with, and its public half as a JWK.
struct EcKey {
    pkcs8: Vec<u8>,
    jwk: serde_json::Value,
}

fn ec_key(kid: &str) -> EcKey {
    let pair = rcgen::KeyPair::generate().unwrap();
    // An uncompressed SEC1 point: 0x04, then x, then y.
    let point = pair.public_key_raw();
    assert_eq!((point.len(), point[0]), (65, 4));
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    EcKey {
        pkcs8: pair.serialize_der(),
        jwk: json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": kid,
            "x": b64(&point[1..33]),
            "y": b64(&point[33..]),
        }),
    }
}

fn jwks(keys: &[&EcKey]) -> String {
    json!({"keys": keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()}).to_string()
}

/// A token for `aud`, from `ISSUER`, valid until 2100, signed by `key` and naming `kid`.
fn token(key: &EcKey, kid: &str, aud: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        &json!({"iss": ISSUER, "aud": aud, "exp": 4102444800u64, "sub": "someone"}),
        &EncodingKey::from_ec_der(&key.pkcs8),
    )
    .unwrap()
}

/// A PUT body for `target`.
fn put(target: &str, issuer: &str, audience: Option<&str>, jwks: &str) -> String {
    let mut body = json!({"target": target, "issuer": issuer, "jwks": jwks});
    if let Some(audience) = audience {
        body["audience"] = json!(audience);
    }
    body.to_string()
}

/// The point of the feature: the requirement written through the API reaches the configuration
/// the data planes are served, and the verifier they run accepts a token signed by a key in its
/// JWKS while refusing one signed by any other key, even one claiming the same `kid`.
#[tokio::test]
async fn the_compiled_policy_accepts_tokens_from_its_own_keys_only() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let ours = ec_key("k1");
    let theirs = ec_key("k1");
    let document = jwks(&[&ours]);
    ok(
        &app,
        "PUT",
        JWT,
        s.ed,
        &put("route:orders-api", ISSUER, Some("orders"), &document),
    )
    .await;

    let policy = jwt_on(&compiled(&store).await, COMPILED_ROUTE).expect("the route requires a JWT");
    assert_eq!(
        policy,
        JwtPolicy {
            issuer: Some(ISSUER.into()),
            audience: Some("orders".into()),
            jwks: document,
        }
    );
    let keys = gapura_core::jwt::keys(&policy.jwks).expect("the stored JWKS reads");
    assert_eq!(keys.usable(), 1);
    let verify = |t: &str| gapura_core::jwt::verify(&policy, &keys, Some(t));
    assert_eq!(verify(&token(&ours, "k1", "orders")), Ok(()));
    assert_eq!(
        verify(&token(&theirs, "k1", "orders")),
        Err(Refusal::BadSignature),
        "another key under the same kid"
    );
    assert_eq!(
        verify(&token(&ours, "k2", "orders")),
        Err(Refusal::UnknownKey)
    );
    assert_eq!(
        verify(&token(&ours, "k1", "billing")),
        Err(Refusal::Claims),
        "the right key for the wrong audience"
    );
}

/// PUT on each kind of target; the list shows issuer, audience and the number of usable keys,
/// never the JWKS, and one target's GET returns its JWKS as sent.
#[tokio::test]
async fn each_target_kind_is_listed_and_one_is_read_with_its_jwks() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let (a, b) = (ec_key("a"), ec_key("b"));
    let two = jwks(&[&a, &b]);
    // Pretty-printed, to show it is kept as sent rather than re-serialised.
    let one = serde_json::to_string_pretty(&parse(&jwks(&[&a]))).unwrap();
    ok(
        &app,
        "PUT",
        JWT,
        s.ed,
        &put("workspace", ISSUER, None, &two),
    )
    .await;
    ok(
        &app,
        "PUT",
        JWT,
        s.ed,
        &put("service:orders", "https://svc.example", Some("svc"), &one),
    )
    .await;
    ok(
        &app,
        "PUT",
        JWT,
        s.ed,
        &put(
            "route:orders-api",
            "https://route.example",
            Some("api"),
            &one,
        ),
    )
    .await;

    let listed = read(&app, JWT, s.vi).await;
    assert_eq!(
        listed,
        json!([
            {"target": "workspace", "issuer": ISSUER, "audience": null, "keys": 2},
            {"target": "service:orders", "issuer": "https://svc.example", "audience": "svc", "keys": 1},
            {"target": "route:orders-api", "issuer": "https://route.example", "audience": "api", "keys": 1},
        ])
    );
    assert_eq!(
        read(&app, &format!("{JWT}?target=service:orders"), s.vi).await,
        json!({"target": "service:orders", "issuer": "https://svc.example", "audience": "svc", "jwks": one})
    );
    assert_eq!(
        read(&app, &format!("{JWT}?target=workspace"), s.vi).await["jwks"],
        two
    );

    // A target without one of its own, or one that does not exist, has none to read.
    ok(
        &app,
        "DELETE",
        &format!("{JWT}?target=route:orders-api"),
        s.ed,
        "",
    )
    .await;
    for target in ["route:orders-api", "route:missing"] {
        let (status, body) = send(
            &app,
            "GET",
            &format!("{JWT}?target={target}"),
            Some(s.vi),
            "",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{target}: {body}");
        assert_eq!(sentence(&body), format!("{target} has no JWT requirement."));
    }
    let (status, body) = send(
        &app,
        "GET",
        &format!("{JWT}?target=consumer:x"),
        Some(s.vi),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(parse(&body)["field"], "target");
}

#[tokio::test]
async fn the_most_specific_requirement_applies() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let document = jwks(&[&ec_key("k1")]);
    for (target, issuer) in [
        ("workspace", "https://ws.example"),
        ("service:orders", "https://svc.example"),
        ("route:orders-api", "https://route.example"),
    ] {
        ok(
            &app,
            "PUT",
            JWT,
            s.ed,
            &put(target, issuer, None, &document),
        )
        .await;
    }
    // A key requirement beside it is another kind, and both apply.
    ok(
        &app,
        "PUT",
        "/api/workspaces/default/key-auth",
        s.ed,
        r#"{"target":"workspace"}"#,
    )
    .await;

    for (issuer, from, then_delete) in [
        ("https://route.example", "route", Some("route:orders-api")),
        ("https://svc.example", "service", Some("service:orders")),
        ("https://ws.example", "workspace", None),
    ] {
        let config = compiled(&store).await;
        let policy = jwt_on(&config, COMPILED_ROUTE).unwrap();
        assert_eq!(policy.issuer.as_deref(), Some(issuer));
        let route = row(&app, ROUTES, "orders-api", s.vi).await;
        assert_eq!(route["jwt"], json!({"issuer": issuer, "from": from}));
        assert_eq!(
            route["key_auth"],
            json!({"header": "x-api-key", "from": "workspace"})
        );
        if let Some(target) = then_delete {
            ok(&app, "DELETE", &format!("{JWT}?target={target}"), s.ed, "").await;
        }
    }
    // The service shows its own requirement or the workspace's, never a route's.
    assert_eq!(
        row(&app, SERVICES, "orders", s.vi).await["jwt"],
        json!({"issuer": "https://ws.example", "from": "workspace"})
    );
    ok(&app, "DELETE", &format!("{JWT}?target=workspace"), s.ed, "").await;
    assert_eq!(jwt_on(&compiled(&store).await, COMPILED_ROUTE), None);
    assert_eq!(
        row(&app, ROUTES, "orders-api", s.vi).await["jwt"],
        serde_json::Value::Null
    );
    assert_eq!(
        row(&app, SERVICES, "orders", s.vi).await["jwt"],
        serde_json::Value::Null
    );
}

/// Create, the same requirement again (nothing written), a change, and removal: each write is one
/// policy entry recording what the requirement asks for and how many keys it holds, never the
/// JWKS.
#[tokio::test]
async fn the_audit_records_the_requirement_not_the_keys() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let (a, b) = (ec_key("a"), ec_key("b"));
    let first = put("service:orders", ISSUER, Some("orders"), &jwks(&[&a]));
    ok(&app, "PUT", JWT, s.ed, &first).await;

    let before = everything(&store).await;
    ok(&app, "PUT", JWT, s.ada, &first).await;
    assert_eq!(everything(&store).await, before, "a save of nothing");

    let second = put("service:orders", ISSUER, None, &jwks(&[&a, &b]));
    ok(&app, "PUT", JWT, s.ed, &second).await;
    ok(
        &app,
        "DELETE",
        &format!("{JWT}?target=service:orders"),
        s.ed,
        "",
    )
    .await;

    let one = json!({"target": "service:orders", "kind": "jwt", "issuer": ISSUER, "audience": "orders", "keys": 1});
    let two = json!({"target": "service:orders", "kind": "jwt", "issuer": ISSUER, "audience": null, "keys": 2});
    let null = serde_json::Value::Null;
    assert_eq!(
        policy_audits(&store).await,
        vec![
            ("create".to_string(), null.clone(), one.clone()),
            ("update".to_string(), one, two.clone()),
            ("delete".to_string(), two, null),
        ]
    );
    let text: Vec<String> = store
        .client()
        .await
        .unwrap()
        .query("select a::text from audit_log a", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    for key in [&a, &b] {
        let x = key.jwk["x"].as_str().unwrap();
        assert!(
            text.iter().all(|row| !row.contains(x)),
            "the audit holds key material"
        );
    }

    // Deleting what is no longer there is 404, and writes nothing.
    let before = everything(&store).await;
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("{JWT}?target=service:orders"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(sentence(&body), "service:orders has no JWT requirement.");
    assert_eq!(everything(&store).await, before);
}

#[tokio::test]
async fn bad_input_is_named_and_writes_nothing() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let good = jwks(&[&ec_key("k1")]);
    let no_alg =
        json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"}]}).to_string();
    let long = "a".repeat(513);
    // Past the limit only by whitespace around a usable key set, so the size is all that is wrong.
    let oversize = format!("{good}{}", " ".repeat(64 * 1024 + 1 - good.len()));
    let before = everything(&store).await;

    for (body, field) in [
        (put("consumer:x", ISSUER, None, &good), "target"),
        (
            json!({"target": "workspace", "jwks": good}).to_string(),
            "issuer",
        ),
        (put("workspace", "", None, &good), "issuer"),
        (
            put("workspace", "https://id.example\nx", None, &good),
            "issuer",
        ),
        (put("workspace", "a\u{0}b", None, &good), "issuer"),
        (put("workspace", &long, None, &good), "issuer"),
        (put("workspace", ISSUER, Some(&long), &good), "audience"),
        (put("workspace", ISSUER, Some("a\tb"), &good), "audience"),
        (
            json!({"target": "workspace", "issuer": ISSUER}).to_string(),
            "jwks",
        ),
        (put("workspace", ISSUER, None, "{not json"), "jwks"),
        (put("workspace", ISSUER, None, r#"{"no":"keys"}"#), "jwks"),
        (put("workspace", ISSUER, None, r#"{"keys":[]}"#), "jwks"),
        (put("workspace", ISSUER, None, &no_alg), "jwks"),
        (put("workspace", ISSUER, None, &oversize), "jwks"),
    ] {
        let (status, answer) = send(&app, "PUT", JWT, Some(s.ed), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert_eq!(parse(&answer)["field"], field, "{body}: {answer}");
        assert!(!sentence(&answer).is_empty());
    }
    let (status, answer) = send(
        &app,
        "DELETE",
        &format!("{JWT}?target=consumer:x"),
        Some(s.ed),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(parse(&answer)["field"], "target");

    for (method, path, body, said) in [
        (
            "PUT",
            JWT.to_string(),
            put("route:missing", ISSUER, None, &good),
            "There is no route named missing in this workspace.",
        ),
        (
            "PUT",
            JWT.to_string(),
            put("service:missing", ISSUER, None, &good),
            "There is no service named missing in this workspace.",
        ),
        (
            "DELETE",
            format!("{JWT}?target=route:orders-api"),
            String::new(),
            "route:orders-api has no JWT requirement.",
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

    // A shared secret beside a public key is refused, by name; the public key alone is not.
    let ours = ec_key("k1");
    let mut with_secret = parse(&jwks(&[&ours]));
    with_secret["keys"].as_array_mut().unwrap().push(json!({
        "kty": "oct", "alg": "HS256", "kid": "k2", "k": "c2VjcmV0LWJ1dC1yZWFkYWJsZQ"
    }));
    let before = everything(&store).await;
    let (status, answer) = send(
        &app,
        "PUT",
        JWT,
        Some(s.ed),
        &put("workspace", ISSUER, None, &with_secret.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(parse(&answer)["field"], "jwks");
    assert_eq!(
        sentence(&answer),
        "Use public keys only: an oct key is a shared secret, and anyone who can read this workspace could read it."
    );
    assert_eq!(
        everything(&store).await,
        before,
        "the secret was not stored"
    );
    ok(
        &app,
        "PUT",
        JWT,
        s.ed,
        &put("workspace", ISSUER, None, &jwks(&[&ours])),
    )
    .await;

    // A JWKS at the limit is not too large, though its JSON-escaped body is more than any other
    // write may send.
    let at_limit = format!("{good}{}", " ".repeat(64 * 1024 - good.len()));
    ok(
        &app,
        "PUT",
        JWT,
        s.ed,
        &put("workspace", ISSUER, None, &at_limit),
    )
    .await;
}

#[tokio::test]
async fn a_viewer_reads_an_editor_writes_and_no_role_is_refused() {
    let Some((store, _guard)) = fresh_store().await else {
        return;
    };
    let app = console(Some(store.clone()));
    let s = seed(&store, &app).await;
    let document = jwks(&[&ec_key("k1")]);
    ok(
        &app,
        "PUT",
        JWT,
        s.ed,
        &put("workspace", ISSUER, None, &document),
    )
    .await;
    let off = format!("{JWT}?target=workspace");

    assert_eq!(read(&app, JWT, s.vi).await[0]["target"], "workspace");
    assert_eq!(read(&app, &off, s.vi).await["jwks"], document);
    let before = everything(&store).await;
    for (method, path, body) in [
        ("PUT", JWT, put("route:orders-api", ISSUER, None, &document)),
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
            ("GET", "/jwt", String::new()),
            ("GET", "/jwt?target=workspace", String::new()),
            ("PUT", "/jwt", put("workspace", ISSUER, None, &document)),
            ("DELETE", "/jwt?target=workspace", String::new()),
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
    assert_eq!(
        everything(&store).await,
        before,
        "the refusals wrote nothing"
    );

    // A route with a JWT requirement of its own is not deleted from under it.
    ok(
        &app,
        "PUT",
        JWT,
        s.ed,
        &put("route:orders-api", ISSUER, None, &document),
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
        &format!("{JWT}?target=route:orders-api"),
        s.ed,
        "",
    )
    .await;
    assert_eq!(read(&app, JWT, s.vi).await, json!([]));
}

#[tokio::test]
async fn kubernetes_mode_has_none_of_it() {
    let app = console(None);
    for path in [JWT, "/api/workspaces/default/jwt?target=workspace"] {
        let (status, body) = send(&app, "GET", path, None, "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(sentence(&body).contains("keeps no configuration"), "{body}");
    }
}
