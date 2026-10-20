//! End-to-end: the real `gapura` binary against a generated config dir and a mock upstream.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Echo upstream: JSON with method, path, query, headers. Paths containing `slow` sleep 600 ms.
async fn echo(req: Request) -> Json<Value> {
    if req.uri().path().contains("slow") {
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
    let headers: serde_json::Map<String, Value> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                Value::String(String::from_utf8_lossy(v.as_bytes()).into_owned()),
            )
        })
        .collect();
    Json(
        json!({ "method": req.method().as_str(), "path": req.uri().path(), "query": req.uri().query(), "headers": headers }),
    )
}

/// Serve the echo upstream on an already-bound listener.
async fn spawn_upstream(listener: TcpListener) -> SocketAddr {
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(any(echo));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// `(dead, live)`. Port 1 is the dead endpoint: binding it needs root, so nothing on the machine
/// can turn it live mid-test the way a freed ephemeral port can, and it always sorts below the
/// live port. Clusters sort endpoints by (address, port) and round-robin starts at 0, so the retry
/// scenario always tries dead first.
async fn spawn_dead_and_upstream() -> (SocketAddr, SocketAddr) {
    let live = TcpListener::bind("127.0.0.1:0").unwrap();
    (
        SocketAddr::from(([127, 0, 0, 1], 1)),
        spawn_upstream(live).await,
    )
}

/// An upstream that answers each connection once, then closes the socket a moment later without
/// saying so. Pingora finishes the response and pools the connection before the FIN arrives, so
/// the next request is handed a connection the backend has already closed -- the common case
/// `error_while_proxy` grants one retry for.
async fn spawn_closing_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Read to the end of the request headers; a GET carries no body.
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(n) if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") => break,
                        Ok(0) | Err(_) => return,
                        Ok(_) => continue,
                    }
                }
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

struct Gateway {
    child: Child,
    http: u16,
    admin: u16,
    /// Access-log lines read off the gateway's stdout, in order.
    logs: Arc<Mutex<Vec<String>>>,
    _dir: tempfile::TempDir,
}

impl Gateway {
    /// The access log line for `request_id`, parsed. `logging` runs after the client already has
    /// its response, so the line can still be in flight when the request returns: wait for it.
    async fn access_log(&self, request_id: &str) -> Value {
        for _ in 0..200 {
            if let Some(line) = self.logged(request_id) {
                return line;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("no access log line for request id {request_id}");
    }

    fn logged(&self, request_id: &str) -> Option<Value> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["request_id"] == request_id)
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Client whose DNS maps the test hostnames to the gateway; no redirects followed.
fn client(gw: &Gateway) -> reqwest::Client {
    let addr: SocketAddr = format!("127.0.0.1:{}", gw.http).parse().unwrap();
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve("echo.test", addr)
        .resolve("other.test", addr)
        .resolve("second.test", addr)
        .resolve("unknown.test", addr)
        .build()
        .unwrap()
}

fn url(gw: &Gateway, host: &str, path: &str) -> String {
    format!("http://{host}:{}{path}", gw.http)
}

/// One Gateway on the HTTP port, one HTTPRoute with a rule per scenario, and three Services.
fn config(http_port: u16, upstream: SocketAddr, dead: SocketAddr, reuse: SocketAddr) -> String {
    format!(
        r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {{ name: gapura }}
spec: {{ controllerName: gapura.dev/controller }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {{ name: main, namespace: infra, generation: 1 }}
spec:
  gatewayClassName: gapura
  listeners:
  - {{ name: http, port: {http_port}, protocol: HTTP, allowedRoutes: {{ namespaces: {{ from: All }} }} }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{ name: echo, namespace: apps, generation: 1, creationTimestamp: "2026-09-10T00:00:00Z" }}
spec:
  parentRefs: [{{ name: main, namespace: infra }}]
  hostnames: [echo.test]
  rules:
  - matches: [{{ path: {{ type: PathPrefix, value: /api }} }}]
    filters:
    - type: RequestHeaderModifier
      requestHeaderModifier: {{ set: [{{ name: X-Gateway, value: gapura }}], add: [{{ name: X-Add, value: one }}] }}
    - type: ResponseHeaderModifier
      responseHeaderModifier: {{ set: [{{ name: X-Resp, value: "yes" }}] }}
    backendRefs: [{{ name: echo, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /rewrite }} }}]
    filters:
    - type: URLRewrite
      urlRewrite: {{ hostname: internal.svc, path: {{ type: ReplacePrefixMatch, replacePrefixMatch: /internal }} }}
    backendRefs: [{{ name: echo, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /old }} }}]
    filters:
    - type: RequestRedirect
      requestRedirect: {{ scheme: https, hostname: new.test, statusCode: 301, path: {{ type: ReplaceFullPath, replaceFullPath: /new }} }}
  - matches: [{{ path: {{ type: PathPrefix, value: /status303 }} }}]
    filters:
    - type: RequestRedirect
      requestRedirect: {{ scheme: https, hostname: new.test, statusCode: 303 }}
  - matches: [{{ path: {{ type: PathPrefix, value: /status307 }} }}]
    filters:
    - type: RequestRedirect
      requestRedirect: {{ scheme: https, hostname: new.test, statusCode: 307 }}
  - matches: [{{ path: {{ type: PathPrefix, value: /status308 }} }}]
    filters:
    - type: RequestRedirect
      requestRedirect: {{ scheme: https, hostname: new.test, statusCode: 308 }}
  - matches: [{{ path: {{ type: PathPrefix, value: /slow }} }}]
    timeouts: {{ backendRequest: 300ms }}
    backendRefs: [{{ name: echo, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /noslow }} }}]
    timeouts: {{ backendRequest: 0s }}
    backendRefs: [{{ name: echo, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /nobackend }} }}]
    backendRefs: [{{ name: ghost, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /empty }} }}]
    backendRefs: [{{ name: empty, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /retry }} }}]
    backendRefs: [{{ name: flaky, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /limited }} }}]
    backendRefs: [{{ name: limited, port: 80 }}]
  - matches: [{{ path: {{ type: RegularExpression, value: "^/v\\d+/info" }} }}]
    backendRefs: [{{ name: echo, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /mirror }} }}]
    filters:
    - type: RequestMirror
      requestMirror: {{ backendRef: {{ name: shadow, port: 80 }} }}
    backendRefs: [{{ name: echo, port: 80 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /mirrordown }} }}]
    filters:
    - type: RequestMirror
      requestMirror: {{ backendRef: {{ name: shadow-down, port: 80 }} }}
    backendRefs: [{{ name: echo, port: 80 }}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{ name: other, namespace: apps, generation: 1, creationTimestamp: "2026-09-10T00:00:00Z" }}
spec:
  parentRefs: [{{ name: main, namespace: infra }}]
  hostnames: [other.test]
  rules:
  - matches: [{{ path: {{ type: PathPrefix, value: /reusedmirror }} }}]
    filters:
    - type: RequestMirror
      requestMirror: {{ backendRef: {{ name: shadow, port: 80 }} }}
    backendRefs: [{{ name: reuse, port: 80 }}]
  - backendRefs: [{{ name: echo, port: 80 }}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {{ name: second, namespace: infra, generation: 1 }}
spec:
  gatewayClassName: gapura
  listeners:
  - {{ name: http, port: {http_port}, protocol: HTTP, allowedRoutes: {{ namespaces: {{ from: All }} }} }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{ name: onsecond, namespace: apps, generation: 1, creationTimestamp: "2026-09-10T00:00:00Z" }}
spec:
  parentRefs: [{{ name: second, namespace: infra }}]
  hostnames: [second.test]
  rules:
  - filters:
    - type: ResponseHeaderModifier
      responseHeaderModifier: {{ set: [{{ name: X-Gateway-Name, value: second }}] }}
    backendRefs: [{{ name: echo, port: 80 }}]
---
apiVersion: v1
kind: Service
metadata: {{ name: echo, namespace: apps }}
spec: {{ ports: [{{ name: http, port: 80 }}] }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: echo-1, namespace: apps, labels: {{ kubernetes.io/service-name: echo }} }}
addressType: IPv4
endpoints: [{{ addresses: ["{up_ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: http, port: {up_port} }}]
---
apiVersion: v1
kind: Service
metadata: {{ name: shadow, namespace: apps }}
spec: {{ ports: [{{ name: http, port: 80 }}] }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: shadow-1, namespace: apps, labels: {{ kubernetes.io/service-name: shadow }} }}
addressType: IPv4
endpoints: [{{ addresses: ["{up_ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: http, port: {up_port} }}]
---
apiVersion: v1
kind: Service
metadata:
  name: limited
  namespace: apps
  annotations: {{ gapura.dev/rate-limit: "3/h" }}
spec: {{ ports: [{{ name: http, port: 80 }}] }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: limited-1, namespace: apps, labels: {{ kubernetes.io/service-name: limited }} }}
addressType: IPv4
endpoints: [{{ addresses: ["{up_ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: http, port: {up_port} }}]
---
apiVersion: v1
kind: Service
metadata: {{ name: shadow-down, namespace: apps }}
spec: {{ ports: [{{ name: http, port: 80 }}] }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: shadow-down-1, namespace: apps, labels: {{ kubernetes.io/service-name: shadow-down }} }}
addressType: IPv4
endpoints: [{{ addresses: ["{dead_ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: http, port: {dead_port} }}]
---
apiVersion: v1
kind: Service
metadata: {{ name: empty, namespace: apps }}
spec: {{ ports: [{{ name: http, port: 80 }}] }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: empty-1, namespace: apps, labels: {{ kubernetes.io/service-name: empty }} }}
addressType: IPv4
endpoints: []
ports: [{{ name: http, port: 1 }}]
---
apiVersion: v1
kind: Service
metadata: {{ name: flaky, namespace: apps }}
spec: {{ ports: [{{ name: http, port: 80 }}] }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: flaky-dead, namespace: apps, labels: {{ kubernetes.io/service-name: flaky }} }}
addressType: IPv4
endpoints: [{{ addresses: ["{dead_ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: http, port: {dead_port} }}]
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: flaky-live, namespace: apps, labels: {{ kubernetes.io/service-name: flaky }} }}
addressType: IPv4
endpoints: [{{ addresses: ["{up_ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: http, port: {up_port} }}]
---
apiVersion: v1
kind: Service
metadata: {{ name: reuse, namespace: apps }}
spec: {{ ports: [{{ name: http, port: 80 }}] }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: reuse-1, namespace: apps, labels: {{ kubernetes.io/service-name: reuse }} }}
addressType: IPv4
endpoints: [{{ addresses: ["{reuse_ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: http, port: {reuse_port} }}]
"#,
        up_ip = upstream.ip(),
        up_port = upstream.port(),
        dead_ip = dead.ip(),
        dead_port = dead.port(),
        reuse_ip = reuse.ip(),
        reuse_port = reuse.port(),
    )
}

async fn setup() -> (Gateway, reqwest::Client) {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway(|http| config(http, upstream, dead, upstream)).await;
    let c = client(&gw);
    (gw, c)
}

/// True once the admin's /debug/config holds a listener on `http`: the same store the proxy
/// routes from, so a "yes" means the first config swap already happened. The port pins the answer
/// to this child: another gateway that holds this admin port serves its own config, on its own
/// http port.
async fn ready_to_serve(admin: u16, http: u16) -> bool {
    let Ok(r) = reqwest::get(format!("http://127.0.0.1:{admin}/debug/config")).await else {
        return false;
    };
    let Ok(v) = r.json::<serde_json::Value>().await else {
        return false;
    };
    v.get("listeners")
        .and_then(|l| l.as_array())
        .is_some_and(|l| l.iter().any(|l| l["port"] == http))
}

/// The request id the readiness probe sends. Each child logs to its own stdout, so finding it in
/// `gw.logs` means `gw` answered; no per-child id is needed.
const PROBE_ID: &str = "harness-readiness-probe";

/// True once a request to the http port has come back through this child's own access log. A TCP
/// accept only proves that something listens there, and a gateway whose bind lost the race is
/// still running, with the winner answering on its port. The probe matches no route, so the
/// gateway answers it with a local 404 and never contacts an upstream. Its log line is written
/// after the response, so it can show up on a later call rather than this one.
async fn answers_on_http(gw: &Gateway) -> bool {
    let _ = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/", gw.http))
        .header("x-request-id", PROBE_ID)
        .timeout(Duration::from_secs(1))
        .send()
        .await;
    gw.logged(PROBE_ID).is_some()
}

/// Start the binary on ports chosen here, rendering the config once the http port is known.
///
/// `free_port` drops its listener before the child binds, so another listener in this binary -- a
/// parallel test's gateway or upstream -- can take the same ephemeral port in between. If it does
/// before the child starts, the gateway refuses to start on an address it cannot bind, and the
/// race shows up as an immediate clean exit; retrying with fresh ports is the fix. If it does
/// between that check and Pingora's own bind, Pingora logs "is in use, will try again" and retries
/// once a second while the process stays up, and every request to the port reaches the other
/// listener. Readiness therefore demands answers from this child on both ports, which holds off
/// until the other listener's test ends and the retry wins. A child that starts but never becomes
/// ready is a real failure, and fails the test with whatever it managed to log; a holder that
/// outlived the whole wait would fail the same way, and would need a retry on fresh ports.
async fn start_gateway(render: impl Fn(u16) -> String) -> Gateway {
    start_gateway_with(render, &[]).await
}

/// `start_gateway`, plus arguments the scenario needs on the command line.
async fn start_gateway_with(render: impl Fn(u16) -> String, extra: &[&str]) -> Gateway {
    start_gateway_from(
        |dir, http| {
            std::fs::write(dir.join("config.yaml"), render(http)).unwrap();
            vec![
                "--config-dir".to_string(),
                dir.to_str().unwrap().to_string(),
            ]
        },
        extra,
    )
    .await
}

/// The gateway reading its configuration from wherever `source` says. It is handed each
/// attempt's temporary directory and HTTP port, writes there what it needs, and returns the
/// arguments that name it.
async fn start_gateway_from(
    source: impl Fn(&std::path::Path, u16) -> Vec<String>,
    extra: &[&str],
) -> Gateway {
    const ATTEMPTS: u32 = 5;
    // What the last child to exit managed to say, so the final panic can show it.
    let mut last_logs = String::new();
    for attempt in 1..=ATTEMPTS {
        let (http, admin, https) = (free_port(), free_port(), free_port());
        let dir = tempfile::tempdir().unwrap();
        let source_args = source(dir.path(), http);
        let mut child = Command::new(env!("CARGO_BIN_EXE_gapura"))
            .args(&source_args)
            .args([
                "--listen-http",
                &format!("127.0.0.1:{http}"),
                "--listen-https",
                &format!("127.0.0.1:{https}"),
                "--admin",
                &format!("127.0.0.1:{admin}"),
                "--log-level",
                "warn",
            ])
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        // Access logs go to stdout. Keep a thread draining the pipe: left unread it fills, and the
        // gateway then blocks in `logging` for as long as the test runs. The thread ends on EOF,
        // which Drop causes by killing the child.
        let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let stdout = child.stdout.take().expect("stdout is piped");
        let sink = Arc::clone(&logs);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });
        let mut gw = Gateway {
            child,
            http,
            admin,
            logs,
            _dir: dir,
        };
        let mut exited = false;
        let mut ready = false;
        for _ in 0..200 {
            if matches!(gw.child.try_wait(), Ok(Some(_))) {
                exited = true;
                break;
            }
            if let Ok(r) = reqwest::get(format!("http://127.0.0.1:{admin}/readyz")).await {
                // Pingora binds each service independently: /readyz only proves the admin listener,
                // and `answers_on_http` only proves the data port. Neither proves the first
                // config swap reached the store the proxy routes from -- on a loaded runner the
                // gap was observable as a 404 "no route" for the test's first request. The store
                // is the same one /debug/config serves, so waiting for it to hold this child's
                // listener is waiting for the proxy to have something to route with.
                if r.status() == 200
                    && answers_on_http(&gw).await
                    && ready_to_serve(admin, http).await
                {
                    ready = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if ready {
            return gw;
        }
        if !exited {
            let captured = gw.logs.lock().unwrap().join("\n");
            panic!(
                "gateway started on http={http} admin={admin} but never became ready; \
                 its stdout was:\n{captured}"
            );
        }
        last_logs = gw.logs.lock().unwrap().join("\n");
        eprintln!(
            "gateway exited before becoming ready on attempt {attempt}, retrying on new ports"
        );
    }
    panic!(
        "the gateway exited before becoming ready on all {ATTEMPTS} attempts. Either it lost the \
         port race every time, or it cannot start at all -- the second is a real regression and \
         looks identical from here. Its stdout on the last attempt was:\n{last_logs}"
    );
}

/// A data plane in `--control-plane` mode, polling a stand-in that serves one configuration:
/// whatever `snapshot` compiles to once the gateway's HTTP port is known. Policies exist only in
/// store mode, so this is the way to a refused credential.
async fn start_store_gateway(snapshot: gapura_core::store::StoreSnapshot) -> Gateway {
    let served = Arc::new(Mutex::new(String::new()));
    let body = Arc::clone(&served);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let control = listener.local_addr().unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let app = Router::new().route(
        "/v1/config",
        axum::routing::get(move || {
            let config = body.lock().unwrap().clone();
            async move {
                (
                    [("content-type", "application/json"), ("etag", "\"v1\"")],
                    config,
                )
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    start_gateway_from(
        move |dir, http| {
            let settings = gapura_core::store::StoreSettings {
                http_ports: vec![http],
            };
            let config = gapura_core::store::compile(&snapshot, &settings);
            *served.lock().unwrap() = serde_json::to_string(&config).unwrap();
            let token = dir.join("token");
            std::fs::write(&token, "e2e").unwrap();
            vec![
                "--control-plane".to_string(),
                format!("http://{control}"),
                "--control-plane-insecure-http".to_string(),
                "--control-plane-token-file".to_string(),
                token.to_str().unwrap().to_string(),
            ]
        },
        &[],
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn routes_with_request_and_response_filters() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/api/x?y=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-resp"], "yes");
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    assert_eq!(rid.len(), 32, "generated request id is 32 hex chars");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["path"], "/api/x");
    assert_eq!(body["query"], "y=1");
    let h = &body["headers"];
    assert_eq!(h["x-gateway"], "gapura");
    assert_eq!(h["x-add"], "one");
    assert_eq!(h["x-forwarded-proto"], "http");
    assert_eq!(h["x-forwarded-host"], "echo.test");
    assert_eq!(h["x-forwarded-for"], "127.0.0.1");
    assert_eq!(h["x-request-id"], rid);
    assert!(h["traceparent"].as_str().unwrap().starts_with("00-"));
}

#[tokio::test(flavor = "multi_thread")]
async fn request_id_and_traceparent_pass_through() {
    let (gw, c) = setup().await;
    let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let r = c
        .get(url(&gw, "echo.test", "/api"))
        .header("X-Request-Id", "abc-123")
        .header("traceparent", tp)
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["x-request-id"], "abc-123");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["headers"]["x-request-id"], "abc-123");
    assert_eq!(body["headers"]["traceparent"], tp);
}

#[tokio::test(flavor = "multi_thread")]
async fn url_rewrite_changes_path_and_host() {
    let (gw, c) = setup().await;
    let body: Value = c
        .get(url(&gw, "echo.test", "/rewrite/a/b?k=v"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["path"], "/internal/a/b");
    assert_eq!(body["query"], "k=v");
    assert_eq!(body["headers"]["host"], "internal.svc");
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_is_answered_locally() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/old/thing"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 301);
    assert_eq!(r.headers()["location"], "https://new.test/new");
    assert!(r.headers().contains_key("x-request-id"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_remaining_crd_redirect_status_codes_answer_locally() {
    let (gw, c) = setup().await;
    for code in [303u16, 307, 308] {
        let r = c
            .get(url(&gw, "echo.test", &format!("/status{code}/x")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), code, "GET /status{code}");
        assert_eq!(
            r.headers()["location"],
            format!("https://new.test/status{code}/x")
        );
        assert!(
            r.headers().contains_key("x-request-id"),
            "answered locally like every redirect"
        );
        // A redirect response is headers-only and never touches the method: a POST is answered
        // with the same status instead of being proxied or rewritten.
        let r = c
            .post(url(&gw, "echo.test", &format!("/status{code}/x")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), code, "POST /status{code}");
        assert_eq!(
            r.headers()["location"],
            format!("https://new.test/status{code}/x")
        );
        assert_eq!(r.text().await.unwrap(), "", "no body on a redirect");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn regex_path_match_routes() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/v42/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["path"], "/v42/info");
    let r = c
        .get(url(&gw, "echo.test", "/vx/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        404,
        "a path the pattern does not match has no other rule to catch it"
    );
}

/// Poll the admin /metrics text until it contains `needle`, or panic with what it last saw.
/// The mirror is fire-and-forget, so its metric lands shortly after the primary responded.
async fn wait_for_metric(gw: &Gateway, needle: &str) {
    for _ in 0..200 {
        let text = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        if text.contains(needle) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("metric {needle:?} never showed up on the admin endpoint");
}

#[tokio::test(flavor = "multi_thread")]
async fn mirrored_requests_fire_and_are_counted() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/mirror/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "the primary is unaffected by the mirror");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["path"], "/mirror/x");
    wait_for_metric(
        &gw,
        "gapura_mirror_requests_total{result=\"sent\",route=\"apps/echo\"}",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retry_on_a_reused_connection_mirrors_only_once() {
    // #145: pingora runs upstream_request_filter on every attempt, and error_while_proxy grants
    // one retry when a reused upstream connection fails. The first attempt had already run the
    // filter, so the retry fired the mirror a second time for the same request.
    let reuse = spawn_closing_upstream().await;
    let dead = SocketAddr::from(([127, 0, 0, 1], 1));
    // A live echo for the mirror to land on; the primary uses the closing upstream.
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    let gw = start_gateway(move |http| config(http, upstream, dead, reuse)).await;
    let c = client(&gw);
    let r = c
        .get(url(&gw, "other.test", "/reusedmirror/a"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "the first request is served and mirrored");
    let r = c
        .get(url(&gw, "other.test", "/reusedmirror/b"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "the pooled connection is dead, the retry on the fresh one serves"
    );
    // One copy per request, on this route's own label so nothing else moves the count. Copies
    // land milliseconds apart, so wait for the total, settle, and require it to hold.
    wait_for_metric(
        &gw,
        "gapura_mirror_requests_total{result=\"sent\",route=\"apps/other\"} 2",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("gapura_mirror_requests_total{result=\"sent\",route=\"apps/other\"} 2"),
        "each request is mirrored exactly once, retry included: {metrics}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dead_mirror_backend_leaves_the_primary_alone() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/mirrordown/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "a failing mirror must never fail the primary request"
    );
    wait_for_metric(
        &gw,
        "gapura_mirror_requests_total{result=\"error\",route=\"apps/echo\"}",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn not_found_for_unknown_host_and_unmatched_path() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "unknown.test", "/api"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(r.headers()["x-gapura-error"], "NO_ROUTE");
    assert_eq!(r.text().await.unwrap(), "404 no route\n");
    // The same answer for a caller that asked for JSON, and the key in its access log line.
    let r = c
        .get(url(&gw, "unknown.test", "/api"))
        .header("accept", "application/json")
        .header("x-request-id", "no-route-json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(r.headers()["content-type"], "application/json");
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": {"key": "NO_ROUTE", "message": "no route", "request_id": "no-route-json"}})
    );
    let line = gw.access_log("no-route-json").await;
    assert_eq!(line["error_key"], "NO_ROUTE", "{line}");
    let r = c
        .get(url(&gw, "echo.test", "/nomatch"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = c
        .get(url(&gw, "other.test", "/anything"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "second route on the same listener");
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_backend_is_500_and_no_endpoints_is_503() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/nobackend"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 500);
    assert_eq!(r.headers()["x-gapura-error"], "NO_BACKEND");
    assert_eq!(r.text().await.unwrap(), "500 no valid backend\n");
    let r = c
        .get(url(&gw, "echo.test", "/empty"))
        .header("x-request-id", "empty")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["x-gapura-error"], "NO_ENDPOINTS");
    assert_eq!(r.text().await.unwrap(), "503 no ready endpoints\n");
    let line = gw.access_log("empty").await;
    assert_eq!(line["error_key"], "NO_ENDPOINTS", "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_failure_retries_once_on_another_endpoint() {
    let (gw, c) = setup().await;
    let r = c.get(url(&gw, "echo.test", "/retry")).send().await.unwrap();
    let status = r.status();
    // Which endpoint answered, and why it failed, is only visible in the body and the access log
    // (it carries the upstream address and the error), so a failure here has to carry both.
    let body = r.text().await.unwrap();
    assert_eq!(
        status,
        200,
        "first endpoint is dead, retry hits the live one; body={body:?} log={:?}",
        gw.logs.lock().unwrap()
    );
    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics
            .contains(r#"gapura_upstream_errors_total{cluster="apps/flaky:80",kind="connect"} 1"#),
        "{metrics}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dead_endpoint_is_ejected_and_stops_receiving_traffic() {
    let (gw, c) = setup().await;
    // `flaky` is the dead 127.0.0.1:1 and the live echo, dead first. Each request moves the
    // round-robin cursor twice (the retry asks again), so every first attempt lands on the dead
    // endpoint until five connect errors in a row eject it.
    for i in 0..20 {
        let r = c.get(url(&gw, "echo.test", "/retry")).send().await.unwrap();
        assert_eq!(r.status(), 200, "request {i}");
    }
    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // Every attempt on the dead endpoint is a connect error: five after twenty requests means it
    // got nothing once it was ejected.
    for needle in [
        r#"gapura_upstream_errors_total{cluster="apps/flaky:80",kind="connect"} 5"#,
        r#"gapura_upstream_ejections_total{cluster="apps/flaky:80"} 1"#,
        r#"gapura_upstream_ejected_endpoints{cluster="apps/flaky:80"} 1"#,
    ] {
        assert!(
            metrics.contains(needle),
            "{needle} missing from:\n{metrics}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn backend_timeout_is_504_and_zero_disables_it() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/slow"))
        .header("x-request-id", "slow")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 504);
    assert_eq!(r.headers()["x-gapura-error"], "UPSTREAM_TIMEOUT");
    let line = gw.access_log("slow").await;
    assert_eq!(line["error_key"], "UPSTREAM_TIMEOUT", "{line}");
    let r = c
        .get(url(&gw, "echo.test", "/noslow"))
        .header("x-request-id", "noslow")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "0s disables the timeout, the 600 ms upstream still answers"
    );
    assert!(
        r.headers().get("x-gapura-error").is_none(),
        "an upstream's answer carries no key"
    );
    let line = gw.access_log("noslow").await;
    assert!(line["error_key"].is_null(), "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_endpoints() {
    let (gw, c) = setup().await;
    c.get(url(&gw, "echo.test", "/api")).send().await.unwrap();
    let base = format!("http://127.0.0.1:{}", gw.admin);
    assert_eq!(
        reqwest::get(format!("{base}/healthz"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok\n"
    );
    assert_eq!(
        reqwest::get(format!("{base}/readyz"))
            .await
            .unwrap()
            .status(),
        200
    );
    let metrics = reqwest::get(format!("{base}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains(r#"gapura_requests_total{code="200",route="apps/echo"}"#),
        "{metrics}"
    );
    let cfg: Value = reqwest::get(format!("{base}/debug/config"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["listeners"][0]["id"], "infra/main/http");
    assert_eq!(
        reqwest::get(format!("{base}/nope")).await.unwrap().status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_gateway_on_the_same_port_is_reachable() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "second.test", "/anything"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "a route attached to the second Gateway must be served"
    );
    assert_eq!(r.headers()["x-gateway-name"], "second");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["headers"]["x-forwarded-host"], "second.test");
    // The first Gateway keeps working on the same port.
    let first = c.get(url(&gw, "echo.test", "/api")).send().await.unwrap();
    assert_eq!(first.status(), 200);
    assert_eq!(first.headers()["x-resp"], "yes");
}

#[tokio::test(flavor = "multi_thread")]
async fn access_log_of_a_proxied_request_times_the_upstream_leg() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/api/logged"))
        .header("X-Request-Id", "log-proxied")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let line = gw.access_log("log-proxied").await;
    assert_eq!(line["status"], 200, "{line}");
    assert_eq!(line["route"], "apps/echo", "{line}");
    let upstream_ms = line["upstream_duration_ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("a proxied request records the upstream leg: {line}"));
    assert!(
        upstream_ms <= line["duration_ms"].as_u64().unwrap(),
        "the upstream leg is part of the request, not longer than it: {line}"
    );
    assert_eq!(line["client_abort"], false, "{line}");
}

/// A client that goes away mid-request: the header promises a body that never arrives and the
/// connection is closed instead. That is a downstream failure, and the log must call it an abort
/// rather than a gateway error.
#[tokio::test(flavor = "multi_thread")]
async fn access_log_records_a_client_that_went_away() {
    let (gw, _c) = setup().await;
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", gw.http))
        .await
        .unwrap();
    sock.write_all(
        concat!(
            // The path carries "slow" on purpose: the mock upstream sleeps 600 ms for it, so it
            // cannot answer before the half-close below lands. Without that, which side ended
            // the request was a race -- on a fast runner the 200 came back first and the line
            // logged status 200 with client_abort, not the status 0 this test asserts.
            "POST /api/slow-abort HTTP/1.1\r\n",
            "Host: echo.test\r\n",
            "X-Request-Id: log-abort\r\n",
            "Content-Length: 32\r\n",
            "\r\n",
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    // Half-close: the request body can never arrive now, so the gateway's read of it fails.
    sock.shutdown().await.unwrap();
    let line = gw.access_log("log-abort").await;
    assert_eq!(line["client_abort"], true, "{line}");
    assert_eq!(
        line["status"], 0,
        "an abort is not answered, so there is no status to log: {line}"
    );
    drop(sock);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rate_limited_route_answers_429_with_the_headers_a_client_reads() {
    let (gw, c) = setup().await;
    // The window is an hour, far longer than any run of this test: no schedule of requests can
    // cross a bucket boundary inside it, so the fixed window is a plain counter here and the
    // fourth request is 429 by construction (#57 — at 3/min a slow runner could spread the
    // burst across two 60s windows and never trip it).
    for i in 0..3 {
        let r = c
            .get(url(&gw, "echo.test", "/limited"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "request {i} is inside the allowance");
    }
    let r = c
        .get(url(&gw, "echo.test", "/limited"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429, "the request past the allowance");
    assert_eq!(r.headers()["x-gapura-error"], "RATE_LIMITED");
    assert_eq!(r.headers()["x-ratelimit-limit"], "3");
    assert_eq!(r.headers()["x-ratelimit-remaining"], "0");
    let retry: u64 = r.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (1..=3600).contains(&retry),
        "the rest of this hour's window: {retry}"
    );
    assert!(r.headers().contains_key("x-request-id"));
    assert_eq!(r.text().await.unwrap(), "429 too many requests\n");
    // The rejection is a fact of the route, so it is counted where the traffic is.
    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("gapura_rate_limited_total"), "{metrics}");
}

/// A key_auth route on `/keyed`, and two callers: one without a key, one with a key no consumer
/// was issued. The key says which of the two, and nothing about why.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_api_key_is_401_and_says_missing_or_invalid() {
    use gapura_core::config::{KeyAuthPolicy, PathMatch, Plugin, Protocol};
    use gapura_core::store::{StorePlugin, StoreRoute, StoreService, StoreSnapshot};
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    let gw = start_store_gateway(StoreSnapshot {
        services: vec![StoreService {
            workspace: String::new(),
            name: "echo".into(),
            protocol: Protocol::Http,
            host: upstream.ip().to_string(),
            port: upstream.port(),
            connect_timeout_ms: None,
            read_timeout_ms: None,
            tls_verify: true,
            tls_ca_pem: None,
            tls_sni: None,
        }],
        routes: vec![StoreRoute {
            workspace: String::new(),
            name: "keyed".into(),
            service: "echo".into(),
            hosts: vec![],
            paths: vec![PathMatch::Prefix("/keyed".into())],
            methods: vec![],
            headers: vec![],
            strip_path: false,
            priority: 0,
        }],
        plugins: vec![StorePlugin {
            workspace: String::new(),
            route: Some("keyed".into()),
            service: None,
            plugin: Plugin::KeyAuth(KeyAuthPolicy::default()),
        }],
        ..StoreSnapshot::default()
    })
    .await;
    let c = client(&gw);
    let r = c
        .get(url(&gw, "echo.test", "/keyed"))
        .header("x-request-id", "no-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Key realm=\"x-api-key\"");
    assert_eq!(r.headers()["x-gapura-error"], "AUTH_KEY_MISSING");
    assert_eq!(r.text().await.unwrap(), "401 unauthorized\n");
    let line = gw.access_log("no-key").await;
    assert_eq!(line["status"], 401, "{line}");
    assert_eq!(line["error_key"], "AUTH_KEY_MISSING", "{line}");

    let r = c
        .get(url(&gw, "echo.test", "/keyed"))
        .header("x-api-key", "never-issued")
        .header("accept", "application/json")
        .header("x-request-id", "bad-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["x-gapura-error"], "AUTH_KEY_INVALID");
    assert_eq!(r.headers()["content-type"], "application/json");
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": {"key": "AUTH_KEY_INVALID", "message": "unauthorized", "request_id": "bad-key"}})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unlimited_route_is_untouched_by_a_neighbors_limit() {
    let (gw, c) = setup().await;
    // The limit lives on the rule whose backend carries the annotation; /api/x backs onto the
    // unannotated echo service and must keep answering.
    for _ in 0..5 {
        let r = c.get(url(&gw, "echo.test", "/api/x")).send().await.unwrap();
        assert_eq!(r.status(), 200, "no annotation, no limit");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trusted_proxy_may_name_the_client_in_the_access_log() {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway_with(
        |http| config(http, upstream, dead, upstream),
        &["--trusted-proxy", "127.0.0.0/8"],
    )
    .await;
    let r = client(&gw)
        .get(url(&gw, "echo.test", "/api/x"))
        .header("x-forwarded-for", "198.51.100.5")
        .send()
        .await
        .unwrap();
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    let line = gw.access_log(&rid).await;
    assert_eq!(
        line["client_ip"], "198.51.100.5",
        "the connection came from a trusted network, so its header names the client"
    );
}

/// #160: a trusted proxy that adds its own `X-Forwarded-For` line instead of appending to the
/// client's. The client's line comes first and must never be read as the client.
#[tokio::test(flavor = "multi_thread")]
async fn every_forwarded_for_line_is_walked_behind_a_trusted_proxy() {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway_with(
        |http| config(http, upstream, dead, upstream),
        &["--trusted-proxy", "127.0.0.0/8"],
    )
    .await;
    let r = client(&gw)
        .get(url(&gw, "echo.test", "/api/x"))
        .header("x-forwarded-for", "6.6.6.6")
        .header("x-forwarded-for", "198.51.100.5")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body["headers"]["x-forwarded-for"], "6.6.6.6, 198.51.100.5, 127.0.0.1",
        "every inbound line is kept, in order, with the peer appended"
    );
    let line = gw.access_log(&rid).await;
    assert_eq!(line["client_ip"], "198.51.100.5", "{line}");
}

/// #161: matched on the first `Host` line, a backend could serve the second. Two lines are a
/// malformed request and are refused before any route is consulted.
#[tokio::test(flavor = "multi_thread")]
async fn two_host_lines_are_refused_as_400() {
    let (gw, _c) = setup().await;
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", gw.http))
        .await
        .unwrap();
    sock.write_all(
        concat!(
            "GET /api/x HTTP/1.1\r\n",
            "Host: echo.test\r\n",
            "Host: other.test\r\n",
            "X-Request-Id: two-hosts\r\n",
            "Connection: close\r\n",
            "\r\n",
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    sock.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-gapura-error: invalid_request_target"),
        "{response}"
    );
    let line = gw.access_log("two-hosts").await;
    assert_eq!(line["status"], 400, "{line}");
    assert_eq!(line["error_key"], "INVALID_REQUEST_TARGET", "{line}");
    assert_eq!(line["route"], "-", "no route is consulted: {line}");
    assert!(line["upstream"].is_null(), "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_status_serves_the_computed_patches() {
    let (gw, _c) = setup().await;
    let v: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{}/debug/status", gw.admin))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = v.as_array().unwrap();
    assert!(
        !arr.is_empty(),
        "file mode has no API server: this is the only place the conditions live: {v}"
    );
    assert!(
        arr.iter()
            .any(|p| p["kind"] == "Gateway" || p["kind"] == "HTTPRoute"),
        "the config fixture has a Gateway and routes, so both carry conditions: {v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_query_string_is_logged_only_when_asked_for() {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway_with(
        |http| config(http, upstream, dead, upstream),
        &["--access-log-query"],
    )
    .await;
    let r = client(&gw)
        .get(url(&gw, "echo.test", "/api/x?msg=it-works&page=2"))
        .send()
        .await
        .unwrap();
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    let line = gw.access_log(&rid).await;
    assert_eq!(
        line["query"], "msg=it-works&page=2",
        "the deployment asked, so the line names the exact request: {line}"
    );
    assert_eq!(
        line["path"], "/api/x",
        "the path never carries the query: {line}"
    );

    // Without the flag the field is absent -- not null, absent -- so the default keeps
    // tokens out of the log without every consumer having to know about it.
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway_with(|http| config(http, upstream, dead, upstream), &[]).await;
    let r = client(&gw)
        .get(url(&gw, "echo.test", "/api/x?msg=secret-token"))
        .send()
        .await
        .unwrap();
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    let line = gw.access_log(&rid).await;
    assert!(line.get("query").is_none(), "no flag, no query: {line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_named_client_header_is_believed_behind_a_trusted_proxy() {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway_with(
        |http| config(http, upstream, dead, upstream),
        &[
            "--trusted-proxy",
            "127.0.0.0/8",
            "--trusted-client-header",
            "CF-Connecting-IP",
        ],
    )
    .await;
    // No X-Forwarded-For at all -- the CDN-tunnel shape -- only the named header.
    let r = client(&gw)
        .get(url(&gw, "echo.test", "/api/x"))
        .header("CF-Connecting-IP", "198.51.100.7")
        .send()
        .await
        .unwrap();
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    let line = gw.access_log(&rid).await;
    assert_eq!(
        line["client_ip"], "198.51.100.7",
        "trusted peer, no chain: the named header is the only place the client is named"
    );

    // A chain that names a client still wins over the header.
    let r = client(&gw)
        .get(url(&gw, "echo.test", "/api/x"))
        .header("CF-Connecting-IP", "203.0.113.1")
        .header("X-Forwarded-For", "198.51.100.5")
        .send()
        .await
        .unwrap();
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    let line = gw.access_log(&rid).await;
    assert_eq!(
        line["client_ip"], "198.51.100.5",
        "a chain that names a client keeps its precedence: {line}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_named_client_header_from_an_untrusted_peer_is_ignored() {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway_with(
        |http| config(http, upstream, dead, upstream),
        &["--trusted-client-header", "CF-Connecting-IP"],
    )
    .await;
    let r = client(&gw)
        .get(url(&gw, "echo.test", "/api/x"))
        .header("CF-Connecting-IP", "198.51.100.7")
        .send()
        .await
        .unwrap();
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    let line = gw.access_log(&rid).await;
    assert_eq!(
        line["client_ip"], "127.0.0.1",
        "no trusted network, so the header is not believed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_untrusted_caller_cannot_name_itself_in_the_access_log() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "echo.test", "/api/x"))
        .header("x-forwarded-for", "198.51.100.5")
        .send()
        .await
        .unwrap();
    let rid = r.headers()["x-request-id"].to_str().unwrap().to_string();
    let line = gw.access_log(&rid).await;
    assert_eq!(
        line["client_ip"], "127.0.0.1",
        "no trusted network is configured, so the header is not believed"
    );
}

/// The store-mode snapshot: one route for echo.test to the echo upstream behind key_auth,
/// limited for everyone to 3 an hour per address and for `tight` to 2 an hour of its own, counted
/// per consumer. Hour windows, so no run of the test crosses a boundary (#57).
fn consumer_limited(upstream: SocketAddr) -> gapura_core::store::StoreSnapshot {
    use gapura_core::config::{KeyAuthPolicy, LimitBy, PathMatch, Plugin, Protocol, RateLimit};
    use gapura_core::store::{
        StoreCredential, StorePlugin, StoreRateLimit, StoreRoute, StoreService, StoreSnapshot,
    };
    use sha2::{Digest, Sha256};
    let hash = |key: &str| -> String {
        Sha256::digest(key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let hour = |limit, by| RateLimit {
        limit,
        window_ms: 3_600_000,
        by,
    };
    StoreSnapshot {
        services: vec![StoreService {
            workspace: "shop".into(),
            name: "echo".into(),
            protocol: Protocol::Http,
            host: upstream.ip().to_string(),
            port: upstream.port(),
            connect_timeout_ms: None,
            read_timeout_ms: None,
            tls_verify: true,
            tls_ca_pem: None,
            tls_sni: None,
        }],
        routes: vec![StoreRoute {
            workspace: "shop".into(),
            name: "api".into(),
            service: "echo".into(),
            hosts: vec!["echo.test".into()],
            paths: vec![PathMatch::Prefix("/".into())],
            methods: vec![],
            headers: vec![],
            strip_path: false,
            priority: 0,
        }],
        plugins: vec![StorePlugin {
            workspace: "shop".into(),
            route: None,
            service: None,
            plugin: Plugin::KeyAuth(KeyAuthPolicy::default()),
        }],
        credentials: ["tight", "roomy"]
            .map(|c| StoreCredential {
                key_hash: hash(&format!("{c}-key")),
                consumer: c.into(),
                workspace: "shop".into(),
            })
            .into(),
        rate_limits: vec![
            StoreRateLimit {
                workspace: "shop".into(),
                route: None,
                service: None,
                consumer: None,
                limit: hour(3, LimitBy::Ip),
            },
            StoreRateLimit {
                workspace: "shop".into(),
                route: Some("api".into()),
                service: None,
                consumer: Some("tight".into()),
                limit: hour(2, LimitBy::Consumer),
            },
        ],
    }
}

/// A consumer's own limit, end to end: once key_auth has named the caller, `tight` is held to
/// its own 2 an hour while `roomy`, from the same address, still has the 3 an hour everyone has
/// -- untouched by `tight`'s requests, which count in a window of their own.
///
/// Two things the limit must not leak. The upstream is told the bare username, not the
/// `workspace/username` the data plane counts under. And the metric is labelled with the rule,
/// never the consumer, because a label per consumer grows without bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_consumer_s_own_limit_holds_it_and_no_one_else() {
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    let gw = start_store_gateway(consumer_limited(upstream)).await;
    let c = client(&gw);
    let status = |key: Option<&'static str>| {
        let mut req = c.get(url(&gw, "echo.test", "/"));
        if let Some(key) = key {
            req = req.header("x-api-key", key);
        }
        async move { req.send().await.unwrap().status() }
    };
    let r = c
        .get(url(&gw, "echo.test", "/"))
        .header("x-api-key", "tight-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "tight 0");
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body["headers"][gapura_core::credentials::CONSUMER_HEADER],
        "tight",
        "the upstream is told the bare username, not the workspace-qualified id"
    );
    assert_eq!(status(Some("tight-key")).await, 200, "tight 1");
    let r = c
        .get(url(&gw, "echo.test", "/"))
        .header("x-api-key", "tight-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429, "past tight's own allowance");
    assert_eq!(r.headers()["x-ratelimit-limit"], "2");
    for i in 0..3 {
        assert_eq!(status(Some("roomy-key")).await, 200, "roomy {i}");
    }
    assert_eq!(
        status(Some("roomy-key")).await,
        429,
        "past everyone's allowance"
    );
    // Without a key key_auth refuses first: there is no consumer, and no limit is spent.
    assert_eq!(status(None).await, 401);

    // Both refusals above were counted, under the rule's name: `tight`'s own limit does not
    // get a label of its own, and no consumer's name reaches the metrics at all.
    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics
            .lines()
            .any(|l| l == r#"gapura_rate_limited_total{route="shop/api#0"} 2"#),
        "both 429s count under the rule's label:\n{metrics}"
    );
    let named: Vec<&str> = metrics
        .lines()
        .filter(|l| l.contains("tight") || l.contains("roomy"))
        .collect();
    assert!(
        named.is_empty(),
        "a consumer's name is a metric label: {named:?}"
    );
}
