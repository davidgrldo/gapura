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
use tokio::io::AsyncWriteExt;

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

/// `(dead, live)` on 127.0.0.1 with `dead.port() < live.port()`. The dead listener is dropped so
/// connects are refused; the live one serves the echo upstream. Clusters sort endpoints by
/// (address, port) and round-robin starts at 0, so the retry scenario always tries dead first.
async fn spawn_dead_and_upstream() -> (SocketAddr, SocketAddr) {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let (dead, live) = if a.local_addr().unwrap().port() < b.local_addr().unwrap().port() {
        (a, b)
    } else {
        (b, a)
    };
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    (dead_addr, spawn_upstream(live).await)
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
fn config(http_port: u16, upstream: SocketAddr, dead: SocketAddr) -> String {
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
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{ name: other, namespace: apps, generation: 1, creationTimestamp: "2026-09-10T00:00:00Z" }}
spec:
  parentRefs: [{{ name: main, namespace: infra }}]
  hostnames: [other.test]
  rules:
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
"#,
        up_ip = upstream.ip(),
        up_port = upstream.port(),
        dead_ip = dead.ip(),
        dead_port = dead.port(),
    )
}

async fn setup() -> (Gateway, reqwest::Client) {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let http = free_port();
    let gw = start_gateway(config(http, upstream, dead), http).await;
    let c = client(&gw);
    (gw, c)
}

/// Start the binary with HTTP bound on `http`, the port the config was rendered with.
async fn start_gateway(yaml: String, http: u16) -> Gateway {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.yaml"), yaml).unwrap();
    let admin = free_port();
    let https = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gapura"))
        .args([
            "--config-dir",
            dir.path().to_str().unwrap(),
            "--listen-http",
            &format!("127.0.0.1:{http}"),
            "--listen-https",
            &format!("127.0.0.1:{https}"),
            "--admin",
            &format!("127.0.0.1:{admin}"),
            "--log-level",
            "warn",
        ])
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
    let gw = Gateway {
        child,
        http,
        admin,
        logs,
        _dir: dir,
    };
    for _ in 0..200 {
        if let Ok(r) = reqwest::get(format!("http://127.0.0.1:{admin}/readyz")).await {
            // Pingora binds each service independently: /readyz only proves the admin listener
            // and the loaded config, so also wait for the data-plane port to accept connections.
            if r.status() == 200 && std::net::TcpStream::connect(("127.0.0.1", http)).is_ok() {
                return gw;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("gateway did not become ready");
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
async fn not_found_for_unknown_host_and_unmatched_path() {
    let (gw, c) = setup().await;
    let r = c
        .get(url(&gw, "unknown.test", "/api"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(r.text().await.unwrap(), "404 no route\n");
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
    assert_eq!(r.text().await.unwrap(), "500 no valid backend\n");
    let r = c.get(url(&gw, "echo.test", "/empty")).send().await.unwrap();
    assert_eq!(r.status(), 503);
    assert_eq!(r.text().await.unwrap(), "503 no ready endpoints\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_failure_retries_once_on_another_endpoint() {
    let (gw, c) = setup().await;
    let r = c.get(url(&gw, "echo.test", "/retry")).send().await.unwrap();
    assert_eq!(
        r.status(),
        200,
        "first endpoint is dead, retry hits the live one"
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
async fn backend_timeout_is_504_and_zero_disables_it() {
    let (gw, c) = setup().await;
    let r = c.get(url(&gw, "echo.test", "/slow")).send().await.unwrap();
    assert_eq!(r.status(), 504);
    let r = c
        .get(url(&gw, "echo.test", "/noslow"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "0s disables the timeout, the 600 ms upstream still answers"
    );
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
            "POST /api/abort HTTP/1.1\r\n",
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
