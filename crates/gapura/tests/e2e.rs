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
"#,
        up_ip = upstream.ip(),
        up_port = upstream.port(),
        dead_ip = dead.ip(),
        dead_port = dead.port(),
    )
}

async fn setup() -> (Gateway, reqwest::Client) {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway(|http| config(http, upstream, dead)).await;
    let c = client(&gw);
    (gw, c)
}

/// True once the admin's /debug/config holds at least one listener: the same store the proxy
/// routes from, so a "yes" means the first config swap already happened.
async fn ready_to_serve(admin: u16) -> bool {
    let Ok(r) = reqwest::get(format!("http://127.0.0.1:{admin}/debug/config")).await else {
        return false;
    };
    let Ok(v) = r.json::<serde_json::Value>().await else {
        return false;
    };
    v.get("listeners")
        .and_then(|l| l.as_array())
        .is_some_and(|l| !l.is_empty())
}

/// Start the binary on ports chosen here, rendering the config once the http port is known.
///
/// `free_port` drops its listener before the child binds, so another test binary running in
/// parallel can take the same ephemeral port in between. The gateway refuses to start on an
/// address it cannot bind, so that race shows up as an immediate clean exit; retrying with fresh
/// ports is the fix. A child that starts but never becomes ready is a real failure, not a race,
/// and fails the test with whatever it managed to log.
async fn start_gateway(render: impl Fn(u16) -> String) -> Gateway {
    start_gateway_with(render, &[]).await
}

/// `start_gateway`, plus arguments the scenario needs on the command line.
async fn start_gateway_with(render: impl Fn(u16) -> String, extra: &[&str]) -> Gateway {
    const ATTEMPTS: u32 = 5;
    // What the last child to exit managed to say, so the final panic can show it.
    let mut last_logs = String::new();
    for attempt in 1..=ATTEMPTS {
        let (http, admin, https) = (free_port(), free_port(), free_port());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.yaml"), render(http)).unwrap();
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
                // and a TCP accept on the data port only proves its socket. Neither proves the
                // first config swap reached the store the proxy routes from -- on a loaded runner
                // the gap was observable as a 404 "no route" for the test's first request. The
                // store is the same one /debug/config serves, so waiting for it to hold at least
                // one listener is waiting for the proxy to have something to route with.
                if r.status() == 200
                    && std::net::TcpStream::connect(("127.0.0.1", http)).is_ok()
                    && ready_to_serve(admin).await
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
    // The rejection is a fact of the route, so it is counted where the traffic is.
    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("gapura_rate_limited_total"), "{metrics}");
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
        |http| config(http, upstream, dead),
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
    let gw = start_gateway_with(|http| config(http, upstream, dead), &["--access-log-query"]).await;
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
    let gw = start_gateway_with(|http| config(http, upstream, dead), &[]).await;
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
        |http| config(http, upstream, dead),
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
        |http| config(http, upstream, dead),
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
