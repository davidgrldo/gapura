//! End-to-end: the real `gapura` binary, configured from a generated config dir or a stub control
//! plane, against a mock upstream.

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

/// Echo upstream: JSON with method, path, query, headers, and `values`, every value of each header
/// in the order it arrived. `headers` keeps one value a name, the last, so it cannot show a header
/// sent twice; `values` can. Paths containing `slow` sleep 600 ms.
async fn echo(req: Request) -> Json<Value> {
    if req.uri().path().contains("slow") {
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
    let text = |v: &axum::http::HeaderValue| {
        Value::String(String::from_utf8_lossy(v.as_bytes()).into_owned())
    };
    let headers: serde_json::Map<String, Value> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), text(v)))
        .collect();
    let mut values = serde_json::Map::new();
    for (k, v) in req.headers() {
        if let Value::Array(list) = values
            .entry(k.as_str())
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            list.push(text(v));
        }
    }
    Json(
        json!({ "method": req.method().as_str(), "path": req.uri().path(), "query": req.uri().query(), "headers": headers, "values": values }),
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

/// An upstream that answers each connection once with `answer`, then closes the socket a moment
/// later. Unless `answer` says `connection: close`, it closes without saying so: Pingora finishes
/// the response and pools the connection before the FIN arrives, so the next request is handed a
/// connection the backend has already closed -- the common case `error_while_proxy` grants one
/// retry for.
async fn spawn_closing_upstream(answer: &'static [u8]) -> SocketAddr {
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
                let _ = sock.write_all(answer).await;
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

/// One POST a stand-in collector received.
#[derive(Clone)]
struct Posted {
    path: String,
    headers: axum::http::HeaderMap,
    body: Value,
    /// Whether the collector answered it 500.
    refused: bool,
}

/// A stand-in log and trace collector: it keeps every POST and answers the first `refuse_first`
/// of them 500, the rest 200.
async fn spawn_collector(refuse_first: usize) -> (SocketAddr, Arc<Mutex<Vec<Posted>>>) {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let posted: Arc<Mutex<Vec<Posted>>> = Arc::default();
    let sent = Arc::new(AtomicUsize::new(0));
    let keep = Arc::clone(&posted);
    let app = Router::new().fallback(any(move |req: Request| {
        let (keep, sent) = (Arc::clone(&keep), Arc::clone(&sent));
        async move {
            let path = req.uri().path().to_string();
            let headers = req.headers().clone();
            let bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
                .await
                .unwrap();
            let body = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
            let refused = sent.fetch_add(1, SeqCst) < refuse_first;
            keep.lock().unwrap().push(Posted {
                path,
                headers,
                body,
                refused,
            });
            if refused {
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            } else {
                axum::http::StatusCode::OK
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, posted)
}

/// What the collector took at `path`: every record of every POST it answered 200, an access-log
/// line for `/logs` and an OTLP span for anything else.
fn delivered(posted: &[Posted], path: &str) -> Vec<Value> {
    posted
        .iter()
        .filter(|p| p.path == path && !p.refused)
        .flat_map(|p| match path {
            "/logs" => p.body.as_array().cloned().unwrap_or_default(),
            _ => p.body["resourceSpans"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|rs| rs["scopeSpans"].as_array().into_iter().flatten())
                .flat_map(|ss| ss["spans"].as_array().cloned().unwrap_or_default())
                .collect(),
        })
        .collect()
}

/// A span attribute's OTLP value, `{"stringValue": ...}` or `{"intValue": ...}`; null if absent.
fn span_attr(span: &Value, key: &str) -> Value {
    span["attributes"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["key"] == key)
        .map(|a| a["value"].clone())
        .unwrap_or(Value::Null)
}

/// Wait up to 10 s for `done` to hold over what the collector got: a batch waits up to a second
/// to fill, and a refused one is sent again after a short delay.
async fn collected(posted: &Arc<Mutex<Vec<Posted>>>, done: impl Fn(&[Posted]) -> bool) {
    for _ in 0..200 {
        if done(&posted.lock().unwrap()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got: Vec<(String, bool, Value)> = posted
        .lock()
        .unwrap()
        .iter()
        .map(|p| (p.path.clone(), p.refused, p.body.clone()))
        .collect();
    panic!("the collector never got what the test waits for; it got {got:?}");
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

/// Start the binary on ports chosen here, rendering the config once the http port is known. The
/// port race and what readiness waits for are described on [`start_gateway_from`].
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
    start_store_gateway_with(snapshot, &[]).await
}

/// `start_store_gateway`, plus arguments the scenario needs on the command line.
async fn start_store_gateway_with(
    snapshot: gapura_core::store::StoreSnapshot,
    extra: &[&str],
) -> Gateway {
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
        extra,
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

/// With both sinks on: every request's access-log line reaches the http_log endpoint with the
/// headers file's headers, the same line as stdout, and a batch the collector refuses is sent
/// again; a span keeps the caller's trace, names the caller's span as its parent, and is the
/// parent the upstream is told of; a trace that starts here has a span with no parent; a caller
/// that did not sample is logged but has no span; and the caller's credential is in nothing
/// exported.
#[tokio::test(flavor = "multi_thread")]
async fn access_logs_and_spans_reach_their_collectors() {
    let (collector, posted) = spawn_collector(1).await;
    let dir = tempfile::tempdir().unwrap();
    let headers = dir.path().join("headers");
    std::fs::write(
        &headers,
        "# the collector's token\nAuthorization: Bearer sink-token\n",
    )
    .unwrap();
    let logs = format!("http://{collector}/logs");
    let traces = format!("http://{collector}/v1/traces");
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let gw = start_gateway_with(
        |http| config(http, upstream, dead, upstream),
        &[
            "--http-log-url",
            logs.as_str(),
            "--http-log-headers-file",
            headers.to_str().unwrap(),
            "--otlp-traces-url",
            traces.as_str(),
        ],
    )
    .await;
    let c = client(&gw);

    let r = c
        .get(url(&gw, "echo.test", "/api/traced"))
        .header("x-request-id", "traced")
        .header(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )
        .header("authorization", "Bearer caller-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let echoed: Value = r.json().await.unwrap();
    let upstream_tp = echoed["headers"]["traceparent"]
        .as_str()
        .unwrap()
        .to_string();
    let upstream_tp: Vec<&str> = upstream_tp.split('-').collect();
    assert_eq!(
        upstream_tp[1], "0af7651916cd43dd8448eb211c80319c",
        "the caller's trace"
    );
    assert_ne!(
        upstream_tp[2], "b7ad6b7169203331",
        "the upstream's parent is the gateway's span"
    );
    assert_eq!(upstream_tp[3], "01");

    let r = c
        .get(url(&gw, "echo.test", "/api/rooted"))
        .header("x-request-id", "rooted")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = c
        .get(url(&gw, "echo.test", "/api/unsampled"))
        .header("x-request-id", "unsampled")
        .header(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-00",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let stdout_traced = gw.access_log("traced").await;
    let rooted = gw.access_log("rooted").await["trace_id"]
        .as_str()
        .unwrap()
        .to_string();
    gw.access_log("unsampled").await;

    let traces_wanted = ["0af7651916cd43dd8448eb211c80319c", rooted.as_str()];
    collected(&posted, |p| {
        let lines = delivered(p, "/logs");
        let spans = delivered(p, "/v1/traces");
        ["traced", "rooted", "unsampled"]
            .iter()
            .all(|id| lines.iter().any(|l| l["request_id"] == *id))
            && traces_wanted
                .iter()
                .all(|t| spans.iter().any(|s| s["traceId"] == *t))
    })
    .await;
    let posted = posted.lock().unwrap().clone();

    let refused: Vec<&Posted> = posted.iter().filter(|p| p.refused).collect();
    assert_eq!(refused.len(), 1);
    assert!(
        posted
            .iter()
            .any(|p| !p.refused && p.path == refused[0].path && p.body == refused[0].body),
        "the refused batch was sent again, the same records"
    );
    for p in &posted {
        assert_eq!(p.headers["content-type"], "application/json");
        if p.path == "/logs" {
            assert_eq!(p.headers["authorization"], "Bearer sink-token");
        } else {
            assert!(
                p.headers.get("authorization").is_none(),
                "only the http_log sink's file"
            );
        }
    }

    let lines = delivered(&posted, "/logs");
    let traced = lines.iter().find(|l| l["request_id"] == "traced").unwrap();
    assert_eq!(
        *traced, stdout_traced,
        "the exported line is the stdout line"
    );
    assert!(traced["consumer"].is_null());

    let spans = delivered(&posted, "/v1/traces");
    let span = spans
        .iter()
        .find(|s| s["traceId"] == "0af7651916cd43dd8448eb211c80319c")
        .unwrap();
    assert_eq!(span["parentSpanId"], "b7ad6b7169203331");
    assert_eq!(
        span["spanId"], upstream_tp[2],
        "the span the upstream was told is its parent"
    );
    assert_eq!(span["name"], "GET apps/echo");
    assert_eq!(
        span_attr(span, "http.response.status_code"),
        json!({"intValue": "200"})
    );
    assert_eq!(
        span_attr(span, "gapura.route"),
        json!({"stringValue": "apps/echo"})
    );
    assert_eq!(
        span_attr(span, "gapura.service"),
        json!({"stringValue": "apps/echo:80"})
    );
    let root = spans
        .iter()
        .find(|s| s["traceId"] == rooted.as_str())
        .unwrap();
    assert!(
        root.get("parentSpanId").is_none(),
        "a trace that starts here has no parent"
    );
    assert!(
        spans
            .iter()
            .all(|s| s["traceId"] != "11111111111111111111111111111111"),
        "a caller that did not sample has no span"
    );

    let everything =
        serde_json::to_string(&posted.iter().map(|p| &p.body).collect::<Vec<_>>()).unwrap();
    assert!(
        !everything.contains("caller-secret"),
        "a caller credential was exported"
    );
}

/// In store mode an exported line names the consumer key_auth identified, and so does the span.
/// With `--access-log-query`, a credential in the query string -- under a common name, or under
/// the name of the header the rule's key_auth reads, here `x-shop-key`, which no list of common
/// names holds -- reaches neither stdout nor the collector, and the key the caller authenticated
/// with is nowhere in the export.
#[tokio::test(flavor = "multi_thread")]
async fn an_exported_record_names_its_consumer_and_never_its_key() {
    use gapura_core::config::{KeyAuthPolicy, Plugin};
    let (collector, posted) = spawn_collector(0).await;
    let logs = format!("http://{collector}/logs");
    let traces = format!("http://{collector}/v1/traces");
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    // The shared fixture's key_auth reads `x-api-key`, a name the redaction knows anyway. This
    // one reads a header of its own, so the query's `x-shop-key` is redacted only because the
    // rule names it.
    let mut snapshot = consumer_limited(upstream);
    for p in &mut snapshot.plugins {
        if matches!(p.plugin, Plugin::KeyAuth(_)) {
            p.plugin = Plugin::KeyAuth(KeyAuthPolicy {
                header: "x-shop-key".into(),
                ..Default::default()
            });
        }
    }
    let gw = start_store_gateway_with(
        snapshot,
        &[
            "--access-log-query",
            "--http-log-url",
            logs.as_str(),
            "--otlp-traces-url",
            traces.as_str(),
        ],
    )
    .await;
    let r = client(&gw)
        .get(url(
            &gw,
            "echo.test",
            "/orders?x-shop-key=roomy-key&api_key=leak-me&page=2",
        ))
        .header("x-shop-key", "roomy-key")
        .header("x-request-id", "keyed")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let stdout = gw.access_log("keyed").await;
    assert_eq!(stdout["consumer"], "shop/roomy");
    assert_eq!(
        stdout["query"],
        "x-shop-key=<redacted>&api_key=<redacted>&page=2"
    );
    let trace_id = stdout["trace_id"].as_str().unwrap().to_string();

    collected(&posted, |p| {
        delivered(p, "/logs")
            .iter()
            .any(|l| l["request_id"] == "keyed")
            && delivered(p, "/v1/traces")
                .iter()
                .any(|s| s["traceId"] == trace_id.as_str())
    })
    .await;
    let posted = posted.lock().unwrap().clone();
    let line = delivered(&posted, "/logs")
        .into_iter()
        .find(|l| l["request_id"] == "keyed")
        .unwrap();
    assert_eq!(line, stdout, "the exported line is the stdout line");
    let span = delivered(&posted, "/v1/traces")
        .into_iter()
        .find(|s| s["traceId"] == trace_id.as_str())
        .unwrap();
    assert_eq!(
        span_attr(&span, "gapura.consumer"),
        json!({"stringValue": "shop/roomy"})
    );

    let everything =
        serde_json::to_string(&posted.iter().map(|p| &p.body).collect::<Vec<_>>()).unwrap();
    for secret in ["roomy-key", "leak-me"] {
        assert!(!everything.contains(secret), "{secret} was exported");
    }
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
    let reuse = spawn_closing_upstream(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
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

/// An endpoint that sends `100 Continue` before each 503 has failed once per request: only the
/// final head is its answer. Counted as a success, the 100 reset the endpoint's failures every
/// time, so five such requests never ejected it.
#[tokio::test(flavor = "multi_thread")]
async fn a_503_after_an_interim_100_counts_toward_ejection() {
    use gapura_core::config::{PathMatch, Protocol};
    use gapura_core::store::{StoreRoute, StoreService, StoreSnapshot};
    let upstream = spawn_closing_upstream(
        b"HTTP/1.1 100 Continue\r\n\r\n\
          HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    )
    .await;
    let gw = start_store_gateway(StoreSnapshot {
        services: vec![StoreService {
            workspace: String::new(),
            name: "continued".into(),
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
            name: "continued".into(),
            service: "continued".into(),
            hosts: vec![],
            paths: vec![PathMatch::Prefix("/continued".into())],
            methods: vec![],
            headers: vec![],
            strip_path: false,
            priority: 0,
        }],
        ..StoreSnapshot::default()
    })
    .await;
    let c = client(&gw);
    for i in 0..5 {
        let r = c
            .get(url(&gw, "echo.test", "/continued"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 503, "request {i}");
    }
    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let needle = format!(r#"gapura_upstream_ejections_total{{cluster="{upstream}"}} 1"#);
    assert!(
        metrics.contains(&needle),
        "{needle} missing from:\n{metrics}"
    );
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

/// With `--drain-seconds`, SIGTERM makes /readyz answer 503 at once while the proxy still accepts
/// new connections and serves them; a SIGINT during the drain still stops the process at once.
#[tokio::test(flavor = "multi_thread")]
async fn sigterm_drains_before_the_listeners_close() {
    let (dead, upstream) = spawn_dead_and_upstream().await;
    let mut gw = start_gateway_with(
        |http| config(http, upstream, dead, upstream),
        &["--drain-seconds", "60"],
    )
    .await;
    let signal = |name: &str, gw: &Gateway| {
        let ok = Command::new("kill")
            .args([format!("-{name}"), gw.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill -{name} failed");
    };
    signal("TERM", &gw);
    let readyz = format!("http://127.0.0.1:{}/readyz", gw.admin);
    let mut answer = None;
    for _ in 0..100 {
        let r = reqwest::get(&readyz).await.expect("admin still accepts");
        if r.status() == 503 {
            answer = Some(r.text().await.unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(answer.as_deref(), Some("not ready: draining\n"));
    // A new client is a new connection: the listener is still accepting, not only finishing the
    // ones it had.
    let r = client(&gw)
        .get(url(&gw, "echo.test", "/api"))
        .send()
        .await
        .expect("the proxy still accepts while draining");
    assert_eq!(r.status(), 200);
    signal("INT", &gw);
    for _ in 0..100 {
        if gw.child.try_wait().unwrap().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("SIGINT during the drain did not stop the gateway");
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

/// Behind a trusted proxy the policy judges the address the access log names, the forwarded
/// one: `/walled` denies 198.51.100.0/24 and also wants a key, `/inside` allows only 127.0.0.1.
/// A denied address gets 403 `IP_FORBIDDEN` without a challenge, before its key is read; an
/// admitted one goes on to the key check, or upstream.
#[tokio::test(flavor = "multi_thread")]
async fn a_denied_address_is_403_before_its_key_is_read() {
    use gapura_core::config::{IpRestrictionPolicy, KeyAuthPolicy, PathMatch, Plugin, Protocol};
    use gapura_core::store::{StorePlugin, StoreRoute, StoreService, StoreSnapshot};
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    let route = |name: &str| StoreRoute {
        workspace: String::new(),
        name: name.into(),
        service: "echo".into(),
        hosts: vec![],
        paths: vec![PathMatch::Prefix(format!("/{name}"))],
        methods: vec![],
        headers: vec![],
        strip_path: false,
        priority: 0,
    };
    let on = |route: &str, plugin: Plugin| StorePlugin {
        workspace: String::new(),
        route: Some(route.into()),
        service: None,
        plugin,
    };
    let nets = |list: &[&str]| list.iter().map(|n| n.parse().unwrap()).collect();
    let gw = start_store_gateway_with(
        StoreSnapshot {
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
            routes: vec![route("walled"), route("inside")],
            plugins: vec![
                on("walled", Plugin::KeyAuth(KeyAuthPolicy::default())),
                on(
                    "walled",
                    Plugin::IpRestriction(IpRestrictionPolicy {
                        allow: vec![],
                        deny: nets(&["198.51.100.0/24"]),
                    }),
                ),
                on(
                    "inside",
                    Plugin::IpRestriction(IpRestrictionPolicy {
                        allow: nets(&["127.0.0.1"]),
                        deny: vec![],
                    }),
                ),
            ],
            ..StoreSnapshot::default()
        },
        &["--trusted-proxy", "127.0.0.0/8"],
    )
    .await;
    let c = client(&gw);
    let get = |path: &str, forwarded: Option<&str>, rid: &str| {
        let mut req = c
            .get(url(&gw, "echo.test", path))
            .header("x-request-id", rid);
        if let Some(addr) = forwarded {
            req = req.header("x-forwarded-for", addr);
        }
        req.send()
    };

    let r = get("/walled", Some("198.51.100.5"), "denied")
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(r.headers()["x-gapura-error"], "IP_FORBIDDEN");
    assert!(
        r.headers().get("www-authenticate").is_none(),
        "no challenge"
    );
    assert_eq!(r.text().await.unwrap(), "403 forbidden\n");
    let line = gw.access_log("denied").await;
    assert_eq!(line["status"], 403, "{line}");
    assert_eq!(line["error_key"], "IP_FORBIDDEN", "{line}");
    assert_eq!(line["client_ip"], "198.51.100.5", "{line}");

    let r = get("/walled", None, "admitted").await.unwrap();
    assert_eq!(r.status(), 401, "admitted by address, refused by key");
    assert_eq!(r.headers()["x-gapura-error"], "AUTH_KEY_MISSING");

    let r = get("/inside", None, "local").await.unwrap();
    assert_eq!(r.status(), 200);
    let r = get("/inside", Some("198.51.100.5"), "outside")
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(r.headers()["x-gapura-error"], "IP_FORBIDDEN");
}

/// An upstream that reads the whole request body before it answers, and answers its length. One
/// that answered first would have its response on the way to the client before the count could
/// trip, and a request whose response has begun can no longer be answered 413.
async fn spawn_counting_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(any(|body: axum::body::Bytes| async move {
        body.len().to_string()
    }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Writes `request` to the gateway's HTTP port as it is, on a connection of its own, and reads
/// the status line of the first response on it. For what reqwest cannot say: a chunked body (it
/// is built without its `stream` feature) and headers that wait on `100 Continue`. An error is
/// whatever ended the exchange first, the write or the read; ten seconds without a status line is
/// a failure, not a hang.
async fn status_line(gw: &Gateway, request: &[u8]) -> std::io::Result<String> {
    let exchange = async {
        let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", gw.http)).await?;
        sock.write_all(request).await?;
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(2).any(|w| w == b"\r\n") {
            let n = sock.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            head.extend_from_slice(&buf[..n]);
        }
        let end = head.windows(2).position(|w| w == b"\r\n").unwrap();
        Ok(String::from_utf8_lossy(&head[..end]).into_owned())
    };
    tokio::time::timeout(Duration::from_secs(10), exchange)
        .await
        .unwrap_or_else(|_| panic!("no status line within 10s"))
}

/// A store-mode gateway whose route `/sized` takes bodies of at most 1024 bytes, in front of the
/// counting upstream, which reads every body whole.
async fn start_sized_gateway() -> Gateway {
    use gapura_core::config::{PathMatch, Plugin, Protocol, RequestSizeLimitPolicy};
    use gapura_core::store::{StorePlugin, StoreRoute, StoreService, StoreSnapshot};
    let upstream = spawn_counting_upstream().await;
    start_store_gateway(StoreSnapshot {
        services: vec![StoreService {
            workspace: String::new(),
            name: "counter".into(),
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
            name: "sized".into(),
            service: "counter".into(),
            hosts: vec![],
            paths: vec![PathMatch::Prefix("/sized".into())],
            methods: vec![],
            headers: vec![],
            strip_path: false,
            priority: 0,
        }],
        plugins: vec![StorePlugin {
            workspace: String::new(),
            route: Some("sized".into()),
            service: None,
            plugin: Plugin::RequestSizeLimit(RequestSizeLimitPolicy { max_bytes: 1024 }),
        }],
        ..StoreSnapshot::default()
    })
    .await
}

/// `/sized` takes bodies of at most 1024 bytes. A longer one is refused 413 `REQUEST_TOO_LARGE`
/// whether its length is declared, checked before anything upstream, or only known as it streams,
/// counted chunk by chunk. A declared length is refused before the client is asked for the body,
/// so a client waiting on `100 Continue` gets the 413 instead; a body at the limit goes through.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_too_large_is_413_declared_or_streamed() {
    let gw = start_sized_gateway().await;
    let c = client(&gw);

    // Declared: refused from Content-Length alone, in the Access phase.
    let r = c
        .post(url(&gw, "echo.test", "/sized"))
        .body(vec![b'a'; 2048])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
    assert_eq!(r.headers()["x-gapura-error"], "REQUEST_TOO_LARGE");
    assert_eq!(r.text().await.unwrap(), "413 request too large\n");

    // At the limit: the upstream read all of it.
    let r = c
        .post(url(&gw, "echo.test", "/sized"))
        .body(vec![b'a'; 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "1024");

    // Streamed: three 512-byte chunks and no length, so only the count can refuse it, on the
    // chunk that crosses 1024. The gateway answers 413 and closes the connection. A client
    // still writing the body then may see its write fail or the connection reset before it
    // reads the 413, so the status line is asserted only when it arrived; the access log line,
    // found by the request id the request carries, is asserted either way, since it is written
    // whatever the client managed to read.
    let mut chunked = b"POST /sized HTTP/1.1\r\nHost: echo.test\r\nTransfer-Encoding: chunked\r\n\
                        x-request-id: streamed\r\n\r\n"
        .to_vec();
    for _ in 0..3 {
        chunked.extend_from_slice(b"200\r\n");
        chunked.extend_from_slice(&[b'a'; 512]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    match status_line(&gw, &chunked).await {
        Ok(line) => assert!(line.starts_with("HTTP/1.1 413 "), "{line}"),
        Err(e) => eprintln!("the streamed refusal reached the client as {e}"),
    }
    let line = gw.access_log("streamed").await;
    assert_eq!(line["status"], 413, "{line}");
    assert_eq!(line["error_key"], "REQUEST_TOO_LARGE", "{line}");

    // Waiting on 100 Continue: the headers alone are refused, and no 100 is sent first, so the
    // client never sends the body at all.
    let line = status_line(
        &gw,
        b"POST /sized HTTP/1.1\r\nHost: echo.test\r\nContent-Length: 4096\r\n\
          Expect: 100-continue\r\nx-request-id: expect\r\n\r\n",
    )
    .await
    .unwrap();
    assert!(line.starts_with("HTTP/1.1 413 "), "{line}");

    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for reason in ["content_length", "streamed"] {
        assert!(
            metrics
                .lines()
                .any(|l| l.starts_with("gapura_policy_refused_total")
                    && l.contains("policy=\"request_size_limit\"")
                    && l.contains(&format!("reason=\"{reason}\""))),
            "{reason}: {metrics}"
        );
    }
}

/// `/t` edits the request on its way upstream and the response on its way back; `/k` wants a key
/// and edits the response alike. The request edits run before the gateway sets its own account of
/// the request, so a transform that replaces `X-Request-Id` and adds an `X-Forwarded-For` hop
/// still has the upstream see the client's id and the peer as the last hop; the response edits
/// run after it, so a transform that removes `X-Request-Id` removes it. A refusal the
/// gateway writes itself is the rule's answer too, and gets the same response edits.
#[tokio::test(flavor = "multi_thread")]
async fn transformers_edit_the_request_upstream_and_the_response_downstream() {
    use gapura_core::config::{
        HeaderEdits, KeyAuthPolicy, PathMatch, Plugin, Protocol, RequestTransformerPolicy,
        ResponseTransformerPolicy,
    };
    use gapura_core::store::{StorePlugin, StoreRoute, StoreService, StoreSnapshot};
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    let route = |name: &str| StoreRoute {
        workspace: String::new(),
        name: name.into(),
        service: "echo".into(),
        hosts: vec![],
        paths: vec![PathMatch::Prefix(format!("/{name}"))],
        methods: vec![],
        headers: vec![],
        strip_path: false,
        priority: 0,
    };
    let on = |route: &str, plugin: Plugin| StorePlugin {
        workspace: String::new(),
        route: Some(route.into()),
        service: None,
        plugin,
    };
    let pair = |name: &str, value: &str| (name.to_string(), value.to_string());
    let response = || {
        Plugin::ResponseTransformer(ResponseTransformerPolicy {
            headers: HeaderEdits {
                remove: vec!["x-request-id".into()],
                add: vec![pair("x-served-by", "gapura")],
                ..HeaderEdits::default()
            },
        })
    };
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
        routes: vec![route("t"), route("k")],
        plugins: vec![
            on(
                "t",
                Plugin::RequestTransformer(RequestTransformerPolicy {
                    headers: HeaderEdits {
                        remove: vec!["x-debug".into()],
                        rename: vec![pair("x-old", "x-new")],
                        // The gateway sets both after the transform: its id wins over the
                        // replace, and the peer it appends goes after the hop the add writes.
                        // Were the transform run after the gateway, the replace would forge the
                        // id and the add would find the header already set.
                        replace: vec![pair("x-request-id", "forged")],
                        add: vec![
                            pair("x-team", "core"),
                            pair("x-forwarded-for", "203.0.113.9"),
                        ],
                        append: vec![pair("x-tag", "gw")],
                    },
                    query: HeaderEdits {
                        remove: vec!["secret".into()],
                        add: vec![pair("v", "2")],
                        ..HeaderEdits::default()
                    },
                }),
            ),
            on("t", response()),
            on("k", Plugin::KeyAuth(KeyAuthPolicy::default())),
            on("k", response()),
        ],
        ..StoreSnapshot::default()
    })
    .await;
    let c = client(&gw);

    let r = c
        .get(url(&gw, "echo.test", "/t?secret=s&keep=1"))
        .header("x-request-id", "transformed")
        .header("x-debug", "1")
        .header("x-old", "a")
        // A rename sets the new name, as Kong's does: the client's own goes.
        .header("x-new", "client")
        .header("x-tag", "client")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-served-by"], "gapura");
    assert!(
        r.headers().get("x-request-id").is_none(),
        "the transform has the last word over the gateway's own id: {:?}",
        r.headers()
    );
    let body: Value = r.json().await.unwrap();
    let h = &body["headers"];
    assert!(h.get("x-debug").is_none(), "{body}");
    assert!(h.get("x-old").is_none(), "{body}");
    assert_eq!(body["values"]["x-new"], json!(["a"]), "{body}");
    assert_eq!(h["x-team"], "core", "{body}");
    assert_eq!(body["values"]["x-tag"], json!(["client", "gw"]), "{body}");
    assert_eq!(body["query"], "keep=1&v=2", "{body}");
    assert_eq!(body["path"], "/t", "{body}");
    // Set after the transform, so still the gateway's: the client's id and not the forged one,
    // and the peer appended after the hop the transform wrote.
    assert_eq!(
        body["values"]["x-request-id"],
        json!(["transformed"]),
        "{body}"
    );
    assert_eq!(
        body["values"]["x-forwarded-for"],
        json!(["203.0.113.9, 127.0.0.1"]),
        "{body}"
    );
    // The access log keeps the id the response no longer carries.
    let line = gw.access_log("transformed").await;
    assert_eq!(line["status"], 200, "{line}");

    let r = c
        .get(url(&gw, "echo.test", "/k"))
        .header("x-request-id", "refused")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["x-gapura-error"], "AUTH_KEY_MISSING");
    assert_eq!(r.headers()["x-served-by"], "gapura");
    assert!(
        r.headers().get("x-request-id").is_none(),
        "{:?}",
        r.headers()
    );
    assert_eq!(r.text().await.unwrap(), "401 unauthorized\n");
}

/// `/c` wants a key and has a cors policy, and its upstream answers every request with its own
/// `Access-Control-Allow-Origin: *`, counting them. A preflight carries no key: it is answered
/// before the key check and never reaches the upstream, 204 for an origin the policy allows and
/// 403 for one it does not. Every other answer carries the policy's headers in place of the
/// upstream's -- the gateway's own 401 too, so a page can read why it was refused -- and
/// `Vary: Origin` whatever the origin.
#[tokio::test(flavor = "multi_thread")]
async fn cors_preflights_before_the_key_check_and_heads_every_answer() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use gapura_core::config::{CorsPolicy, KeyAuthPolicy, PathMatch, Plugin, Protocol};
    use gapura_core::store::{
        StoreCredential, StorePlugin, StoreRoute, StoreService, StoreSnapshot,
    };
    use sha2::{Digest, Sha256};

    let served = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let count = Arc::clone(&served);
    let app = Router::new().fallback(any(move || {
        count.fetch_add(1, Ordering::SeqCst);
        async { ([("access-control-allow-origin", "*")], "upstream") }
    }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let on = |plugin: Plugin| StorePlugin {
        workspace: "shop".into(),
        route: Some("c".into()),
        service: None,
        plugin,
    };
    let gw = start_store_gateway(StoreSnapshot {
        services: vec![StoreService {
            workspace: "shop".into(),
            name: "cors".into(),
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
            name: "c".into(),
            service: "cors".into(),
            hosts: vec![],
            paths: vec![PathMatch::Prefix("/c".into())],
            methods: vec![],
            headers: vec![],
            strip_path: false,
            priority: 0,
        }],
        plugins: vec![
            on(Plugin::KeyAuth(KeyAuthPolicy::default())),
            on(Plugin::Cors(CorsPolicy {
                origins: vec!["https://app.example".into(), "https://*.example.org".into()],
                methods: vec!["GET".into(), "POST".into()],
                expose_headers: vec!["x-gapura-error".into()],
                credentials: true,
                max_age: Some(600),
                ..CorsPolicy::default()
            })),
        ],
        credentials: vec![StoreCredential {
            key_hash: format!("{:x}", Sha256::digest(b"c-key")),
            consumer: "page".into(),
            workspace: "shop".into(),
        }],
        ..StoreSnapshot::default()
    })
    .await;
    let c = client(&gw);
    let preflight = |origin: &str| {
        c.request(reqwest::Method::OPTIONS, url(&gw, "echo.test", "/c"))
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .send()
    };
    let get = |origin: &str, key: Option<&str>| {
        let mut req = c.get(url(&gw, "echo.test", "/c")).header("origin", origin);
        if let Some(key) = key {
            req = req.header("x-api-key", key);
        }
        req.send()
    };
    let header = |r: &reqwest::Response, name: &str| {
        r.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };
    let varies_by_origin = |r: &reqwest::Response| {
        r.headers()
            .get_all("vary")
            .iter()
            .any(|v| v.to_str().unwrap().contains("Origin"))
    };

    let r = preflight("https://app.example").await.unwrap();
    assert_eq!(r.status(), 204);
    for (name, value) in [
        ("access-control-allow-origin", "https://app.example"),
        ("access-control-allow-credentials", "true"),
        ("access-control-allow-methods", "GET, POST"),
        ("access-control-max-age", "600"),
    ] {
        assert_eq!(header(&r, name).as_deref(), Some(value), "{name}");
    }
    assert!(varies_by_origin(&r), "{:?}", r.headers());
    assert!(header(&r, "x-request-id").is_some());

    let r = preflight("https://evil.example").await.unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(r.headers()["x-gapura-error"], "CORS_ORIGIN_FORBIDDEN");
    assert_eq!(header(&r, "access-control-allow-origin"), None);
    assert!(varies_by_origin(&r));
    assert_eq!(
        served.load(Ordering::SeqCst),
        0,
        "no preflight went upstream"
    );

    let r = get("https://a.example.org", None).await.unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["x-gapura-error"], "AUTH_KEY_MISSING");
    assert_eq!(
        header(&r, "access-control-allow-origin").as_deref(),
        Some("https://a.example.org")
    );
    assert_eq!(
        header(&r, "access-control-expose-headers").as_deref(),
        Some("x-gapura-error")
    );
    assert!(varies_by_origin(&r));

    let r = get("https://a.example.org", Some("c-key")).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        header(&r, "access-control-allow-origin").as_deref(),
        Some("https://a.example.org"),
        "the policy's origin, not the upstream's *"
    );
    assert_eq!(
        header(&r, "access-control-allow-credentials").as_deref(),
        Some("true")
    );
    assert_eq!(r.text().await.unwrap(), "upstream");

    // Two labels under the suffix are not one: served, but no page may read the answer.
    let r = get("https://a.b.example.org", Some("c-key")).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(header(&r, "access-control-allow-origin"), None);
    assert_eq!(header(&r, "access-control-allow-credentials"), None);
    assert!(varies_by_origin(&r));
    assert_eq!(served.load(Ordering::SeqCst), 2);
}

/// Reads one response head off `sock`, through its blank line, and returns it whole, keeping in
/// `pending` whatever arrived past it: an interim head and the final one can come in one read.
async fn read_head(
    sock: &mut tokio::net::TcpStream,
    pending: &mut Vec<u8>,
) -> std::io::Result<String> {
    loop {
        if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            let head: Vec<u8> = pending.drain(..end + 4).collect();
            return Ok(String::from_utf8_lossy(&head).into_owned());
        }
        let mut buf = [0u8; 1024];
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

/// A chunked upload that waits on `100 Continue`, as curl sends every chunked upload, to an
/// upstream that sends the 100 once it starts reading the body, as hyper (the counting upstream
/// here), Go, Node and nginx do. The gateway relays the 100, the client sends three 512-byte
/// chunks, and the count refuses the one that crosses 1024. The client is then answered 413 after
/// the 100, not left with a closed connection, and the access log records the 413 and its key,
/// not the 100.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_refused_after_100_continue_is_still_answered_413() {
    let gw = start_sized_gateway().await;
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", gw.http))
        .await
        .unwrap();
    sock.write_all(
        b"POST /sized HTTP/1.1\r\nHost: echo.test\r\nTransfer-Encoding: chunked\r\n\
          Expect: 100-continue\r\nx-request-id: continued\r\n\r\n",
    )
    .await
    .unwrap();
    let mut pending = Vec::new();
    let first = tokio::time::timeout(Duration::from_secs(10), read_head(&mut sock, &mut pending))
        .await
        .expect("neither 100 Continue nor an answer to the headers within 10s")
        .unwrap();
    eprintln!("first head on the wire: {first:?}");
    if first.starts_with("HTTP/1.1 100 ") {
        let mut body = Vec::new();
        for _ in 0..3 {
            body.extend_from_slice(b"200\r\n");
            body.extend_from_slice(&[b'a'; 512]);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"0\r\n\r\n");
        // The refusal closes the connection with the rest of the body unread, which can reset it
        // before the client reads the 413, as in the streamed case without a 100: the status is
        // asserted when it arrived, and the access log line either way.
        let answer = async {
            sock.write_all(&body).await?;
            read_head(&mut sock, &mut pending).await
        };
        match tokio::time::timeout(Duration::from_secs(10), answer)
            .await
            .expect("no answer to the body within 10s")
        {
            Ok(head) => {
                eprintln!("final head on the wire: {head:?}");
                assert!(head.starts_with("HTTP/1.1 413 "), "{head}");
            }
            Err(e) => eprintln!("the refusal after the 100 reached the client as {e}"),
        }
    } else {
        // The upstream did not send 100 Continue, so the gateway had none to relay and answered
        // the headers with a final status. Whatever the reason, that answer must still be the
        // refusal.
        assert!(first.starts_with("HTTP/1.1 413 "), "{first}");
    }
    let line = gw.access_log("continued").await;
    assert_eq!(line["status"], 413, "{line}");
    assert_eq!(line["error_key"], "REQUEST_TOO_LARGE", "{line}");
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
/// malformed request and are refused before any route is consulted. Since Pingora 0.9 Pingora
/// itself refuses them as it reads the request, before any Gapura hook runs, so the 400 is
/// Pingora's: no `X-Gapura-Error`, no access log line.
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
        !response.contains("\"path\""),
        "never forwarded: {response}"
    );
}

/// RUSTSEC-2026-0390: a header the client names in `Connection` is hop-by-hop and stops here, so
/// an HTTP/1 hop behind the gateway cannot be told to strip one; naming a header the gateway
/// sets for the upstream is refused as 400, not taken for a client that went away.
#[tokio::test(flavor = "multi_thread")]
async fn connection_nominated_headers_stop_at_the_gateway() {
    let (gw, _c) = setup().await;
    let exchange = |request: &'static str| async move {
        let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", gw.http))
            .await
            .unwrap();
        sock.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        sock.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).to_ascii_lowercase()
    };

    let forwarded = exchange(concat!(
        "GET /api/x HTTP/1.1\r\n",
        "Host: echo.test\r\n",
        "Connection: close, x-probe\r\n",
        "X-Probe: 1\r\n",
        "\r\n",
    ))
    .await;
    assert!(forwarded.starts_with("http/1.1 200"), "{forwarded}");
    assert!(!forwarded.contains("\"x-probe\""), "{forwarded}");
    assert!(
        forwarded.contains("\"x-forwarded-for\":\"127.0.0.1\""),
        "{forwarded}"
    );

    let refused = exchange(concat!(
        "GET /api/x HTTP/1.1\r\n",
        "Host: echo.test\r\n",
        "Connection: close, X-Forwarded-For\r\n",
        "X-Request-Id: nominates-xff\r\n",
        "\r\n",
    ))
    .await;
    assert!(refused.starts_with("http/1.1 400"), "{refused}");
    assert!(
        refused.contains("x-gapura-error: invalid_request_target"),
        "{refused}"
    );
    let line = gw.access_log("nominates-xff").await;
    assert_eq!(line["status"], 400, "{line}");
    assert_eq!(line["client_abort"], false, "{line}");
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

/// The store-mode snapshot: one route for echo.test to the echo upstream behind
/// key_auth, limited for everyone to 3 an hour per address and for `tight` to 2 an hour of its
/// own, which counts by address as well.
///
/// Both limits count by address on purpose. Every request in the test comes from one address, so
/// `tight`'s requests and everyone else's have the same client, `127.0.0.1`, and the only thing
/// that keeps `tight`'s count out of everyone's is the window's name. Counting `tight`'s limit by
/// consumer would separate the two by the kind of client instead, whatever the window were
/// called, and the test could not tell a window shared in name from one kept apart.
///
/// Hour windows, so a run is very unlikely to cross a boundary (#57).
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
                limit: hour(2, LimitBy::Ip),
            },
        ],
    }
}

/// A consumer's own limit, end to end: once key_auth has named the caller, `tight` is held to
/// its own 2 an hour while `roomy`, from the same address, still has the 3 an hour everyone has
/// -- untouched by `tight`'s requests, which count in a window of their own.
///
/// Both limits count by address (see `consumer_limited`), so the two windows have the same
/// client and differ only in their name. A data plane that counted `tight` under the rule's
/// window would let `tight` spend two of `roomy`'s three, and `roomy` would be refused at its
/// second request. That is what this test proves; counting by consumer is covered by the unit
/// tests in `rate_limit.rs`.
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
    for i in 0..2 {
        assert_eq!(status(Some("roomy-key")).await, 200, "roomy {i}");
    }
    // Without a key key_auth refuses first: there is no consumer, and the limit is not reached.
    // Were it spent, this address would have used up all 3 and roomy's next request would fail.
    assert_eq!(status(None).await, 401);
    assert_eq!(status(Some("roomy-key")).await, 200, "roomy 2");
    let r = c
        .get(url(&gw, "echo.test", "/"))
        .header("x-api-key", "roomy-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429, "past everyone's allowance");
    assert_eq!(
        r.headers()["x-ratelimit-limit"],
        "3",
        "everyone's limit, not tight's"
    );

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

const JWT_ISSUER: &str = "https://idp.e2e";

/// A P-256 key pair: its public JWK, and its PKCS#8 for signing.
struct EcKey {
    jwk: Value,
    pkcs8: Vec<u8>,
}

fn ec_key(kid: &str) -> EcKey {
    use base64::Engine;
    let pair = rcgen::KeyPair::generate().unwrap();
    // An uncompressed SEC1 point: 0x04, then x, then y.
    let point = pair.public_key_raw();
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    EcKey {
        pkcs8: pair.serialize_der(),
        jwk: json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid,
                    "x": b64(&point[1..33]), "y": b64(&point[33..])}),
    }
}

fn jwks_of(keys: &[&EcKey]) -> String {
    json!({"keys": keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()}).to_string()
}

/// A token from `JWT_ISSUER`, valid until 2100, signed by `key` and naming its `kid`.
fn signed_by(key: &EcKey) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = key.jwk["kid"].as_str().map(str::to_string);
    jsonwebtoken::encode(
        &header,
        &json!({"iss": JWT_ISSUER, "sub": "e2e", "exp": 4102444800u64}),
        &jsonwebtoken::EncodingKey::from_ec_der(&key.pkcs8),
    )
    .unwrap()
}

/// A private CA's PEM, and a certificate for 127.0.0.1 it signed.
fn idp_tls() -> (
    String,
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "e2e idp ca");
    let ca = params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    (
        ca.pem(),
        leaf.der().clone(),
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key.serialize_der(),
        )),
    )
}

/// HTTPS on 127.0.0.1 answering every request with what `document` holds at the time, as an
/// IdP's jwks_uri does. Aborting the handle takes it down: new connections are refused.
async fn spawn_jwks_server(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    document: Arc<Mutex<String>>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, document) = (acceptor.clone(), Arc::clone(&document));
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let (mut buf, mut seen) = ([0u8; 4096], Vec::new());
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let body = document.lock().unwrap().clone();
                let answer = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(answer.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, server)
}

/// One route, `/guarded`, requiring a JWT from `JWT_ISSUER` whose keys are at `uri`.
fn jwt_guarded(upstream: SocketAddr, uri: &str, ca_pem: &str) -> gapura_core::store::StoreSnapshot {
    use gapura_core::config::{JwtPolicy, PathMatch, Plugin, Protocol};
    use gapura_core::store::{StorePlugin, StoreRoute, StoreService, StoreSnapshot};
    StoreSnapshot {
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
            name: "guarded".into(),
            service: "echo".into(),
            hosts: vec![],
            paths: vec![PathMatch::Prefix("/guarded".into())],
            methods: vec![],
            headers: vec![],
            strip_path: false,
            priority: 0,
        }],
        plugins: vec![StorePlugin {
            workspace: String::new(),
            route: Some("guarded".into()),
            service: None,
            plugin: Plugin::Jwt(JwtPolicy {
                issuer: Some(JWT_ISSUER.into()),
                jwks_uri: Some(uri.into()),
                jwks_ca_pem: Some(ca_pem.into()),
                ..JwtPolicy::default()
            }),
        }],
        ..StoreSnapshot::default()
    }
}

async fn guarded(gw: &Gateway, token: &str) -> reqwest::Response {
    client(gw)
        .get(url(gw, "echo.test", "/guarded"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

/// Ask `/guarded` with `token` until it answers `status`, for up to 10 s.
async fn until_guarded_answers(gw: &Gateway, token: &str, status: u16) {
    for _ in 0..100 {
        if guarded(gw, token).await.status() == status {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("/guarded never answered {status}");
}

/// The point of the feature: keys come from the IdP's URL, a rotated key is picked up once a
/// token names it, and the last good keys outlive the IdP -- while running and across a restart.
#[tokio::test(flavor = "multi_thread")]
async fn a_jwks_uri_is_fetched_rotated_and_outlives_its_idp() {
    let (ca_pem, cert, key) = idp_tls();
    let (first, second) = (ec_key("first"), ec_key("second"));
    let document = Arc::new(Mutex::new(jwks_of(&[&first])));
    let (idp, server) = spawn_jwks_server(cert, key, Arc::clone(&document)).await;
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    let uri = format!("https://{idp}/jwks");
    let cache = tempfile::tempdir().unwrap();
    let cache_file = cache.path().join("cache.json");
    let args = [
        "--control-plane-interval",
        "1",
        "--config-cache",
        cache_file.to_str().unwrap(),
    ];

    let gw = start_store_gateway_with(jwt_guarded(upstream, &uri, &ca_pem), &args).await;
    until_guarded_answers(&gw, &signed_by(&first), 200).await;

    // The IdP rotates. The first token naming the new key is refused, and asks for a refetch.
    *document.lock().unwrap() = jwks_of(&[&second]);
    until_guarded_answers(&gw, &signed_by(&second), 200).await;

    // The IdP goes away: the keys already fetched keep verifying.
    server.abort();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(guarded(&gw, &signed_by(&second)).await.status(), 200);
    drop(gw);

    // A restart with the IdP still down verifies with the cached keys from its first request,
    // while its own fetch fails and is counted.
    let gw = start_store_gateway_with(jwt_guarded(upstream, &uri, &ca_pem), &args).await;
    assert_eq!(guarded(&gw, &signed_by(&second)).await.status(), 200);
    wait_for_metric(
        &gw,
        &format!("gapura_jwks_fetch_errors_total{{uri=\"{uri}\"}} 1"),
    )
    .await;
}

/// A URL that has never answered leaves its policy with no keys, which refuses every token as
/// invalid -- never admits one unverified.
#[tokio::test(flavor = "multi_thread")]
async fn a_jwks_uri_that_never_loads_refuses_every_token() {
    let (ca_pem, _, _) = idp_tls();
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    let uri = format!("https://{dead}/jwks");
    let gw = start_store_gateway_with(
        jwt_guarded(upstream, &uri, &ca_pem),
        &["--control-plane-interval", "1"],
    )
    .await;
    let r = guarded(&gw, &signed_by(&ec_key("any"))).await;
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["x-gapura-error"], "AUTH_JWT_INVALID");
    assert_eq!(r.headers()["www-authenticate"], "Bearer");
    wait_for_metric(
        &gw,
        &format!("gapura_jwks_last_success_timestamp_seconds{{uri=\"{uri}\"}} 0"),
    )
    .await;
}

/// One store route to `upstream` at `/{name}`.
fn one_route(upstream: SocketAddr, name: &str) -> gapura_core::store::StoreSnapshot {
    use gapura_core::config::{PathMatch, Protocol};
    use gapura_core::store::{StoreRoute, StoreService, StoreSnapshot};
    StoreSnapshot {
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
            name: name.into(),
            service: "echo".into(),
            hosts: vec![],
            paths: vec![PathMatch::Prefix(format!("/{name}"))],
            methods: vec![],
            headers: vec![],
            strip_path: false,
            priority: 0,
        }],
        ..StoreSnapshot::default()
    }
}

/// Ask `path` until it answers `status`, for up to 10 s. The data plane takes a configuration on
/// its next poll rather than at once, so a single request right after the stand-in changes its
/// answer would race that poll.
async fn until_answers(gw: &Gateway, path: &str, status: u16) {
    for _ in 0..100 {
        let r = client(gw).get(url(gw, "echo.test", path)).send().await;
        if r.is_ok_and(|r| r.status() == status) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{path} never answered {status}");
}

/// A data plane the control plane refuses keeps routing the configuration it holds, says so on
/// /metrics, and takes the next one it can read. The refusal is the stand-in's: what decides it
/// is gapura-control's, tested there; here, what the data plane sends and does about it.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_configuration_keeps_the_last_one_and_says_so() {
    use axum::http::{header, HeaderMap, StatusCode};
    let upstream = spawn_upstream(TcpListener::bind("127.0.0.1:0").unwrap()).await;
    // Status, body and ETag the stand-in answers with; and the agent and features it last heard.
    let answer = Arc::new(Mutex::new((200u16, String::new(), "\"v1\"".to_string())));
    let heard = Arc::new(Mutex::new((String::new(), String::new())));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let control = listener.local_addr().unwrap();
    let app = {
        let (answer, heard) = (Arc::clone(&answer), Arc::clone(&heard));
        Router::new().route(
            "/v1/config",
            axum::routing::get(move |headers: HeaderMap| {
                let text = |name: &str| {
                    headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string()
                };
                *heard.lock().unwrap() = (text("user-agent"), text("x-gapura-features"));
                let (status, body, etag) = answer.lock().unwrap().clone();
                async move {
                    (
                        StatusCode::from_u16(status).unwrap(),
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (header::ETAG, etag),
                        ],
                        body,
                    )
                }
            }),
        )
    };
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let first = Arc::clone(&answer);
    let gw = start_gateway_from(
        move |dir, http| {
            let settings = gapura_core::store::StoreSettings {
                http_ports: vec![http],
            };
            let config = gapura_core::store::compile(&one_route(upstream, "first"), &settings);
            first.lock().unwrap().1 = serde_json::to_string(&config).unwrap();
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
        &["--control-plane-interval", "1"],
    )
    .await;
    until_answers(&gw, "/first", 200).await;
    let (agent, features) = heard.lock().unwrap().clone();
    assert!(agent.starts_with("gapura/"), "{agent}");
    assert_eq!(features, gapura_core::features::FEATURES.join(","));

    // Refused: it keeps routing what it holds, and says so.
    *answer.lock().unwrap() = (
        409,
        r#"{"error":"incompatible","missing":["cors"]}"#.to_string(),
        "\"v2\"".to_string(),
    );
    // From the start of a line: the gauge's HELP text begins "1 while", so the bare name and
    // value also match `# HELP gapura_config_incompatible 1 while ...` at any value.
    wait_for_metric(&gw, "\ngapura_config_incompatible 1\n").await;
    until_answers(&gw, "/first", 200).await;

    // A configuration it can read again: taken, and the gauge clears.
    let settings = gapura_core::store::StoreSettings {
        http_ports: vec![gw.http],
    };
    let second = gapura_core::store::compile(&one_route(upstream, "second"), &settings);
    *answer.lock().unwrap() = (
        200,
        serde_json::to_string(&second).unwrap(),
        "\"v3\"".to_string(),
    );
    until_answers(&gw, "/second", 200).await;
    wait_for_metric(&gw, "\ngapura_config_incompatible 0\n").await;
}

/// An HTTP/1 head read off `sock` a byte at a time, lowercased. Unlike `read_head`, nothing after
/// it is read: what the other side sends straight after a 101 stays on the socket, for HTTP/2.
async fn read_head_unbuffered(sock: &mut tokio::net::TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && sock.read(&mut byte).await.unwrap() == 1 {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).to_ascii_lowercase()
}

/// An upstream that takes every upgrade it is offered: a 101, then HTTP/2 for `h2c`, as an h2c
/// server does, or an echo of the bytes for `websocket`. Anything else is answered over HTTP/1.1
/// with the `Upgrade` it arrived with, `-` for none. The list is the path of every request it
/// served over HTTP/2.
async fn spawn_upgrading_upstream() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&served);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let served = Arc::clone(&log);
            tokio::spawn(async move {
                let head = read_head_unbuffered(&mut sock).await;
                let upgrade = head
                    .lines()
                    .find_map(|l| l.strip_prefix("upgrade:"))
                    .map(|v| v.trim().to_string());
                let switch = |to: &str| {
                    format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: {to}\r\n\r\n")
                };
                match upgrade.as_deref() {
                    Some("h2c") => {
                        sock.write_all(switch("h2c").as_bytes()).await.unwrap();
                        let mut h2 = h2::server::handshake(sock).await.unwrap();
                        while let Some(Ok((req, mut respond))) = h2.accept().await {
                            let path = req.uri().path().to_string();
                            served.lock().unwrap().push(path.clone());
                            let mut body = respond
                                .send_response(http::Response::new(()), false)
                                .unwrap();
                            body.send_data(path.into(), true).unwrap();
                        }
                    }
                    Some("websocket") => {
                        sock.write_all(switch("websocket").as_bytes())
                            .await
                            .unwrap();
                        let (mut from, mut to) = sock.split();
                        let _ = tokio::io::copy(&mut from, &mut to).await;
                    }
                    other => {
                        let body = format!("upgrade: {}", other.unwrap_or("-"));
                        let _ = sock
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
                                    body.len()
                                )
                                .as_bytes(),
                            )
                            .await;
                    }
                }
            });
        }
    });
    (addr, served)
}

/// `/open` for anyone, `/private` behind key_auth, both on `upstream`.
fn open_and_private(upstream: SocketAddr) -> gapura_core::store::StoreSnapshot {
    use gapura_core::config::{KeyAuthPolicy, PathMatch, Plugin, Protocol};
    use gapura_core::store::{StorePlugin, StoreRoute, StoreService, StoreSnapshot};
    let route = |name: &str| StoreRoute {
        workspace: String::new(),
        name: name.into(),
        service: "upgrading".into(),
        hosts: vec![],
        paths: vec![PathMatch::Prefix(format!("/{name}"))],
        methods: vec![],
        headers: vec![],
        strip_path: false,
        priority: 0,
    };
    StoreSnapshot {
        services: vec![StoreService {
            workspace: String::new(),
            name: "upgrading".into(),
            protocol: Protocol::Http,
            host: upstream.ip().to_string(),
            port: upstream.port(),
            connect_timeout_ms: None,
            read_timeout_ms: None,
            tls_verify: true,
            tls_ca_pem: None,
            tls_sni: None,
        }],
        routes: vec![route("open"), route("private")],
        plugins: vec![StorePlugin {
            workspace: String::new(),
            route: Some("private".into()),
            service: None,
            plugin: Plugin::KeyAuth(KeyAuthPolicy::default()),
        }],
        ..StoreSnapshot::default()
    }
}

/// `Upgrade: h2c` is not a way past the route policies. An h2c upstream answers it with a 101
/// and speaks HTTP/2 from then on, and every request on that tunnel reaches it on any path,
/// matched and checked by nothing: here `/private` without a key, after asking `/open` to
/// upgrade. So the upstream never hears the offer, and the request is served as HTTP/1.1.
#[tokio::test(flavor = "multi_thread")]
async fn an_h2c_upgrade_is_not_a_tunnel_past_the_policies() {
    let (upstream, tunnelled) = spawn_upgrading_upstream().await;
    let gw = start_store_gateway(open_and_private(upstream)).await;
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", gw.http))
        .await
        .unwrap();
    sock.write_all(
        b"GET /open HTTP/1.1\r\nHost: echo.test\r\nConnection: Upgrade, HTTP2-Settings\r\n\
          Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n",
    )
    .await
    .unwrap();
    let head = read_head_unbuffered(&mut sock).await;
    if head.starts_with("http/1.1 101") {
        let (h2, conn) = h2::client::handshake(sock).await.unwrap();
        tokio::spawn(conn);
        let mut h2 = h2.ready().await.unwrap();
        let req = http::Request::get("http://echo.test/private")
            .body(())
            .unwrap();
        let (resp, _) = h2.send_request(req, true).unwrap();
        let status = tokio::time::timeout(Duration::from_secs(5), resp)
            .await
            .unwrap()
            .unwrap()
            .status();
        panic!(
            "the 101 made a tunnel: /private answered {status} without a key, and the upstream \
             served {:?}",
            tunnelled.lock().unwrap()
        );
    }
    assert!(head.starts_with("http/1.1 200"), "{head}");
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .expect("a content-length")
        .trim()
        .parse()
        .unwrap();
    let mut body = vec![0; len];
    sock.read_exact(&mut body).await.unwrap();
    assert_eq!(body, b"upgrade: -", "the upstream heard the offer");
}

/// WebSocket is the upgrade the gateway keeps: the route's policies judged the handshake, and
/// what follows is that one conversation, never another request.
#[tokio::test(flavor = "multi_thread")]
async fn a_websocket_upgrade_still_tunnels() {
    let (upstream, _) = spawn_upgrading_upstream().await;
    let gw = start_store_gateway(open_and_private(upstream)).await;
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", gw.http))
        .await
        .unwrap();
    sock.write_all(
        b"GET /open HTTP/1.1\r\nHost: echo.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
          Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    )
    .await
    .unwrap();
    let head = read_head_unbuffered(&mut sock).await;
    assert!(head.starts_with("http/1.1 101"), "{head}");
    sock.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    sock.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
}
