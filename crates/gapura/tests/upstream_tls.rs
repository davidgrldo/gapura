//! End-to-end: TLS from the gateway to the backend, verified through BackendTLSPolicy or
//! unverified through the `gapura.dev/backend-tls: insecure` annotation.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn ca(name: &str) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    (params.self_signed(&key).unwrap(), key)
}

/// Leaf for `san` signed by `ca`, as DER for the rustls server.
fn leaf(
    san: &str,
    ca: &(Certificate, KeyPair),
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![san.to_string()])
        .unwrap()
        .signed_by(&key, &ca.0, &ca.1)
        .unwrap();
    (
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// Minimal HTTPS/1.1 server: answers every request with `tls ok sni=<sni>` and closes.
async fn spawn_tls_upstream(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> SocketAddr {
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
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let sni = tls.get_ref().1.server_name().unwrap_or("").to_string();
                let mut buf = vec![0u8; 8192];
                let mut n = 0;
                loop {
                    let Ok(read) = tls.read(&mut buf[n..]).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    n += read;
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if n == buf.len() {
                        return;
                    }
                }
                let body = format!("tls ok sni={sni}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

fn indent(s: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    s.lines()
        .map(|l| format!("{pad}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Four Services on port 443: `echo` verified by CA-A, `badhost` verified but with the wrong
/// hostname, `selfsigned` trusted via the annotation, `nocm` with a missing ConfigMap.
fn config(http: u16, verified: SocketAddr, selfsigned: SocketAddr, ca_pem: &str) -> String {
    let service = |name: &str, addr: SocketAddr, annotation: &str| {
        format!(
            r#"
apiVersion: v1
kind: Service
metadata: {{ name: {name}, namespace: apps{annotation} }}
spec: {{ ports: [{{ name: https, port: 443 }}] }}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {{ name: {name}-1, namespace: apps, labels: {{ kubernetes.io/service-name: {name} }} }}
addressType: IPv4
endpoints: [{{ addresses: ["{ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: https, port: {port} }}]
---"#,
            ip = addr.ip(),
            port = addr.port()
        )
    };
    let policy = |name: &str, hostname: &str, cm: &str| {
        format!(
            r#"
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata: {{ name: {name}-tls, namespace: apps }}
spec:
  targetRefs: [{{ group: "", kind: Service, name: {name} }}]
  validation:
    caCertificateRefs: [{{ group: "", kind: ConfigMap, name: {cm} }}]
    hostname: {hostname}
---"#
        )
    };
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
  - {{ name: http, port: {http}, protocol: HTTP, allowedRoutes: {{ namespaces: {{ from: All }} }} }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{ name: tls, namespace: apps, generation: 1, creationTimestamp: "2026-09-10T00:00:00Z" }}
spec:
  parentRefs: [{{ name: main, namespace: infra }}]
  hostnames: [tls.test]
  rules:
  - matches: [{{ path: {{ type: PathPrefix, value: /ca }} }}]
    backendRefs: [{{ name: echo, port: 443 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /badhost }} }}]
    backendRefs: [{{ name: badhost, port: 443 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /insecure }} }}]
    backendRefs: [{{ name: selfsigned, port: 443 }}]
  - matches: [{{ path: {{ type: PathPrefix, value: /missing }} }}]
    backendRefs: [{{ name: nocm, port: 443 }}]
---
apiVersion: v1
kind: ConfigMap
metadata: {{ name: ca-a, namespace: apps }}
data:
  ca.crt: |
{ca}
---{svc_echo}{svc_bad}{svc_self}{svc_nocm}{pol_echo}{pol_bad}{pol_nocm}
"#,
        ca = indent(ca_pem, 4),
        svc_echo = service("echo", verified, ""),
        svc_bad = service("badhost", verified, ""),
        svc_self = service(
            "selfsigned",
            selfsigned,
            ", annotations: { gapura.dev/backend-tls: insecure }"
        ),
        svc_nocm = service("nocm", verified, ""),
        pol_echo = policy("echo", "echo.apps.svc", "ca-a"),
        pol_bad = policy("badhost", "wrong.example", "ca-a"),
        pol_nocm = policy("nocm", "echo.apps.svc", "does-not-exist"),
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

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
    gw.logs.lock().unwrap().iter().any(|l| l.contains(PROBE_ID))
}

/// Start the binary on ports chosen here, rendering the config once the http port is known.
///
/// `free_port` drops its listener before the child binds, so anything else on the machine can take
/// the port in between. If it does before the child starts, the gateway refuses to start on an
/// address it cannot bind, and the race shows up as an immediate clean exit; retrying on fresh
/// ports is the fix. If it does between that check and Pingora's own bind, Pingora logs "is in
/// use, will try again" and retries once a second while the process stays up, and every request to
/// the port reaches the other listener. Readiness therefore demands answers from this child on the
/// ports the test uses, which holds off until the other listener is gone and the retry wins. A
/// child that starts but never becomes ready is a real failure, not a race; a holder that outlived
/// the whole wait would fail the same way, and would need a retry on fresh ports.
async fn start(render: impl Fn(u16) -> String) -> Gateway {
    for attempt in 1..=5u32 {
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
                // and `answers_on_http` only proves the data port. `ready_to_serve` pins the admin
                // port to this child too, by finding its http port in the config it serves.
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
            panic!("gateway started on http={http} admin={admin} but never became ready");
        }
        eprintln!(
            "gateway exited before becoming ready on attempt {attempt}, retrying on new ports"
        );
    }
    panic!("gateway lost the port race five times running");
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_tls_verified_insecure_and_invalid() {
    let ca_a = ca("ca-a");
    let ca_b = ca("ca-b");
    let (echo_cert, echo_key) = leaf("echo.apps.svc", &ca_a);
    let (self_cert, self_key) = leaf("selfsigned.apps.svc", &ca_b);
    let verified = spawn_tls_upstream(echo_cert, echo_key).await;
    let selfsigned = spawn_tls_upstream(self_cert, self_key).await;
    let gw = start(|http| config(http, verified, selfsigned, &ca_a.0.pem())).await;
    let c = reqwest::Client::builder()
        .resolve(
            "tls.test",
            format!("127.0.0.1:{}", gw.http).parse().unwrap(),
        )
        .build()
        .unwrap();
    let url = |p: &str| format!("http://tls.test:{}{p}", gw.http);

    let r = c.get(url("/ca")).send().await.unwrap();
    assert_eq!(
        r.status(),
        200,
        "CA from the ConfigMap verifies the backend"
    );
    assert_eq!(r.text().await.unwrap(), "tls ok sni=echo.apps.svc");

    let r = c.get(url("/badhost")).send().await.unwrap();
    assert_eq!(r.status(), 502, "hostname mismatch fails verification");

    let r = c.get(url("/insecure")).send().await.unwrap();
    assert_eq!(
        r.status(),
        200,
        "annotation skips verification, SNI still sent"
    );
    assert_eq!(r.text().await.unwrap(), "tls ok sni=selfsigned.apps.svc");

    let r = c.get(url("/missing")).send().await.unwrap();
    assert_eq!(
        r.status(),
        500,
        "policy with a missing ConfigMap invalidates the backend"
    );
    assert_eq!(r.text().await.unwrap(), "500 no valid backend\n");

    let metrics = reqwest::get(format!("http://127.0.0.1:{}/metrics", gw.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics
            .contains(r#"gapura_upstream_errors_total{cluster="apps/badhost:443",kind="connect"}"#),
        "{metrics}"
    );
}
