//! End-to-end TLS: certificate selection by SNI.
//!
//! Hostnames use a two-label base (`gw.test`) because rustls-webpki, like NSS, refuses to match a
//! wildcard with fewer than two labels after `*.` (`*.test` would never validate for `x.test`).

use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair};

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

/// Leaf cert for `san`, signed by `ca`; returns (cert PEM, key PEM).
fn leaf(san: &str, ca: &(Certificate, KeyPair)) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec![san.to_string()]).unwrap();
    let cert = params.signed_by(&key, &ca.0, &ca.1).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

async fn spawn_upstream() -> SocketAddr {
    use axum::{routing::any, Router};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(any(|req: axum::extract::Request| async move {
        let proto = req
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let host = req
            .headers()
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        format!("{proto} {host}")
    }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn config(
    http: u16,
    https: u16,
    upstream: SocketAddr,
    a: &(String, String),
    w: &(String, String),
) -> String {
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
  - name: https-a
    port: {https}
    protocol: HTTPS
    hostname: a.gw.test
    tls: {{ certificateRefs: [{{ name: cert-a }}] }}
    allowedRoutes: {{ namespaces: {{ from: All }} }}
  - name: https-w
    port: {https}
    protocol: HTTPS
    hostname: "*.gw.test"
    tls: {{ certificateRefs: [{{ name: cert-w }}] }}
    allowedRoutes: {{ namespaces: {{ from: All }} }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{ name: all, namespace: apps, generation: 1, creationTimestamp: "2026-09-10T00:00:00Z" }}
spec:
  parentRefs: [{{ name: main, namespace: infra }}]
  hostnames: ["a.gw.test", "*.gw.test"]
  rules:
  - backendRefs: [{{ name: echo, port: 80 }}]
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
endpoints: [{{ addresses: ["{ip}"], conditions: {{ ready: true }} }}]
ports: [{{ name: http, port: {port} }}]
---
apiVersion: v1
kind: Secret
metadata: {{ name: cert-a, namespace: infra }}
type: kubernetes.io/tls
data: {{ tls.crt: {a_crt}, tls.key: {a_key} }}
---
apiVersion: v1
kind: Secret
metadata: {{ name: cert-w, namespace: infra }}
type: kubernetes.io/tls
data: {{ tls.crt: {w_crt}, tls.key: {w_key} }}
"#,
        ip = upstream.ip(),
        port = upstream.port(),
        a_crt = b64(&a.0),
        a_key = b64(&a.1),
        w_crt = b64(&w.0),
        w_key = b64(&w.1),
    )
}

struct Gateway {
    child: Child,
    https: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the binary on ports chosen here, rendering the config once they are known.
///
/// `free_port` drops its listener before the child binds, so anything else on the machine can take
/// the port in between. The gateway refuses to start on an address it cannot bind, so that race
/// shows up as an immediate clean exit; retrying on fresh ports is the fix. A child that starts but
/// never becomes ready is a real failure, not a race.
async fn start(render: impl Fn(u16, u16) -> String) -> Gateway {
    for attempt in 1..=5u32 {
        let (http, https, admin) = (free_port(), free_port(), free_port());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.yaml"), render(http, https)).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_gapura"))
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
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut gw = Gateway {
            child,
            https,
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
                // Pingora binds each service independently: /readyz only proves the admin listener
                // and the loaded config, so also wait for the data-plane service to accept
                // connections. Probe the plain HTTP port of the same service: a bare connect to the
                // TLS port would log a handshake error on every run.
                if r.status() == 200 && std::net::TcpStream::connect(("127.0.0.1", http)).is_ok() {
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
            panic!("gateway started on https={https} but never became ready");
        }
        eprintln!(
            "gateway exited before becoming ready on attempt {attempt}, retrying on new ports"
        );
    }
    panic!("gateway lost the port race five times running");
}

fn client_trusting(ca_pem: &str, gw: &Gateway) -> reqwest::Client {
    let addr: SocketAddr = format!("127.0.0.1:{}", gw.https).parse().unwrap();
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .resolve("a.gw.test", addr)
        .resolve("x.gw.test", addr)
        .https_only(true)
        .build()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_is_selected_by_sni() {
    let ca_a = ca("ca-a");
    let ca_w = ca("ca-w");
    let leaf_a = leaf("a.gw.test", &ca_a);
    let leaf_w = leaf("*.gw.test", &ca_w);
    let upstream = spawn_upstream().await;
    let gw = start(|http, https| config(http, https, upstream, &leaf_a, &leaf_w)).await;
    let https = gw.https;

    let trust_a = client_trusting(&ca_a.0.pem(), &gw);
    let r = trust_a
        .get(format!("https://a.gw.test:{https}/"))
        .send()
        .await
        .expect("cert-a served for SNI a.gw.test");
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "https a.gw.test");

    let err = trust_a
        .get(format!("https://x.gw.test:{https}/"))
        .send()
        .await
        .expect_err("cert-w is not signed by ca-a");
    assert!(
        err.is_connect() || err.to_string().to_lowercase().contains("certificate"),
        "{err}"
    );

    let trust_w = client_trusting(&ca_w.0.pem(), &gw);
    let r = trust_w
        .get(format!("https://x.gw.test:{https}/"))
        .send()
        .await
        .expect("cert-w served for SNI x.gw.test");
    assert_eq!(r.text().await.unwrap(), "https x.gw.test");
}
