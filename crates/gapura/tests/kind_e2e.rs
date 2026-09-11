//! Control-plane e2e against a real API server (kind). Run through `hack/kind-e2e.sh`.
//! The gateway runs on the host, so pod IPs are unreachable: this asserts status, config, the
//! Lease, and hot reload, not proxied traffic (that is Plan 4's in-cluster conformance job).

use std::future::Future;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::Value;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn kubectl(args: &[&str]) -> String {
    let out = Command::new("kubectl")
        .args(args)
        .output()
        .expect("kubectl on PATH");
    assert!(
        out.status.success(),
        "kubectl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Poll `check` every 500 ms until it resolves to `true`; panic after `timeout`.
async fn wait_for<F>(what: &str, timeout: Duration, mut check: impl FnMut() -> F)
where
    F: Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("timed out waiting for {what}");
}

/// `GET /debug/config` on the admin endpoint.
async fn fetch_config(http: Client, url: String) -> Value {
    http.get(url).send().await.unwrap().json().await.unwrap()
}

/// Route ids (`ns/name`) attached to the first listener of the routing config.
async fn listener0_routes(http: Client, url: String) -> Vec<String> {
    let cfg = fetch_config(http, url).await;
    cfg["listeners"][0]["rules"]
        .as_array()
        .map(|rules| {
            rules
                .iter()
                .filter_map(|r| r["route"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

struct Gateway(Child);

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The gateway against the kind cluster, ready, with the admin port it ended up on.
///
/// `free_port` drops its listener before the child binds, so anything else on the machine can take
/// the port in between; the gateway refuses to start on an address it cannot bind, so that race
/// shows up as an immediate clean exit and retrying on fresh ports is the fix. The HTTP port is
/// fixed, though, so a child that keeps exiting is more likely to be that port already in use than
/// the race five times over -- the last panic says both.
async fn start(http: &Client) -> (Gateway, u16) {
    for attempt in 1..=5u32 {
        let admin = free_port();
        let mut gw = Gateway(
            Command::new(env!("CARGO_BIN_EXE_gapura"))
                .args([
                    "--kubernetes",
                    "--listen-http",
                    "127.0.0.1:8080",
                    "--listen-https",
                    &format!("127.0.0.1:{}", free_port()),
                    "--admin",
                    &format!("127.0.0.1:{admin}"),
                    "--lease-namespace",
                    "gapura-system",
                    "--identity",
                    "kind-e2e",
                    "--publish-address",
                    "203.0.113.10",
                    "--log-level",
                    "info",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut exited = false;
        while Instant::now() < deadline {
            if matches!(gw.0.try_wait(), Ok(Some(_))) {
                exited = true;
                break;
            }
            let ready = http
                .get(format!("http://127.0.0.1:{admin}/readyz"))
                .send()
                .await
                .map(|r| r.status() == 200)
                .unwrap_or(false);
            if ready {
                return (gw, admin);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if !exited {
            panic!("gateway started on admin={admin} but never became ready");
        }
        eprintln!(
            "gateway exited before becoming ready on attempt {attempt}, retrying on new ports"
        );
    }
    panic!(
        "the gateway exited before becoming ready five times running: either 127.0.0.1:8080 is \
         already in use, or it lost the race for its ephemeral ports every time"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a kind cluster; run hack/kind-e2e.sh"]
async fn status_config_lease_and_hot_reload() {
    if std::env::var_os("GAPURA_KIND").is_none() {
        eprintln!("GAPURA_KIND not set, skipping");
        return;
    }
    let http = Client::new();
    let (_gw, admin) = start(&http).await;
    let admin_url = |p: &str| format!("http://127.0.0.1:{admin}{p}");
    let config_url = admin_url("/debug/config");

    let cfg = fetch_config(http.clone(), config_url.clone()).await;
    assert_eq!(cfg["listeners"][0]["id"], "gapura-e2e/main/http");
    assert!(
        cfg["clusters"]["gapura-e2e/echo:80"]["endpoints"]
            .as_array()
            .is_some_and(|e| !e.is_empty()),
        "{cfg}"
    );

    wait_for(
        "Gateway Programmed=True",
        Duration::from_secs(30),
        || async {
            kubectl(&[
                "-n",
                "gapura-e2e",
                "get",
                "gateway",
                "main",
                "-o",
                "jsonpath={.status.conditions[?(@.type==\"Programmed\")].status}",
            ]) == "True"
        },
    )
    .await;
    assert_eq!(
        kubectl(&[
            "-n",
            "gapura-e2e",
            "get",
            "gateway",
            "main",
            "-o",
            "jsonpath={.status.addresses[0].value}"
        ]),
        "203.0.113.10"
    );
    assert_eq!(
        kubectl(&[
            "-n",
            "gapura-e2e",
            "get",
            "gateway",
            "main",
            "-o",
            "jsonpath={.status.listeners[0].attachedRoutes}"
        ]),
        "1"
    );
    assert_eq!(
        kubectl(&[
            "-n",
            "gapura-e2e",
            "get",
            "httproute",
            "echo",
            "-o",
            "jsonpath={.status.parents[0].conditions[?(@.type==\"Accepted\")].status}"
        ]),
        "True"
    );
    assert_eq!(
        kubectl(&[
            "get",
            "gatewayclass",
            "gapura",
            "-o",
            "jsonpath={.status.conditions[?(@.type==\"Accepted\")].status}"
        ]),
        "True"
    );
    assert_eq!(
        kubectl(&[
            "-n",
            "gapura-system",
            "get",
            "lease",
            "gapura-leader",
            "-o",
            "jsonpath={.spec.holderIdentity}"
        ]),
        "kind-e2e"
    );

    // hot reload: a second route shows up in the config without a restart
    let route2 = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: echo2, namespace: gapura-e2e }
spec:
  parentRefs: [{ name: main }]
  hostnames: [echo2.e2e]
  rules:
  - backendRefs: [{ name: echo, port: 80 }]
"#;
    let dir = tempfile::tempdir().unwrap();
    let route2_path = dir.path().join("route2.yaml");
    std::fs::write(&route2_path, route2).unwrap();
    kubectl(&["apply", "-f", route2_path.to_str().unwrap()]);
    wait_for("echo2 in config", Duration::from_secs(15), || {
        let routes = listener0_routes(http.clone(), config_url.clone());
        async move { routes.await.iter().any(|r| r == "gapura-e2e/echo2") }
    })
    .await;
    kubectl(&["-n", "gapura-e2e", "delete", "httproute", "echo2"]);
    wait_for("echo2 removed", Duration::from_secs(15), || {
        let routes = listener0_routes(http.clone(), config_url.clone());
        async move { routes.await.iter().all(|r| r != "gapura-e2e/echo2") }
    })
    .await;
}
