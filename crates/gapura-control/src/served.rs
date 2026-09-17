//! What a gateway is actually serving, read from its admin port.

use serde::{Deserialize, Serialize};
use std::time::Duration;

// A gateway that is unreachable must become an error quickly rather than a hang. One whose
// admin port completes the TCP handshake and then never writes a response — deadlocked,
// thrashing, or blackholed by a NetworkPolicy — would otherwise hold the handler open
// forever and let tasks accumulate, so the console must give up and say it does not know.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// One route as the data plane resolved it. Only the fields the console shows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ServedRule {
    /// `namespace/name` of the route this rule came from.
    pub route: String,
    pub cluster: Option<String>,
}

/// One listener of a gateway's routing config, with the rules it is serving. Mirrors the
/// fields of `gapura-core`'s `ListenerConfig` that the overview screen shows; the rest (TLS
/// material, the port-precedence table) never leaves the admin port, and serde drops whatever
/// it does not name here without complaint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ServedListener {
    /// `namespace/gateway/listener`, so a rule can be attributed to the Gateway serving it.
    pub id: String,
    pub port: u16,
    /// The port a client dials, when a Service maps it onto a different bound port. Absent
    /// when they are the same, so the screen shows one number unless there really are two.
    #[serde(default)]
    pub client_port: Option<u16>,
    /// Defaulted, unlike `id`, `port` and `rules`: it is display-only here (nothing in this
    /// crate parses it), so a response that omits it should not turn a reachable gateway into
    /// an unreachable one over a field nobody acts on.
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub hostname: Option<String>,
    pub rules: Vec<ServedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    pub listeners: Vec<ServedListener>,
}

pub struct Admin {
    base: String,
    http: reqwest::Client,
}

impl Admin {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .expect("a client configured with nothing but timeouts always builds"),
        }
    }

    pub async fn served(&self) -> anyhow::Result<Served> {
        #[derive(Deserialize)]
        struct Config {
            listeners: Vec<ServedListener>,
        }
        let config: Config = self
            .http
            .get(format!("{}/debug/config", self.base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(Served {
            listeners: config.listeners,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{routing::get, Json, Router};

    /// A stand-in for a gateway's admin port, serving one canned /debug/config.
    pub(crate) async fn stub_admin(body: serde_json::Value) -> String {
        let app = Router::new().route(
            "/debug/config",
            get(move || {
                let body = body.clone();
                async move { Json(body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn rules_are_read_out_of_the_listeners() {
        let base = stub_admin(serde_json::json!({
            "listeners": [
                { "id": "infra/main/http", "port": 80, "rules": [
                    { "route": "apps/checkout", "cluster": "apps/checkout:80" },
                    { "route": "apps/billing", "cluster": null }
                ] }
            ]
        }))
        .await;

        let got = Admin::new(base).served().await.unwrap();

        assert_eq!(got.listeners[0].rules.len(), 2);
        assert_eq!(got.listeners[0].rules[0].route, "apps/checkout");
        assert_eq!(got.listeners[0].rules[1].cluster, None);
    }

    #[tokio::test]
    async fn every_rule_stays_with_the_listener_that_serves_it() {
        // Which listener a rule came from is the only thing that says which Gateway is
        // serving the route, and a listener id names it: `namespace/gateway/listener`.
        // Flattening the listeners away leaves presence answerable only as "somewhere in
        // this config", which cannot tell a route serving on one Gateway from one that is
        // not serving on another.
        let base = stub_admin(serde_json::json!({
            "listeners": [
                { "id": "infra/main/http", "port": 80, "rules": [
                    { "route": "apps/checkout", "cluster": "apps/checkout:80" }
                ] },
                { "id": "infra/second/http", "port": 8080, "rules": [
                    { "route": "apps/billing", "cluster": null }
                ] }
            ]
        }))
        .await;

        let got = Admin::new(base).served().await.unwrap();

        assert_eq!(got.listeners.len(), 2);
        assert_eq!(got.listeners[0].id, "infra/main/http");
        assert_eq!(got.listeners[0].rules[0].route, "apps/checkout");
        assert_eq!(got.listeners[1].id, "infra/second/http");
        assert_eq!(got.listeners[1].rules[0].route, "apps/billing");
    }

    #[tokio::test]
    async fn a_gateway_that_is_not_answering_is_an_error_not_an_empty_list() {
        // Nothing is listening on this port. Not knowing must not look like knowing nothing.
        let got = Admin::new("http://127.0.0.1:1").served().await;
        assert!(
            got.is_err(),
            "an unreachable gateway must not resolve to zero rules"
        );
    }

    /// A stand-in for a gateway that is up enough to accept a connection and then never
    /// answers: deadlocked, thrashing, or blackholed after the handshake.
    async fn silent_stub() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // The accepted sockets are held rather than dropped: dropping one closes the
            // connection, and the client would then fail on the close instead of on the
            // timeout this test is about.
            let mut accepted = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                accepted.push(socket);
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_gateway_that_accepts_and_never_answers_is_an_error_not_a_hang() {
        let base = silent_stub().await;
        // Far above the client's own timeout, so a failure here reads as "the client
        // returned an error late or not at all" rather than as a flaky harness.
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Admin::new(base).served(),
        )
        .await
        .expect("the client's own timeout must fire long before this one");
        assert!(
            outcome.is_err(),
            "a gateway that never responds must become an error"
        );
    }
}
