//! What a gateway is actually serving, read from its admin port.

use serde::Deserialize;
use std::time::Duration;

// A gateway that is unreachable must become an error quickly rather than a hang. One whose
// admin port completes the TCP handshake and then never writes a response — deadlocked,
// thrashing, or blackholed by a NetworkPolicy — would otherwise hold the handler open
// forever and let tasks accumulate, so the console must give up and say it does not know.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// One route as the data plane resolved it. Only the fields the console shows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServedRule {
    /// `namespace/name` of the route this rule came from.
    pub route: String,
    pub cluster: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    pub rules: Vec<ServedRule>,
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
            listeners: Vec<Listener>,
        }
        #[derive(Deserialize)]
        struct Listener {
            rules: Vec<ServedRule>,
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
            rules: config.listeners.into_iter().flat_map(|l| l.rules).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Json, Router};

    /// A stand-in for a gateway's admin port, serving one canned /debug/config.
    async fn stub(body: serde_json::Value) -> String {
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
        let base = stub(serde_json::json!({
            "listeners": [
                { "rules": [
                    { "route": "apps/checkout", "cluster": "apps/checkout:80" },
                    { "route": "apps/billing", "cluster": null }
                ] }
            ]
        }))
        .await;

        let got = Admin::new(base).served().await.unwrap();

        assert_eq!(got.rules.len(), 2);
        assert_eq!(got.rules[0].route, "apps/checkout");
        assert_eq!(got.rules[1].cluster, None);
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
