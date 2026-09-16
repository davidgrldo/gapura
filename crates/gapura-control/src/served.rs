//! What a gateway is actually serving, read from its admin port.

use serde::Deserialize;

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
            http: reqwest::Client::new(),
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
}
