//! Where the declared side comes from: the HTTPRoutes the API server is holding.
//!
//! This module fetches, and `declared` parses what it fetched. Keeping the two apart is
//! what lets the parsing be tested against fixtures with no cluster anywhere in sight, and
//! leaves this thin enough to be tested against a stub.

use crate::declared::{routes_from_list, DeclaredRoute};
use kube::api::{ApiResource, DynamicObject, GroupVersionKind, ListParams};
use kube::core::Request;
use kube::{Client, Config, Resource};
use std::time::Duration;

const GROUP: &str = "gateway.networking.k8s.io";
const VERSION: &str = "v1";
const KIND: &str = "HTTPRoute";
/// Said out loud rather than derived from the kind: kube-rs pluralises by a rule that is
/// only usually right, and a kind it got wrong would answer 404 in a real cluster while
/// every test here still passed.
const PLURAL: &str = "httproutes";

/// An API server that completes the handshake and then never writes a response would hold a
/// console request open forever, exactly as a silent gateway would. kube leaves this unset
/// so that long-lived watches are allowed to idle; this reader only ever lists, so it can
/// afford to insist on an answer.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The declared side of the console's two sources: what is in the cluster, and what our
/// controller said about it.
pub struct Source {
    /// The client, or why one could not be built from what we were given. The failure is
    /// carried rather than panicked on, so that a base URL which is not a URL reaches the
    /// caller as the same kind of error as an API server that is simply not answering.
    client: Result<Client, String>,
}

impl Source {
    /// A source reading the API server at `base` with no credentials and no CA: what a test
    /// points at a stub. In a cluster use [`Source::from_environment`], which brings the
    /// service account's token and the cluster's certificate authority with it.
    pub fn new(base: String) -> Self {
        Self {
            client: client_at(&base).map_err(|e| format!("{base}: {e:#}")),
        }
    }

    /// The client this process's surroundings imply: the mounted service account when it
    /// runs inside a cluster, and the caller's kubeconfig when it does not.
    pub async fn from_environment() -> anyhow::Result<Self> {
        Ok(Self {
            client: Ok(client_from(Config::infer().await?)?),
        })
    }

    /// Every HTTPRoute in the cluster, carrying `controller`'s verdict on each.
    pub async fn routes(&self, controller: &str) -> anyhow::Result<Vec<DeclaredRoute>> {
        let client = self.client.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
        let resource =
            ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk(GROUP, VERSION, KIND), PLURAL);
        // Every namespace, because the console scopes what it shows by the caller's grants,
        // which it cannot do over a list it never asked for.
        let path = DynamicObject::url_path(&resource, None);
        // One request, and whatever that request returns. A cluster holding more routes
        // than the API server will put in one response is truncated here, and paginating
        // quietly would turn that into a short list nobody can tell is short. #48 is where
        // it gets fixed; until then the limitation stays where it can be seen.
        let list = Request::new(path).list(&ListParams::default())?;
        let json = client.request_text(list).await?;
        routes_from_list(&json, controller)
    }
}

/// A client pointed at one URL and told nothing else.
fn client_at(base: &str) -> anyhow::Result<Client> {
    // Parsed into the URL type `Config::new` asks for.
    client_from(Config::new(base.parse()?))
}

fn client_from(mut config: Config) -> anyhow::Result<Client> {
    config.read_timeout = Some(READ_TIMEOUT);
    Ok(Client::try_from(config)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};

    /// A stand-in for the API server, answering the list request with the same fixture the
    /// parser is tested against. It is mounted at the one path the client is expected to
    /// ask for, so a reader that went looking somewhere else fails here rather than passing.
    async fn stub_api(body: &'static str) -> String {
        let app = Router::new().route(
            "/apis/gateway.networking.k8s.io/v1/httproutes",
            get(move || async move { body }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn routes_are_read_from_the_api_server() {
        let body = include_str!("../tests/fixtures/httproutes.json");
        let base = stub_api(body).await;
        let got = Source::new(base)
            .routes("gapura.dev/controller")
            .await
            .unwrap();
        assert!(!got.is_empty());
    }

    #[tokio::test]
    async fn an_api_server_that_is_not_answering_is_an_error_not_an_empty_list() {
        // The same rule the admin reader follows: not knowing must not look like knowing
        // there is nothing, because the join renders those differently.
        let got = Source::new("http://127.0.0.1:1".to_string())
            .routes("gapura.dev/controller")
            .await;
        assert!(got.is_err());
    }

    /// A stand-in for an API server that is up enough to accept a connection and then never
    /// answers: overloaded, deadlocked, or blackholed after the handshake.
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
    async fn an_api_server_that_accepts_and_never_answers_is_an_error_not_a_hang() {
        let base = silent_stub().await;
        // Far above the client's own timeout, so a failure here reads as "the client
        // returned an error late or not at all" rather than as a flaky harness.
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            Source::new(base).routes("gapura.dev/controller"),
        )
        .await
        .expect("the client's own timeout must fire long before this one");
        assert!(
            outcome.is_err(),
            "an API server that never responds must become an error"
        );
    }
}
