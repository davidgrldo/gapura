//! `GET /v1/config`: the endpoint data planes poll for their configuration.
//!
//! A conditional GET. The data plane sends the version it holds as `If-None-Match` and gets
//! either 304 or the configuration that replaces it. The call is also the liveness signal, so a
//! 304 still records that the caller is alive -- there is no second endpoint reporting a fact
//! this one already carries.
//!
//! **This is the one endpoint that serves private key material.** `admin.rs` on the data plane
//! redacts `tls/key_pem` even on its admin port, and that rule is right; this is its single
//! exception, because a data plane cannot terminate TLS without the key. It is why this call is
//! authenticated in both directions, and why this listens on its own port rather than
//! sharing the console's: an operator can reach the console through an ingress without that
//! also publishing the keys.

use std::sync::Arc;

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use gapura_core::store::{compile, StoreSettings, StoreSnapshot};
use sha2::{Digest, Sha256};

use crate::store::Store;

pub struct ConfigApi {
    pub store: Arc<Store>,
    pub settings: StoreSettings,
}

/// A TLS acceptor for the configuration endpoint from a PEM certificate chain and its key.
///
/// ponytail: read once, at start. A rotated certificate (cert-manager renews well before expiry)
/// takes effect at the next restart; a resolver that re-reads the files on change is the upgrade
/// if restarts on rotation become a burden.
pub fn tls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use anyhow::{anyhow, Context};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("reading the configuration endpoint's certificate: {e:?}"))?;
    anyhow::ensure!(
        !chain.is_empty(),
        "the configuration endpoint's certificate file holds no PEM certificate"
    );
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| anyhow!("reading the configuration endpoint's key: {e:?}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("the configuration endpoint's certificate and key do not match")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Serves `router` over TLS on `listener` until the listener fails.
///
/// A handshake that has not finished in ten seconds is dropped, so a client that opens a
/// connection and sends nothing holds a task for that long and no longer.
pub async fn serve_tls(
    listener: tokio::net::TcpListener,
    router: Router,
    acceptor: tokio_rustls::TlsAcceptor,
) -> std::io::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // Out of file descriptors and the like: the next accept may succeed once some close.
            Err(e) if is_transient(&e) => {
                tracing::warn!(error = %e, "accepting a configuration connection");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => return Err(e),
        };
        let acceptor = acceptor.clone();
        // The same extension `into_make_service_with_connect_info` adds on the plain listener,
        // so the handler reads the peer one way whichever listener it came in on.
        let service = TowerToHyperService::new(router.clone().layer(Extension(ConnectInfo(peer))));
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(tcp),
            )
            .await
            {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
            {
                tracing::debug!(%peer, error = %e, "configuration connection ended");
            }
        });
    }
}

fn is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | Interrupted | WouldBlock
    ) || e.raw_os_error() == Some(24) // EMFILE
        || e.raw_os_error() == Some(23) // ENFILE
}

/// What a data plane is sent for `snapshot`: the compiled configuration's bytes and their tag.
/// The console's "in sync" reads the tag from here too, so the two cannot disagree.
///
/// The tag is what is served, not the store's version counter. The counter restarts when the
/// database is restored or recreated, and it does not move when a control-plane flag or a new
/// release changes what the same rows compile to; in each case a data plane holding an old tag
/// would be told 304 and keep a configuration that is no longer the one served. The snapshot is
/// read on every call anyway, so this costs CPU and no I/O. Config has no unordered maps, so
/// equal configurations serialise to equal bytes.
pub fn served(
    snapshot: &StoreSnapshot,
    settings: &StoreSettings,
) -> serde_json::Result<(Vec<u8>, String)> {
    let body = serde_json::to_vec(&compile(snapshot, settings))?;
    let etag = format!("\"{:x}\"", Sha256::digest(&body));
    Ok((body, etag))
}

pub fn router(api: Arc<ConfigApi>) -> Router {
    Router::new()
        .route("/v1/config", get(serve))
        .with_state(api)
}

/// `peer` is `None` only where nothing supplied it -- a test's router called directly. Both
/// listeners `main` starts do.
async fn serve(
    State(api): State<Arc<ConfigApi>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return unauthorized();
    };
    let (id, token_id) = match api.store.authenticate(token).await {
        Ok(Some(ids)) => ids,
        Ok(None) => return unauthorized(),
        Err(e) => {
            tracing::error!(error = %e, "authenticating a data plane");
            // The store is unreachable, not the token wrong. Saying 401 would send an operator
            // hunting a credential that is fine.
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let (version, snapshot) = match api.store.snapshot().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "reading the configuration");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let sent = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    // Recorded before the body is built and whatever the answer turns out to be: the caller is
    // alive either way, and a 304 is the overwhelming majority of these calls.
    if let Err(e) = api
        .store
        .record_call(
            id,
            token_id,
            version,
            sent,
            peer.map(|p| p.0 .0.ip().to_canonical()),
        )
        .await
    {
        // Liveness is for a human looking at a console. Losing it must not cost a data plane
        // its configuration.
        tracing::warn!(error = %e, "recording a data plane's call");
    }

    let (body, etag) = match served(&snapshot, &api.settings) {
        Ok(served) => served,
        Err(e) => {
            tracing::error!(error = %e, "serialising the configuration");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if sent.is_some_and(|v| v == etag) {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    (
        StatusCode::OK,
        [
            (header::ETAG, etag),
            (header::CONTENT_TYPE, "application/json".to_string()),
            // The response is the gateway's private keys. No shared cache should hold it,
            // and the conditional request is what makes caching unnecessary anyway.
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// `WWW-Authenticate` so the failure is legible to whoever is holding a curl, because being
/// debuggable with curl is worth keeping.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_endpoint_answers_over_tls_to_a_client_that_trusts_its_certificate() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let acceptor = tls_acceptor(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // The handler is not what is under test, so any router shows the transport works -- and
        // that the connection's peer reaches it, the way `serve` reads it.
        let router = Router::new().route(
            "/v1/config",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                format!("served over tls to {}", peer.ip())
            }),
        );
        tokio::spawn(serve_tls(listener, router, acceptor));

        let trusting = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap(),
            )
            .build()
            .unwrap();
        let body = trusting
            .get(format!("https://localhost:{port}/v1/config"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "served over tls to 127.0.0.1");

        // Plain HTTP to a TLS port gets no answer it could read as a configuration.
        let plain = reqwest::Client::new()
            .get(format!("http://localhost:{port}/v1/config"))
            .send()
            .await;
        assert!(plain.map(|r| !r.status().is_success()).unwrap_or(true));
    }

    #[test]
    fn a_key_that_is_not_the_certificate_s_is_refused() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        assert!(tls_acceptor(
            cert.cert.pem().as_bytes(),
            other.key_pair.serialize_pem().as_bytes()
        )
        .is_err());
        assert!(tls_acceptor(b"", cert.key_pair.serialize_pem().as_bytes()).is_err());
    }
}
