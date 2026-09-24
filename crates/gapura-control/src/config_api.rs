//! `GET /v1/config`: the endpoint data planes poll for their configuration.
//!
//! A conditional GET. The data plane sends the version it holds as `If-None-Match` and gets
//! either 304 or the configuration that replaces it. The call is also the liveness signal, so a
//! 304 still records that the caller is alive -- there is no second endpoint reporting a fact
//! this one already carries.
//!
//! **This is the one endpoint that serves private key material.** `admin.rs` on the data plane
//! redacts `tls/key_pem` even on its admin port, and that rule is right; this is its single
//! exception, because a data plane cannot terminate TLS without the key. It is why ADR 4 asks
//! for authentication in both directions, and why this listens on its own port rather than
//! sharing the console's: an operator can reach the console through an ingress without that
//! also publishing the keys.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use gapura_core::store::{compile, StoreSettings};

use crate::store::Store;

pub struct ConfigApi {
    pub store: Arc<Store>,
    pub settings: StoreSettings,
}

pub fn router(api: Arc<ConfigApi>) -> Router {
    Router::new()
        .route("/v1/config", get(serve))
        .with_state(api)
}

async fn serve(State(api): State<Arc<ConfigApi>>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return unauthorized();
    };
    let id = match api.store.authenticate(token).await {
        Ok(Some(id)) => id,
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

    // Recorded before the body is built and whatever the answer turns out to be: the caller is
    // alive either way, and a 304 is the overwhelming majority of these calls.
    if let Err(e) = api.store.record_call(id, version).await {
        // Liveness is for a human looking at a console. Losing it must not cost a data plane
        // its configuration.
        tracing::warn!(error = %e, "recording a data plane's call");
    }

    let etag = format!("\"{version}\"");
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag)
    {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }

    let config = compile(&snapshot, &api.settings);
    match serde_json::to_vec(&config) {
        Ok(body) => (
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
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "serialising the configuration");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// `WWW-Authenticate` so the failure is legible to whoever is holding a curl, which ADR 3 said
/// was worth keeping.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
    )
        .into_response()
}
