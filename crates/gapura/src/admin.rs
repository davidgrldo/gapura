//! Admin endpoints on their own port (never exposed through the Kubernetes Service):
//! /healthz, /readyz, /metrics, /debug/config.

use std::sync::Arc;

use async_trait::async_trait;
use http::{header, Response, StatusCode};
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;
use prometheus::{Encoder, TextEncoder};

use crate::store::Store;

pub struct AdminApp {
    pub store: Arc<Store>,
}

fn respond(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .expect("static response")
}

impl AdminApp {
    pub fn handle(&self, path: &str) -> Response<Vec<u8>> {
        match path {
            "/healthz" => respond(StatusCode::OK, "text/plain", b"ok\n".to_vec()),
            "/readyz" => {
                if self.store.is_ready() {
                    // The generation of the runtime actually being served right now.
                    let generation = self.store.load().generation;
                    respond(
                        StatusCode::OK,
                        "text/plain",
                        format!("ready (generation {generation})\n").into_bytes(),
                    )
                } else {
                    respond(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "text/plain",
                        b"not ready: no config loaded yet\n".to_vec(),
                    )
                }
            }
            "/metrics" => {
                let encoder = TextEncoder::new();
                let mut buf = Vec::new();
                match encoder.encode(&prometheus::gather(), &mut buf) {
                    Ok(()) => respond(StatusCode::OK, encoder.format_type(), buf),
                    Err(e) => respond(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "text/plain",
                        format!("metrics encode failed: {e}\n").into_bytes(),
                    ),
                }
            }
            "/debug/config" => {
                let runtime = self.store.load_full();
                match serde_json::to_vec_pretty(&runtime.config) {
                    Ok(json) => respond(StatusCode::OK, "application/json", json),
                    Err(e) => respond(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "text/plain",
                        format!("serialize failed: {e}\n").into_bytes(),
                    ),
                }
            }
            _ => respond(
                StatusCode::NOT_FOUND,
                "text/plain",
                b"404 not found\n".to_vec(),
            ),
        }
    }
}

#[async_trait]
impl ServeHttp for AdminApp {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = session.req_header().uri.path().to_string();
        self.handle(&path)
    }
}

#[cfg(test)]
mod tests {
    use gapura_core::config::{ListenerConfig, Protocol};
    use gapura_core::Config;

    use super::*;

    #[test]
    fn readyz_flips_after_first_swap_and_debug_config_dumps_json() {
        let store = Arc::new(Store::empty());
        let app = AdminApp {
            store: store.clone(),
        };
        assert_eq!(app.handle("/healthz").status(), StatusCode::OK);
        let not_ready = app.handle("/readyz");
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(String::from_utf8_lossy(not_ready.body()).starts_with("not ready"));
        store.swap(Config {
            listeners: vec![ListenerConfig {
                id: "infra/main/http".into(),
                port: 80,
                protocol: Protocol::Http,
                hostname: None,
                tls: None,
                rules: vec![],
                table: vec![],
            }],
            clusters: Default::default(),
        });
        let ready = app.handle("/readyz");
        assert_eq!(ready.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(ready.body()).into_owned();
        assert!(body.starts_with("ready (generation"), "{body}");
        assert_eq!(body, "ready (generation 1)\n");
        let cfg = app.handle("/debug/config");
        assert_eq!(cfg.headers()[header::CONTENT_TYPE], "application/json");
        assert!(String::from_utf8_lossy(cfg.body()).contains("infra/main/http"));
        let metrics = app.handle("/metrics");
        assert_eq!(metrics.status(), StatusCode::OK);
        assert_eq!(app.handle("/nope").status(), StatusCode::NOT_FOUND);
    }
}
