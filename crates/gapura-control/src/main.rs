//! The gapura control plane: serves the console and reads on its behalf.

mod api;
pub mod declared;
pub mod rows;
pub mod scope;
pub mod served;
pub mod session;
pub mod state;

use rand::RngCore;
use std::sync::Arc;

/// The env var holding the session-signing key, so restarts (and a fleet of replicas)
/// verify each other's cookies instead of only their own process's.
const SESSION_KEY_VAR: &str = "GAPURA_SESSION_KEY";

fn session_key() -> Vec<u8> {
    if let Ok(key) = std::env::var(SESSION_KEY_VAR) {
        return key.into_bytes();
    }
    tracing::warn!(
        "{SESSION_KEY_VAR} is not set; generating a random session key for this process \
         only, so every session will be invalidated the next time it restarts"
    );
    let mut key = vec![0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    let state = state::AppState {
        // No groups are mapped yet: readers, and the config that populates this, are
        // later work. An empty mapping grants nothing, which is the safe default.
        mapping: Arc::new(scope::Mapping::new()),
        session_key: Arc::new(session_key()),
        rows: Arc::new(Vec::new()),
    };
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!(addr = %listener.local_addr()?, "gapura-control listening");
    axum::serve(listener, api::router_with(state)).await?;
    Ok(())
}
