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

/// Below this length a key is not a secret. `Hmac::new_from_slice` accepts a key of any
/// length, including none, so an empty or unresolved Secret would otherwise sign sessions
/// that anyone can forge — and a forged session naming a group with a `*` grant reads every
/// namespace, defeating the scoping without going anywhere near the scoping code.
const MIN_SESSION_KEY_BYTES: usize = 32;

/// The key a configured `GAPURA_SESSION_KEY` yields, or why it is not usable as one.
fn checked_session_key(configured: &str) -> anyhow::Result<Vec<u8>> {
    let key = configured.as_bytes();
    anyhow::ensure!(
        key.len() >= MIN_SESSION_KEY_BYTES,
        "{SESSION_KEY_VAR} is {} bytes long; it must be at least {MIN_SESSION_KEY_BYTES}",
        key.len()
    );
    Ok(key.to_vec())
}

fn random_session_key() -> Vec<u8> {
    let mut key = vec![0u8; MIN_SESSION_KEY_BYTES];
    rand::rng().fill_bytes(&mut key);
    key
}

fn session_key() -> anyhow::Result<Vec<u8>> {
    // An absent variable is a development convenience rather than a weak secret, so it
    // still falls back to a random key; a variable that is set but too short is a
    // misconfiguration that must stop the process instead of running unprotected.
    let Ok(configured) = std::env::var(SESSION_KEY_VAR) else {
        tracing::warn!(
            "{SESSION_KEY_VAR} is not set; generating a random session key for this process \
             only, so every session will be invalidated the next time it restarts"
        );
        return Ok(random_session_key());
    };
    checked_session_key(&configured)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    let state = state::AppState {
        // No groups are mapped yet: readers, and the config that populates this, are
        // later work. An empty mapping grants nothing, which is the safe default.
        mapping: Arc::new(scope::Mapping::new()),
        session_key: Arc::new(session_key()?),
        rows: Arc::new(Vec::new()),
    };
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!(addr = %listener.local_addr()?, "gapura-control listening");
    axum::serve(listener, api::router_with(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_key_is_refused() {
        // What an unresolved Secret looks like: the variable is set, to nothing.
        assert!(checked_session_key("").is_err());
    }

    #[test]
    fn a_key_shorter_than_the_minimum_is_refused() {
        let error = checked_session_key(&"k".repeat(MIN_SESSION_KEY_BYTES - 1))
            .expect_err("one byte short is still short");
        let error = error.to_string();
        assert!(
            error.contains(SESSION_KEY_VAR) && error.contains(&MIN_SESSION_KEY_BYTES.to_string()),
            "the error must name the variable and the minimum, got {error}"
        );
    }

    #[test]
    fn a_key_of_adequate_length_is_taken_as_it_stands() {
        let configured = "k".repeat(MIN_SESSION_KEY_BYTES);
        assert_eq!(
            checked_session_key(&configured).unwrap(),
            configured.as_bytes()
        );
    }

    #[test]
    fn the_generated_fallback_key_passes_the_same_check() {
        // The fallback is a convenience, not an exemption: it must clear the bar it sets.
        assert!(random_session_key().len() >= MIN_SESSION_KEY_BYTES);
    }
}
