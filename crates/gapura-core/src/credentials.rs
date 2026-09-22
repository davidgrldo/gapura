//! Identifying a caller by an API key.
//!
//! ADR 1 put this after JWT deliberately. JWT proves the extension mechanism and looks nothing
//! up; this is the seam that looks a credential up, and the two bets are worth taking one at a
//! time so a failure in either is unambiguous.
//!
//! The lookup is a map in the configuration, not a query. A round trip per request would put the
//! control plane on the data path and take every gateway down with it; the cost is that
//! revocation waits for the next poll, which is the bound ADR 3 already accepts for routes.

use crate::config::Config;
use sha2::{Digest, Sha256};

/// The header an upstream is told the caller's name in.
///
/// Set by the gateway and **removed from the inbound request first**, always. Without that
/// removal a caller could send it themselves and the upstream would believe them, which turns
/// an authentication feature into an impersonation one.
pub const CONSUMER_HEADER: &str = "x-consumer-username";

#[derive(Debug, PartialEq)]
pub enum Refusal {
    Missing,
    Unknown,
}

impl Refusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Refusal::Missing => "missing",
            Refusal::Unknown => "unknown",
        }
    }
}

/// The consumer a presented key belongs to.
pub fn identify<'a>(config: &'a Config, presented: Option<&str>) -> Result<&'a str, Refusal> {
    let Some(key) = presented.map(str::trim).filter(|k| !k.is_empty()) else {
        return Err(Refusal::Missing);
    };
    let digest = hex(&Sha256::digest(key.as_bytes()));
    config
        .credentials
        .get(&digest)
        .map(String::as_str)
        .ok_or(Refusal::Unknown)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, KeyAuthPolicy};
    use std::collections::BTreeMap;

    fn config_with(key: &str, consumer: &str) -> Config {
        Config {
            credentials: BTreeMap::from([(hex(&Sha256::digest(key.as_bytes())), consumer.into())]),
            ..Config::default()
        }
    }

    #[test]
    fn a_key_that_was_issued_names_its_consumer() {
        let c = config_with("gpak_secret", "team-orders");
        assert_eq!(identify(&c, Some("gpak_secret")), Ok("team-orders"));
    }

    #[test]
    fn no_key_and_an_unknown_key_are_different_answers() {
        let c = config_with("gpak_secret", "team-orders");
        assert_eq!(identify(&c, None), Err(Refusal::Missing));
        assert_eq!(identify(&c, Some("")), Err(Refusal::Missing));
        assert_eq!(identify(&c, Some("   ")), Err(Refusal::Missing));
        assert_eq!(identify(&c, Some("gpak_wrong")), Err(Refusal::Unknown));
    }

    /// The configuration holds hashes. Presenting the hash rather than the key must not work, or
    /// anyone who read a disk cache would hold working credentials.
    #[test]
    fn presenting_the_stored_hash_is_not_presenting_the_key() {
        let c = config_with("gpak_secret", "team-orders");
        let stored = c.credentials.keys().next().unwrap().clone();
        assert_eq!(identify(&c, Some(&stored)), Err(Refusal::Unknown));
    }

    #[test]
    fn a_configuration_with_no_credentials_admits_nobody() {
        assert_eq!(
            identify(&Config::default(), Some("anything")),
            Err(Refusal::Unknown)
        );
    }

    #[test]
    fn the_default_header_is_the_one_callers_usually_send() {
        assert_eq!(KeyAuthPolicy::default().header, "x-api-key");
    }
}
