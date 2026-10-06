//! Identifying a caller by an API key.
//!
//! This came after JWT deliberately. JWT proves the extension mechanism and looks nothing
//! up; this is the seam that looks a credential up, and the two bets are worth taking one at a
//! time so a failure in either is unambiguous.
//!
//! The lookup is a map in the configuration, not a query. A round trip per request would put the
//! control plane on the data path and take every gateway down with it; the cost is that
//! revocation waits for the next poll, which is the bound routes already accept.

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

/// The consumer a presented key belongs to, when a policy scoped to `workspace` may accept it.
///
/// A key issued in another workspace is `Unknown`, the same answer as a key never issued: a
/// caller learns nothing about what exists elsewhere. `None` accepts any key the configuration
/// holds, which is what a configuration without workspaces means.
pub fn identify<'a>(
    config: &'a Config,
    presented: Option<&str>,
    workspace: Option<&str>,
) -> Result<&'a str, Refusal> {
    let Some(key) = presented.map(str::trim).filter(|k| !k.is_empty()) else {
        return Err(Refusal::Missing);
    };
    let digest = hex(&Sha256::digest(key.as_bytes()));
    if let Some(workspace) = workspace {
        if config
            .credential_workspaces
            .get(&digest)
            .map(String::as_str)
            != Some(workspace)
        {
            return Err(Refusal::Unknown);
        }
    }
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
        assert_eq!(identify(&c, Some("gpak_secret"), None), Ok("team-orders"));
    }

    #[test]
    fn no_key_and_an_unknown_key_are_different_answers() {
        let c = config_with("gpak_secret", "team-orders");
        assert_eq!(identify(&c, None, None), Err(Refusal::Missing));
        assert_eq!(identify(&c, Some(""), None), Err(Refusal::Missing));
        assert_eq!(identify(&c, Some("   "), None), Err(Refusal::Missing));
        assert_eq!(
            identify(&c, Some("gpak_wrong"), None),
            Err(Refusal::Unknown)
        );
    }

    /// The configuration holds hashes. Presenting the hash rather than the key must not work, or
    /// anyone who read a disk cache would hold working credentials.
    #[test]
    fn presenting_the_stored_hash_is_not_presenting_the_key() {
        let c = config_with("gpak_secret", "team-orders");
        let stored = c.credentials.keys().next().unwrap().clone();
        assert_eq!(identify(&c, Some(&stored), None), Err(Refusal::Unknown));
    }

    #[test]
    fn a_configuration_with_no_credentials_admits_nobody() {
        assert_eq!(
            identify(&Config::default(), Some("anything"), None),
            Err(Refusal::Unknown)
        );
    }

    #[test]
    fn the_default_header_is_the_one_callers_usually_send() {
        assert_eq!(KeyAuthPolicy::default().header, "x-api-key");
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn config() -> Config {
        let digest = |k: &str| hex(&Sha256::digest(k.as_bytes()));
        Config {
            credentials: BTreeMap::from([
                (digest("gpak_orders"), "mobile".into()),
                (digest("gpak_billing"), "mobile".into()),
            ]),
            credential_workspaces: BTreeMap::from([
                (digest("gpak_orders"), "orders".into()),
                (digest("gpak_billing"), "billing".into()),
            ]),
            ..Config::default()
        }
    }

    #[test]
    fn a_key_opens_its_own_workspace_only() {
        let c = config();
        assert_eq!(
            identify(&c, Some("gpak_orders"), Some("orders")),
            Ok("mobile")
        );
        assert_eq!(
            identify(&c, Some("gpak_orders"), Some("billing")),
            Err(Refusal::Unknown),
            "the same answer as a key never issued"
        );
        assert_eq!(
            identify(&c, Some("gpak_billing"), Some("billing")),
            Ok("mobile")
        );
    }

    #[test]
    fn a_key_with_no_workspace_recorded_is_refused_by_a_scoped_policy() {
        let mut c = config();
        c.credential_workspaces.clear();
        assert_eq!(
            identify(&c, Some("gpak_orders"), Some("orders")),
            Err(Refusal::Unknown)
        );
        // And accepted by a policy that names none, as before workspaces.
        assert_eq!(identify(&c, Some("gpak_orders"), None), Ok("mobile"));
    }
}
