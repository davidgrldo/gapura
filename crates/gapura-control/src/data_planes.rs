//! Data planes: who may register them, and how their health reads.
//!
//! ADR 5 rule 4: registering a data plane, issuing and revoking its tokens and deleting it are a
//! superuser's, because a data plane fetches every workspace's configuration, private keys
//! included. Anyone with a role somewhere reads the list.

use crate::access::{Rows, User};
use crate::configuration::{self, FieldError};
use crate::grants::Refusal;
use serde::{Deserialize, Serialize};

/// A data plane that called within this long is connected. The control plane does not know each
/// one's interval (5 seconds by default); two minutes covers a 30-second interval with misses.
pub const CONNECTED_WITHIN_SECS: i64 = 120;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataPlaneInput {
    pub name: String,
}

pub fn name(input: DataPlaneInput) -> Result<String, FieldError> {
    configuration::name(&input.name, "name")
}

pub fn may_read(rows: &Rows, caller: &User) -> Result<(), Refusal> {
    if rows.waiting(caller) {
        return Err(configuration::no_role());
    }
    Ok(())
}

/// A superuser's, and an enabled one's: the store reads the caller again inside each write
/// without refusing a disabled account, so this is where one disabled since sign-in is stopped.
pub fn may_write(caller: &User) -> Result<(), Refusal> {
    if caller.superuser && !caller.disabled {
        return Ok(());
    }
    Err(Refusal::Forbidden(
        "Data planes are a superuser's: each one fetches every workspace's configuration, \
         private keys included."
            .into(),
    ))
}

/// Whether a data plane holds what is served now: `None` when it sent no tag.
pub fn in_sync(sent: Option<&str>, current: &str) -> Option<bool> {
    sent.map(|s| s == current)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenView {
    pub prefix: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DataPlaneView {
    pub name: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub last_seen_address: Option<String>,
    /// `connected`, `not_seen` or `never`.
    pub status: &'static str,
    pub in_sync: Option<bool>,
    pub tokens: Vec<TokenView>,
}

/// What registering or issuing answers with, the only time a token is shown. Its `Debug` hides
/// the token.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct IssuedToken {
    pub name: String,
    pub token: String,
    pub prefix: String,
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedToken")
            .field("name", &self.name)
            .field("token", &"<redacted>")
            .field("prefix", &self.prefix)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_sync_is_unknown_without_a_tag() {
        assert_eq!(in_sync(None, "\"a\""), None);
        assert_eq!(in_sync(Some("\"a\""), "\"a\""), Some(true));
        assert_eq!(in_sync(Some("\"b\""), "\"a\""), Some(false));
    }

    #[test]
    fn a_name_follows_the_configuration_rule() {
        assert_eq!(
            name(DataPlaneInput {
                name: "edge-1".into()
            })
            .unwrap(),
            "edge-1"
        );
        assert_eq!(
            name(DataPlaneInput { name: "..".into() })
                .unwrap_err()
                .field,
            "name"
        );
    }

    #[test]
    fn only_an_enabled_superuser_may_write() {
        let mut caller = User {
            id: uuid::Uuid::nil(),
            name: "root".into(),
            method: crate::access::Method::Local,
            superuser: true,
            disabled: false,
            groups: Vec::new(),
            last_sign_in: None,
        };
        assert!(may_write(&caller).is_ok());
        caller.disabled = true;
        assert!(
            may_write(&caller).is_err(),
            "a disabled superuser holds nothing"
        );
        caller.disabled = false;
        caller.superuser = false;
        assert!(may_write(&caller).is_err());
    }

    #[test]
    fn an_issued_token_is_not_printed() {
        let t = IssuedToken {
            name: "e".into(),
            token: "gpdp_secret".into(),
            prefix: "gpdp_s".into(),
        };
        assert!(!format!("{t:?}").contains("secret"));
    }
}
