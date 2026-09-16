//! What handlers need: the readers, and the rule about who sees what.

use crate::login::{Oidc, PendingLogins};
use crate::rows::Row;
use crate::scope::Mapping;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct AppState {
    pub mapping: Arc<Mapping>,
    pub session_key: Arc<Vec<u8>>,
    /// Rows the API serves. A stand-in until the readers are wired: it exists so the
    /// filtering invariant can be tested over the path a request actually takes.
    pub rows: Arc<Vec<Row>>,
    pub oidc: Arc<Oidc>,
    /// Sign-ins sent to the identity provider and not yet heard back about.
    pub pending: PendingLogins,
    /// How long a session minted now stays valid, in the cookie and in its `Max-Age`.
    pub session_lifetime: Duration,
}
