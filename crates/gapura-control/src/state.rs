//! What handlers need: the readers, and the rule about who sees what.

use crate::kube_source::Source;
use crate::login::{Oidc, PendingLogins};
use crate::scope::Mapping;
use crate::served::Admin;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct AppState {
    pub mapping: Arc<Mapping>,
    pub session_key: Arc<[u8]>,
    /// What the cluster was told to serve.
    pub source: Arc<Source>,
    /// What a gateway resolved out of it and is actually serving.
    pub admin: Arc<Admin>,
    /// The GatewayClass controllerName whose verdicts we read. It belongs beside the reader
    /// rather than inside it because it is configuration, and the mismatch it guards against
    /// is one an operator changes without rebuilding anything.
    pub controller_name: Arc<String>,
    pub oidc: Arc<Oidc>,
    /// Sign-ins sent to the identity provider and not yet heard back about.
    pub pending: PendingLogins,
    /// How long a session minted now stays valid, in the cookie and in its `Max-Age`.
    pub session_lifetime: Duration,
}
