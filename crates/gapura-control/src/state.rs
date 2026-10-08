//! What handlers need: the readers, and the rule about who sees what.

use crate::kube_source::Source;
use crate::login::{AuthMode, LocalUsers, Oidc};
use crate::scope::Mapping;
use crate::served::Admin;
use crate::store::Store;
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
    /// How sign-in happens and, in local mode, the users it happens against.
    pub auth_mode: AuthMode,
    pub local_users: LocalUsers,
    /// How long a session minted now stays valid, in the cookie and in its `Max-Age`.
    pub session_lifetime: Duration,
    /// Set in store mode, when `DATABASE_URL` is: accounts and roles are rows there, and every
    /// request reads its caller back from it. `None` is Kubernetes mode.
    pub store: Option<Arc<Store>>,
    /// Failed sign-ins, counted per name at an address and per address.
    pub sign_in: Arc<crate::throttle::Throttle>,
    /// What the store's rows are compiled with, the same settings the configuration endpoint
    /// uses, so the console can say whether a data plane holds what is served now.
    pub store_settings: gapura_core::store::StoreSettings,
}
