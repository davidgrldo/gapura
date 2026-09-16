//! What handlers need: the readers, and the rule about who sees what.

use crate::scope::Mapping;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub mapping: Arc<Mapping>,
    pub session_key: Arc<Vec<u8>>,
}
