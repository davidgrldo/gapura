//! The gapura control plane: serves the console and reads on its behalf.
//!
//! A library crate with a thin binary so the modules are reachable as `gapura_control::*`
//! from integration tests, and so `pub` means something: in a binary crate it was a
//! promise nothing could check.

pub mod access;
pub mod access_api;
pub mod api;
pub mod assets;
pub mod bootstrap;
pub mod config_api;
pub mod declared;
pub mod grants;
pub mod kube_source;
pub mod login;
pub mod password;
pub mod rows;
pub mod scope;
pub mod served;
pub mod session;
pub mod state;
pub mod store;
