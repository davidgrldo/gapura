//! Pure translation core of Gapura, the Rust API gateway.
//!
//! Input: a [`Snapshot`] of Kubernetes Gateway API resources (GatewayClass, Gateway, HTTPRoute,
//! ReferenceGrant, Namespace, Service, EndpointSlice, Secret), loaded from JSON or YAML.
//! Output: a routing [`Config`] for the data plane plus status patches for the API server,
//! via [`translate()`]. Request matching lives in [`matcher`].
//! No I/O, no clock, no async: everything is deterministic and covered by golden tests.

pub mod config;
pub mod credentials;
pub mod duration;
pub mod hostname;
pub mod input;
pub mod matcher;
pub mod snapshot;
pub mod status;
pub mod store;
pub mod translate;

pub use config::Config;
pub use matcher::{PortMatch, RequestAttrs};
pub use snapshot::{ObjectRef, Settings, Snapshot, SnapshotError};
pub use store::{compile, StoreSnapshot};
pub use translate::{translate, Translation};
