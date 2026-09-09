//! Pure translation core of Gapura.
//!
//! Input: a [`Snapshot`] of Kubernetes Gateway API resources.
//! Output: a routing [`Config`] for the data plane and status patches for the API server.
//! No I/O, no clock, no async. Everything here is deterministic and unit-testable.

pub mod config;
pub mod duration;
pub mod hostname;
pub mod input;
pub mod snapshot;
pub mod status;
pub mod translate;

pub use config::Config;
pub use snapshot::{ObjectRef, Settings, Snapshot, SnapshotError};
pub use translate::{translate, Translation};
