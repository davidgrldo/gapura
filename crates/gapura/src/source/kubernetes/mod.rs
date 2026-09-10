//! Kubernetes config source: watch ten kinds, fold them into a Snapshot, translate, swap, and
//! hand status to the leader's writer. Runs as a Pingora background service (Task 10).

pub mod kinds;
pub mod reconcile;
pub mod status;
