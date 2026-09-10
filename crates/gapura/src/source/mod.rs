//! Where Config comes from. Plan 2 ships the file source (dev and test); Plan 3 adds Kubernetes.

pub mod file;
#[expect(dead_code, reason = "wired in Task 10")]
pub mod kubernetes;
