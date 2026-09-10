//! Leader election on a coordination.k8s.io Lease. Only the leader writes status; every
//! replica keeps serving traffic. The decision is pure, the loop is thin.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use k8s_openapi::jiff::Timestamp;
use kube::api::entry::{CommitError, Entry};
use kube::api::{Api, PostParams};
use kube::Client;
use pingora::server::ShutdownWatch;

use crate::telemetry::METRICS;

#[derive(Debug, Clone)]
pub struct LeaderOpts {
    pub namespace: String,
    pub name: String,
    pub identity: String,
    pub lease_secs: i32,
    pub renew_every: Duration,
}

impl Default for LeaderOpts {
    fn default() -> Self {
        Self {
            namespace: "default".to_string(),
            name: "gapura-leader".to_string(),
            identity: "gapura".to_string(),
            lease_secs: 15,
            renew_every: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Acquire,
    Renew,
    Wait,
}

/// Absent or expired leases are acquired, our own is renewed, a live one held by someone else waits.
pub fn decide(spec: Option<&LeaseSpec>, identity: &str, now_secs: i64) -> Decision {
    let Some(spec) = spec else {
        return Decision::Acquire;
    };
    if spec.holder_identity.as_deref() == Some(identity) {
        return Decision::Renew;
    }
    let renewed = spec
        .renew_time
        .as_ref()
        .map(|t| t.0.as_second())
        .unwrap_or(0);
    let duration = i64::from(spec.lease_duration_seconds.unwrap_or(0));
    if renewed + duration <= now_secs {
        Decision::Acquire
    } else {
        Decision::Wait
    }
}

pub async fn run(
    client: Client,
    opts: LeaderOpts,
    is_leader: Arc<AtomicBool>,
    mut shutdown: ShutdownWatch,
) {
    let api = Api::<Lease>::namespaced(client, &opts.namespace);
    let mut tick = tokio::time::interval(opts.renew_every);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        // A hung API call must not pin leadership: bound each step by the lease duration
        // (client-go's RenewDeadline) and give up leadership when it elapses.
        // client-go's RenewDeadline: strictly below the lease duration, so leadership is dropped
        // before another replica can acquire the expired Lease.
        let lease = Duration::from_secs(u64::try_from(opts.lease_secs).unwrap_or(15));
        let deadline = lease
            .saturating_sub(opts.renew_every)
            .max(Duration::from_secs(1));
        let outcome = tokio::select! {
            r = tokio::time::timeout(deadline, step(&api, &opts)) => r,
            _ = shutdown.changed() => return,
        };
        let leader = match outcome {
            Ok(Ok(leader)) => leader,
            Ok(Err(e)) => {
                tracing::warn!(lease = %opts.name, error = %e, "lease step failed, not leader");
                false
            }
            Err(_) => {
                tracing::warn!(lease = %opts.name, secs = deadline.as_secs(), "lease step timed out, not leader");
                false
            }
        };
        let was = is_leader.swap(leader, Ordering::AcqRel);
        METRICS.leader.set(i64::from(leader));
        if was != leader {
            tracing::info!(identity = %opts.identity, leader, "leadership changed");
        }
    }
}

/// One acquire-or-renew attempt. Optimistic concurrency: `commit` fails with 409 when another
/// replica changed the Lease first, and that replica is the leader.
async fn step(api: &Api<Lease>, opts: &LeaderOpts) -> anyhow::Result<bool> {
    let now = Timestamp::now();
    let entry = api.entry(&opts.name).await?;
    let decision = match &entry {
        Entry::Occupied(o) => decide(o.get().spec.as_ref(), &opts.identity, now.as_second()),
        Entry::Vacant(_) => Decision::Acquire,
    };
    if decision == Decision::Wait {
        return Ok(false);
    }
    let mut occupied = entry
        .or_insert(|| Lease {
            metadata: ObjectMeta {
                name: Some(opts.name.clone()),
                namespace: Some(opts.namespace.clone()),
                ..Default::default()
            },
            spec: None,
        })
        .and_modify(|lease| {
            let spec = lease.spec.get_or_insert_with(Default::default);
            if decision == Decision::Acquire {
                spec.acquire_time = Some(MicroTime(now));
                spec.lease_transitions = Some(spec.lease_transitions.unwrap_or(0) + 1);
            }
            spec.holder_identity = Some(opts.identity.clone());
            spec.lease_duration_seconds = Some(opts.lease_secs);
            spec.renew_time = Some(MicroTime(now));
        });
    match occupied.commit(&PostParams::default()).await {
        Ok(()) => Ok(true),
        Err(CommitError::Save(kube::Error::Api(e))) if e.code == 409 => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(holder: &str, renewed_secs: i64, duration: i32) -> LeaseSpec {
        LeaseSpec {
            holder_identity: Some(holder.to_string()),
            renew_time: Some(MicroTime(Timestamp::from_second(renewed_secs).unwrap())),
            lease_duration_seconds: Some(duration),
            ..Default::default()
        }
    }

    #[test]
    fn decide_covers_absent_mine_live_and_expired() {
        assert_eq!(decide(None, "me", 1000), Decision::Acquire);
        assert_eq!(
            decide(Some(&spec("me", 990, 15)), "me", 1000),
            Decision::Renew
        );
        assert_eq!(
            decide(Some(&spec("me", 0, 15)), "me", 1000),
            Decision::Renew,
            "our own stale lease is just renewed"
        );
        assert_eq!(
            decide(Some(&spec("other", 990, 15)), "me", 1000),
            Decision::Wait
        );
        assert_eq!(
            decide(Some(&spec("other", 985, 15)), "me", 1000),
            Decision::Acquire,
            "expired exactly now"
        );
        let no_renew = LeaseSpec {
            holder_identity: Some("other".into()),
            ..Default::default()
        };
        assert_eq!(
            decide(Some(&no_renew), "me", 1000),
            Decision::Acquire,
            "never renewed counts as expired"
        );
    }
}
