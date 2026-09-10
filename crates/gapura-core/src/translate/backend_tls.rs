//! BackendTLSPolicy plus the `gapura.dev/backend-tls` Service annotation, resolved to `ClusterTls`.

use std::cmp::Reverse;

use crate::config::ClusterTls;
use crate::input::{BackendTlsPolicy, Service};
use crate::snapshot::{ObjectRef, Snapshot};
use crate::status::reasons;

use super::listeners::Rejection;

/// Service annotation; the only accepted value is `insecure`.
pub(crate) const ANNOTATION: &str = "gapura.dev/backend-tls";

/// TLS settings for Service `svc_ref` port `port_name`, or `Ok(None)` for plain HTTP.
pub(crate) fn resolve(
    svc_ref: &ObjectRef,
    svc: &Service,
    port_name: Option<&str>,
    snap: &Snapshot,
) -> Result<Option<ClusterTls>, Rejection> {
    let insecure = match svc
        .metadata
        .annotations
        .get(ANNOTATION)
        .map(String::as_str)
    {
        None => false,
        Some("insecure") => true,
        Some(other) => {
            return Err((
                reasons::UNSUPPORTED_VALUE,
                format!(
                    "Service {svc_ref}: annotation {ANNOTATION}={other} is not supported, use `insecure`"
                ),
            ))
        }
    };
    match (select_policy(svc_ref, port_name, snap), insecure) {
        (None, false) => Ok(None),
        (None, true) => Ok(Some(ClusterTls {
            sni: format!("{}.{}.svc", svc_ref.name, svc_ref.namespace),
            ca_pem: None,
            insecure: true,
        })),
        (Some((pref, policy)), insecure) => {
            let hostname = &policy.spec.validation.hostname;
            if hostname.is_empty() {
                return Err((
                    reasons::UNSUPPORTED_VALUE,
                    format!("BackendTLSPolicy {pref}: validation.hostname is required"),
                ));
            }
            let ca_pem = if insecure {
                None
            } else {
                ca_bundle(pref, policy, snap)?
            };
            Ok(Some(ClusterTls {
                sni: hostname.clone(),
                ca_pem,
                insecure,
            }))
        }
    }
}

/// Higher wins: sectionName match, then older creationTimestamp (RFC 3339 sorts lexically), then smaller name.
type Rank<'a> = (bool, Reverse<&'a str>, Reverse<&'a str>);

/// The policy that applies to this Service port. A `sectionName` equal to the port name beats a
/// Service-wide policy; ties go to the oldest policy, then the lexically smallest name.
fn select_policy<'a>(
    svc_ref: &ObjectRef,
    port_name: Option<&str>,
    snap: &'a Snapshot,
) -> Option<(&'a ObjectRef, &'a BackendTlsPolicy)> {
    let wanted = port_name.unwrap_or("");
    let mut best: Option<(Rank<'a>, &'a ObjectRef, &'a BackendTlsPolicy)> = None;
    for (pref, policy) in &snap.backend_tls_policies {
        if pref.namespace != svc_ref.namespace {
            continue;
        }
        for target in &policy.spec.target_refs {
            let group = target.group.as_deref().unwrap_or("");
            if !group.is_empty() || target.kind != "Service" || target.name != svc_ref.name {
                continue;
            }
            let specific = match target.section_name.as_deref() {
                None => false,
                Some(s) if s == wanted => true,
                Some(_) => continue,
            };
            let rank = (
                specific,
                Reverse(policy.metadata.creation_timestamp.as_deref().unwrap_or("")),
                Reverse(pref.name.as_str()),
            );
            if best.as_ref().is_none_or(|(b, _, _)| rank > *b) {
                best = Some((rank, pref, policy));
            }
        }
    }
    best.map(|(_, pref, policy)| (pref, policy))
}

/// PEM bundle from `caCertificateRefs`, or `None` for `wellKnownCACertificates: System`.
fn ca_bundle(
    pref: &ObjectRef,
    policy: &BackendTlsPolicy,
    snap: &Snapshot,
) -> Result<Option<String>, Rejection> {
    let v = &policy.spec.validation;
    match (
        v.ca_certificate_refs.is_empty(),
        v.well_known_ca_certificates.as_deref(),
    ) {
        (true, Some("System")) => Ok(None),
        (true, Some(other)) => Err((
            reasons::UNSUPPORTED_VALUE,
            format!(
                "BackendTLSPolicy {pref}: wellKnownCACertificates {other} is not supported, use System"
            ),
        )),
        (true, None) => Err((
            reasons::UNSUPPORTED_VALUE,
            format!("BackendTLSPolicy {pref}: set caCertificateRefs or wellKnownCACertificates"),
        )),
        (false, Some(_)) => Err((
            reasons::UNSUPPORTED_VALUE,
            format!(
                "BackendTLSPolicy {pref}: caCertificateRefs and wellKnownCACertificates are mutually exclusive"
            ),
        )),
        (false, None) => {
            let mut pem = String::new();
            for r in &v.ca_certificate_refs {
                let group = r.group.as_deref().unwrap_or("");
                if !group.is_empty() || r.kind != "ConfigMap" {
                    return Err((
                        reasons::INVALID_KIND,
                        format!(
                            "BackendTLSPolicy {pref}: caCertificateRefs kind {group}/{} is not supported, only core ConfigMap",
                            r.kind
                        ),
                    ));
                }
                let cref = ObjectRef::new(pref.namespace.clone(), r.name.clone());
                let cm = snap.config_maps.get(&cref).ok_or((
                    reasons::BACKEND_NOT_FOUND,
                    format!("BackendTLSPolicy {pref}: ConfigMap {cref} not found"),
                ))?;
                let ca = cm.data.get("ca.crt").ok_or((
                    reasons::UNSUPPORTED_VALUE,
                    format!("BackendTLSPolicy {pref}: ConfigMap {cref} has no ca.crt key"),
                ))?;
                if !ca.contains("-----BEGIN CERTIFICATE-----") {
                    return Err((
                        reasons::UNSUPPORTED_VALUE,
                        format!(
                            "BackendTLSPolicy {pref}: ConfigMap {cref} ca.crt is not a PEM certificate bundle"
                        ),
                    ));
                }
                pem.push_str(ca.trim_end());
                pem.push('\n');
            }
            Ok(Some(pem))
        }
    }
}
