//! Step 2 of translation: Gateway listeners. Validity, TLS resolution, conflicts.
//! Produces `ListenerBuild`s that routes attach to in a later step.

use std::collections::BTreeSet;

use base64::Engine;

use crate::config::{MatchEntry, Protocol, RouteRule, TlsBundle};
use crate::input::{AllowedRoutes, Listener, RouteGroupKind, Secret};
use crate::snapshot::{ObjectRef, Settings, Snapshot};
use crate::status::{reasons, types, Condition, ConditionStatus};
use crate::translate::grants;

pub(crate) const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";

/// `(reason, message)` for a False/True condition.
pub(crate) type Rejection = (&'static str, String);

pub(crate) struct GatewayBuild {
    pub r#ref: ObjectRef,
    pub generation: Option<i64>,
    pub listeners: Vec<ListenerBuild>,
    /// Set when the Gateway itself is refused, whatever its listeners say.
    pub rejected: Option<Rejection>,
}

pub(crate) struct ListenerBuild {
    pub name: String,
    pub port: u16,
    /// Lowercased.
    pub hostname: Option<String>,
    /// `None` when the protocol is unsupported.
    pub protocol: Option<Protocol>,
    pub allowed: Option<AllowedRoutes>,
    pub tls: Option<TlsBundle>,
    pub accepted: Result<(), Rejection>,
    pub resolved: Result<(), Rejection>,
    pub conflict: Option<Rejection>,
    pub supported_kinds: Vec<RouteGroupKind>,
    pub attached_routes: u32,
    pub rules: Vec<RouteRule>,
    pub table: Vec<MatchEntry>,
}

impl ListenerBuild {
    pub fn programmed(&self) -> bool {
        self.accepted.is_ok() && self.conflict.is_none() && self.serves()
    }

    /// Whether the data plane can carry this listener at all. An `allowedRoutes.kinds` that also
    /// names a kind we do not serve sets `ResolvedRefs=False`, but the kinds we do serve keep
    /// working; every other unresolved reference (a broken TLS Secret, say) means we serve nothing.
    fn serves(&self) -> bool {
        match &self.resolved {
            Ok(()) => true,
            Err((reason, _)) => {
                *reason == reasons::INVALID_ROUTE_KINDS
                    && !self.supported_kinds.is_empty()
                    // An HTTPS listener without a certificate has nothing to serve.
                    && (self.protocol != Some(Protocol::Https) || self.tls.is_some())
            }
        }
    }

    /// Conditions in a fixed order: Accepted, Programmed, ResolvedRefs, Conflicted. The Gateway can
    /// veto: a listener of a refused Gateway is never programmed.
    pub fn conditions(&self, generation: Option<i64>, gateway_ok: bool) -> Vec<Condition> {
        let accepted = match &self.accepted {
            Ok(()) => Condition::new(
                types::ACCEPTED,
                ConditionStatus::True,
                reasons::ACCEPTED,
                "Listener is accepted",
                generation,
            ),
            Err((reason, msg)) => Condition::new(
                types::ACCEPTED,
                ConditionStatus::False,
                reason,
                msg.clone(),
                generation,
            ),
        };
        let programmed = if gateway_ok && self.programmed() {
            Condition::new(
                types::PROGRAMMED,
                ConditionStatus::True,
                reasons::PROGRAMMED,
                "Listener is programmed",
                generation,
            )
        } else {
            Condition::new(
                types::PROGRAMMED,
                ConditionStatus::False,
                reasons::INVALID,
                "Listener is not valid",
                generation,
            )
        };
        let resolved = match &self.resolved {
            Ok(()) => Condition::new(
                types::RESOLVED_REFS,
                ConditionStatus::True,
                reasons::RESOLVED_REFS,
                "All references resolved",
                generation,
            ),
            Err((reason, msg)) => Condition::new(
                types::RESOLVED_REFS,
                ConditionStatus::False,
                reason,
                msg.clone(),
                generation,
            ),
        };
        let conflicted = match &self.conflict {
            None => Condition::new(
                types::CONFLICTED,
                ConditionStatus::False,
                reasons::NO_CONFLICTS,
                "No conflicts",
                generation,
            ),
            Some((reason, msg)) => Condition::new(
                types::CONFLICTED,
                ConditionStatus::True,
                reason,
                msg.clone(),
                generation,
            ),
        };
        vec![accepted, programmed, resolved, conflicted]
    }

    /// Add compiled rules under the given effective hostnames (empty = any host).
    pub fn add_route(&mut self, rules: &[RouteRule], hostnames: &[String]) {
        let hosts: Vec<Option<String>> = if hostnames.is_empty() {
            vec![None]
        } else {
            hostnames.iter().cloned().map(Some).collect()
        };
        for rule in rules {
            let idx = self.rules.len();
            self.rules.push(rule.clone());
            for host in &hosts {
                for m in &rule.matches {
                    self.table.push(MatchEntry {
                        hostname: host.clone(),
                        matcher: m.clone(),
                        rule: idx,
                    });
                }
            }
        }
    }
}

pub(crate) fn build(
    snap: &Snapshot,
    settings: &Settings,
    classes: &BTreeSet<String>,
) -> Vec<GatewayBuild> {
    let mut out = Vec::new();
    for (r, gw) in &snap.gateways {
        if !classes.contains(&gw.spec.gateway_class_name) {
            continue;
        }
        let mut listeners: Vec<ListenerBuild> = gw
            .spec
            .listeners
            .iter()
            .map(|l| build_listener(l, r, snap, settings))
            .collect();
        detect_conflicts(&mut listeners);
        let rejected = gw
            .spec
            .infrastructure
            .as_ref()
            .and_then(|i| i.parameters_ref.as_ref())
            .map(|r| {
                (
                    reasons::INVALID_PARAMETERS,
                    format!(
                        "spec.infrastructure.parametersRef {}/{} {} is not supported",
                        r.group.as_deref().unwrap_or(""),
                        r.kind,
                        r.name
                    ),
                )
            });
        out.push(GatewayBuild {
            r#ref: r.clone(),
            generation: gw.metadata.generation,
            listeners,
            rejected,
        });
    }
    out
}

fn build_listener(
    l: &Listener,
    gw_ref: &ObjectRef,
    snap: &Snapshot,
    settings: &Settings,
) -> ListenerBuild {
    let protocol = match l.protocol.as_str() {
        "HTTP" => Some(Protocol::Http),
        "HTTPS" => Some(Protocol::Https),
        _ => None,
    };
    let passthrough = l
        .tls
        .as_ref()
        .and_then(|t| t.mode.as_deref())
        .is_some_and(|m| m != "Terminate");

    let bound = match protocol {
        Some(Protocol::Https) => &settings.https_ports,
        _ => &settings.http_ports,
    };

    let accepted: Result<(), Rejection> = if protocol.is_none() {
        Err((
            reasons::UNSUPPORTED_PROTOCOL,
            format!(
                "protocol {} is not supported, use HTTP or HTTPS",
                l.protocol
            ),
        ))
    } else if !bound.contains(&l.port) {
        Err((
            reasons::PORT_UNAVAILABLE,
            format!(
                "port {} is not bound for {} by this deployment, bound ports: {:?}",
                l.port, l.protocol, bound
            ),
        ))
    } else if protocol == Some(Protocol::Https) && passthrough {
        Err((
            reasons::UNSUPPORTED_PROTOCOL,
            "TLS passthrough is not supported in v0.1".to_string(),
        ))
    } else {
        Ok(())
    };

    let (supported_kinds, kinds_ok) = supported_kinds(l.allowed_routes.as_ref());

    // TLS is resolved whatever `allowedRoutes.kinds` says: a listener that also names a kind we do
    // not serve still terminates TLS for the kinds we do, and a programmed HTTPS listener must
    // always carry a certificate.
    let mut tls = None;
    let mut tls_error: Option<Rejection> = None;
    if protocol == Some(Protocol::Https) && !passthrough {
        match resolve_tls(l, gw_ref, snap) {
            Ok(bundle) => tls = Some(bundle),
            Err(rejection) => tls_error = Some(rejection),
        }
    }

    // ResolvedRefs carries one reason: an unknown route kind is reported before a broken reference.
    let resolved: Result<(), Rejection> = if !kinds_ok {
        Err((
            reasons::INVALID_ROUTE_KINDS,
            "only HTTPRoute is supported in allowedRoutes.kinds".to_string(),
        ))
    } else if let Some(rejection) = tls_error {
        Err(rejection)
    } else {
        Ok(())
    };

    ListenerBuild {
        name: l.name.clone(),
        port: l.port,
        hostname: l.hostname.as_ref().map(|h| h.to_ascii_lowercase()),
        protocol,
        allowed: l.allowed_routes.clone(),
        tls,
        accepted,
        resolved,
        conflict: None,
        supported_kinds,
        attached_routes: 0,
        rules: Vec::new(),
        table: Vec::new(),
    }
}

/// Which route kinds this listener supports, and whether the requested kinds are acceptable.
fn supported_kinds(allowed: Option<&AllowedRoutes>) -> (Vec<RouteGroupKind>, bool) {
    let http_route = RouteGroupKind {
        group: Some(GATEWAY_GROUP.to_string()),
        kind: "HTTPRoute".to_string(),
    };
    let is_http_route = |k: &RouteGroupKind| {
        k.kind == "HTTPRoute" && k.group.as_deref().is_none_or(|g| g == GATEWAY_GROUP)
    };
    match allowed.map(|a| &a.kinds) {
        None => (vec![http_route], true),
        Some(kinds) if kinds.is_empty() => (vec![http_route], true),
        Some(kinds) => {
            // supportedKinds advertises the intersection; ResolvedRefs needs every requested kind
            // to be one we serve (Gateway API: an unsupported kind is InvalidRouteKinds even when
            // a supported one is listed next to it).
            let advertised = if kinds.iter().any(is_http_route) {
                vec![http_route]
            } else {
                Vec::new()
            };
            let all_known = kinds.iter().all(is_http_route);
            (advertised, all_known)
        }
    }
}

fn resolve_tls(l: &Listener, gw_ref: &ObjectRef, snap: &Snapshot) -> Result<TlsBundle, Rejection> {
    let tls = l.tls.as_ref().ok_or((
        reasons::INVALID_CERTIFICATE_REF,
        "HTTPS listener requires tls.certificateRefs".to_string(),
    ))?;
    let cref = tls.certificate_refs.first().ok_or((
        reasons::INVALID_CERTIFICATE_REF,
        "tls.certificateRefs is empty".to_string(),
    ))?;
    let kind = cref.kind.as_deref().unwrap_or("Secret");
    let group = cref.group.as_deref().unwrap_or("");
    if kind != "Secret" || !group.is_empty() {
        return Err((
            reasons::INVALID_CERTIFICATE_REF,
            format!("certificateRef kind {group}/{kind} is not supported, only core Secret"),
        ));
    }
    let ns = cref
        .namespace
        .clone()
        .unwrap_or_else(|| gw_ref.namespace.clone());
    if ns != gw_ref.namespace
        && !grants::permits(
            snap,
            GATEWAY_GROUP,
            "Gateway",
            &gw_ref.namespace,
            "",
            "Secret",
            &ns,
            &cref.name,
        )
    {
        return Err((
            reasons::REF_NOT_PERMITTED,
            format!(
                "reference to Secret {ns}/{} is not permitted by any ReferenceGrant",
                cref.name
            ),
        ));
    }
    let secret = snap
        .secrets
        .get(&ObjectRef::new(ns.clone(), cref.name.clone()))
        .ok_or((
            reasons::INVALID_CERTIFICATE_REF,
            format!("Secret {ns}/{} not found", cref.name),
        ))?;
    if secret.type_.as_deref() != Some("kubernetes.io/tls") {
        return Err((
            reasons::INVALID_CERTIFICATE_REF,
            format!("Secret {ns}/{} must have type kubernetes.io/tls", cref.name),
        ));
    }
    let cert_pem = pem_field(secret, "tls.crt", "CERTIFICATE")?;
    let key_pem = pem_field(secret, "tls.key", "PRIVATE KEY")?;
    Ok(TlsBundle {
        secret: format!("{ns}/{}", cref.name),
        cert_pem,
        key_pem,
    })
}

/// Decode one base64 field of a Secret and check it looks like PEM of the given kind.
fn pem_field(secret: &Secret, key: &str, marker: &str) -> Result<String, Rejection> {
    let raw = secret.data.get(key).ok_or((
        reasons::INVALID_CERTIFICATE_REF,
        format!("Secret {} has no {key}", secret.metadata.name),
    ))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|_| {
            (
                reasons::INVALID_CERTIFICATE_REF,
                format!("{key} is not valid base64"),
            )
        })?;
    let text = String::from_utf8(bytes).map_err(|_| {
        (
            reasons::INVALID_CERTIFICATE_REF,
            format!("{key} is not UTF-8 PEM"),
        )
    })?;
    if !text.contains("-----BEGIN") || !text.contains(marker) {
        return Err((
            reasons::INVALID_CERTIFICATE_REF,
            format!("{key} is not a PEM {marker}"),
        ));
    }
    Ok(text)
}

/// Same port with different protocols -> ProtocolConflict; same port and same hostname -> HostnameConflict.
fn detect_conflicts(listeners: &mut [ListenerBuild]) {
    for i in 0..listeners.len() {
        for j in (i + 1)..listeners.len() {
            if listeners[i].port != listeners[j].port {
                continue;
            }
            let rejection: Rejection = if listeners[i].protocol != listeners[j].protocol {
                (
                    reasons::PROTOCOL_CONFLICT,
                    format!(
                        "listeners {} and {} share port {} with different protocols",
                        listeners[i].name, listeners[j].name, listeners[i].port
                    ),
                )
            } else if listeners[i].hostname == listeners[j].hostname {
                (
                    reasons::HOSTNAME_CONFLICT,
                    format!(
                        "listeners {} and {} share port {} and hostname {}",
                        listeners[i].name,
                        listeners[j].name,
                        listeners[i].port,
                        listeners[i]
                            .hostname
                            .clone()
                            .unwrap_or_else(|| "(none)".to_string())
                    ),
                )
            } else {
                continue;
            };
            listeners[i]
                .conflict
                .get_or_insert_with(|| rejection.clone());
            listeners[j]
                .conflict
                .get_or_insert_with(|| rejection.clone());
        }
    }
}
