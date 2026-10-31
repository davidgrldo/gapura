//! Which parts of a configuration a data plane can read, so the control plane can refuse to send
//! one it cannot, rather than let it fail to parse -- or parse it and ignore what it does not
//! know, which a new field allows.
//!
//! The data plane sends [`FEATURES`] on each poll. The control plane works out what the
//! configuration it serves uses ([`Config::needs`]) and answers 409 with what [`missing`] says
//! the caller lacks, and the data plane keeps serving the configuration it has.

use std::collections::BTreeSet;

use crate::config::{Config, Plugin};

/// What this build reads, sorted: every [`Plugin::kind`], and one name for each field that a
/// data plane predating it would misread rather than refuse. A test fails while a kind is
/// missing here; a field has no such check, which is why [`Config`] says when one needs a name.
pub const FEATURES: &[&str] = &[
    "acl",
    "auth",
    "cors",
    "ip_restriction",
    "jwks_uri",
    "jwt",
    "jwt_consumer_claim",
    "key_auth",
    "request_size_limit",
    "request_transformer",
    "response_transformer",
];

/// What a data plane that names no features is taken to read: rc.17 and every release before it
/// send none. rc.16 read only these, and nothing on the wire tells it from rc.17, which reads
/// every kind in [`FEATURES`]; so a headerless data plane is assumed to read the least, and an
/// rc.17 one is refused a newer kind it could read until it is upgraded -- refused, never sent
/// something an rc.16 would fail on or misread. Releases before rc.16 read less still, which is
/// why the upgrade note asks for rc.16 first.
pub const LEGACY_FEATURES: &[&str] = &["jwt", "key_auth"];

impl Config {
    /// The features this configuration uses: the kind of every policy on every rule, and
    /// `jwks_uri` or `jwt_consumer_claim` wherever a JWT policy names one.
    pub fn needs(&self) -> BTreeSet<&'static str> {
        let mut needs = BTreeSet::new();
        let plugins = self
            .listeners
            .iter()
            .flat_map(|l| &l.rules)
            .flat_map(|r| &r.plugins);
        for plugin in plugins {
            needs.insert(plugin.kind());
            if matches!(plugin, Plugin::Jwt(jwt) if jwt.jwks_uri.is_some()) {
                needs.insert("jwks_uri");
            }
            if matches!(plugin, Plugin::Jwt(jwt) if jwt.consumer_claim.is_some()) {
                needs.insert("jwt_consumer_claim");
            }
        }
        needs
    }
}

/// What `needs` asks for that a data plane reading `has` lacks, sorted. `None` is a data plane
/// that named nothing (rc.17 and older name none), read as [`LEGACY_FEATURES`]. The one decision:
/// `/v1/config` answers with it and the console's list shows it, so the two cannot disagree.
pub fn missing(needs: &BTreeSet<&'static str>, has: Option<&[String]>) -> Vec<String> {
    needs
        .iter()
        .filter(|need| match has {
            Some(has) => !has.iter().any(|h| h == **need),
            None => !LEGACY_FEATURES.contains(need),
        })
        .map(|need| need.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AclPolicy, AuthPolicy, CorsPolicy, Filters, IpRestrictionPolicy, JwtPolicy, KeyAuthPolicy,
        ListenerConfig, Protocol, RequestSizeLimitPolicy, RequestTransformerPolicy,
        ResponseTransformerPolicy, RouteRule, Timeouts,
    };

    /// One policy of every kind. The `match` is exhaustive so that a new kind does not compile
    /// here until it is listed in it; whoever lists it adds a sample to `all` beside it, and
    /// `features_name_every_kind_and_stay_sorted` then fails until [`FEATURES`] names it.
    fn every_kind() -> Vec<Plugin> {
        let all = vec![
            Plugin::Jwt(JwtPolicy::default()),
            Plugin::KeyAuth(KeyAuthPolicy::default()),
            Plugin::IpRestriction(IpRestrictionPolicy::default()),
            Plugin::RequestSizeLimit(RequestSizeLimitPolicy { max_bytes: 1 }),
            Plugin::RequestTransformer(RequestTransformerPolicy::default()),
            Plugin::ResponseTransformer(ResponseTransformerPolicy::default()),
            Plugin::Cors(CorsPolicy::default()),
            Plugin::Auth(AuthPolicy::default()),
            Plugin::Acl(AclPolicy::default()),
        ];
        for plugin in &all {
            match plugin {
                Plugin::Jwt(_)
                | Plugin::KeyAuth(_)
                | Plugin::IpRestriction(_)
                | Plugin::RequestSizeLimit(_)
                | Plugin::RequestTransformer(_)
                | Plugin::ResponseTransformer(_)
                | Plugin::Cors(_)
                | Plugin::Auth(_)
                | Plugin::Acl(_) => {}
            }
        }
        all
    }

    fn with(plugins: Vec<Plugin>) -> Config {
        Config {
            listeners: vec![ListenerConfig {
                id: "default/gw/http".into(),
                port: 80,
                client_port: None,
                protocol: Protocol::Http,
                hostname: None,
                tls: None,
                rules: vec![RouteRule {
                    route: "default/orders".into(),
                    rule_index: 0,
                    creation_timestamp: String::new(),
                    matches: vec![],
                    filters: Filters::default(),
                    backends: vec![],
                    timeouts: Timeouts::default(),
                    rate_limit: None,
                    plugins,
                }],
            }],
            ..Config::default()
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn features_name_every_kind_and_stay_sorted() {
        for plugin in every_kind() {
            assert!(
                FEATURES.contains(&plugin.kind()),
                "{} is not in FEATURES",
                plugin.kind()
            );
        }
        assert!(
            FEATURES.windows(2).all(|w| w[0] < w[1]),
            "FEATURES is sorted, without repeats"
        );
        assert!(LEGACY_FEATURES.iter().all(|f| FEATURES.contains(f)));
    }

    #[test]
    fn a_configuration_needs_the_kinds_it_uses_and_jwks_uri_only_when_named() {
        assert!(Config::default().needs().is_empty());
        assert_eq!(
            with(vec![Plugin::Jwt(JwtPolicy::default())]).needs(),
            BTreeSet::from(["jwt"])
        );
        let uri = with(vec![
            Plugin::Jwt(JwtPolicy {
                jwks_uri: Some("https://idp.example/jwks".into()),
                ..JwtPolicy::default()
            }),
            Plugin::IpRestriction(IpRestrictionPolicy::default()),
        ]);
        assert_eq!(
            uri.needs(),
            BTreeSet::from(["ip_restriction", "jwks_uri", "jwt"])
        );
    }

    #[test]
    fn a_jwt_policy_that_names_a_consumer_claim_needs_it() {
        let named = Plugin::Jwt(JwtPolicy {
            consumer_claim: Some("sub".into()),
            ..JwtPolicy::default()
        });
        assert!(with(vec![named]).needs().contains("jwt_consumer_claim"));
        assert!(!with(vec![Plugin::Jwt(JwtPolicy::default())])
            .needs()
            .contains("jwt_consumer_claim"));
    }

    #[test]
    fn missing_reads_silence_as_the_legacy_baseline() {
        let needs = with(every_kind()).needs();
        assert_eq!(
            missing(&needs, None),
            [
                "acl",
                "auth",
                "cors",
                "ip_restriction",
                "request_size_limit",
                "request_transformer",
                "response_transformer"
            ]
        );
        assert!(missing(&needs, Some(&names(FEATURES))).is_empty());
        let without: Vec<&str> = FEATURES
            .iter()
            .copied()
            .filter(|f| *f != "ip_restriction")
            .collect();
        assert_eq!(missing(&needs, Some(&names(&without))), ["ip_restriction"]);
        // Naming nothing is not saying nothing: it lacks everything.
        let key_auth = with(vec![Plugin::KeyAuth(KeyAuthPolicy::default())]).needs();
        assert_eq!(missing(&key_auth, Some(&[] as &[String])), ["key_auth"]);
        assert!(missing(&key_auth, None).is_empty());
    }
}
