//! The policies kept through `/api/workspaces/{ws}/policies/{kind}`: one endpoint for every kind
//! whose stored configuration is the policy itself, checked here and stored in the form the data
//! plane reads. key_auth, jwt and rate_limit keep the endpoints they had.
//!
//! Pure, like `consumers`: the same check reads a request's body and a stored row, so a row only
//! SQL written by hand could make fails the snapshot as a request carrying it would be refused.

use crate::configuration::FieldError;
use gapura_core::client_ip::Cidr;
use gapura_core::config::{IpRestrictionPolicy, Plugin};
use serde::{Deserialize, Serialize};

/// The kinds this endpoint keeps, as [`Plugin::kind`] names them.
pub const KINDS: &[&str] = &["ip_restriction"];

/// The most addresses and networks an ip_restriction policy lists, allow and deny together:
/// 1000 of the longest IPv6 networks still fit in the 64 KiB a request body may carry.
pub const MAX_NETWORKS: usize = 1000;

fn field(field: &str, sentence: impl Into<String>) -> FieldError {
    FieldError {
        field: field.into(),
        sentence: sentence.into(),
    }
}

/// A `PUT` body.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInput {
    pub target: String,
    /// The policy, in the shape its kind reads.
    pub config: serde_json::Value,
    /// The policy row's `updated_at` as this caller last read it, which a `PUT` replacing a
    /// policy must send; a missing or different one answers 409 (#197, #223), and so does one
    /// sent when there is none to replace.
    #[serde(default)]
    pub seen_updated_at: Option<String>,
}

/// `config` as a policy of `kind`, or the field that is wrong with it.
pub fn parse(kind: &str, config: serde_json::Value) -> Result<Plugin, FieldError> {
    match kind {
        "ip_restriction" => ip_restriction(config).map(Plugin::IpRestriction),
        _ => Err(field("kind", "There is no such policy kind.")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpRestrictionInput {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

fn ip_restriction(config: serde_json::Value) -> Result<IpRestrictionPolicy, FieldError> {
    let input: IpRestrictionInput = serde_json::from_value(config).map_err(|_| {
        field(
            "config",
            "Send allow and deny, each a list of addresses or networks such as 10.0.0.0/8.",
        )
    })?;
    // Nothing listed restricts nothing: a policy that looks like it guards a route and admits
    // everyone.
    if input.allow.is_empty() && input.deny.is_empty() {
        return Err(field(
            "allow",
            "List at least one address or network to allow or to deny.",
        ));
    }
    if input.allow.len() + input.deny.len() > MAX_NETWORKS {
        return Err(field(
            "allow",
            format!("List at most {MAX_NETWORKS} addresses and networks, allow and deny together."),
        ));
    }
    let networks = |name: &str, list: &[String]| -> Result<Vec<Cidr>, FieldError> {
        list.iter()
            .map(|text| {
                text.parse::<Cidr>().map_err(|e| {
                    field(
                        name,
                        format!(
                            "{e}. Write an address such as 203.0.113.7 or a network such as \
                             10.0.0.0/8."
                        ),
                    )
                })
            })
            .collect()
    };
    Ok(IpRestrictionPolicy {
        allow: networks("allow", &input.allow)?,
        deny: networks("deny", &input.deny)?,
    })
}

/// What a stored row holds of `plugin`: the policy without its `kind` tag, which the row's name
/// already says. Also what the list shows, so a reader sees the form the data plane reads: a
/// bare address as the network of one it is.
pub fn config(plugin: &Plugin) -> serde_json::Value {
    let mut value = serde_json::to_value(plugin).expect("a policy serialises");
    value
        .as_object_mut()
        .expect("a policy is an object")
        .remove("kind");
    value
}

/// A policy of one kind as the list shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KindPolicyView {
    pub target: String,
    pub config: serde_json::Value,
    /// The policy row's stamp, which a `PUT` replacing it sends back as `seen_updated_at`.
    pub updated_at: String,
}

/// Where a route or a service gets a policy of one kind from, as its list row shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyFromView {
    /// `"route"`, `"service"` or `"workspace"`.
    pub from: &'static str,
    /// The policy row's own stamp.
    pub updated_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_ip_restriction_is_stored_in_the_form_the_data_plane_reads() {
        let plugin = parse(
            "ip_restriction",
            json!({"allow": ["203.0.113.7", "10.0.0.0/8"]}),
        )
        .unwrap();
        assert_eq!(
            config(&plugin),
            json!({"allow": ["203.0.113.7/32", "10.0.0.0/8"]})
        );
        assert_eq!(parse("ip_restriction", config(&plugin)).unwrap(), plugin);
    }

    /// The store writes a row under `plugin.kind()` and reads it back under the path's kind, so
    /// the two must be one name for every kind this endpoint keeps.
    #[test]
    fn each_kind_parses_to_a_plugin_of_that_kind() {
        let minimal = |kind: &str| match kind {
            "ip_restriction" => json!({"deny": ["10.0.0.0/8"]}),
            other => panic!("no minimal configuration for {other}: add one here"),
        };
        for kind in KINDS {
            let plugin = parse(kind, minimal(kind)).unwrap();
            assert_eq!(plugin.kind(), *kind);
            assert_eq!(parse(kind, config(&plugin)).unwrap(), plugin);
        }
    }

    #[test]
    fn a_bad_ip_restriction_names_its_field() {
        let refused = |config: serde_json::Value| parse("ip_restriction", config).unwrap_err();
        assert_eq!(refused(json!({})).field, "allow");
        assert_eq!(refused(json!({"allow": [], "deny": []})).field, "allow");
        assert_eq!(refused(json!({"allow": ["10.0.0.0/33"]})).field, "allow");
        assert_eq!(refused(json!({"deny": ["nope"]})).field, "deny");
        assert_eq!(refused(json!({"deny": "10.0.0.0/8"})).field, "config");
        assert_eq!(
            refused(json!({"allow": ["10.0.0.0/8"], "mode": "x"})).field,
            "config"
        );
        let many: Vec<String> = (0..=MAX_NETWORKS)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
            .collect();
        assert_eq!(refused(json!({"deny": many})).field, "allow");
        assert_eq!(parse("oauth2", json!({})).unwrap_err().field, "kind");
    }
}
