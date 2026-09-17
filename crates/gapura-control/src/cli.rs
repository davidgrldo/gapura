//! What this process was told at startup.

use clap::Parser;
use std::collections::BTreeMap;

#[derive(Parser, Debug)]
#[command(name = "gapura-control", about = "The gapura control plane")]
pub struct Args {
    /// Address to serve the console and its API on.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub listen: std::net::SocketAddr,

    /// Base URL of a gapura admin port, e.g. `http://gapura.gapura-system:9090`.
    #[arg(long)]
    pub gateway_admin: String,

    /// The GatewayClass controllerName whose verdicts we read. Must match the value the
    /// gateway runs with, or every route reads as pending.
    #[arg(long, default_value = "gapura.dev/controller")]
    pub controller_name: String,

    /// `group=namespace` grant, repeatable. `group=*` grants every namespace.
    #[arg(long = "grant", value_parser = parse_grant)]
    pub grants: Vec<(String, String)>,

    /// Log level filter, e.g. `info` or `gapura_control=debug`. Fixed at compile time before
    /// this existed, which meant a chatty dependency could not be quieted without a rebuild.
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// The OpenID Connect issuer, e.g. `https://id.example.com/realms/engineering`. Its
    /// discovery document is where every other endpoint is read from.
    #[arg(long)]
    pub oidc_issuer: String,

    /// The client id this console is registered under with the identity provider.
    #[arg(long)]
    pub oidc_client_id: String,

    /// The client secret. Taken from the environment as well as the flag, because a
    /// `--flag value` puts the secret in the process listing for anyone on the node.
    #[arg(long, env = "GAPURA_OIDC_CLIENT_SECRET", hide_env_values = true)]
    pub oidc_client_secret: String,

    /// Where the provider sends the browser back: this console's own `/auth/callback`,
    /// and it must match the redirect URI registered with the provider exactly.
    #[arg(long)]
    pub oidc_redirect_url: String,

    /// The ID token claim listing a person's groups. Providers disagree on the name:
    /// Keycloak and Okta say `groups`, Entra ID says `roles`.
    #[arg(long, default_value = "groups")]
    pub oidc_groups_claim: String,

    /// A scope to request beyond `openid`, repeatable. Most providers only put the groups
    /// claim in the ID token when the scope that carries it was asked for, and the name of
    /// that scope is theirs to choose, so there is no default that is right everywhere.
    #[arg(long = "oidc-scope")]
    pub oidc_scopes: Vec<String>,

    /// How long a session lasts, in seconds. Short, because nothing is stored and so a
    /// session cannot be revoked before it expires; not so short that an identity-provider
    /// outage throws people out of a console they were already reading.
    #[arg(long, default_value_t = 60 * 60)]
    pub session_lifetime_seconds: u64,
}

fn parse_grant(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((group, namespace)) if !group.is_empty() && !namespace.is_empty() => {
            Ok((group.to_string(), namespace.to_string()))
        }
        _ => Err(format!("expected group=namespace, got {s:?}")),
    }
}

impl Args {
    /// The grants, collected the way `scope::visible` wants them.
    pub fn mapping(&self) -> BTreeMap<String, Vec<String>> {
        let mut mapping: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (group, namespace) in &self.grants {
            mapping
                .entry(group.clone())
                .or_default()
                .push(namespace.clone());
        }
        mapping
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything without a default, so a test only has to name what it is about.
    const REQUIRED: &[&str] = &[
        "gapura-control",
        "--gateway-admin",
        "http://gw:9090",
        "--oidc-issuer",
        "https://id.example.test",
        "--oidc-client-id",
        "console",
        "--oidc-client-secret",
        "not a real secret",
        "--oidc-redirect-url",
        "https://console.example.test/auth/callback",
    ];

    fn args(extra: &[&str]) -> Args {
        let mut argv = REQUIRED.to_vec();
        argv.extend_from_slice(extra);
        Args::parse_from(argv)
    }

    #[test]
    fn a_grant_names_a_group_and_a_namespace() {
        let a = args(&["--grant", "team-a=apps"]);
        assert_eq!(a.mapping().get("team-a"), Some(&vec!["apps".to_string()]));
    }

    #[test]
    fn one_group_may_be_granted_several_namespaces() {
        let a = args(&["--grant", "team-a=apps", "--grant", "team-a=shop"]);
        assert_eq!(
            a.mapping().get("team-a"),
            Some(&vec!["apps".to_string(), "shop".to_string()])
        );
    }

    #[test]
    fn a_grant_without_an_equals_sign_is_refused() {
        let mut argv = REQUIRED.to_vec();
        argv.extend_from_slice(&["--grant", "nonsense"]);
        let e = Args::try_parse_from(argv);
        assert!(e.is_err(), "a malformed grant must not be silently ignored");
    }

    #[test]
    fn granting_nothing_is_allowed_and_grants_nothing() {
        assert!(args(&[]).mapping().is_empty());
    }

    #[test]
    fn the_controller_name_defaults_to_the_gateways_own_default() {
        assert_eq!(args(&[]).controller_name, "gapura.dev/controller");
    }

    #[test]
    fn a_session_lasts_an_hour_unless_it_is_told_otherwise() {
        // Long enough that a provider outage does not evict a reader mid-task, short enough
        // that nothing stored means nothing revocable stays valid for a working day.
        assert_eq!(args(&[]).session_lifetime_seconds, 3600);
    }

    #[test]
    fn the_groups_claim_has_a_name_the_commonest_providers_agree_on() {
        assert_eq!(args(&[]).oidc_groups_claim, "groups");
    }

    #[test]
    fn signing_in_is_not_optional_configuration() {
        // The premise of this component is that its users have no cluster identity, so a
        // control plane with no identity provider is one nobody can ever get into. It must
        // refuse to start rather than serve four-oh-ones forever.
        let e = Args::try_parse_from(["gapura-control", "--gateway-admin", "http://gw:9090"]);
        assert!(e.is_err(), "an issuer and a client must be required");
    }
}
