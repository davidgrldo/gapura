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

    fn args(extra: &[&str]) -> Args {
        let mut argv = vec!["gapura-control", "--gateway-admin", "http://gw:9090"];
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
        let e = Args::try_parse_from([
            "gapura-control",
            "--gateway-admin",
            "http://gw:9090",
            "--grant",
            "nonsense",
        ]);
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
}
