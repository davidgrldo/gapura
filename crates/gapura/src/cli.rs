//! Command line arguments and the `gapura_core::Settings` derived from them.

use std::net::SocketAddr;

use clap::Parser;
use gapura_core::{ObjectRef, Settings};

#[derive(Debug, Parser, Clone)]
#[command(
    name = "gapura",
    version,
    about = "Kubernetes Gateway API data plane on Pingora"
)]
pub struct Args {
    /// Directory of Gateway API YAML documents (dev and test mode).
    #[arg(
        long,
        value_name = "DIR",
        required_unless_present = "kubernetes",
        conflicts_with = "kubernetes"
    )]
    pub config_dir: Option<std::path::PathBuf>,

    /// Plain HTTP listen address. Repeatable.
    #[arg(long, default_value = "0.0.0.0:80")]
    pub listen_http: Vec<SocketAddr>,

    /// HTTPS listen address. Repeatable.
    #[arg(long, default_value = "0.0.0.0:443")]
    pub listen_https: Vec<SocketAddr>,

    /// Admin listen address (/healthz, /readyz, /metrics, /debug/config).
    #[arg(long, default_value = "0.0.0.0:9090")]
    pub admin: SocketAddr,

    /// GatewayClass controllerName this instance handles.
    #[arg(long, default_value = "gapura.dev/controller")]
    pub controller_name: String,

    /// Address published in Gateway status (the LoadBalancer IP). Repeatable.
    #[arg(long = "publish-address")]
    pub publish_addresses: Vec<String>,

    /// Log level filter, e.g. `info` or `gapura=debug`.
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Worker threads per Pingora service. 0 asks the machine, which does not see cgroup limits;
    /// set it to the CPU limit in Kubernetes.
    #[arg(long, default_value_t = 0)]
    pub threads: usize,

    /// Read Gateway API resources from the Kubernetes API server (in-cluster, or $KUBECONFIG).
    #[arg(long)]
    pub kubernetes: bool,

    /// `namespace/name` of the Service whose LoadBalancer addresses are published in Gateway status.
    #[arg(
        long,
        value_name = "NAMESPACE/NAME",
        requires = "kubernetes",
        conflicts_with = "config_dir"
    )]
    pub publish_service: Option<String>,

    /// Namespace of the leader-election Lease.
    #[arg(long, env = "POD_NAMESPACE", default_value = "default")]
    pub lease_namespace: String,

    /// Name of the leader-election Lease.
    #[arg(long, default_value = "gapura-leader")]
    pub lease_name: String,

    /// This replica's identity in the Lease; defaults to $POD_NAME, then $HOSTNAME.
    #[arg(long, env = "POD_NAME")]
    pub identity: Option<String>,

    /// Never write status or take the Lease (read-only controller, for dry runs).
    #[arg(long, requires = "kubernetes", conflicts_with = "config_dir")]
    pub no_status: bool,
}

impl Args {
    /// Cross-argument checks clap cannot express. A port listed under both `--listen-http` and
    /// `--listen-https` would make Pingora fail the second bind at startup.
    pub fn validate(&self) -> Result<(), String> {
        let https = ports_of(&self.listen_https);
        let shared: Vec<String> = ports_of(&self.listen_http)
            .into_iter()
            .filter(|p| https.contains(p))
            .map(|p| p.to_string())
            .collect();
        if shared.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "port {} listed in both --listen-http and --listen-https",
                shared.join(", ")
            ))
        }
    }

    pub fn identity(&self) -> String {
        self.identity
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| format!("gapura-{}", std::process::id()))
    }

    pub fn worker_threads(&self) -> usize {
        if self.threads > 0 {
            self.threads
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        }
    }

    /// `--publish-service namespace/name` parsed.
    pub fn publish_service_ref(&self) -> anyhow::Result<Option<ObjectRef>> {
        match &self.publish_service {
            None => Ok(None),
            Some(s) => match s.split_once('/') {
                Some((ns, name)) if !ns.is_empty() && !name.is_empty() => {
                    Ok(Some(ObjectRef::new(ns, name)))
                }
                _ => anyhow::bail!("--publish-service must be namespace/name, got {s}"),
            },
        }
    }

    pub fn settings(&self) -> Settings {
        Settings {
            controller_name: self.controller_name.clone(),
            http_ports: ports_of(&self.listen_http),
            https_ports: ports_of(&self.listen_https),
            gateway_addresses: self.publish_addresses.clone(),
        }
    }
}

/// Sorted, unique ports of the given listen addresses.
fn ports_of(addrs: &[SocketAddr]) -> Vec<u16> {
    let mut ports: Vec<u16> = addrs.iter().map(|a| a.port()).collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_are_split_per_protocol() {
        let args = Args::parse_from(["gapura", "--config-dir", "/tmp/x"]);
        let settings = args.settings();
        assert_eq!(settings.http_ports, vec![80]);
        assert_eq!(settings.https_ports, vec![443]);
        assert_eq!(settings.controller_name, "gapura.dev/controller");
    }

    #[test]
    fn http_ports_are_sorted_and_unique() {
        let args = Args::parse_from([
            "gapura",
            "--config-dir",
            "/tmp/x",
            "--listen-http",
            "0.0.0.0:8080",
            "--listen-http",
            "0.0.0.0:80",
            "--listen-http",
            "[::]:8080",
            "--listen-https",
            "0.0.0.0:8443",
        ]);
        let settings = args.settings();
        assert_eq!(settings.http_ports, vec![80, 8080]);
        assert_eq!(settings.https_ports, vec![8443]);
    }

    #[test]
    fn kubernetes_mode_needs_no_config_dir() {
        let a = Args::try_parse_from([
            "gapura",
            "--kubernetes",
            "--publish-service",
            "gapura-system/gapura",
        ])
        .unwrap();
        assert!(a.kubernetes && a.config_dir.is_none());
        assert_eq!(
            a.publish_service_ref().unwrap(),
            Some(gapura_core::ObjectRef::new("gapura-system", "gapura"))
        );
        assert!(!a.identity().is_empty());
    }

    #[test]
    fn exactly_one_source_is_required() {
        assert!(Args::try_parse_from(["gapura"]).is_err(), "no source");
        assert!(
            Args::try_parse_from(["gapura", "--config-dir", "x", "--kubernetes"]).is_err(),
            "both sources"
        );
        assert!(
            Args::try_parse_from(["gapura", "--publish-service", "a/b", "--config-dir", "x"])
                .is_err(),
            "publish-service needs --kubernetes"
        );
        assert!(
            Args::try_parse_from(["gapura", "--publish-service", "a/b"]).is_err(),
            "publish-service alone"
        );
        assert!(
            Args::try_parse_from(["gapura", "--no-status", "--config-dir", "x"]).is_err(),
            "no-status needs --kubernetes"
        );
        let a =
            Args::try_parse_from(["gapura", "--kubernetes", "--publish-service", "nonamespace"])
                .unwrap();
        assert!(a.publish_service_ref().is_err());
    }

    #[test]
    fn http_and_https_ports_must_not_overlap() {
        let a = Args::try_parse_from([
            "gapura",
            "--config-dir",
            "x",
            "--listen-http",
            "0.0.0.0:8080",
            "--listen-https",
            "0.0.0.0:8080",
        ])
        .unwrap();
        let err = a.validate().unwrap_err();
        assert!(err.contains("8080"), "{err}");

        let ok = Args::try_parse_from(["gapura", "--config-dir", "x"]).unwrap();
        assert_eq!(ok.validate(), Ok(()));
    }

    #[test]
    fn threads_defaults_to_available_parallelism_and_can_be_pinned() {
        let auto = Args::try_parse_from(["gapura", "--kubernetes"]).unwrap();
        assert_eq!(auto.threads, 0, "0 means: ask the machine");
        assert_eq!(
            auto.worker_threads(),
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        );
        let pinned = Args::try_parse_from(["gapura", "--kubernetes", "--threads", "3"]).unwrap();
        assert_eq!(pinned.worker_threads(), 3);
    }
}
