//! Command line arguments and the `gapura_core::Settings` derived from them.

use std::net::SocketAddr;

use clap::Parser;
use gapura_core::Settings;

#[derive(Debug, Parser, Clone)]
#[command(
    name = "gapura",
    version,
    about = "Kubernetes Gateway API data plane on Pingora"
)]
pub struct Args {
    /// Directory of Gateway API YAML documents (dev and test mode).
    #[arg(long, value_name = "DIR")]
    pub config_dir: std::path::PathBuf,

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
}

impl Args {
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
}
