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
    /// Ports we actually bind. Gateway listeners on other ports get `PortUnavailable`.
    pub fn supported_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .listen_http
            .iter()
            .chain(&self.listen_https)
            .map(|a| a.port())
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    pub fn settings(&self) -> Settings {
        Settings {
            controller_name: self.controller_name.clone(),
            supported_ports: self.supported_ports(),
            gateway_addresses: self.publish_addresses.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_ports_are_sorted_and_unique() {
        let args = Args::parse_from([
            "gapura",
            "--config-dir",
            "/tmp/x",
            "--listen-http",
            "0.0.0.0:8080",
            "--listen-https",
            "0.0.0.0:8443",
            "--listen-https",
            "[::]:8080",
        ]);
        assert_eq!(args.supported_ports(), vec![8080, 8443]);
        assert_eq!(args.settings().controller_name, "gapura.dev/controller");
    }
}
