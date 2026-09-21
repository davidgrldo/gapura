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
        // Three sources now, exactly one of which a deployment picks. ADR 2 made that
        // exclusivity the point: a deployment should have one answer to "where does this come
        // from", so clap refuses the combinations rather than arbitrating them at runtime.
        required_unless_present_any = ["kubernetes", "control_plane"],
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

    /// Addresses published in one Gateway's status, as `namespace/name=ip-or-host`. Repeatable;
    /// a Gateway with an override does not get the global `--publish-address` list. This is
    /// what makes two Gateways whose routes overlap tellable apart: give each its own address
    /// (its own Service), and pair it with the bind-port remap of the colliding listener.
    #[arg(long = "gateway-address", value_name = "NAMESPACE/NAME=ADDRESS")]
    pub gateway_addresses: Vec<String>,

    /// Network allowed to set `X-Forwarded-For`, as a CIDR or a bare address. Repeatable.
    /// Without this the header is ignored and the access log records the peer, which is the
    /// proxy itself wherever one sits in front.
    #[arg(long = "trusted-proxy", value_name = "CIDR")]
    pub trusted_proxies: Vec<crate::proxy::client::Cidr>,

    /// A request header naming the client by a single IP, e.g. CF-Connecting-IP or X-Real-IP.
    /// Believed only when the peer is a --trusted-proxy and the request carries no
    /// X-Forwarded-For chain: the shape of a CDN tunnel that names the client nowhere else.
    /// Repeatable; the first header present on a request wins.
    #[arg(long = "trusted-client-header", value_name = "NAME")]
    pub trusted_client_headers: Vec<String>,

    /// Include the request's query string in the access log. Off by default: query strings carry
    /// tokens and other secrets, and an access log is written to be read. With it on, a log line
    /// names the exact request, not just its path.
    #[arg(long = "access-log-query")]
    pub access_log_query: bool,

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

    /// Base URL of a `gapura-control` configuration endpoint, e.g.
    /// `https://gapura-control.gapura-system:8081`. The third configuration source, after
    /// `--config-dir` and `--kubernetes`, and exclusive with both: ADR 2 has a deployment read
    /// from exactly one place, so that "where does this come from" has one answer.
    #[arg(long, conflicts_with_all = ["config_dir", "kubernetes"], requires = "control_plane_token_file")]
    pub control_plane: Option<String>,

    /// File holding the token this data plane authenticates with (ADR 4). A file rather than a
    /// flag so it never reaches a process list, a shell history, or a crash dump of argv.
    #[arg(long)]
    pub control_plane_token_file: Option<std::path::PathBuf>,

    /// Where the last configuration received is kept, so a gateway that loses the control plane
    /// keeps serving what it has rather than waking up empty. Absent disables the cache, which
    /// means a control plane that is down at startup leaves this gateway unready.
    #[arg(long)]
    pub config_cache: Option<std::path::PathBuf>,

    /// How often to ask. Propagation is bounded by this; ADR 3 records that the fix, when it
    /// matters, is to hold the request open rather than to invert the direction.
    #[arg(long, default_value = "5", value_name = "SECONDS")]
    pub control_plane_interval: u64,

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
    /// Cross-argument checks clap cannot express.
    ///
    /// A port listed under both `--listen-http` and `--listen-https` would make Pingora fail the
    /// second bind at startup. An address listed twice is worse than a failed bind: Pingora sets
    /// `SO_REUSEPORT`, so both services bind it and the kernel splits new connections between
    /// them, which reads as a gateway answering at random. `first_unbindable` cannot catch it
    /// either, since it releases each socket before trying the next one.
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        let repeated: std::collections::BTreeSet<String> = self
            .listen_http
            .iter()
            .chain(self.listen_https.iter())
            .chain(std::iter::once(&self.admin))
            .filter(|addr| !seen.insert(**addr))
            .map(|addr| addr.to_string())
            .collect();
        if !repeated.is_empty() {
            return Err(format!(
                "address {} listed more than once across --listen-http, --listen-https and --admin",
                repeated.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }

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

    pub fn settings(&self) -> Result<Settings, String> {
        let mut overrides = std::collections::BTreeMap::new();
        for entry in &self.gateway_addresses {
            let (ref_, address) = entry.split_once('=').ok_or_else(|| {
                format!("--gateway-address must be namespace/name=address, got {entry:?}")
            })?;
            let (namespace, name) = ref_.split_once('/').ok_or_else(|| {
                format!("--gateway-address must be namespace/name=address, got {entry:?}")
            })?;
            if namespace.is_empty() || name.is_empty() || address.is_empty() {
                return Err(format!(
                    "--gateway-address must be namespace/name=address, got {entry:?}"
                ));
            }
            overrides
                .entry(format!("{namespace}/{name}"))
                .or_insert_with(Vec::new)
                .push(address.to_string());
        }
        Ok(Settings {
            controller_name: self.controller_name.clone(),
            http_ports: ports_of(&self.listen_http),
            https_ports: ports_of(&self.listen_https),
            gateway_addresses: self.publish_addresses.clone(),
            gateway_address_overrides: overrides,
        })
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
        let settings = args.settings().expect("valid settings");
        assert_eq!(settings.http_ports, vec![80]);
        assert_eq!(settings.https_ports, vec![443]);
        assert_eq!(settings.controller_name, "gapura.dev/controller");
        assert!(settings.gateway_address_overrides.is_empty());
    }

    #[test]
    fn gateway_addresses_group_per_gateway() {
        let args = Args::parse_from([
            "gapura",
            "--config-dir",
            "/tmp/x",
            "--gateway-address=infra/a=127.0.0.1",
            "--gateway-address=infra/a=lb.example.com",
            "--gateway-address=infra/b=127.0.0.2",
        ]);
        let s = args.settings().expect("valid settings");
        assert_eq!(
            s.gateway_address_overrides
                .get("infra/a")
                .map(Vec::as_slice),
            Some(["127.0.0.1".to_string(), "lb.example.com".to_string()].as_slice())
        );
        assert_eq!(
            s.gateway_address_overrides
                .get("infra/b")
                .map(Vec::as_slice),
            Some(["127.0.0.2".to_string()].as_slice())
        );
    }

    #[test]
    fn malformed_gateway_addresses_are_rejected() {
        for bad in [
            "infra/a",          // no =address
            "infra=127.0.0.1",  // no namespace/name on the left
            "=127.0.0.1",       // empty ref
            "infra/=127.0.0.1", // empty name
            "infra/a=",         // empty address
        ] {
            let args = Args::parse_from([
                "gapura",
                "--config-dir",
                "/tmp/x",
                format!("--gateway-address={bad}").as_str(),
            ]);
            assert!(
                args.settings().is_err(),
                "{bad:?} must be rejected by settings()"
            );
        }
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
        let settings = args.settings().expect("valid settings");
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
    fn a_repeated_listen_address_is_rejected() {
        // Not merely a failed bind: Pingora sets SO_REUSEPORT, so the proxy and the admin server
        // both bind the shared address and the kernel splits connections between them. Ten
        // requests to /healthz come back as a mix of 200 and 404, and nothing is logged.
        let clash = Args::try_parse_from([
            "gapura",
            "--config-dir",
            "x",
            "--listen-http",
            "127.0.0.1:18099",
            "--admin",
            "127.0.0.1:18099",
        ])
        .unwrap();
        let err = clash.validate().unwrap_err();
        assert!(err.contains("127.0.0.1:18099"), "{err}");

        let twice = Args::try_parse_from([
            "gapura",
            "--config-dir",
            "x",
            "--listen-https",
            "0.0.0.0:8443",
            "--listen-https",
            "0.0.0.0:8443",
        ])
        .unwrap();
        let err = twice.validate().unwrap_err();
        assert!(err.contains("0.0.0.0:8443"), "{err}");

        let distinct = Args::try_parse_from([
            "gapura",
            "--config-dir",
            "x",
            "--listen-http",
            "0.0.0.0:8080",
            "--listen-https",
            "0.0.0.0:8443",
            "--admin",
            "0.0.0.0:9090",
        ])
        .unwrap();
        assert_eq!(distinct.validate(), Ok(()));
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

    #[test]
    fn bindable_reports_the_address_already_in_use() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let taken = held.local_addr().unwrap();
        let free: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(
            crate::first_unbindable(&[free]).is_none(),
            "port 0 is always bindable"
        );
        let (addr, err) = crate::first_unbindable(&[taken]).expect("the held port is not bindable");
        assert_eq!(addr, taken);
        assert!(!err.is_empty());
    }
}

#[cfg(test)]
mod trusted_proxy_tests {
    use super::*;

    #[test]
    fn trusted_proxies_are_parsed_and_repeatable() {
        let args = Args::parse_from([
            "gapura",
            "--config-dir",
            "/tmp/x",
            "--trusted-proxy",
            "10.0.0.0/8",
            "--trusted-proxy",
            "192.168.1.1",
        ]);
        assert_eq!(args.trusted_proxies.len(), 2);
        assert!(args.trusted_proxies[0].contains("10.9.9.9".parse().unwrap()));
        assert!(args.trusted_proxies[1].contains("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn no_trusted_proxy_flag_means_an_empty_list() {
        let args = Args::parse_from(["gapura", "--config-dir", "/tmp/x"]);
        assert!(args.trusted_proxies.is_empty());
    }

    #[test]
    fn access_log_query_is_off_unless_asked_for() {
        let args = Args::parse_from(["gapura", "--config-dir", "/tmp/x"]);
        assert!(!args.access_log_query);
        let args = Args::parse_from(["gapura", "--config-dir", "/tmp/x", "--access-log-query"]);
        assert!(args.access_log_query);
    }

    #[test]
    fn trusted_client_headers_are_parsed_and_repeatable() {
        let args = Args::parse_from([
            "gapura",
            "--config-dir",
            "/tmp/x",
            "--trusted-client-header",
            "CF-Connecting-IP",
            "--trusted-client-header",
            "X-Real-IP",
        ]);
        assert_eq!(
            args.trusted_client_headers,
            ["CF-Connecting-IP", "X-Real-IP"]
        );
    }
}
