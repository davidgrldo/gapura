//! Gapura data plane binary: load config, build the Pingora server, serve.

mod admin;
mod cli;
mod proxy;
mod source;
mod store;
mod telemetry;

use std::sync::Arc;

use clap::{CommandFactory, Parser};
use pingora::apps::http_app::HttpServer;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::ServerConf;
use pingora::server::Server;
use pingora::services::background::background_service;
use pingora::services::listening::Service;

/// The first address that cannot be bound, with the OS message.
///
/// Pingora binds its listeners on a service thread and `expect`s on failure, and our panic hook
/// only counts the panic, so a process that cannot bind :80 would otherwise keep running with no
/// listener while every probe on the admin port stays green. Checking here turns that into a clear
/// exit. The socket is released immediately, so a competing process could still take the port in
/// the window between this check and Pingora's own bind; that race costs a restart, not silence.
/// If a future version enables Pingora's graceful upgrade (`Opt { upgrade: true }`, where the new
/// process takes the listening sockets from the old one), this check must become conditional on
/// that flag, or it would refuse to start for exactly the upgrade it exists to protect, the old
/// process still holding the ports.
fn first_unbindable(addrs: &[std::net::SocketAddr]) -> Option<(std::net::SocketAddr, String)> {
    addrs
        .iter()
        .find_map(|addr| match std::net::TcpListener::bind(addr) {
            Ok(_) => None,
            Err(e) => Some((*addr, e.to_string())),
        })
}

fn main() {
    let args = cli::Args::parse();
    if let Err(msg) = args.validate() {
        // Same exit code and formatting as clap's own usage errors.
        cli::Args::command()
            .error(clap::error::ErrorKind::ArgumentConflict, msg)
            .exit();
    }
    telemetry::init_logging(&args.log_level);
    telemetry::install_panic_hook();

    let mut wanted: Vec<std::net::SocketAddr> = args.listen_http.clone();
    wanted.extend(args.listen_https.iter().copied());
    wanted.push(args.admin);
    if let Some((addr, error)) = first_unbindable(&wanted) {
        tracing::error!(%addr, %error, "cannot bind a listen address, refusing to start");
        std::process::exit(1);
    }

    let store = Arc::new(store::Store::empty());
    let settings = args.settings().expect("valid settings");
    if let Some(dir) = &args.config_dir {
        match source::file::apply(dir, &settings, &store) {
            Ok(summary) => tracing::info!(?summary, dir = %dir.display(), "config loaded"),
            Err(e) => {
                tracing::error!(error = %e, "cannot load config directory");
                std::process::exit(1);
            }
        }
    }

    let conf = ServerConf {
        threads: args.worker_threads(),
        grace_period_seconds: Some(30),
        graceful_shutdown_timeout_seconds: Some(30),
        ..ServerConf::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    if args.kubernetes {
        let publish_service = match args.publish_service_ref() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "invalid --publish-service");
                std::process::exit(2);
            }
        };
        let source = source::kubernetes::KubeSource {
            settings: settings.clone(),
            store: store.clone(),
            publish_service,
            leader: source::kubernetes::leader::LeaderOpts {
                namespace: args.lease_namespace.clone(),
                name: args.lease_name.clone(),
                identity: args.identity(),
                ..Default::default()
            },
            read_only: args.no_status,
        };
        server.add_service(background_service("kubernetes", source));
        tracing::info!(
            lease = %format!("{}/{}", args.lease_namespace, args.lease_name),
            identity = %args.identity(),
            read_only = args.no_status,
            "kubernetes source enabled"
        );
    }

    let mut proxy = http_proxy_service(
        &server.configuration,
        proxy::GapuraProxy {
            store: store.clone(),
            trusted_proxies: args.trusted_proxies.clone(),
            limiter: Default::default(),
            access_log_query: args.access_log_query,
        },
    );
    for addr in &args.listen_http {
        proxy.add_tcp(&addr.to_string());
    }
    for addr in &args.listen_https {
        let resolver = proxy::tls::SniResolver {
            store: store.clone(),
            port: addr.port(),
        };
        let mut tls = match TlsSettings::with_callbacks(Box::new(resolver)) {
            Ok(tls) => tls,
            Err(e) => {
                tracing::error!(error = %e, "cannot create TLS settings");
                std::process::exit(1);
            }
        };
        tls.enable_h2();
        proxy.add_tls_with_settings(&addr.to_string(), None, tls);
    }
    server.add_service(proxy);

    let mut admin = Service::new(
        "gapura admin".to_string(),
        HttpServer::new_app(admin::AdminApp {
            store: store.clone(),
        }),
    );
    admin.add_tcp(&args.admin.to_string());
    admin.threads = Some(1); // probes and scrapes do not need a worker per core
    server.add_service(admin);

    tracing::info!(http = ?args.listen_http, https = ?args.listen_https, admin = %args.admin, "gapura listening");
    server.run_forever();
}
