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

    let store = Arc::new(store::Store::empty());
    let settings = args.settings();
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
        threads: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
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
