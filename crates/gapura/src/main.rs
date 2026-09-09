//! Gapura data plane binary: load config, build the Pingora server, serve.

mod admin;
mod cli;
mod proxy;
mod source;
mod store;
mod telemetry;

use std::sync::Arc;

use clap::Parser;
use pingora::apps::http_app::HttpServer;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::ServerConf;
use pingora::server::Server;
use pingora::services::listening::Service;

fn main() {
    let args = cli::Args::parse();
    telemetry::init_logging(&args.log_level);
    telemetry::install_panic_hook();

    let store = Arc::new(store::Store::empty());
    let settings = args.settings();
    match source::file::apply(&args.config_dir, &settings, &store) {
        Ok(summary) => {
            tracing::info!(?summary, dir = %args.config_dir.display(), "config loaded")
        }
        Err(e) => {
            tracing::error!(error = %e, "cannot load config directory");
            std::process::exit(1);
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
