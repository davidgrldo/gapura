//! The gapura control plane's entry point: parse, configure, serve. Everything the console
//! is lives in the library crate, reachable as `gapura_control::*`.

mod cli;

use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    // A bad filter falls back to info rather than refusing to start: an operator typing
    // `--log-level debugg` wants the logs they asked for, not a process that exits.
    let filter = EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
    // A mismatch between this and the gateway's --controller-name makes every route read as
    // pending, with nothing on the screen explaining why. Saying it here turns that into a
    // line someone can compare rather than a silence they have to deduce.
    tracing::info!(
        controller_name = %args.controller_name,
        gateway_admin = %args.gateway_admin,
        grants = args.grants.len(),
        oidc_issuer = %args.oidc_issuer,
        oidc_groups_claim = %args.oidc_groups_claim,
        "gapura-control starting"
    );
    let state = gapura_control::state::AppState {
        mapping: Arc::new(args.mapping()),
        session_key: Arc::from(gapura_control::session::session_key()?),
        source: Arc::new(gapura_control::kube_source::Source::from_environment().await?),
        admin: Arc::new(gapura_control::served::Admin::new(&args.gateway_admin)),
        controller_name: Arc::new(args.controller_name.clone()),
        oidc: Arc::new(gapura_control::login::Oidc::new(
            &args.oidc_issuer,
            &args.oidc_client_id,
            &args.oidc_client_secret,
            &args.oidc_redirect_url,
            &args.oidc_groups_claim,
            &args.oidc_scopes,
        )?),
        pending: gapura_control::login::PendingLogins::default(),
        session_lifetime: std::time::Duration::from_secs(args.session_lifetime_seconds),
    };
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(addr = %listener.local_addr()?, "gapura-control listening");
    axum::serve(listener, gapura_control::api::router_with(state)).await?;
    Ok(())
}
