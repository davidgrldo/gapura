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
        oidc_issuer = args.oidc_issuer.as_deref().unwrap_or("(local mode)"),
        oidc_groups_claim = %args.oidc_groups_claim,
        "gapura-control starting"
    );
    // Auth mode resolves before anything OIDC is touched: local mode never builds a client,
    // never requires an issuer, and a users file that names nobody stops the process here --
    // the honest failure, not a console that starts and signs nobody in.
    let (auth_mode, local_users) = match args.auth_mode.as_str() {
        "local" => {
            let path = args
                .local_users_file
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--auth-mode local requires --local-users-file"))?;
            let users = gapura_control::login::LocalUsers::load(path)?;
            tracing::info!(users = users.len(), path, "local sign-in enabled");
            (gapura_control::login::AuthMode::Local, users)
        }
        "oidc" => {
            // Required here rather than by clap: local mode passes no OIDC flags at all, and
            // a required clap arg would make the IdP-less mode impossible to express.
            for (flag, value) in [
                ("--oidc-issuer", args.oidc_issuer.as_deref()),
                ("--oidc-client-id", args.oidc_client_id.as_deref()),
                ("--oidc-client-secret", args.oidc_client_secret.as_deref()),
                ("--oidc-redirect-url", args.oidc_redirect_url.as_deref()),
            ] {
                if value.filter(|v| !v.is_empty()).is_none() {
                    anyhow::bail!("{flag} is required with --auth-mode oidc");
                }
            }
            (gapura_control::login::AuthMode::Oidc, Default::default())
        }
        other => anyhow::bail!("--auth-mode must be local or oidc, got {other:?}"),
    };
    let state = gapura_control::state::AppState {
        mapping: Arc::new(args.mapping()),
        session_key: Arc::from(gapura_control::session::session_key()?),
        source: Arc::new(gapura_control::kube_source::Source::from_environment().await?),
        admin: Arc::new(gapura_control::served::Admin::new(&args.gateway_admin)),
        controller_name: Arc::new(args.controller_name.clone()),
        auth_mode,
        local_users,
        oidc: Arc::new(gapura_control::login::Oidc::new(
            args.oidc_issuer.as_deref().unwrap_or_default(),
            args.oidc_client_id.as_deref().unwrap_or_default(),
            args.oidc_client_secret.as_deref().unwrap_or_default(),
            args.oidc_redirect_url.as_deref().unwrap_or_default(),
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
