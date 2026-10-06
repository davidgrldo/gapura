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
        store = args.database_url.is_some(),
        "gapura-control starting"
    );
    // Every flag is checked before anything touches the store, so a typo during an upgrade stops
    // the process before a migration runs, rather than leaving a new schema for the old image to
    // roll back onto. Auth mode resolves before anything OIDC is touched: local mode never builds
    // a client, never requires an issuer, and a users file that names nobody stops the process
    // here -- the honest failure, not a console that starts and signs nobody in.
    let store_mode = args.database_url.is_some();
    let (auth_mode, local_users) = match args.auth_mode.as_str() {
        // In store mode a local account is a row, so there is no file to read.
        "local" if store_mode => (gapura_control::login::AuthMode::Local, Default::default()),
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
    // Parsed here, with the other flags, so an issuer or redirect URL that was never going to
    // work stops the process before the store is touched. Parsing does no network work; the
    // provider is first asked anything at the first sign-in. Local mode carries the never-used
    // stand-in: Oidc::new("") cannot parse, and the state is built unconditionally. Nothing in
    // local mode ever touches it.
    let oidc = Arc::new(match auth_mode {
        gapura_control::login::AuthMode::Oidc => gapura_control::login::Oidc::new(
            args.oidc_issuer.as_deref().expect("validated above"),
            args.oidc_client_id.as_deref().expect("validated above"),
            args.oidc_client_secret.as_deref().expect("validated above"),
            args.oidc_redirect_url.as_deref().expect("validated above"),
            &args.oidc_groups_claim,
            &args.oidc_scopes,
        )?,
        gapura_control::login::AuthMode::Local => gapura_control::login::Oidc::unused()?,
    });
    // With `DATABASE_URL` set the console is in store mode: its accounts and roles are rows
    // there, and the two flags that describe them in Kubernetes mode are refused rather than
    // ignored -- an operator who passed them expected them to mean something. Refused before
    // the Kubernetes client is built, so a stray flag is the error reported, not whatever the
    // client finds wrong first.
    if store_mode {
        anyhow::ensure!(
            args.local_users_file.is_none(),
            "--local-users-file cannot be used with DATABASE_URL: in store mode the console's \
             accounts are rows in Postgres"
        );
        anyhow::ensure!(
            args.grants.is_empty(),
            "--grant cannot be used with DATABASE_URL: in store mode access comes from role and \
             group bindings in Postgres"
        );
    }
    // The session key and the Kubernetes client are part of "every flag" too: a key Secret that
    // resolves to nothing has to stop the process before the store is migrated, not after.
    let session_key = Arc::from(gapura_control::session::session_key()?);
    let source = Arc::new(gapura_control::kube_source::Source::from_environment().await?);
    let store = match &args.database_url {
        Some(url) => {
            let store = Arc::new(gapura_control::store::Store::connect(url).await?);
            store.migrate().await?;
            gapura_control::bootstrap::run(&store).await?;
            // Made now rather than by the first unknown name to sign in, which would otherwise
            // take twice as long as every sign-in after it.
            std::sync::LazyLock::force(&gapura_control::password::DUMMY);
            Some(store)
        }
        None => None,
    };
    let state = gapura_control::state::AppState {
        mapping: Arc::new(args.mapping()),
        session_key,
        source,
        admin: Arc::new(gapura_control::served::Admin::new(&args.gateway_admin)),
        controller_name: Arc::new(args.controller_name.clone()),
        auth_mode,
        local_users,
        oidc,
        pending: gapura_control::login::PendingLogins::default(),
        session_lifetime: std::time::Duration::from_secs(args.session_lifetime_seconds),
        store: store.clone(),
        sign_in: Arc::new(gapura_control::throttle::Throttle::new(
            args.trusted_proxies.clone(),
        )),
    };
    // Served only when there is a store to serve it from, on its own listener: two servers in
    // one process rather than one router, so the port is the boundary and not a path prefix
    // somebody can get wrong later.
    if let Some(store) = store {
        let api = Arc::new(gapura_control::config_api::ConfigApi {
            store,
            settings: gapura_core::store::StoreSettings {
                http_ports: args.data_plane_http_ports.clone(),
            },
        });
        let listener = tokio::net::TcpListener::bind(args.listen_config).await?;
        tracing::info!(addr = %listener.local_addr()?, "configuration endpoint listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, gapura_control::config_api::router(api)).await {
                tracing::error!(error = %e, "the configuration endpoint stopped");
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(addr = %listener.local_addr()?, "gapura-control listening");
    // With each connection's address, which the sign-in limits count against.
    axum::serve(
        listener,
        gapura_control::api::router_with(state)
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
