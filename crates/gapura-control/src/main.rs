//! The gapura control plane: serves the console and reads on its behalf.

mod api;
pub mod declared;
pub mod rows;
pub mod scope;
pub mod served;
pub mod session;
pub mod state;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!(addr = %listener.local_addr()?, "gapura-control listening");
    axum::serve(listener, api::router()).await?;
    Ok(())
}
