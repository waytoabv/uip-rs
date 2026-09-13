use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use uip_core::{Config, LookupCache};
use uip_ingest::firewall::FirewallCtx;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Config::from_env();
    let pool = uip_core::connect(&cfg.database_url).await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;

    let cache = Arc::new(LookupCache::new());
    let (log_tx, log_rx) = tokio::sync::mpsc::channel(8192);
    let (event_tx, _) = tokio::sync::broadcast::channel(1024);

    let writer = tokio::spawn(uip_ingest::writer::run_writer(
        log_rx, pool.clone(), cache, event_tx.clone(),
    ));

    let udp_sock = tokio::net::UdpSocket::bind(&cfg.syslog_addr).await?;
    tracing::info!(addr = %cfg.syslog_addr, "syslog listener up");
    let fw_ctx = FirewallCtx {
        wan_interfaces: cfg.wan_interfaces.clone(),
        wan_ips: Default::default(),
    };
    tokio::spawn(uip_ingest::udp::run_udp(udp_sock, log_tx, fw_ctx));

    let app = uip_api::router(pool, event_tx);
    let listener = tokio::net::TcpListener::bind(&cfg.http_addr).await?;
    tracing::info!(addr = %cfg.http_addr, "http listener up");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;

    // UDP-Task endet mit dem Prozess; der Writer endet, sobald sein Kanal schließt.
    drop(writer);
    Ok(())
}
