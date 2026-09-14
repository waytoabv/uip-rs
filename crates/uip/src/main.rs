use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use uip_core::{Config, LiveRow, LookupCache};
use uip_ingest::firewall::FirewallCtx;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Config::from_env();
    let pool = uip_core::connect(&cfg.database_url).await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    uip_api::services::seed_if_empty(&pool).await?;

    let settings = uip_core::Settings::load(&pool, |k| std::env::var(k).ok()).await?;
    tracing::info!(
        wan_ips = settings.wan_ips.len(),
        rdns = settings.rdns_enabled,
        threat = settings.abuseipdb_key.is_some(),
        "settings loaded"
    );

    let wake_enricher = Arc::new(tokio::sync::Notify::new());

    let cache = Arc::new(LookupCache::new());
    let (log_tx, log_rx) = tokio::sync::mpsc::channel(8192);
    let (event_tx, _) = tokio::sync::broadcast::channel::<Arc<LiveRow>>(1024);

    let writer = tokio::spawn(uip_ingest::writer::run_writer(
        log_rx, pool.clone(), cache, event_tx.clone(), wake_enricher.clone(),
    ));

    let udp_sock = tokio::net::UdpSocket::bind(&cfg.syslog_addr).await?;
    tracing::info!(addr = %cfg.syslog_addr, "syslog listener up");
    let fw_ctx = FirewallCtx {
        wan_interfaces: cfg.wan_interfaces.clone(),
        wan_ips: settings.wan_ips.clone(),
    };
    tokio::spawn(uip_ingest::udp::run_udp(udp_sock, log_tx, fw_ctx));

    // GeoIP: fehlende oder veraltete mmdb-Dateien sind kein Fehler, nur leere
    // Anreicherung. Der Watcher übernimmt Aktualisierungen von geoipupdate,
    // erkennbar an einer neuen mtime.
    let geo = Arc::new(uip_enrich::geoip::MaxmindGeo::from_dir(&settings.geoip_dir)?);
    tokio::spawn(uip_enrich::geoip::watch_for_updates(geo.clone()));

    let rdns: Option<Arc<dyn uip_enrich::RdnsSource>> = if settings.rdns_enabled {
        match uip_enrich::rdns::Rdns::from_system() {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                tracing::warn!(error = %e, "no system resolver, reverse dns stays off");
                None
            }
        }
    } else {
        None
    };

    let threat: Arc<dyn uip_enrich::ThreatSource> = match &settings.abuseipdb_key {
        Some(key) => Arc::new(uip_enrich::abuseipdb::AbuseIpDb::new(key.clone())),
        None => Arc::new(uip_enrich::abuseipdb::NoThreatSource),
    };

    tokio::spawn(uip_enrich::run_worker(
        pool.clone(),
        uip_enrich::Sources { geo, rdns, threat },
        uip_enrich::Exclusions(settings.exclusions()),
        wake_enricher,
    ));

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
