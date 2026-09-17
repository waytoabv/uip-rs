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
    let pihole_tx = log_tx.clone();
    let (event_tx, _) = tokio::sync::broadcast::channel::<Arc<LiveRow>>(1024);

    let writer = tokio::spawn(uip_ingest::writer::run_writer(
        log_rx, pool.clone(), cache, event_tx.clone(), wake_enricher.clone(),
    ));

    let udp_sock = tokio::net::UdpSocket::bind(&cfg.syslog_addr).await?;
    tracing::info!(addr = %cfg.syslog_addr, "syslog listener up");
    let fw_ctx = FirewallCtx {
        wan_interfaces: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
            cfg.wan_interfaces.clone(),
        )),
        wan_ips: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(settings.wan_ips.clone())),
    };
    // Der Empfänger zählt, was ankommt, und verwirft die Firewall-Zeilen über
    // den eigenen Weg. Der Port stammt aus derselben Adresse, auf der gelauscht
    // wird — zwei Stellen dafür liefen unweigerlich auseinander.
    let syslog_port = cfg
        .syslog_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<i32>().ok())
        .unwrap_or(514);
    let collector = uip_ingest::collector::Collector::new(syslog_port);
    tokio::spawn(uip_ingest::collector::run_bookkeeping(
        collector.clone(),
        fw_ctx.clone(),
        pool.clone(),
    ));
    tokio::spawn(uip_ingest::udp::run_udp(udp_sock, log_tx, fw_ctx, collector));

    // GeoIP: fehlende oder veraltete mmdb-Dateien sind kein Fehler, nur leere
    // Anreicherung. Der Watcher bemerkt neue Dateien an ihrer mtime,
    // erkennbar an einer neuen mtime.
    let geo = Arc::new(uip_enrich::geoip::MaxmindGeo::from_dir(&settings.geoip_dir)?);
    tokio::spawn(uip_enrich::geoip::watch_for_updates(geo.clone()));

    // Die Datenbanken holt die Anwendung selbst, sobald Zugangsdaten
    // hinterlegt sind — vorher lag das bei geoipupdate und einem systemd-Timer,
    // und wer den Schlüssel erst nach dem Installieren bekam, hatte keinen Weg
    // mehr hinein.
    // Bedingungslos: die Aufgabe liest die Zugangsdaten selbst und wartet, bis
    // welche da sind. Hier auf `settings` zu prüfen hieße, dass ein im Dialog
    // nachgetragener Schlüssel erst nach einem Neustart etwas bewirkt.
    tokio::spawn(uip_enrich::maxmind::run_updater(pool.clone(), geo.clone()));

    // Der Auflöser wird immer gebaut, wenn das System einen hergibt; ob er
    // benutzt wird, entscheidet ein Schalter, den der Worker laufend nachliest.
    // Ihn hier wegzulassen hieße, dass das Wiedereinschalten einen Neustart
    // braucht.
    let rdns: Option<Arc<dyn uip_enrich::RdnsSource>> = match uip_enrich::rdns::Rdns::from_system()
    {
        Ok(r) => Some(Arc::new(r)),
        Err(e) => {
            tracing::warn!(error = %e, "no system resolver, reverse dns stays off");
            None
        }
    };
    let rdns_enabled = Arc::new(std::sync::atomic::AtomicBool::new(settings.rdns_enabled));

    // Auch ohne Schlüssel: die Quelle meldet sich dann als abgeschaltet und
    // nimmt einen später eingetragenen Schlüssel an. `NoThreatSource` könnte
    // das nicht — aus ihr wird nie eine AbuseIPDB-Quelle.
    let threat: Arc<dyn uip_enrich::ThreatSource> = Arc::new(
        uip_enrich::abuseipdb::AbuseIpDb::new(settings.abuseipdb_key.clone().unwrap_or_default()),
    );

    tokio::spawn(uip_enrich::run_worker(
        pool.clone(),
        uip_enrich::Sources { geo, rdns, threat, rdns_enabled },
        uip_enrich::Exclusions(settings.exclusions()),
        wake_enricher,
    ));

    // Pi-hole liefert DNS-Abfragen, die am Gateway-Syslog vorbeilaufen. Die
    // Zeilen gehen in denselben Writer — dahinter ist es gewöhnliches DNS.
    //
    // Beide Aufgaben starten bedingungslos und lesen ihre Einstellungen selbst
    // nach. Sie hier von `settings` abhängig zu machen hieße, dass ein im
    // Dialog eingerichteter Dienst bis zum nächsten Neustart stillsteht — und
    // ein abgeschalteter bis dahin weiterläuft.
    tokio::spawn(uip_enrich::pihole::run_pihole(pihole_tx, pool.clone()));

    // Gerätenamen aus dem Controller. Aufgelöst wird beim Lesen, hier wird
    // nur der Bestand aktuell gehalten.
    tokio::spawn(uip_enrich::unifi::run_unifi(pool.clone()));

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
