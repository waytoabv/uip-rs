use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::{PgPool, Row as _};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use uip_core::{LiveRow, LookupCache, ParsedLog};

const BATCH_MAX: usize = 200;
const FLUSH_EVERY: Duration = Duration::from_millis(200);

/// Eine Zeile, fertig aufgelöst für den UNNEST-Insert.
struct Row {
    timestamp: DateTime<Utc>,
    log_type_id: i16,
    direction_id: Option<i16>,
    rule_id: Option<i16>,
    rule_action_id: Option<i16>,
    protocol_id: Option<i16>,
    iface_in_id: Option<i16>,
    iface_out_id: Option<i16>,
    hostname_id: Option<i16>,
    src_ip: Option<IpNetwork>,
    dst_ip: Option<IpNetwork>,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    mac_address: Option<MacAddress>,
    dns_query: Option<String>,
    dns_type: Option<String>,
    dns_answer: Option<String>,
    dhcp_event: Option<String>,
    wifi_event: Option<String>,
    severity: Option<i16>,
    program_id: Option<i16>,
    details: Option<serde_json::Value>,
    raw_log: Option<String>,
    live: LiveRow,
}

async fn resolve(p: ParsedLog, pool: &PgPool, cache: &LookupCache) -> Result<Row, sqlx::Error> {
    let log_type = p.log_type.expect("parse_log always sets log_type");
    let rule_id = match (&p.rule_name, &p.rule_desc) {
        (None, None) => None,
        (n, d) => Some(cache.rule_id(pool, n.as_deref(), d.as_deref()).await?),
    };
    let mut iface_in_id = None;
    if let Some(i) = &p.interface_in {
        iface_in_id = Some(cache.interface_id(pool, i).await?);
    }
    let mut iface_out_id = None;
    if let Some(i) = &p.interface_out {
        iface_out_id = Some(cache.interface_id(pool, i).await?);
    }
    let mut protocol_id = None;
    if let Some(pr) = &p.protocol {
        protocol_id = Some(cache.protocol_id(pool, pr).await?);
    }
    let mut hostname_id = None;
    if let Some(h) = &p.hostname {
        hostname_id = Some(cache.device_name_id(pool, h).await?);
    }
    let mut program_id = None;
    if let Some(prog) = &p.program {
        program_id = Some(cache.program_id(pool, prog).await?);
    }

    let timestamp = p.timestamp.unwrap_or_else(Utc::now);
    // System- und WLAN-Zeilen tragen raw: bei beiden steckt die Information
    // im Text selbst. Bei WLAN war das der Grund, warum in der Tabelle nichts
    // als eine MAC-Adresse stand — was der Access Point geschrieben hatte,
    // war schon vor dem Speichern verloren.
    let keep_raw = matches!(
        log_type,
        uip_core::types::LogType::System | uip_core::types::LogType::Wifi
    );

    // Die angereicherten Felder bleiben hier leer und werden erst in `flush`
    // aus dem Adress-Cache gefüllt — dort liegt die ganze Stapel-Menge vor,
    // und eine Abfrage für den Stapel ist billiger als eine je Zeile.
    let live = LiveRow {
        timestamp,
        log_type: log_type.as_str(),
        direction: p.direction.map(|d| d.as_str()),
        rule_action: p.rule_action.map(|a| a.as_str()),
        rule_name: p.rule_name.clone(),
        protocol: p.protocol.clone(),
        iface_in: p.interface_in.clone(),
        iface_out: p.interface_out.clone(),
        src_ip: p.src_ip,
        dst_ip: p.dst_ip,
        src_port: p.src_port,
        dst_port: p.dst_port,
        mac_address: p.mac_address.clone(),
        hostname: p.hostname.clone(),
        dns_query: p.dns_query.clone(),
        dns_type: p.dns_type.clone(),
        dns_answer: p.dns_answer.clone(),
        dhcp_event: p.dhcp_event.clone(),
        wifi_event: p.wifi_event.clone(),
        severity: p.severity,
        program: p.program.clone(),
        details: p.details.clone(),
        raw_log: keep_raw.then(|| p.raw_log.clone()),
        geo_country: None,
        geo_city: None,
        geo_lat: None,
        geo_lon: None,
        asn_number: None,
        asn_name: None,
        rdns: None,
        threat_score: None,
        threat_categories: None,
        abuse_is_tor: None,
    };

    Ok(Row {
        timestamp,
        log_type_id: log_type as i16,
        direction_id: p.direction.map(|d| d as i16),
        rule_id,
        rule_action_id: p.rule_action.map(|a| a as i16),
        protocol_id,
        iface_in_id,
        iface_out_id,
        hostname_id,
        src_ip: p.src_ip.map(IpNetwork::from),
        dst_ip: p.dst_ip.map(IpNetwork::from),
        src_port: p.src_port,
        dst_port: p.dst_port,
        mac_address: p
            .mac_address
            .as_deref()
            .and_then(|m| MacAddress::from_str(m).ok()),
        dns_query: p.dns_query,
        dns_type: p.dns_type,
        dns_answer: p.dns_answer,
        dhcp_event: p.dhcp_event,
        wifi_event: p.wifi_event,
        severity: p.severity,
        program_id,
        details: p.details,
        raw_log: keep_raw.then_some(p.raw_log),
        live,
    })
}

/// Was über die Gegenstellen dieses Stapels schon bekannt ist.
///
/// Gefragt wird nach beiden Seiten jeder Zeile; im Cache steht ohnehin nur die
/// Gegenstelle, weil nur sie je nachgeschlagen wird. Eine Abfrage je Stapel
/// statt je Zeile — bei zweihundert Zeilen ist das der Unterschied zwischen
/// einer Abfrage und zweihundert.
async fn known_facts(pool: &PgPool, rows: &[Row]) -> HashMap<IpAddr, uip_core::Enrichment> {
    let mut wanted: Vec<IpNetwork> = Vec::new();
    for r in rows {
        for ip in [r.src_ip, r.dst_ip].into_iter().flatten() {
            if !wanted.contains(&ip) {
                wanted.push(ip);
            }
        }
    }
    if wanted.is_empty() {
        return HashMap::new();
    }

    let found = sqlx::query(
        r#"SELECT host(ip) AS ip, geo_country, geo_city, geo_lat, geo_lon,
                  asn_number, asn_name, rdns, threat_score, threat_categories, abuse_is_tor
           FROM ip_enrichment WHERE ip = ANY($1)"#,
    )
    .bind(&wanted)
    .fetch_all(pool)
    .await;
    let found = match found {
        Ok(rows) => rows,
        // Kein Grund, den Stapel scheitern zu lassen: ohne Cache-Treffer
        // erscheint die Zeile eben leer und wird nachgetragen.
        Err(e) => {
            tracing::debug!(error = %e, "could not read the address cache");
            return HashMap::new();
        }
    };

    found
        .iter()
        .filter_map(|r| {
            let ip: String = r.get("ip");
            let ip: IpAddr = ip.parse().ok()?;
            Some((
                ip,
                uip_core::Enrichment {
                    ip,
                    geo_country: r.get("geo_country"),
                    geo_city: r.get("geo_city"),
                    geo_lat: r.get("geo_lat"),
                    geo_lon: r.get("geo_lon"),
                    asn_number: r.get("asn_number"),
                    asn_name: r.get("asn_name"),
                    rdns: r.get("rdns"),
                    threat_score: r.get("threat_score"),
                    threat_categories: r.get("threat_categories"),
                    abuse_is_tor: r.get("abuse_is_tor"),
                },
            ))
        })
        .collect()
}

/// Trägt die bekannten Angaben in die Live-Zeile ein.
///
/// Welche der beiden Adressen die Gegenstelle ist, entscheidet dieselbe
/// Funktion wie in der Anreicherung (`uip_core::remote_ip`) — zwei Antworten
/// darauf liefen unweigerlich auseinander.
fn fill_from_cache(r: &mut Row, known: &HashMap<IpAddr, uip_core::Enrichment>) {
    let remote = uip_core::remote_ip(
        r.log_type_id,
        r.direction_id,
        r.src_ip.map(|n| n.ip()),
        r.dst_ip.map(|n| n.ip()),
        &HashSet::new(),
    );
    let Some(facts) = remote.and_then(|ip| known.get(&ip)) else { return };
    r.live.geo_country = facts.geo_country.clone();
    r.live.geo_city = facts.geo_city.clone();
    r.live.geo_lat = facts.geo_lat;
    r.live.geo_lon = facts.geo_lon;
    r.live.asn_number = facts.asn_number;
    r.live.asn_name = facts.asn_name.clone();
    r.live.rdns = facts.rdns.clone();
    r.live.threat_score = facts.threat_score;
    r.live.threat_categories = facts.threat_categories.clone();
    r.live.abuse_is_tor = facts.abuse_is_tor;
}

async fn flush(
    rows: &mut Vec<Row>,
    pool: &PgPool,
    events: &broadcast::Sender<uip_core::LiveEvent>,
    wake_enricher: &Arc<tokio::sync::Notify>,
) {
    if rows.is_empty() {
        return;
    }
    let n = rows.len();
    macro_rules! col {
        ($f:ident) => {
            rows.iter().map(|r| r.$f.clone()).collect::<Vec<_>>()
        };
    }
    let res = sqlx::query(
        r#"INSERT INTO logs (timestamp, log_type_id, direction_id, rule_id, rule_action_id,
             protocol_id, iface_in_id, iface_out_id, hostname_id, src_ip, dst_ip,
             src_port, dst_port, mac_address, dns_query, dns_type, dns_answer,
             dhcp_event, wifi_event, raw_log, severity, program_id, details)
           SELECT * FROM UNNEST(
             $1::timestamptz[], $2::smallint[], $3::smallint[], $4::smallint[], $5::smallint[],
             $6::smallint[], $7::smallint[], $8::smallint[], $9::smallint[], $10::inet[], $11::inet[],
             $12::int[], $13::int[], $14::macaddr[], $15::text[], $16::text[], $17::text[],
             $18::text[], $19::text[], $20::text[], $21::smallint[], $22::smallint[], $23::jsonb[])"#,
    )
    .bind(col!(timestamp))
    .bind(col!(log_type_id))
    .bind(col!(direction_id))
    .bind(col!(rule_id))
    .bind(col!(rule_action_id))
    .bind(col!(protocol_id))
    .bind(col!(iface_in_id))
    .bind(col!(iface_out_id))
    .bind(col!(hostname_id))
    .bind(col!(src_ip))
    .bind(col!(dst_ip))
    .bind(col!(src_port))
    .bind(col!(dst_port))
    .bind(col!(mac_address))
    .bind(col!(dns_query))
    .bind(col!(dns_type))
    .bind(col!(dns_answer))
    .bind(col!(dhcp_event))
    .bind(col!(wifi_event))
    .bind(col!(raw_log))
    .bind(col!(severity))
    .bind(col!(program_id))
    .bind(col!(details))
    .execute(pool)
    .await;
    match res {
        Ok(_) => {
            // Was über die Gegenstelle schon bekannt ist, kommt mit — die
            // Zeile soll nicht erst leer erscheinen und Sekunden später
            // nachgebessert werden, wenn die Antwort längst im Cache liegt.
            // Eine Abfrage für den ganzen Stapel, nicht eine je Zeile.
            let known = known_facts(pool, rows).await;
            for mut r in rows.drain(..) {
                fill_from_cache(&mut r, &known);
                let _ = events.send(uip_core::LiveEvent::Row(Arc::new(r.live))); // niemand hört zu → egal
            }
            tracing::debug!(rows = n, "flushed batch");
            // Weckt den Enrichment-Worker: es gibt jetzt frische Zeilen mit
            // enrich_status = 0. Ohne Empfänger (Worker schläft nicht gerade
            // im select!) ist notify_one ein No-Op — der Idle-Poll holt es nach.
            wake_enricher.notify_one();
        }
        Err(e) => {
            tracing::error!(error = %e, rows = n, "batch insert failed, dropping batch");
            rows.clear();
        }
    }
}

pub async fn run_writer(
    mut rx: mpsc::Receiver<ParsedLog>,
    pool: PgPool,
    cache: Arc<LookupCache>,
    events: broadcast::Sender<uip_core::LiveEvent>,
    wake_enricher: Arc<tokio::sync::Notify>,
) {
    let mut buf: Vec<Row> = Vec::with_capacity(BATCH_MAX);
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(p) => {
                    match resolve(p, &pool, &cache).await {
                        Ok(row) => buf.push(row),
                        Err(e) => tracing::error!(error = %e, "lookup resolve failed, dropping row"),
                    }
                    if buf.len() >= BATCH_MAX { flush(&mut buf, &pool, &events, &wake_enricher).await; }
                }
                None => { flush(&mut buf, &pool, &events, &wake_enricher).await; return; }
            },
            _ = tick.tick() => flush(&mut buf, &pool, &events, &wake_enricher).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallCtx;
    use crate::parsers::parse_log;
    use chrono::Utc;
    use uip_core::LookupCache;

    #[sqlx::test(migrations = "../../migrations")]
    async fn writes_batch_and_broadcasts(pool: sqlx::PgPool) {
        let cache = std::sync::Arc::new(LookupCache::new());
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let (btx, mut brx) = tokio::sync::broadcast::channel(256);
        let wake = std::sync::Arc::new(tokio::sync::Notify::new());
        let writer = tokio::spawn(run_writer(rx, pool.clone(), cache, btx, wake));

        let ctx = FirewallCtx::default();
        ctx.set_wan_interfaces(["ppp0".to_string()].into_iter().collect());
        let p = parse_log(
            "Feb  8 16:43:49 UDR kernel: [WAN_IN-D]IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=443",
            Utc::now(), &ctx,
        ).unwrap();
        tx.send(p).await.unwrap();
        drop(tx); // Kanal zu → Writer flusht und endet

        writer.await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM logs").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 1);
        let (status, lt): (i16, i16) = sqlx::query_as(
            "SELECT enrich_status, log_type_id FROM logs LIMIT 1",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(status, 0); // pending für Phase-2-Worker
        assert_eq!(lt, 1);
        let evt = brx.recv().await.unwrap();
        let uip_core::LiveEvent::Row(evt) = evt else { panic!("eine Zeile, kein Nachtrag") };
        assert_eq!(evt.src_ip, Some("1.2.3.4".parse().unwrap()));
        // Die Adresse war unbekannt — dann bleibt es beim Nachtrag später.
        assert_eq!(evt.geo_country, None);
    }

    /// Dieselben Ziele kehren ständig wieder. Ist die Gegenstelle schon
    /// nachgeschlagen, soll die Zeile vollständig erscheinen und nicht erst
    /// leer und Sekunden später nachgebessert — die Antwort liegt ja bereit.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_known_address_arrives_already_enriched(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO ip_enrichment (ip, geo_country, asn_number, asn_name, rdns)
             VALUES ('1.2.3.4', 'DE', 3320, 'Deutsche Telekom AG', 'host.example.')",
        )
        .execute(&pool).await.unwrap();

        let cache = std::sync::Arc::new(LookupCache::new());
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let (btx, mut brx) = tokio::sync::broadcast::channel(256);
        let wake = std::sync::Arc::new(tokio::sync::Notify::new());
        let writer = tokio::spawn(run_writer(rx, pool.clone(), cache, btx, wake));

        let ctx = FirewallCtx::default();
        ctx.set_wan_interfaces(["ppp0".to_string()].into_iter().collect());
        let p = parse_log(
            "Feb  8 16:43:49 UDR kernel: [WAN_IN-D]IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=443",
            Utc::now(), &ctx,
        ).unwrap();
        tx.send(p).await.unwrap();
        drop(tx);
        writer.await.unwrap();

        let uip_core::LiveEvent::Row(evt) = brx.recv().await.unwrap() else {
            panic!("eine Zeile, kein Nachtrag")
        };
        assert_eq!(evt.geo_country.as_deref(), Some("DE"));
        assert_eq!(evt.asn_name.as_deref(), Some("Deutsche Telekom AG"));
        assert_eq!(evt.rdns.as_deref(), Some("host.example."));
    }

    /// Die eigene Seite wird nicht beschriftet: im Cache steht nur die
    /// Gegenstelle, und 10.0.0.5 dort zu suchen fände nichts — oder, schlimmer,
    /// die Angaben eines fremden Netzes mit derselben Adresse.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_local_side_is_never_labelled(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO ip_enrichment (ip, geo_country) VALUES ('10.0.0.5', 'XX')")
            .execute(&pool).await.unwrap();

        let cache = std::sync::Arc::new(LookupCache::new());
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let (btx, mut brx) = tokio::sync::broadcast::channel(256);
        let wake = std::sync::Arc::new(tokio::sync::Notify::new());
        let writer = tokio::spawn(run_writer(rx, pool.clone(), cache, btx, wake));

        let ctx = FirewallCtx::default();
        ctx.set_wan_interfaces(["ppp0".to_string()].into_iter().collect());
        let p = parse_log(
            "Feb  8 16:43:49 UDR kernel: [WAN_IN-D]IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=443",
            Utc::now(), &ctx,
        ).unwrap();
        tx.send(p).await.unwrap();
        drop(tx);
        writer.await.unwrap();

        let uip_core::LiveEvent::Row(evt) = brx.recv().await.unwrap() else {
            panic!("eine Zeile, kein Nachtrag")
        };
        assert_eq!(evt.geo_country, None, "die eigene Adresse zählt nicht");
    }
}
