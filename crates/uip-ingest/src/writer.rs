use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::PgPool;
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
    raw_log: Option<String>,
    live: Arc<LiveRow>,
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

    let timestamp = p.timestamp.unwrap_or_else(Utc::now);
    // System-Logs tragen raw immer (einzige Information); andere nur zur Diagnose nicht nötig → NULL spart Platz.
    let keep_raw = matches!(log_type, uip_core::types::LogType::System);

    // Bewusst ohne geo_*/asn_*/rdns/threat_*: eine frisch geschriebene Zeile ist
    // noch gar nicht angereichert (enrich_status = 0). Die Live-Tabelle zeigt
    // sie hier leer und holt sie beim nächsten /api/logs-Reload nach — ehrlicher
    // als ein Wert, den es zum Sendezeitpunkt noch nicht gab.
    let live = Arc::new(LiveRow {
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
        raw_log: keep_raw.then(|| p.raw_log.clone()),
    });

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
        raw_log: keep_raw.then_some(p.raw_log),
        live,
    })
}

async fn flush(
    rows: &mut Vec<Row>,
    pool: &PgPool,
    events: &broadcast::Sender<Arc<LiveRow>>,
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
             dhcp_event, wifi_event, raw_log)
           SELECT * FROM UNNEST(
             $1::timestamptz[], $2::smallint[], $3::smallint[], $4::smallint[], $5::smallint[],
             $6::smallint[], $7::smallint[], $8::smallint[], $9::smallint[], $10::inet[], $11::inet[],
             $12::int[], $13::int[], $14::macaddr[], $15::text[], $16::text[], $17::text[],
             $18::text[], $19::text[], $20::text[])"#,
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
    .execute(pool)
    .await;
    match res {
        Ok(_) => {
            for r in rows.drain(..) {
                let _ = events.send(r.live); // niemand hört zu → egal
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
    events: broadcast::Sender<Arc<LiveRow>>,
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

        let ctx = FirewallCtx { wan_interfaces: ["ppp0".to_string()].into_iter().collect(), wan_ips: Default::default() };
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
        assert_eq!(evt.src_ip, Some("1.2.3.4".parse().unwrap()));
    }
}
