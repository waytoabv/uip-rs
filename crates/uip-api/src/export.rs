use crate::error::ApiError;
use crate::filters::{Joins, LogFilter};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, Response, StatusCode};
use sqlx::{PgPool, Row};

const LOG_TYPES: [&str; 5] = ["firewall", "dns", "dhcp", "wifi", "system"];
const DIRECTIONS: [&str; 6] = ["inbound", "outbound", "local", "inter_vlan", "vpn", "nat"];
const ACTIONS: [&str; 3] = ["allow", "block", "redirect"];

fn name(table: &[&'static str], id: Option<i16>) -> Option<&'static str> {
    id.and_then(|i| table.get((i as usize).checked_sub(1)?).copied())
}

/// Baut dieselbe WHERE-Klausel wie `/api/logs` (Filter und Suche), aber ohne
/// Cursor und mit einem festen Limit statt Seiten.
///
/// Die CSV entsteht komplett im Speicher: bei 100 000 Zeilen à ~200 Byte sind
/// das rund 20 MB — auf einem 2-GB-LXC vertretbar, aber unschön. Sobald das
/// Limit einmal steigt, ist `Body::from_stream` mit einem `sqlx`-Cursor
/// (`fetch` statt `fetch_all`) der nächste Schritt, keine vorzeitige
/// Optimierung heute.
pub async fn export_csv(
    State(pool): State<PgPool>,
    Query(filter): Query<LogFilter>,
) -> Result<Response<Body>, ApiError> {
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT l.timestamp, l.log_type_id, l.direction_id, l.rule_action_id,
                r.name AS rule_name, ii.name AS iface_in, io.name AS iface_out,
                pr.name AS protocol,
                host(l.src_ip) AS src_ip, l.src_port, host(l.dst_ip) AS dst_ip, l.dst_port,
                l.mac_address::text AS mac_address, dn.name AS hostname,
                l.geo_country, l.geo_city, l.asn_name, l.rdns, l.threat_score,
                l.dns_query, l.dhcp_event, l.wifi_event
         FROM logs l ",
    );
    filter.push_joins(&mut qb, Joins::ALL);
    filter.push_where(&mut qb);
    qb.push(" ORDER BY l.timestamp DESC LIMIT 100000");
    let rows = qb.build().fetch_all(&pool).await?;

    let mut w = csv::Writer::from_writer(Vec::new());
    let _ = w.write_record([
        "timestamp", "log_type", "direction", "action", "rule_name",
        "iface_in", "iface_out", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
        "mac_address", "hostname", "geo_country", "geo_city", "asn_name", "rdns",
        "threat_score", "dns_query", "dhcp_event", "wifi_event",
    ]);
    for r in &rows {
        let ts: chrono::DateTime<chrono::Utc> = r.get("timestamp");
        let opt_str = |v: Option<String>| v.unwrap_or_default();
        let opt_i32 = |v: Option<i32>| v.map(|n| n.to_string()).unwrap_or_default();
        let _ = w.write_record([
            ts.to_rfc3339(),
            name(&LOG_TYPES, r.get("log_type_id")).unwrap_or_default().to_string(),
            name(&DIRECTIONS, r.get("direction_id")).unwrap_or_default().to_string(),
            name(&ACTIONS, r.get("rule_action_id")).unwrap_or_default().to_string(),
            opt_str(r.get("rule_name")),
            opt_str(r.get("iface_in")),
            opt_str(r.get("iface_out")),
            opt_str(r.get("protocol")),
            opt_str(r.get("src_ip")),
            opt_i32(r.get("src_port")),
            opt_str(r.get("dst_ip")),
            opt_i32(r.get("dst_port")),
            opt_str(r.get("mac_address")),
            opt_str(r.get("hostname")),
            opt_str(r.get("geo_country")),
            opt_str(r.get("geo_city")),
            opt_str(r.get("asn_name")),
            opt_str(r.get("rdns")),
            opt_i32(r.get("threat_score")),
            opt_str(r.get("dns_query")),
            opt_str(r.get("dhcp_event")),
            opt_str(r.get("wifi_event")),
        ]);
    }
    let _ = w.flush();
    let body = w.into_inner().unwrap_or_default();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(header::CONTENT_DISPOSITION, "attachment; filename=\"uip-logs.csv\"")
        .body(Body::from(body))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[sqlx::test(migrations = "../../migrations")]
    async fn exports_filtered_rows_as_csv(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO rules (name, descr) VALUES ('A,B', 'mit, Komma')").execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, rule_id, src_ip, dst_port, geo_country)
             VALUES (NOW(), 1, 2, 1, '1.2.3.4', 443, 'DE')",
        ).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO logs (timestamp, log_type_id, src_ip) VALUES (NOW(), 2, '10.0.0.9')")
            .execute(&pool).await.unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get("/api/export?log_type=firewall").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["content-type"], "text/csv; charset=utf-8");
        assert!(res.headers()["content-disposition"].to_str().unwrap().contains("attachment"));

        let body = String::from_utf8(
            axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec()
        ).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[0].starts_with("timestamp,log_type,"), "Kopfzeile fehlt: {:?}", lines[0]);
        assert_eq!(lines.len(), 2, "nur die Firewall-Zeile, plus Kopf");
        assert!(lines[1].contains("1.2.3.4"));
        // Ein Komma im Regelnamen darf die Spalten nicht verschieben.
        assert!(lines[1].contains("\"A,B\""), "Regelname nicht maskiert: {:?}", lines[1]);
        assert!(!lines[1].contains("10.0.0.9"));
    }

    /// Eine tote Datenbank muss als Fehler ankommen, nicht als leere CSV.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_dead_database_is_reported_not_hidden(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/export").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
