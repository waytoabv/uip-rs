use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

#[derive(Deserialize)]
pub struct LogsQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
    pub log_type: Option<String>,
}

fn parse_cursor(s: &str) -> Option<(DateTime<Utc>, i64)> {
    let (ts, id) = s.split_once(':')?;
    let micros: i64 = ts.parse().ok()?;
    Some((Utc.timestamp_micros(micros).single()?, id.parse().ok()?))
}

fn log_type_id(name: &str) -> Option<i16> {
    Some(match name { "firewall" => 1, "dns" => 2, "dhcp" => 3, "wifi" => 4, "system" => 5, _ => return None })
}

pub async fn get_logs(State(pool): State<PgPool>, Query(q): Query<LogsQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let cursor = q.before.as_deref().and_then(parse_cursor);
    let type_filter = q.log_type.as_deref().and_then(log_type_id);

    let rows = sqlx::query(
        r#"SELECT l.id, l.timestamp, l.log_type_id, l.direction_id, l.rule_action_id,
                  -- host() statt ::text: inet hängt sonst die /32 an, und der
                  -- SSE-Stream sendet dieselbe Adresse ohne Maske.
                  host(l.src_ip) AS src_ip, host(l.dst_ip) AS dst_ip,
                  l.src_port, l.dst_port, l.mac_address::text AS mac_address,
                  l.dns_query, l.dns_type, l.dns_answer, l.dhcp_event, l.wifi_event, l.raw_log,
                  l.geo_country, l.geo_city, l.geo_lat::float8 AS geo_lat,
                  l.geo_lon::float8 AS geo_lon, l.asn_number, l.asn_name,
                  l.rdns, l.threat_score, l.threat_categories, l.abuse_is_tor,
                  r.name AS rule_name, r.descr AS rule_desc,
                  ii.name AS iface_in, io.name AS iface_out,
                  pr.name AS protocol, dn.name AS hostname
           FROM logs l
           LEFT JOIN rules r ON r.id = l.rule_id
           LEFT JOIN interfaces ii ON ii.id = l.iface_in_id
           LEFT JOIN interfaces io ON io.id = l.iface_out_id
           LEFT JOIN protocols pr ON pr.id = l.protocol_id
           LEFT JOIN device_names dn ON dn.id = l.hostname_id
           WHERE ($1::timestamptz IS NULL OR (l.timestamp, l.id) < ($1, $2))
             AND ($3::smallint IS NULL OR l.log_type_id = $3)
           ORDER BY l.timestamp DESC, l.id DESC
           LIMIT $4"#,
    )
    .bind(cursor.map(|c| c.0)).bind(cursor.map(|c| c.1).unwrap_or(0))
    .bind(type_filter).bind(limit)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    const LOG_TYPES: [&str; 5] = ["firewall", "dns", "dhcp", "wifi", "system"];
    const DIRECTIONS: [&str; 6] = ["inbound", "outbound", "local", "inter_vlan", "vpn", "nat"];
    const ACTIONS: [&str; 3] = ["allow", "block", "redirect"];
    fn name(table: &[&'static str], id: Option<i16>) -> Option<&'static str> {
        id.and_then(|i| table.get((i as usize).checked_sub(1)?).copied())
    }

    let mut out = Vec::with_capacity(rows.len());
    let mut next_cursor = None;
    for r in &rows {
        let ts: DateTime<Utc> = r.get("timestamp");
        let id: i64 = r.get("id");
        next_cursor = Some(format!("{}:{}", ts.timestamp_micros(), id));
        out.push(json!({
            "id": id,
            "timestamp": ts.to_rfc3339(),
            "log_type": name(&LOG_TYPES, r.get("log_type_id")),
            "direction": name(&DIRECTIONS, r.get("direction_id")),
            "rule_action": name(&ACTIONS, r.get("rule_action_id")),
            "rule_name": r.get::<Option<String>, _>("rule_name"),
            "rule_desc": r.get::<Option<String>, _>("rule_desc"),
            "iface_in": r.get::<Option<String>, _>("iface_in"),
            "iface_out": r.get::<Option<String>, _>("iface_out"),
            "protocol": r.get::<Option<String>, _>("protocol"),
            "hostname": r.get::<Option<String>, _>("hostname"),
            "src_ip": r.get::<Option<String>, _>("src_ip"),
            "dst_ip": r.get::<Option<String>, _>("dst_ip"),
            "src_port": r.get::<Option<i32>, _>("src_port"),
            "dst_port": r.get::<Option<i32>, _>("dst_port"),
            "mac_address": r.get::<Option<String>, _>("mac_address"),
            "dns_query": r.get::<Option<String>, _>("dns_query"),
            "dns_type": r.get::<Option<String>, _>("dns_type"),
            "dns_answer": r.get::<Option<String>, _>("dns_answer"),
            "dhcp_event": r.get::<Option<String>, _>("dhcp_event"),
            "wifi_event": r.get::<Option<String>, _>("wifi_event"),
            "raw_log": r.get::<Option<String>, _>("raw_log"),
            "geo_country": r.get::<Option<String>, _>("geo_country"),
            "geo_city": r.get::<Option<String>, _>("geo_city"),
            "geo_lat": r.get::<Option<f64>, _>("geo_lat"),
            "geo_lon": r.get::<Option<f64>, _>("geo_lon"),
            "asn_number": r.get::<Option<i32>, _>("asn_number"),
            "asn_name": r.get::<Option<String>, _>("asn_name"),
            "rdns": r.get::<Option<String>, _>("rdns"),
            "threat_score": r.get::<Option<i32>, _>("threat_score"),
            "threat_categories": r.get::<Option<Vec<String>>, _>("threat_categories"),
            "abuse_is_tor": r.get::<Option<bool>, _>("abuse_is_tor"),
        }));
    }
    Json(json!({ "rows": out, "next_cursor": next_cursor }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn seed(pool: &sqlx::PgPool, n: i32) {
        for i in 0..n {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, src_ip, dst_port)
                 VALUES (NOW() - make_interval(secs => $1::int), 1, '1.2.3.4', 443)",
            ).bind(i).execute(pool).await.unwrap();
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn health_ok(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get("/api/health").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn logs_pagination_walks_without_gaps(pool: sqlx::PgPool) {
        seed(&pool, 5).await;
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.clone().oneshot(Request::get("/api/logs?limit=3").body(Body::empty()).unwrap()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        ).unwrap();
        assert_eq!(body["rows"].as_array().unwrap().len(), 3);
        let cursor = body["next_cursor"].as_str().unwrap().to_string();

        let res = app.oneshot(Request::get(format!("/api/logs?limit=3&before={cursor}")).body(Body::empty()).unwrap()).await.unwrap();
        let body2: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        ).unwrap();
        assert_eq!(body2["rows"].as_array().unwrap().len(), 2);
        let ids1: Vec<i64> = body["rows"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        let ids2: Vec<i64> = body2["rows"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert!(ids1.iter().all(|i| !ids2.contains(i)));
    }

    /// Der SSE-Stream sendet blanke Adressen; /api/logs muss dieselbe Schreibweise
    /// liefern, sonst zeigt die Tabelle je nach Herkunft der Zeile eine andere.
    #[sqlx::test(migrations = "../../migrations")]
    async fn addresses_come_back_without_netmask(pool: sqlx::PgPool) {
        seed(&pool, 1).await;
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get("/api/logs?limit=1").body(Body::empty()).unwrap()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        ).unwrap();
        assert_eq!(body["rows"][0]["src_ip"].as_str(), Some("1.2.3.4"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn enriched_columns_reach_the_client(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, geo_country, asn_name, rdns, threat_score)
             VALUES (NOW(), 1, '8.8.8.8', 'US', 'GOOGLE', 'dns.google.', 42)",
        ).execute(&pool).await.unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get("/api/logs?limit=1").body(Body::empty()).unwrap()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        ).unwrap();
        let row = &body["rows"][0];
        assert_eq!(row["geo_country"].as_str(), Some("US"));
        assert_eq!(row["asn_name"].as_str(), Some("GOOGLE"));
        assert_eq!(row["rdns"].as_str(), Some("dns.google."));
        assert_eq!(row["threat_score"].as_i64(), Some(42));
    }
}
