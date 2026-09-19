use crate::error::ApiError;
use crate::filters::{Joins, LogFilter};
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
    #[serde(flatten)]
    pub filter: LogFilter,
}

fn parse_cursor(s: &str) -> Option<(DateTime<Utc>, i64)> {
    let (ts, id) = s.split_once(':')?;
    let micros: i64 = ts.parse().ok()?;
    Some((Utc.timestamp_micros(micros).single()?, id.parse().ok()?))
}

pub async fn get_logs(
    State(pool): State<PgPool>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let cursor = q.before.as_deref().and_then(parse_cursor);

    let mut qb = sqlx::QueryBuilder::new(
        "SELECT l.id, l.timestamp, l.log_type_id, l.direction_id, l.rule_action_id,
                -- host() statt ::text: inet hängt sonst die /32 an, und der
                -- SSE-Stream sendet dieselbe Adresse ohne Maske.
                host(l.src_ip) AS src_ip, host(l.dst_ip) AS dst_ip,
                l.src_port, l.dst_port, l.mac_address::text AS mac_address,
                l.dns_query, l.dns_type, l.dns_answer, l.dhcp_event, l.wifi_event, l.raw_log,
                l.geo_country, l.geo_city, l.geo_lat::float8 AS geo_lat,
                l.geo_lon::float8 AS geo_lon, l.asn_number, l.asn_name,
                l.rdns, l.threat_score, l.threat_categories, l.abuse_is_tor,
                das.name AS src_device, dad.name AS dst_device,
                r.name AS rule_name, r.descr AS rule_desc,
                ii.name AS iface_in, io.name AS iface_out,
                pr.name AS protocol, dn.name AS hostname, sv.name AS service_name,
                l.severity, pg.name AS program, l.details
         FROM logs l ",
    );
    q.filter.push_joins(&mut qb, Joins::ALL);
    // Die Gerätenamen stehen seit 0008 in einer eigenen Tabelle, aus der auch
    // der Live-Strom sie bekommt (`/api/devices`) — vorher löste die
    // Zeilenliste über vier Joins auf und der Strom gar nicht.
    qb.push(
        " LEFT JOIN device_addresses das ON das.ip = l.src_ip \
          LEFT JOIN device_addresses dad ON dad.ip = l.dst_ip ",
    );
    // Not part of LogFilter::push_joins: only this endpoint's output needs
    // the service name, and export.rs/dashboard.rs etc. share push_joins.
    qb.push(" LEFT JOIN services sv ON sv.port = l.dst_port AND sv.proto = lower(pr.name) ");
    q.filter.push_where(&mut qb);
    if let Some((ts, id)) = cursor {
        qb.push(" AND (l.timestamp, l.id) < (").push_bind(ts).push(", ").push_bind(id).push(")");
    }
    qb.push(" ORDER BY l.timestamp DESC, l.id DESC LIMIT ").push_bind(limit);
    let rows = qb.build().fetch_all(&pool).await?;

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
            "src_device": r.get::<Option<String>, _>("src_device"),
            "dst_device": r.get::<Option<String>, _>("dst_device"),
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
            "severity": r.get::<Option<i16>, _>("severity"),
            "program": r.get::<Option<String>, _>("program"),
            // Die Felder strukturierter Ereignisse, so wie sie kamen — die
            // Detailzeile zeigt sie, ohne dass hier jedes einzeln benannt
            // werden muss.
            "details": r.get::<Option<serde_json::Value>, _>("details"),
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
            "service": r.get::<Option<String>, _>("service_name").as_deref().map(crate::services::display_name),
        }));
    }
    Ok(Json(json!({ "rows": out, "next_cursor": next_cursor })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get_json(app: &axum::Router, uri: &str) -> serde_json::Value {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "bei {uri}");
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap()).unwrap()
    }

    async fn seed(pool: &sqlx::PgPool, n: i32) {
        for i in 0..n {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, src_ip, dst_port)
                 VALUES (NOW() - make_interval(secs => $1::int), 1, '1.2.3.4', 443)",
            ).bind(i).execute(pool).await.unwrap();
        }
    }


    /// Der entscheidende Punkt der Auflösung beim Lesen: Der Name wirkt auch
    /// für Zeilen, die längst geschrieben waren, als der Controller noch
    /// unbekannt war. Würde beim Schreiben aufgelöst, bliebe alles Alte für
    /// immer namenlos.
    #[sqlx::test(migrations = "../../migrations")]
    async fn unifi_names_apply_to_rows_written_before_the_sync(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, dst_ip, dst_port)
             VALUES (NOW(), 1, '10.0.20.196', '1.1.1.1', 443)",
        ).execute(&pool).await.unwrap();

        // Erst danach lernt der Controller das Gerät kennen. Aufgelöst wird
        // beim Lesen, also gilt der Name auch für diese Zeile.
        sqlx::query(
            "INSERT INTO device_addresses (ip, name, kind) VALUES ('10.0.20.196', 'Wohnzimmer-TV', 'client')",
        ).execute(&pool).await.unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/logs?limit=1").await;
        assert_eq!(body["rows"][0]["src_device"].as_str(), Some("Wohnzimmer-TV"));
        assert!(body["rows"][0]["dst_device"].is_null(), "die Gegenstelle kennt der Controller nicht");
    }

    /// Schweregrad, Programm und die Felder strukturierter Ereignisse — die
    /// drei Dinge, die eine Zeile ohne Adressen und Ports überhaupt erst
    /// lesbar machen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_row_carries_its_severity_program_and_event_fields(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO programs (name) VALUES ('unifi')").execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, severity, program_id, details, wifi_event)
             VALUES (NOW(), 4, '10.10.15.98', 6, 1,
                     '{\"event\": \"WiFi Client Connected\", \"wifiName\": \"#1\", \"wiFiRssi\": \"-60\"}'::jsonb,
                     'connected')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/logs?limit=1").await;
        let row = &body["rows"][0];
        assert_eq!(row["severity"], 6);
        assert_eq!(row["program"], "unifi");
        assert_eq!(row["wifi_event"], "connected");
        assert_eq!(row["details"]["event"], "WiFi Client Connected");
        assert_eq!(row["details"]["wiFiRssi"], "-60");
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

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_endpoint_applies_filters_and_keeps_paging(pool: sqlx::PgPool) {
        for i in 0..4 {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_port)
                 VALUES (NOW() - make_interval(secs => $1::int), $2, $3, '1.2.3.4', 443)",
            )
            .bind(i)
            .bind(if i % 2 == 0 { 1i16 } else { 2i16 })   // firewall / dns
            .bind(if i % 2 == 0 { Some(2i16) } else { None }) // block / -
            .execute(&pool).await.unwrap();
        }
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);

        let body = get_json(&app, "/api/logs?log_type=firewall").await;
        assert_eq!(body["rows"].as_array().unwrap().len(), 2);
        assert!(body["rows"].as_array().unwrap().iter().all(|r| r["log_type"] == "firewall"));

        // Filter und Cursor zusammen: Seite 1 und 2 überschneiden sich nicht.
        let first = get_json(&app, "/api/logs?log_type=firewall&limit=1").await;
        let cursor = first["next_cursor"].as_str().unwrap();
        let second = get_json(&app, &format!("/api/logs?log_type=firewall&limit=1&before={cursor}")).await;
        assert_eq!(second["rows"].as_array().unwrap().len(), 1);
        assert_ne!(first["rows"][0]["id"], second["rows"][0]["id"]);

        // Suche
        let body = get_json(&app, "/api/logs?q=443").await;
        assert_eq!(body["rows"].as_array().unwrap().len(), 4);
        let body = get_json(&app, "/api/logs?q=9.9.9.9").await;
        assert!(body["rows"].as_array().unwrap().is_empty());
    }

    /// Port und Threat-Schwelle gehen durch dieselbe Extraktion wie der Rest
    /// — nur liegen sie im geflatteten Teil, wo serde jeden Wert als
    /// Zeichenkette puffert. Bis das gefangen war, antwortete der Endpunkt mit
    /// 400, und die Oberfläche zeigte eine leere Tabelle zu einem Total > 0.
    #[sqlx::test(migrations = "../../migrations")]
    async fn numeric_filters_reach_the_endpoint(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, dst_port, threat_score)
             VALUES (NOW(), 1, '1.2.3.4', 443, 80)",
        ).execute(&pool).await.unwrap();
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);

        let body = get_json(&app, "/api/logs?limit=50&port=443").await;
        assert_eq!(body["rows"].as_array().unwrap().len(), 1);
        let body = get_json(&app, "/api/logs?limit=50&port=444").await;
        assert!(body["rows"].as_array().unwrap().is_empty());
        let body = get_json(&app, "/api/logs?limit=50&threat_min=50").await;
        assert_eq!(body["rows"].as_array().unwrap().len(), 1);

        // Dieselbe Einbettung, drei weitere Endpunkte.
        for url in [
            "/api/stats/top?what=sources&limit=8&port=443",
            "/api/flows/sankey?limit=10&port=443",
            "/api/flows/host-detail?ip=1.2.3.4&port=443",
        ] {
            let res = app.clone()
                .oneshot(Request::get(url).body(Body::empty()).unwrap())
                .await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{url}");
        }
    }

    /// `service` kommt aus der IANA-Tabelle (dst_port, protocol) und trägt
    /// die eine Anzeige-Ausnahme aus dem Vorgänger: `domain` heißt `DNS`.
    /// Ein Port ohne Eintrag liefert `null`, keinen geratenen Namen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn service_name_is_resolved_by_port_and_protocol(pool: sqlx::PgPool) {
        crate::services::seed_if_empty(&pool).await.unwrap();
        sqlx::query("INSERT INTO protocols (name) VALUES ('tcp'), ('udp')").execute(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, protocol_id, src_ip, dst_port)
             VALUES (NOW(), 1, 1, '1.2.3.4', 443)",
        ).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, protocol_id, src_ip, dst_port)
             VALUES (NOW() - INTERVAL '1 second', 2, 2, '1.2.3.4', 53)",
        ).execute(&pool).await.unwrap();
        // 65535/tcp is unassigned in the IANA registry — no row should match.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, protocol_id, src_ip, dst_port)
             VALUES (NOW() - INTERVAL '2 seconds', 1, 1, '1.2.3.4', 65535)",
        ).execute(&pool).await.unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get("/api/logs?limit=3").body(Body::empty()).unwrap()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        ).unwrap();
        let rows = body["rows"].as_array().unwrap();
        assert_eq!(rows[0]["service"].as_str(), Some("HTTPS"));
        assert_eq!(rows[1]["service"].as_str(), Some("DNS"), "domain must display as DNS");
        assert!(rows[2]["service"].is_null(), "unassigned port must be null, not guessed");
    }

    /// Eine tote Datenbank muss als Fehler ankommen, nicht als leere Liste —
    /// sonst sieht ein Ausfall genauso aus wie eine ruhige Nacht.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_dead_database_is_reported_not_hidden(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/logs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
