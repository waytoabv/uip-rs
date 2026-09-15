//! Alles, was wir über eine einzelne Adresse wissen.
//!
//! Der Flow View zeigt Ströme, die Paarliste Verbindungen — diese Ansicht
//! beantwortet die nächste Frage: *was treibt dieser eine Host?* Mit wem
//! spricht er, auf welchen Diensten, seit wann, und wie viel davon wurde
//! blockiert. Das ist der Punkt, an dem man von „da stimmt etwas nicht" zu
//! „das ist es" kommt.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::error::ApiError;
use crate::filters::LogFilter;

#[derive(Deserialize)]
pub struct HostQuery {
    pub ip: String,
    #[serde(flatten)]
    pub filter: LogFilter,
}

/// Grenzt auf Zeilen ein, an denen die Adresse beteiligt ist — egal auf
/// welcher Seite.
fn push_host(qb: &mut sqlx::QueryBuilder<'_, sqlx::Postgres>, ip: &ipnetwork::IpNetwork) {
    qb.push(" AND (l.src_ip = ").push_bind(*ip).push(" OR l.dst_ip = ").push_bind(*ip).push(")");
}

pub async fn get_host_detail(
    State(pool): State<PgPool>,
    Query(q): Query<HostQuery>,
) -> Result<Json<Value>, ApiError> {
    // Eine unparsbare Adresse ist keine leere Antwort, sondern eine falsche
    // Frage — sie als „nichts gefunden" auszugeben würde sie verschleiern.
    let Ok(addr) = q.ip.parse::<std::net::IpAddr>() else {
        return Ok(Json(json!({ "error": "invalid_ip", "ip": q.ip })));
    };
    let net = ipnetwork::IpNetwork::from(addr);

    // Kennzahlen
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT count(*)::bigint AS total,
                count(*) FILTER (WHERE l.rule_action_id = 1)::bigint AS allowed,
                count(*) FILTER (WHERE l.rule_action_id = 2)::bigint AS blocked,
                count(DISTINCT CASE WHEN l.src_ip = ",
    );
    qb.push_bind(net).push(" THEN host(l.dst_ip) ELSE host(l.src_ip) END)::bigint AS peers,
                min(l.timestamp) AS first_seen,
                max(l.timestamp) AS last_seen,
                max(l.asn_name) AS asn_name,
                max(l.rdns) AS rdns,
                max(l.geo_country) AS geo_country,
                max(l.geo_city) AS geo_city,
                max(l.threat_score) AS max_threat
         FROM logs l ");
    q.filter.push_joins(&mut qb);
    q.filter.push_where(&mut qb);
    push_host(&mut qb, &net);
    let s = qb.build().fetch_one(&pool).await?;

    let summary = json!({
        "ip": q.ip,
        "total": s.get::<i64, _>("total"),
        "allowed": s.get::<i64, _>("allowed"),
        "blocked": s.get::<i64, _>("blocked"),
        "peers": s.get::<i64, _>("peers"),
        "first_seen": s.get::<Option<chrono::DateTime<chrono::Utc>>, _>("first_seen").map(|t| t.to_rfc3339()),
        "last_seen": s.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_seen").map(|t| t.to_rfc3339()),
        "asn_name": s.get::<Option<String>, _>("asn_name"),
        "rdns": s.get::<Option<String>, _>("rdns"),
        "geo_country": s.get::<Option<String>, _>("geo_country"),
        "geo_city": s.get::<Option<String>, _>("geo_city"),
        "max_threat": s.get::<Option<i32>, _>("max_threat"),
    });

    // Gegenstellen
    let mut qb = sqlx::QueryBuilder::new("SELECT CASE WHEN l.src_ip = ");
    qb.push_bind(net).push(" THEN host(l.dst_ip) ELSE host(l.src_ip) END AS peer,
            count(*)::bigint AS total,
            count(*) FILTER (WHERE l.rule_action_id = 2)::bigint AS blocked
         FROM logs l ");
    q.filter.push_joins(&mut qb);
    q.filter.push_where(&mut qb);
    push_host(&mut qb, &net);
    qb.push(" AND l.src_ip IS NOT NULL AND l.dst_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10");
    let peers: Vec<Value> = qb
        .build()
        .fetch_all(&pool)
        .await?
        .iter()
        .filter_map(|r| {
            let peer: Option<String> = r.get("peer");
            peer.map(|p| json!({ "ip": p, "total": r.get::<i64, _>("total"), "blocked": r.get::<i64, _>("blocked") }))
        })
        .collect();

    // Dienste
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT l.dst_port, lower(pr.name) AS protocol, max(sv.name) AS service,
                count(*)::bigint AS total,
                count(*) FILTER (WHERE l.rule_action_id = 2)::bigint AS blocked
         FROM logs l ",
    );
    q.filter.push_joins(&mut qb);
    qb.push(" LEFT JOIN services sv ON sv.port = l.dst_port AND sv.proto = lower(pr.name) ");
    q.filter.push_where(&mut qb);
    push_host(&mut qb, &net);
    qb.push(" AND l.dst_port IS NOT NULL GROUP BY l.dst_port, lower(pr.name) ORDER BY 4 DESC LIMIT 10");
    let services: Vec<Value> = qb
        .build()
        .fetch_all(&pool)
        .await?
        .iter()
        .map(|r| {
            json!({
                "port": r.get::<Option<i32>, _>("dst_port"),
                "protocol": r.get::<Option<String>, _>("protocol"),
                "service": r.get::<Option<String>, _>("service").as_deref().map(crate::services::display_name),
                "total": r.get::<i64, _>("total"),
                "blocked": r.get::<i64, _>("blocked"),
            })
        })
        .collect();

    // Regeln — zeigt, welche Regel diesen Host trifft
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT r.name AS rule, count(*)::bigint AS total FROM logs l ",
    );
    q.filter.push_joins(&mut qb);
    q.filter.push_where(&mut qb);
    push_host(&mut qb, &net);
    qb.push(" AND r.name IS NOT NULL GROUP BY r.name ORDER BY 2 DESC LIMIT 8");
    let rules: Vec<Value> = qb
        .build()
        .fetch_all(&pool)
        .await?
        .iter()
        .map(|r| json!({ "rule": r.get::<Option<String>, _>("rule"), "total": r.get::<i64, _>("total") }))
        .collect();

    Ok(Json(json!({ "summary": summary, "peers": peers, "services": services, "rules": rules })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get_json(app: &axum::Router, uri: &str) -> serde_json::Value {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "bei {uri}");
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap()
    }

    async fn seed(pool: &sqlx::PgPool) {
        sqlx::query("INSERT INTO protocols (name) VALUES ('tcp')").execute(pool).await.unwrap();
        sqlx::query("INSERT INTO rules (name, descr) VALUES ('WAN_IN-D', 'Block')").execute(pool).await.unwrap();
        // Der Host als Quelle, zweimal erlaubt zum selben Ziel …
        for _ in 0..2 {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, rule_id, protocol_id, src_ip, dst_ip, dst_port)
                 VALUES (NOW(), 1, 1, 1, 1, '10.0.0.5', '1.2.3.4', 443)",
            ).execute(pool).await.unwrap();
        }
        // … und einmal blockiert als Ziel, von einer anderen Gegenstelle.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, rule_id, protocol_id, src_ip, dst_ip, dst_port, threat_score)
             VALUES (NOW(), 1, 2, 1, 1, '9.9.9.9', '10.0.0.5', 22, 80)",
        ).execute(pool).await.unwrap();
        // Eine Zeile ohne den Host darf nirgends mitzählen.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, protocol_id, src_ip, dst_ip, dst_port)
             VALUES (NOW(), 1, 1, 1, '172.16.0.1', '8.8.8.8', 53)",
        ).execute(pool).await.unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn counts_both_sides_of_the_conversation(pool: sqlx::PgPool) {
        seed(&pool).await;
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let b = get_json(&app, "/api/flows/host-detail?ip=10.0.0.5").await;
        let s = &b["summary"];
        assert_eq!(s["total"].as_i64(), Some(3), "als Quelle und als Ziel");
        assert_eq!(s["allowed"].as_i64(), Some(2));
        assert_eq!(s["blocked"].as_i64(), Some(1));
        assert_eq!(s["peers"].as_i64(), Some(2), "1.2.3.4 und 9.9.9.9");
        assert_eq!(s["max_threat"].as_i64(), Some(80));
        assert!(s["first_seen"].is_string() && s["last_seen"].is_string());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn lists_peers_services_and_rules(pool: sqlx::PgPool) {
        seed(&pool).await;
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let b = get_json(&app, "/api/flows/host-detail?ip=10.0.0.5").await;

        let peers: Vec<&str> = b["peers"].as_array().unwrap().iter().map(|p| p["ip"].as_str().unwrap()).collect();
        assert!(peers.contains(&"1.2.3.4") && peers.contains(&"9.9.9.9"));
        assert!(!peers.contains(&"8.8.8.8"), "fremde Zeile zählt nicht mit");
        // Die häufigste Gegenstelle steht vorn.
        assert_eq!(b["peers"][0]["ip"].as_str(), Some("1.2.3.4"));
        assert_eq!(b["peers"][0]["total"].as_i64(), Some(2));

        let ports: Vec<i64> = b["services"].as_array().unwrap().iter().map(|s| s["port"].as_i64().unwrap()).collect();
        assert!(ports.contains(&443) && ports.contains(&22));
        assert_eq!(b["rules"][0]["rule"].as_str(), Some("WAN_IN-D"));
    }

    /// Der geteilte Filter muss auch hier greifen, sonst zeigt die Ansicht
    /// etwas anderes als die Liste, aus der man sie geöffnet hat.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_shared_filter_applies(pool: sqlx::PgPool) {
        seed(&pool).await;
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let b = get_json(&app, "/api/flows/host-detail?ip=10.0.0.5&action=block").await;
        assert_eq!(b["summary"]["total"].as_i64(), Some(1));
        assert_eq!(b["summary"]["allowed"].as_i64(), Some(0));
    }

    /// Eine unparsbare Adresse ist eine falsche Frage, keine leere Antwort —
    /// als "nichts gefunden" auszugeben würde den Tippfehler verschleiern.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_bad_address_says_so(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let b = get_json(&app, "/api/flows/host-detail?ip=nonsense").await;
        assert_eq!(b["error"].as_str(), Some("invalid_ip"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_host_is_zeros_not_null(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let b = get_json(&app, "/api/flows/host-detail?ip=10.9.9.9").await;
        assert_eq!(b["summary"]["total"].as_i64(), Some(0));
        assert_eq!(b["peers"].as_array().map(|a| a.len()), Some(0));
    }
}
