//! Dashboard-Aggregate. Kennzahlen, Zeitreihe und Top-Listen teilen sich den
//! `LogFilter` der Log-Ansicht: was dort gefiltert ist, gilt auch hier.
//!
//! Keine gemeinsame Sicht, aus der sich jede Kennzahl ihr Stück schneidet —
//! jede Abfrage joint nur, was sie braucht, und die unabhängigen Aggregate in
//! `get_stats` laufen nebenläufig über den Pool statt nacheinander.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::error::ApiError;
use crate::filters::LogFilter;

const LOG_TYPES: [&str; 5] = ["firewall", "dns", "dhcp", "wifi", "system"];

fn log_type_name(id: i16) -> Option<&'static str> {
    LOG_TYPES.get((id as usize).checked_sub(1)?).copied()
}

/// Same id scheme `logs.rs`/`export.rs` use for `direction_id`
/// (inbound=1, outbound=2, local=3, inter_vlan=4, vpn=5, nat=6) — duplicated
/// here rather than shared, since dashboard.rs may not touch those files.
const DIRECTIONS: [&str; 6] = ["inbound", "outbound", "local", "inter_vlan", "vpn", "nat"];

fn direction_name(id: i16) -> Option<&'static str> {
    DIRECTIONS.get((id as usize).checked_sub(1)?).copied()
}

/// `total`/`allowed`/`blocked` in einer Abfrage — sie teilen sich ohnehin
/// dieselben Joins und dasselbe WHERE, ein `COUNT(*) FILTER` je Bedingung ist
/// billiger als drei getrennte Scans.
async fn fetch_counts(pool: &PgPool, f: &LogFilter) -> Result<(i64, i64, i64), sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE l.rule_action_id = 1) AS allowed,
                COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
         FROM logs l ",
    );
    f.push_joins(&mut qb);
    f.push_where(&mut qb);
    let row = qb.build().fetch_one(pool).await?;
    Ok((row.get("total"), row.get("allowed"), row.get("blocked")))
}

async fn fetch_by_type(pool: &PgPool, f: &LogFilter) -> Result<Vec<(i16, i64)>, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT l.log_type_id, COUNT(*) AS n FROM logs l ");
    f.push_joins(&mut qb);
    f.push_where(&mut qb);
    qb.push(" GROUP BY l.log_type_id");
    let rows = qb.build().fetch_all(pool).await?;
    Ok(rows.iter().map(|r| (r.get("log_type_id"), r.get("n"))).collect())
}

/// Rows with a NULL `direction_id` are counted in the GROUP BY under their
/// own NULL group but dropped by the caller — they simply aren't tagged with
/// a direction yet, not a fake seventh key.
async fn fetch_by_direction(pool: &PgPool, f: &LogFilter) -> Result<Vec<(Option<i16>, i64)>, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT l.direction_id, COUNT(*) AS n FROM logs l ");
    f.push_joins(&mut qb);
    f.push_where(&mut qb);
    qb.push(" GROUP BY l.direction_id");
    let rows = qb.build().fetch_all(pool).await?;
    Ok(rows.iter().map(|r| (r.get("direction_id"), r.get("n"))).collect())
}

async fn fetch_unique_sources(pool: &PgPool, f: &LogFilter) -> Result<i64, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT COUNT(DISTINCT l.src_ip) AS n FROM logs l ");
    f.push_joins(&mut qb);
    f.push_where(&mut qb);
    let row = qb.build().fetch_one(pool).await?;
    Ok(row.get("n"))
}

async fn fetch_threats(pool: &PgPool, f: &LogFilter) -> Result<i64, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT COUNT(*) AS n FROM logs l ");
    f.push_joins(&mut qb);
    f.push_where(&mut qb);
    qb.push(" AND l.threat_score >= 50");
    let row = qb.build().fetch_one(pool).await?;
    Ok(row.get("n"))
}

pub async fn get_stats(
    State(pool): State<PgPool>,
    Query(f): Query<LogFilter>,
) -> Result<Json<Value>, ApiError> {
    // Fünf unabhängige Aggregate über denselben Pool (zehn Verbindungen) —
    // nacheinander ausgeführt würden sich ihre Laufzeiten addieren.
    let ((total, allowed, blocked), by_type_rows, by_direction_rows, unique_sources, threats) = tokio::try_join!(
        fetch_counts(&pool, &f),
        fetch_by_type(&pool, &f),
        fetch_by_direction(&pool, &f),
        fetch_unique_sources(&pool, &f),
        fetch_threats(&pool, &f),
    )?;

    let by_type: serde_json::Map<String, Value> = by_type_rows
        .into_iter()
        .filter_map(|(id, n)| log_type_name(id).map(|name| (name.to_string(), json!(n))))
        .collect();

    let by_direction: serde_json::Map<String, Value> = by_direction_rows
        .into_iter()
        .filter_map(|(id, n)| id.and_then(direction_name).map(|name| (name.to_string(), json!(n))))
        .collect();

    Ok(Json(json!({
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "by_type": Value::Object(by_type),
        "by_direction": Value::Object(by_direction),
        "unique_sources": unique_sources,
        "threats": threats,
    })))
}

/// Mirrors the suffix parsing of `filters::range_start` (private there, and
/// dashboard.rs may not touch filters.rs) — only the duration matters here,
/// to size the `time_bucket` width, not the absolute start.
fn range_duration(range: &str) -> Option<Duration> {
    let (value, unit) = range.split_at(range.len().checked_sub(1)?);
    let n: i64 = value.parse().ok()?;
    match unit {
        "h" => Duration::try_hours(n),
        "d" => Duration::try_days(n),
        "m" => Duration::try_minutes(n),
        _ => None,
    }
}

/// Länge des Zeitfensters, die die Bucket-Breite bestimmt. Kein `to` heißt
/// "bis jetzt"; kein `from`/`range` heißt die Standardansicht von 24 Stunden.
fn window_duration(f: &LogFilter) -> Duration {
    let to = f.to.unwrap_or_else(Utc::now);
    let from = f
        .from
        .or_else(|| f.range.as_deref().and_then(range_duration).map(|d| to - d))
        .unwrap_or(to - Duration::hours(24));
    (to - from).max(Duration::zero())
}

/// Bucket-Breite nach Fenstergröße (Tabelle in der Spec), damit eine Kurve
/// unabhängig vom gewählten Zeitraum ungefähr gleich viele Punkte hat.
fn bucket_width(window: Duration) -> &'static str {
    if window <= Duration::hours(1) {
        "1 minute"
    } else if window <= Duration::hours(6) {
        "5 minutes"
    } else if window <= Duration::hours(24) {
        "15 minutes"
    } else if window <= Duration::days(7) {
        "1 hour"
    } else {
        "6 hours"
    }
}

pub async fn get_series(
    State(pool): State<PgPool>,
    Query(f): Query<LogFilter>,
) -> Result<Json<Value>, ApiError> {
    let width = bucket_width(window_duration(&f));

    let mut qb = sqlx::QueryBuilder::new("SELECT time_bucket(");
    qb.push_bind(width);
    qb.push(
        "::interval, l.timestamp) AS bucket,
                COUNT(*) FILTER (WHERE l.rule_action_id = 1) AS allowed,
                COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked,
                COUNT(*) FILTER (WHERE l.rule_action_id = 3) AS redirect
         FROM logs l ",
    );
    f.push_joins(&mut qb);
    f.push_where(&mut qb);
    qb.push(" GROUP BY bucket ORDER BY bucket");
    let rows = qb.build().fetch_all(&pool).await?;

    let points: Vec<Value> = rows
        .iter()
        .map(|r| {
            let t: DateTime<Utc> = r.get("bucket");
            json!({
                "t": t.to_rfc3339(),
                "allowed": r.get::<i64, _>("allowed"),
                "blocked": r.get::<i64, _>("blocked"),
                "redirect": r.get::<i64, _>("redirect"),
            })
        })
        .collect();

    Ok(Json(json!({ "bucket": width, "points": points })))
}

#[derive(Deserialize)]
pub struct TopQuery {
    pub what: Option<String>,
    pub limit: Option<i64>,
    #[serde(flatten)]
    pub filter: LogFilter,
}

/// Eine Zeile jeder Top-Liste hat dieselbe Form — die Oberfläche stellt jede
/// Dimension als dieselbe Balkenliste dar, unterschiedliche Formen je
/// Dimension brächten nichts.
fn row_json(key: Option<String>, label: Option<String>, count: i64, extra: Value) -> Option<Value> {
    let key = key?;
    Some(json!({
        "key": key,
        "label": label.unwrap_or_else(|| key.clone()),
        "count": count,
        "extra": extra,
    }))
}

pub async fn get_top(
    State(pool): State<PgPool>,
    Query(q): Query<TopQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(10).clamp(1, 100);
    let f = &q.filter;

    let rows: Vec<Value> = match q.what.as_deref() {
        Some("countries") => {
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT l.geo_country AS key,
                        COUNT(*) AS n,
                        COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
                 FROM logs l ",
            );
            f.push_joins(&mut qb);
            f.push_where(&mut qb);
            qb.push(" AND l.geo_country IS NOT NULL GROUP BY l.geo_country ORDER BY n DESC LIMIT ");
            qb.push_bind(limit);
            qb.build()
                .fetch_all(&pool)
                .await?
                .into_iter()
                .filter_map(|r| {
                    let key: Option<String> = r.get("key");
                    let blocked: i64 = r.get("blocked");
                    row_json(key, None, r.get("n"), json!({ "blocked": blocked }))
                })
                .collect()
        }
        Some(what @ ("sources" | "destinations")) => {
            let col = if what == "sources" { "src_ip" } else { "dst_ip" };
            let mut qb = sqlx::QueryBuilder::new(format!(
                "SELECT host(l.{col}) AS key,
                        COUNT(*) AS n,
                        MAX(l.asn_name) AS asn
                 FROM logs l "
            ));
            f.push_joins(&mut qb);
            f.push_where(&mut qb);
            qb.push(format!(" AND l.{col} IS NOT NULL GROUP BY l.{col} ORDER BY n DESC LIMIT "));
            qb.push_bind(limit);
            qb.build()
                .fetch_all(&pool)
                .await?
                .into_iter()
                .filter_map(|r| {
                    let key: Option<String> = r.get("key");
                    let asn: Option<String> = r.get("asn");
                    row_json(key, None, r.get("n"), json!({ "asn": asn }))
                })
                .collect()
        }
        Some("ports") => {
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT l.dst_port AS port,
                        COUNT(*) AS n,
                        COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
                 FROM logs l ",
            );
            f.push_joins(&mut qb);
            f.push_where(&mut qb);
            qb.push(" AND l.dst_port IS NOT NULL GROUP BY l.dst_port ORDER BY n DESC LIMIT ");
            qb.push_bind(limit);
            qb.build()
                .fetch_all(&pool)
                .await?
                .into_iter()
                .filter_map(|r| {
                    let port: Option<i32> = r.get("port");
                    let blocked: i64 = r.get("blocked");
                    row_json(port.map(|p| p.to_string()), None, r.get("n"), json!({ "blocked": blocked }))
                })
                .collect()
        }
        Some("rules") => {
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT l.rule_id AS id, r.name AS name, r.descr AS descr, COUNT(*) AS n
                 FROM logs l ",
            );
            f.push_joins(&mut qb);
            f.push_where(&mut qb);
            qb.push(" AND l.rule_id IS NOT NULL GROUP BY l.rule_id, r.name, r.descr ORDER BY n DESC LIMIT ");
            qb.push_bind(limit);
            qb.build()
                .fetch_all(&pool)
                .await?
                .into_iter()
                .filter_map(|r| {
                    let id: Option<i16> = r.get("id");
                    let name: Option<String> = r.get("name");
                    let descr: Option<String> = r.get("descr");
                    row_json(id.map(|i| i.to_string()), name, r.get("n"), json!({ "descr": descr }))
                })
                .collect()
        }
        Some("interfaces") => {
            // Eine Zeile trägt zu ihrer Eingangs- *und* ihrer Ausgangs-
            // Schnittstelle bei, wenn beide bekannt sind — ein UNION über
            // beide Rollen, aggregiert je Name.
            // SUM(bigint) yields NUMERIC in Postgres, not bigint — cast back
            // so sqlx can decode the outer sums as i64 like everywhere else.
            let mut qb =
                sqlx::QueryBuilder::new("SELECT name, SUM(n)::bigint AS n, SUM(blocked)::bigint AS blocked FROM (");
            qb.push(
                "SELECT ii.name AS name, COUNT(*) AS n,
                        COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
                 FROM logs l ",
            );
            f.push_joins(&mut qb);
            f.push_where(&mut qb);
            qb.push(" AND ii.name IS NOT NULL GROUP BY ii.name UNION ALL ");
            qb.push(
                "SELECT io.name AS name, COUNT(*) AS n,
                        COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
                 FROM logs l ",
            );
            f.push_joins(&mut qb);
            f.push_where(&mut qb);
            qb.push(" AND io.name IS NOT NULL GROUP BY io.name");
            qb.push(") t GROUP BY name ORDER BY n DESC LIMIT ");
            qb.push_bind(limit);
            qb.build()
                .fetch_all(&pool)
                .await?
                .into_iter()
                .filter_map(|r| {
                    let name: Option<String> = r.get("name");
                    let blocked: i64 = r.get("blocked");
                    row_json(name, None, r.get("n"), json!({ "blocked": blocked }))
                })
                .collect()
        }
        Some("asns") => {
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT l.asn_number AS num, l.asn_name AS name,
                        COUNT(*) AS n,
                        COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
                 FROM logs l ",
            );
            f.push_joins(&mut qb);
            f.push_where(&mut qb);
            qb.push(" AND l.asn_number IS NOT NULL GROUP BY l.asn_number, l.asn_name ORDER BY n DESC LIMIT ");
            qb.push_bind(limit);
            qb.build()
                .fetch_all(&pool)
                .await?
                .into_iter()
                .filter_map(|r| {
                    let num: Option<i32> = r.get("num");
                    let name: Option<String> = r.get("name");
                    let blocked: i64 = r.get("blocked");
                    row_json(num.map(|n| n.to_string()), name, r.get("n"), json!({ "blocked": blocked }))
                })
                .collect()
        }
        Some("threats") => {
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT host(l.src_ip) AS key,
                        COUNT(*) AS n,
                        MAX(l.threat_score) AS max_threat,
                        MAX(l.geo_country) AS country
                 FROM logs l ",
            );
            f.push_joins(&mut qb);
            f.push_where(&mut qb);
            qb.push(" AND l.threat_score >= 50 AND l.src_ip IS NOT NULL GROUP BY l.src_ip ORDER BY n DESC LIMIT ");
            qb.push_bind(limit);
            qb.build()
                .fetch_all(&pool)
                .await?
                .into_iter()
                .filter_map(|r| {
                    let key: Option<String> = r.get("key");
                    let max_threat: Option<i32> = r.get("max_threat");
                    let country: Option<String> = r.get("country");
                    row_json(key, None, r.get("n"), json!({ "max_threat": max_threat, "country": country }))
                })
                .collect()
        }
        // Unbekannte Dimension: eine leere Liste, kein Fehler — die
        // Oberfläche zeigt dann einfach nichts an dieser Stelle.
        _ => Vec::new(),
    };

    Ok(Json(json!({ "rows": rows })))
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

    fn app(pool: sqlx::PgPool) -> axum::Router {
        crate::router(pool, tokio::sync::broadcast::channel(8).0)
    }


    /// Die Paarliste beantwortet "wer spricht mit wem" — dafür muss sie
    /// gleiche Paare wirklich zusammenfassen und erlaubt/blockiert getrennt
    /// zählen, sonst sagt eine Zeile mit beidem nichts aus.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ip_pairs_group_and_split_by_action(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO protocols (name) VALUES ('tcp')").execute(&pool).await.unwrap();
        // Dreimal dasselbe Paar: zweimal erlaubt, einmal blockiert.
        for action in [1i16, 1, 2] {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, protocol_id,
                                   src_ip, dst_ip, dst_port, threat_score)
                 VALUES (NOW(), 1, $1, 1, '10.0.0.5', '1.2.3.4', 443, 60)",
            ).bind(action).execute(&pool).await.unwrap();
        }
        // Ein anderes Paar, seltener — muss dahinter einsortiert werden.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, protocol_id,
                               src_ip, dst_ip, dst_port)
             VALUES (NOW(), 1, 1, 1, '10.0.0.9', '8.8.8.8', 53)",
        ).execute(&pool).await.unwrap();
        // Eine DNS-Zeile darf gar nicht auftauchen.
        sqlx::query("INSERT INTO logs (timestamp, log_type_id, src_ip, dst_ip, dst_port) VALUES (NOW(), 2, '10.0.0.5', '1.1.1.1', 53)")
            .execute(&pool).await.unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/stats/ip-pairs").await;
        let pairs = body["pairs"].as_array().unwrap();
        assert_eq!(pairs.len(), 2, "zwei Paare, die DNS-Zeile zählt nicht mit");

        let first = &pairs[0];
        assert_eq!(first["src_ip"].as_str(), Some("10.0.0.5"));
        assert_eq!(first["dst_ip"].as_str(), Some("1.2.3.4"));
        assert_eq!(first["dst_port"].as_i64(), Some(443));
        assert_eq!(first["total"].as_i64(), Some(3));
        assert_eq!(first["allowed"].as_i64(), Some(2));
        assert_eq!(first["blocked"].as_i64(), Some(1));
        assert_eq!(first["max_threat"].as_i64(), Some(60));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn ip_pairs_are_empty_not_null_without_data(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/stats/ip-pairs").await;
        assert_eq!(body["pairs"].as_array().map(|a| a.len()), Some(0));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn empty_database_returns_zeros_and_empty_lists(pool: sqlx::PgPool) {
        let app = app(pool);

        let stats = get_json(&app, "/api/stats").await;
        assert_eq!(stats["total"], 0);
        assert_eq!(stats["blocked"], 0);
        assert_eq!(stats["allowed"], 0);
        assert_eq!(stats["unique_sources"], 0);
        assert_eq!(stats["threats"], 0);
        assert_eq!(stats["by_type"], serde_json::json!({}));
        assert_eq!(stats["by_direction"], serde_json::json!({}));

        let series = get_json(&app, "/api/stats/series").await;
        assert!(series["points"].as_array().unwrap().is_empty());
        assert!(series["bucket"].as_str().is_some(), "kein null-Bucket");

        for what in ["countries", "sources", "destinations", "ports", "rules", "interfaces", "asns", "threats"] {
            let top = get_json(&app, &format!("/api/stats/top?what={what}")).await;
            assert!(top["rows"].as_array().unwrap().is_empty(), "bei {what}");
        }

        // Unbekannte Dimension: leere Liste statt Fehler.
        let top = get_json(&app, "/api/stats/top?what=bogus").await;
        assert!(top["rows"].as_array().unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_filter_applies_to_aggregates_too(pool: sqlx::PgPool) {
        for i in 0..3 {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_port)
                 VALUES (NOW() - make_interval(secs => $1::int), 1, 1, '10.0.0.1', 443)",
            )
            .bind(i)
            .execute(&pool)
            .await
            .unwrap();
        }
        for i in 0..2 {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_port)
                 VALUES (NOW() - make_interval(secs => $1::int), 1, 2, '10.0.0.2', 22)",
            )
            .bind(i)
            .execute(&pool)
            .await
            .unwrap();
        }
        let app = app(pool);

        let all = get_json(&app, "/api/stats").await;
        assert_eq!(all["total"], 5);
        assert_eq!(all["allowed"], 3);
        assert_eq!(all["blocked"], 2);

        // Derselbe Endpunkt, mit ?action=block gefiltert: kleinere Zahlen.
        let blocked_only = get_json(&app, "/api/stats?action=block").await;
        assert_eq!(blocked_only["total"], 2);
        assert_eq!(blocked_only["allowed"], 0);
        assert_eq!(blocked_only["blocked"], 2);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rows_without_a_country_drop_from_the_list_without_shrinking_the_total(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, geo_country) VALUES
                (NOW(), 1, '1.1.1.1', 'DE'), (NOW(), 1, '1.1.1.2', 'DE')",
        )
        .execute(&pool)
        .await
        .unwrap();
        // Drei Zeilen ohne jede Anreicherung — kein Land bekannt.
        for _ in 0..3 {
            sqlx::query("INSERT INTO logs (timestamp, log_type_id, src_ip) VALUES (NOW(), 1, '2.2.2.2')")
                .execute(&pool)
                .await
                .unwrap();
        }
        let app = app(pool);

        let stats = get_json(&app, "/api/stats").await;
        assert_eq!(stats["total"], 5, "alle fünf zählen mit, angereichert oder nicht");

        let top = get_json(&app, "/api/stats/top?what=countries").await;
        let rows = top["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "nur DE erscheint, die drei unangereicherten Zeilen fallen raus");
        assert_eq!(rows[0]["key"], "DE");
        assert_eq!(rows[0]["count"], 2);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_series_buckets_rows_into_the_expected_number_of_points(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip) VALUES
                (NOW(), 1, 1, '10.0.0.1'),
                (NOW() - INTERVAL '5 minutes', 1, 2, '10.0.0.2')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let app = app(pool);

        // Ein Fenster von einer Stunde bucketet auf die Minute — die beiden
        // fünf Minuten auseinanderliegenden Zeilen landen in zwei Buckets.
        let series = get_json(&app, "/api/stats/series?range=1h").await;
        assert_eq!(series["bucket"], "1 minute");
        let points = series["points"].as_array().unwrap();
        assert_eq!(points.len(), 2, "zwei getrennte Minuten-Buckets erwartet: {points:?}");
        let total_allowed: i64 = points.iter().map(|p| p["allowed"].as_i64().unwrap()).sum();
        let total_blocked: i64 = points.iter().map(|p| p["blocked"].as_i64().unwrap()).sum();
        assert_eq!(total_allowed, 1);
        assert_eq!(total_blocked, 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn by_direction_counts_each_direction_and_drops_null_rows(pool: sqlx::PgPool) {
        // inbound=1, outbound=2, local=3, inter_vlan=4, vpn=5, nat=6.
        for (direction_id, n) in [(1, 2), (2, 3), (3, 1), (4, 4), (5, 1), (6, 2)] {
            for _ in 0..n {
                sqlx::query(
                    "INSERT INTO logs (timestamp, log_type_id, direction_id, src_ip) VALUES (NOW(), 1, $1, '10.0.0.1')",
                )
                .bind(direction_id)
                .execute(&pool)
                .await
                .unwrap();
            }
        }
        // Zwei Zeilen ohne direction_id — nicht angereichert, dürfen unter
        // keinem Schlüssel auftauchen.
        for _ in 0..2 {
            sqlx::query("INSERT INTO logs (timestamp, log_type_id, src_ip) VALUES (NOW(), 1, '10.0.0.2')")
                .execute(&pool)
                .await
                .unwrap();
        }
        let app = app(pool);

        let stats = get_json(&app, "/api/stats").await;
        assert_eq!(stats["total"], 15, "13 mit Richtung plus 2 ohne");
        let by_direction = stats["by_direction"].as_object().unwrap();
        assert_eq!(by_direction.len(), 6, "genau die sechs bekannten Richtungen, keine NULL-Gruppe: {by_direction:?}");
        assert_eq!(by_direction["inbound"], 2);
        assert_eq!(by_direction["outbound"], 3);
        assert_eq!(by_direction["local"], 1);
        assert_eq!(by_direction["inter_vlan"], 4);
        assert_eq!(by_direction["vpn"], 1);
        assert_eq!(by_direction["nat"], 2);

        // Derselbe Endpunkt, mit ?direction=inbound gefiltert: nur der eine Schlüssel bleibt übrig.
        let filtered = get_json(&app, "/api/stats?direction=inbound").await;
        assert_eq!(filtered["by_direction"], serde_json::json!({ "inbound": 2 }));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn series_reports_redirect_counts_and_zero_for_empty_buckets(pool: sqlx::PgPool) {
        // action ids: allow=1, block=2, redirect=3.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip) VALUES
                (NOW(), 1, 3, '10.0.0.1'),
                (NOW(), 1, 3, '10.0.0.1'),
                (NOW() - INTERVAL '5 minutes', 1, 1, '10.0.0.2')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let app = app(pool);

        let series = get_json(&app, "/api/stats/series?range=1h").await;
        let points = series["points"].as_array().unwrap();
        assert_eq!(points.len(), 2, "zwei getrennte Minuten-Buckets erwartet: {points:?}");

        let total_redirect: i64 = points.iter().map(|p| p["redirect"].as_i64().unwrap()).sum();
        assert_eq!(total_redirect, 2);

        // Der Bucket ohne redirect-Zeilen liefert eine echte 0, kein fehlendes Feld.
        let bucket_without_redirect =
            points.iter().find(|p| p["redirect"].as_i64() == Some(0)).expect("ein Bucket ohne redirect erwartet");
        assert_eq!(bucket_without_redirect["allowed"], 1);
    }

    /// Eine tote Datenbank muss als Fehler ankommen, nicht als Nullen und
    /// leere Listen — sonst sieht ein Ausfall wie eine ruhige Nacht aus.
    #[sqlx::test(migrations = "../../migrations")]
    async fn stats_reports_a_dead_database_instead_of_hiding_it(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn series_reports_a_dead_database_instead_of_hiding_it(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/stats/series").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn top_reports_a_dead_database_instead_of_hiding_it(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/stats/top?what=countries").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

/// Verkehrspaare: dieselbe Quelle zum selben Ziel auf demselben Dienst,
/// zusammengefasst und nach Menge sortiert.
///
/// Der Flow View zeigt, *wohin* Verkehr fließt; diese Liste zeigt, **wer mit
/// wem** spricht — die Frage, die man beim Aufräumen von Firewall-Regeln
/// tatsächlich stellt. Erlaubt und blockiert werden getrennt gezählt, damit
/// ein Paar mit beidem als solches erkennbar bleibt.
pub async fn get_ip_pairs(
    State(pool): State<PgPool>,
    Query(f): Query<LogFilter>,
) -> Result<Json<Value>, ApiError> {
    let limit: i64 = 25;
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT host(l.src_ip) AS src_ip, host(l.dst_ip) AS dst_ip, l.dst_port,
                lower(pr.name) AS protocol,
                max(sv.name) AS service,
                count(*)::bigint AS total,
                count(*) FILTER (WHERE l.rule_action_id = 1)::bigint AS allowed,
                count(*) FILTER (WHERE l.rule_action_id = 2)::bigint AS blocked,
                max(l.threat_score) AS max_threat,
                max(l.asn_name) AS asn_name
         FROM logs l ",
    );
    f.push_joins(&mut qb);
    qb.push(" LEFT JOIN services sv ON sv.port = l.dst_port AND sv.proto = lower(pr.name) ");
    f.push_where(&mut qb);
    qb.push(
        " AND l.log_type_id = 1 AND l.src_ip IS NOT NULL AND l.dst_ip IS NOT NULL
          AND l.dst_port IS NOT NULL
          GROUP BY l.src_ip, l.dst_ip, l.dst_port, lower(pr.name)
          ORDER BY count(*) DESC LIMIT ",
    );
    qb.push_bind(limit);

    let rows = qb.build().fetch_all(&pool).await?;
    let pairs: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "src_ip": r.get::<Option<String>, _>("src_ip"),
                "dst_ip": r.get::<Option<String>, _>("dst_ip"),
                "dst_port": r.get::<Option<i32>, _>("dst_port"),
                "protocol": r.get::<Option<String>, _>("protocol"),
                "service": r.get::<Option<String>, _>("service").as_deref().map(crate::services::display_name),
                "total": r.get::<i64, _>("total"),
                "allowed": r.get::<i64, _>("allowed"),
                "blocked": r.get::<i64, _>("blocked"),
                "max_threat": r.get::<Option<i32>, _>("max_threat"),
                "asn_name": r.get::<Option<String>, _>("asn_name"),
            })
        })
        .collect();
    Ok(Json(json!({ "pairs": pairs })))
}
