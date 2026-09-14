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

use crate::filters::LogFilter;

const LOG_TYPES: [&str; 5] = ["firewall", "dns", "dhcp", "wifi", "system"];

fn log_type_name(id: i16) -> Option<&'static str> {
    LOG_TYPES.get((id as usize).checked_sub(1)?).copied()
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

pub async fn get_stats(State(pool): State<PgPool>, Query(f): Query<LogFilter>) -> Json<Value> {
    // Vier unabhängige Aggregate über denselben Pool (zehn Verbindungen) —
    // nacheinander ausgeführt würden sich ihre Laufzeiten addieren.
    let joined = tokio::try_join!(
        fetch_counts(&pool, &f),
        fetch_by_type(&pool, &f),
        fetch_unique_sources(&pool, &f),
        fetch_threats(&pool, &f),
    );
    let ((total, allowed, blocked), by_type_rows, unique_sources, threats) =
        joined.unwrap_or_default();

    let by_type: serde_json::Map<String, Value> = by_type_rows
        .into_iter()
        .filter_map(|(id, n)| log_type_name(id).map(|name| (name.to_string(), json!(n))))
        .collect();

    Json(json!({
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "by_type": Value::Object(by_type),
        "unique_sources": unique_sources,
        "threats": threats,
    }))
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

pub async fn get_series(State(pool): State<PgPool>, Query(f): Query<LogFilter>) -> Json<Value> {
    let width = bucket_width(window_duration(&f));

    let mut qb = sqlx::QueryBuilder::new("SELECT time_bucket(");
    qb.push_bind(width);
    qb.push(
        "::interval, l.timestamp) AS bucket,
                COUNT(*) FILTER (WHERE l.rule_action_id = 1) AS allowed,
                COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
         FROM logs l ",
    );
    f.push_joins(&mut qb);
    f.push_where(&mut qb);
    qb.push(" GROUP BY bucket ORDER BY bucket");
    let rows = qb.build().fetch_all(&pool).await.unwrap_or_default();

    let points: Vec<Value> = rows
        .iter()
        .map(|r| {
            let t: DateTime<Utc> = r.get("bucket");
            json!({
                "t": t.to_rfc3339(),
                "allowed": r.get::<i64, _>("allowed"),
                "blocked": r.get::<i64, _>("blocked"),
            })
        })
        .collect();

    Json(json!({ "bucket": width, "points": points }))
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

pub async fn get_top(State(pool): State<PgPool>, Query(q): Query<TopQuery>) -> Json<Value> {
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
                .await
                .unwrap_or_default()
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
                .await
                .unwrap_or_default()
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
                .await
                .unwrap_or_default()
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
                .await
                .unwrap_or_default()
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
                .await
                .unwrap_or_default()
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
                .await
                .unwrap_or_default()
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
                .await
                .unwrap_or_default()
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

    Json(json!({ "rows": rows }))
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
}
