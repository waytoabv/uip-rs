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
use crate::filters::{Joins, LogFilter};

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

/// Alles, was sich zählen lässt, in einem einzigen Durchgang.
///
/// Vorher waren das fünf Abfragen: Summe, nach Typ, nach Richtung, nach
/// Bedrohung, und die Zahl der Quellen. Jede davon las dieselben Millionen
/// Zeilen noch einmal. Nebenläufig ausgeführt sah das kurz aus, war aber
/// fünfmal dieselbe Arbeit auf einem Gerät mit zwei Kernen — gemessen an einer
/// Kopie des Bestands: 1,1 Sekunden Rechenzeit für etwas, das in 0,35 zu haben
/// ist.
///
/// `GROUPING SETS` liefert dieselben drei Ebenen aus einem Scan: die Summe
/// (die leere Menge), die Aufteilung nach Typ und die nach Richtung.
/// `GROUPING()` sagt, welche Zeile welche Ebene ist — ohne das wäre ein
/// NULL-Schlüssel nicht von „über alle Werte hinweg" zu unterscheiden.
struct Totals {
    total: i64,
    allowed: i64,
    blocked: i64,
    threats: i64,
    by_type: Vec<(i16, i64)>,
    /// Zeilen ohne Richtung stehen unter ihrem eigenen NULL-Schlüssel und
    /// werden vom Aufrufer verworfen — sie sind nicht getaggt, keine siebte
    /// Richtung.
    by_direction: Vec<(Option<i16>, i64)>,
}

async fn fetch_totals(pool: &PgPool, f: &LogFilter) -> Result<Totals, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT GROUPING(l.log_type_id) AS g_type, GROUPING(l.direction_id) AS g_dir,
                l.log_type_id, l.direction_id,
                COUNT(*) AS n,
                COUNT(*) FILTER (WHERE l.rule_action_id = 1) AS allowed,
                COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked,
                COUNT(*) FILTER (WHERE l.threat_score >= 50) AS threats
         FROM logs l ",
    );
    f.push_joins(&mut qb, Joins::NONE);
    f.push_where(&mut qb);
    qb.push(" GROUP BY GROUPING SETS ((), (l.log_type_id), (l.direction_id))");

    let mut out = Totals {
        total: 0,
        allowed: 0,
        blocked: 0,
        threats: 0,
        by_type: Vec::new(),
        by_direction: Vec::new(),
    };
    for r in qb.build().fetch_all(pool).await? {
        let n: i64 = r.get("n");
        match (r.get::<i32, _>("g_type"), r.get::<i32, _>("g_dir")) {
            (1, 1) => {
                out.total = n;
                out.allowed = r.get("allowed");
                out.blocked = r.get("blocked");
                out.threats = r.get("threats");
            }
            (0, _) => out.by_type.push((r.get("log_type_id"), n)),
            (_, 0) => out.by_direction.push((r.get("direction_id"), n)),
            _ => {}
        }
    }
    Ok(out)
}

async fn fetch_unique_sources(pool: &PgPool, f: &LogFilter) -> Result<i64, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT COUNT(DISTINCT l.src_ip) AS n FROM logs l ");
    f.push_joins(&mut qb, Joins::NONE);
    f.push_where(&mut qb);
    let row = qb.build().fetch_one(pool).await?;
    Ok(row.get("n"))
}

pub async fn get_stats(
    State(pool): State<PgPool>,
    Query(f): Query<LogFilter>,
) -> Result<Json<Value>, ApiError> {
    // Zwei Abfragen: alles Zählbare in einem Durchgang, und die Zahl der
    // verschiedenen Quellen. Die bleibt für sich — ein `COUNT(DISTINCT)` neben
    // den Gruppierungsebenen zwingt Postgres, die Adressen für jede Ebene
    // erneut zu sortieren, und kostet dann mehr als der eigene Scan.
    let (totals, unique_sources) =
        tokio::try_join!(fetch_totals(&pool, &f), fetch_unique_sources(&pool, &f))?;

    let by_type: serde_json::Map<String, Value> = totals
        .by_type
        .into_iter()
        .filter_map(|(id, n)| log_type_name(id).map(|name| (name.to_string(), json!(n))))
        .collect();

    let by_direction: serde_json::Map<String, Value> = totals
        .by_direction
        .into_iter()
        .filter_map(|(id, n)| id.and_then(direction_name).map(|name| (name.to_string(), json!(n))))
        .collect();

    Ok(Json(json!({
        "total": totals.total,
        "blocked": totals.blocked,
        "allowed": totals.allowed,
        "by_type": Value::Object(by_type),
        "by_direction": Value::Object(by_direction),
        "unique_sources": unique_sources,
        "threats": totals.threats,
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
    f.push_joins(&mut qb, Joins::NONE);
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

/// Der Betreibername zu einer Handvoll Adressen.
///
/// Aus `ip_enrichment`, nicht aus den Log-Zeilen: dort steht er ohnehin, und
/// ein Primärschlüsselzugriff für acht Adressen kostet nichts gegen ein
/// Aggregat über Millionen Zeilen. Der Unterschied ist, dass hier der heutige
/// Name steht und nicht der von damals — bei einem Betreiberwechsel also der
/// neue. Für eine Zeile „wer steckt dahinter" ist das die nützlichere Antwort.
async fn asn_names(
    pool: &PgPool,
    ips: &[String],
) -> Result<std::collections::HashMap<String, String>, sqlx::Error> {
    if ips.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT host(ip), asn_name FROM ip_enrichment WHERE ip = ANY($1::text[]::inet[])",
    )
    .bind(ips)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().filter_map(|(ip, name)| name.map(|n| (ip, n))).collect())
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
            f.push_joins(&mut qb, Joins::NONE);
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
            // Ohne `MAX(l.asn_name)`: den Namen des Betreibers über Millionen
            // Zeilen mitzuaggregieren kostet vierzig Prozent der Abfrage
            // (gemessen 894 → 549 ms bei den Zielen), und gebraucht wird er
            // für die acht Zeilen, die übrig bleiben. Die bekommen ihn danach.
            let mut qb = sqlx::QueryBuilder::new(format!(
                "SELECT host(l.{col}) AS key, COUNT(*) AS n FROM logs l "
            ));
            f.push_joins(&mut qb, Joins::NONE);
            f.push_where(&mut qb);
            qb.push(format!(" AND l.{col} IS NOT NULL GROUP BY l.{col} ORDER BY n DESC LIMIT "));
            qb.push_bind(limit);
            let rows = qb.build().fetch_all(&pool).await?;

            let ips: Vec<String> =
                rows.iter().filter_map(|r| r.get::<Option<String>, _>("key")).collect();
            let asn_of = asn_names(&pool, &ips).await?;
            rows.into_iter()
                .filter_map(|r| {
                    let key: Option<String> = r.get("key");
                    let asn = key.as_ref().and_then(|ip| asn_of.get(ip).cloned());
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
            f.push_joins(&mut qb, Joins::NONE);
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
            f.push_joins(&mut qb, Joins::NONE.rules());
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
            // Eine Zeile zählt für ihre Eingangs- *und* ihre Ausgangs-
            // Schnittstelle. Zwei Gruppierungsebenen holen beides aus einem
            // Durchgang statt aus zwei Abfragen mit `UNION ALL`.
            //
            // Gezählt wird über die Kennung, nicht über den Namen: der Name
            // steht in einer anderen Tabelle, und ihn schon beim Zählen
            // mitzuschleppen hieße, für jede der Millionen Zeilen zu
            // verbinden. Die Handvoll Zeilen, die übrig bleibt, bekommt ihn
            // danach.
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT n.name AS name, t.n, t.blocked FROM (
                   SELECT id, SUM(n)::bigint AS n, SUM(blocked)::bigint AS blocked FROM (
                     SELECT CASE WHEN GROUPING(l.iface_in_id) = 0 THEN l.iface_in_id
                                 ELSE l.iface_out_id END AS id,
                            COUNT(*) AS n,
                            COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
                     FROM logs l ",
            );
            f.push_joins(&mut qb, Joins::NONE);
            f.push_where(&mut qb);
            qb.push(
                " GROUP BY GROUPING SETS ((l.iface_in_id), (l.iface_out_id))
                   ) s WHERE id IS NOT NULL GROUP BY id ORDER BY n DESC LIMIT ",
            );
            qb.push_bind(limit);
            qb.push(" ) t LEFT JOIN interfaces n ON n.id = t.id ORDER BY t.n DESC");
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
            // Gruppiert wird nach der Nummer, nicht nach Nummer *und* Name:
            // der Name ist eine Eigenschaft der Nummer, und ihn in den
            // Gruppenschlüssel zu nehmen kostet bei Millionen Zeilen ein
            // Drittel der Abfrage (gemessen 617 → 375 ms). Nebenbei behoben:
            // schrieb derselbe Betreiber seinen Namen einmal anders, stand er
            // bisher zweimal in der Liste.
            let mut qb = sqlx::QueryBuilder::new(
                "SELECT l.asn_number AS num, MAX(l.asn_name) AS name,
                        COUNT(*) AS n,
                        COUNT(*) FILTER (WHERE l.rule_action_id = 2) AS blocked
                 FROM logs l ",
            );
            f.push_joins(&mut qb, Joins::NONE);
            f.push_where(&mut qb);
            qb.push(" AND l.asn_number IS NOT NULL GROUP BY l.asn_number ORDER BY n DESC LIMIT ");
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
            f.push_joins(&mut qb, Joins::NONE);
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


    /// Jeder Aggregat-Endpunkt mit jedem Filter, der einen Join verlangt.
    ///
    /// Die Joins stehen nicht mehr pauschal in jeder Abfrage, sondern nur dort,
    /// wo Filter oder Ausgabe sie brauchen (`filters::Joins`). Eine vergessene
    /// Tabelle ist dann kein falsches Ergebnis, sondern ein Syntaxfehler in
    /// SQL — aber eben erst zur Laufzeit. Also einmal alles durchrufen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn every_aggregate_survives_a_filter_that_needs_a_join(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO protocols (name) VALUES ('tcp')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO interfaces (name) VALUES ('br0'), ('eth1')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO rules (name, descr) VALUES ('WAN_IN-D', 'Block Bad')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO device_names (name) VALUES ('laptop')").execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, direction_id, rule_action_id, rule_id,
                 protocol_id, iface_in_id, iface_out_id, hostname_id, src_ip, dst_ip,
                 dst_port, geo_country, asn_number, asn_name, threat_score)
             VALUES (NOW(), 1, 1, 2, 1, 1, 1, 2, 1, '1.2.3.4', '10.0.0.5', 443, 'DE', 64512, 'AS Example', 80)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = app(pool);
        // Ein Filter je Nachschlagetabelle: Schnittstelle, Protokoll, und die
        // Volltextsuche, die in allen vieren gleichzeitig sucht.
        let filters = ["iface=br0", "proto=tcp", "q=Block", "q=rule%3ABlock", "q=host%3Alaptop"];
        let endpoints = [
            "/api/stats",
            "/api/stats/series",
            "/api/stats/ip-pairs",
            "/api/logs",
            "/api/logs/count",
            "/api/export",
            "/api/threats/points",
            "/api/flows/sankey",
            "/api/flows/zones",
        ];
        for filter in filters {
            for endpoint in endpoints {
                let uri = format!("{endpoint}?{filter}");
                let res = app
                    .clone()
                    .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(res.status(), StatusCode::OK, "bei {uri}");
            }
            for what in [
                "countries", "sources", "destinations", "ports", "rules", "interfaces", "asns",
                "threats",
            ] {
                let uri = format!("/api/stats/top?what={what}&{filter}");
                get_json(&app, &uri).await;
            }
        }
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

    /// Der Betreibername steht in den Top-Listen der Adressen als Unterzeile.
    /// Er kommt nicht mehr aus einem Aggregat über alle Zeilen, sondern für
    /// die acht übrigen Adressen aus `ip_enrichment` — dasselbe Ergebnis, ein
    /// Drittel weniger Arbeit.
    #[sqlx::test(migrations = "../../migrations")]
    async fn address_lists_name_the_operator(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO ip_enrichment (ip, asn_number, asn_name) VALUES ('8.8.8.8', 15169, 'Google LLC')",
        )
        .execute(&pool)
        .await
        .unwrap();
        for _ in 0..3 {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_ip,
                     asn_number, asn_name)
                 VALUES (NOW(), 1, 1, '10.0.0.5', '8.8.8.8', 15169, 'Google LLC')",
            )
            .execute(&pool)
            .await
            .unwrap();
        }
        // Dieselbe Nummer, anders geschrieben: früher ergab das zwei Zeilen in
        // der Betreiberliste, weil der Name im Gruppenschlüssel stand.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_ip,
                 asn_number, asn_name)
             VALUES (NOW(), 1, 2, '10.0.0.5', '8.8.4.4', 15169, 'GOOGLE')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = app(pool);
        let dests = get_json(&app, "/api/stats/top?what=destinations").await;
        assert_eq!(dests["rows"][0]["key"], "8.8.8.8");
        assert_eq!(dests["rows"][0]["extra"]["asn"], "Google LLC");
        // Eine Adresse ohne Eintrag in der Anreicherung bleibt ohne Unterzeile,
        // statt dass die Zeile ganz fehlt.
        assert_eq!(dests["rows"][1]["key"], "8.8.4.4");
        assert!(dests["rows"][1]["extra"]["asn"].is_null());

        let asns = get_json(&app, "/api/stats/top?what=asns").await;
        assert_eq!(asns["rows"].as_array().map(|a| a.len()), Some(1), "eine Nummer, eine Zeile");
        assert_eq!(asns["rows"][0]["key"], "15169");
        assert_eq!(asns["rows"][0]["count"], 4);
        assert_eq!(asns["rows"][0]["extra"]["blocked"], 1);
    }

    /// Eine Zeile zählt für beide Schnittstellen, die sie nennt. Die Liste
    /// entsteht jetzt aus einem Durchgang mit zwei Gruppierungsebenen statt
    /// aus zwei Abfragen — dieselbe Summe muss dabei herauskommen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn interfaces_count_both_ends_of_a_row(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO interfaces (name) VALUES ('br15'), ('eth1')")
            .execute(&pool)
            .await
            .unwrap();
        // Zwei Zeilen br15 → eth1, eine davon blockiert; eine Zeile nur mit
        // Eingang.
        for action in [1i16, 2] {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, iface_in_id, iface_out_id, src_ip)
                 VALUES (NOW(), 1, $1, 1, 2, '10.0.0.5')",
            )
            .bind(action)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, iface_in_id, src_ip)
             VALUES (NOW(), 1, 1, 1, '10.0.0.6')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let body = get_json(&app(pool), "/api/stats/top?what=interfaces").await;
        let rows = body["rows"].as_array().unwrap();
        let find = |name: &str| {
            rows.iter()
                .find(|r| r["key"] == name)
                .unwrap_or_else(|| panic!("{name} fehlt in {body}"))
                .clone()
        };
        assert_eq!(find("br15")["count"], 3, "dreimal als Eingang");
        assert_eq!(find("eth1")["count"], 2, "zweimal als Ausgang");
        assert_eq!(find("br15")["extra"]["blocked"], 1);
        assert_eq!(find("eth1")["extra"]["blocked"], 1);
    }

    /// Die Summe, die Aufteilung nach Typ und die nach Richtung kommen aus
    /// einer einzigen Abfrage mit drei Gruppierungsebenen. Verwechselt man die
    /// Ebenen, zählt jede Zahl etwas anderes, als ihr Name sagt — und es fiele
    /// niemandem auf, weil alle plausibel aussehen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn stats_split_the_same_rows_three_ways(pool: sqlx::PgPool) {
        // Vier Firewall-Zeilen (drei erlaubt eingehend, eine blockiert
        // ausgehend, eine davon mit hohem Score) und eine DNS-Zeile ohne
        // Richtung und ohne Aktion.
        for (action, direction, score) in
            [(1i16, 1i16, None), (1, 1, None), (1, 1, Some(90)), (2, 2, Some(95))]
        {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, direction_id, rule_action_id,
                     src_ip, dst_ip, threat_score)
                 VALUES (NOW(), 1, $1, $2, '1.2.3.4', '10.0.0.5', $3)",
            )
            .bind(direction)
            .bind(action)
            .bind(score)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, dns_query)
             VALUES (NOW(), 2, '10.0.0.9', 'example.com')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let stats = get_json(&app(pool), "/api/stats").await;
        assert_eq!(stats["total"], 5, "alle Zeilen, auch die ohne Aktion");
        assert_eq!(stats["allowed"], 3);
        assert_eq!(stats["blocked"], 1);
        assert_eq!(stats["threats"], 2, "ab Score 50");
        assert_eq!(stats["unique_sources"], 2);
        assert_eq!(stats["by_type"]["firewall"], 4);
        assert_eq!(stats["by_type"]["dns"], 1);
        assert_eq!(stats["by_direction"]["inbound"], 3);
        assert_eq!(stats["by_direction"]["outbound"], 1);
        assert!(
            stats["by_direction"].as_object().map(|m| m.len()) == Some(2),
            "die Zeile ohne Richtung bekommt keine eigene: {}",
            stats["by_direction"]
        );
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
    f.push_joins(&mut qb, Joins::NONE.protocols());
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
