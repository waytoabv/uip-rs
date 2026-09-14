//! Threat Map. Blockierter Verkehr, gruppiert nach Ort (auf eine
//! Nachkommastelle gerundete Koordinaten, ~11 km) — feiner ist bei
//! GeoIP-Genauigkeit Fiktion.

use axum::extract::{Query, State};
use axum::Json;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::error::ApiError;
use crate::filters::LogFilter;

pub async fn get_points(
    State(pool): State<PgPool>,
    Query(f): Query<LogFilter>,
) -> Result<Json<Value>, ApiError> {
    let mut points_qb = sqlx::QueryBuilder::new(
        "SELECT ROUND(l.geo_lat, 1)::float8 AS lat,
                ROUND(l.geo_lon, 1)::float8 AS lon,
                MAX(l.geo_country) AS country,
                MAX(l.geo_city) AS city,
                COUNT(*) AS count,
                MAX(l.threat_score) AS max_threat,
                host(MAX(l.src_ip)) AS sample_ip
         FROM logs l ",
    );
    f.push_joins(&mut points_qb);
    f.push_where(&mut points_qb);
    points_qb.push(
        " AND l.log_type_id = 1 AND l.rule_action_id = 2 \
          AND l.geo_lat IS NOT NULL AND l.geo_lon IS NOT NULL \
          GROUP BY ROUND(l.geo_lat, 1), ROUND(l.geo_lon, 1) \
          ORDER BY count DESC \
          LIMIT 2000",
    );

    // Zweite, kleine Abfrage: wie viel blockierter Firewall-Verkehr insgesamt
    // in diesem Filter steckt, unabhängig von Koordinaten. Ohne sie kann die
    // Oberfläche eine leere Karte nicht erklären — "kein blockierter
    // Verkehr" und "blockierter Verkehr, aber noch nicht angereichert" sehen
    // sonst identisch aus.
    let mut total_qb = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM logs l ");
    f.push_joins(&mut total_qb);
    f.push_where(&mut total_qb);
    total_qb.push(" AND l.log_type_id = 1 AND l.rule_action_id = 2");

    let (rows, blocked_total) = tokio::try_join!(
        points_qb.build().fetch_all(&pool),
        total_qb.build_query_scalar::<i64>().fetch_one(&pool),
    )?;

    let points: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "lat": r.get::<f64, _>("lat"),
                "lon": r.get::<f64, _>("lon"),
                "country": r.get::<Option<String>, _>("country"),
                "city": r.get::<Option<String>, _>("city"),
                "count": r.get::<i64, _>("count"),
                "max_threat": r.get::<Option<i32>, _>("max_threat"),
                "sample_ip": r.get::<Option<String>, _>("sample_ip"),
            })
        })
        .collect();

    Ok(Json(json!({ "points": points, "blocked_total": blocked_total })))
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

    /// Fügt eine firewall-Zeile mit fester Aktion, Koordinaten und Threat-Score ein.
    #[allow(clippy::too_many_arguments)]
    async fn insert(
        pool: &sqlx::PgPool,
        action: i16,
        log_type: i16,
        src_ip: &str,
        lat: Option<f64>,
        lon: Option<f64>,
        country: Option<&str>,
        threat_score: Option<i32>,
    ) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip,
                 geo_lat, geo_lon, geo_country, threat_score)
             VALUES (NOW(), $1, $2, $3::inet, $4, $5, $6, $7)",
        )
        .bind(log_type)
        .bind(action)
        .bind(src_ip)
        .bind(lat)
        .bind(lon)
        .bind(country)
        .bind(threat_score)
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn empty_database_returns_empty_points(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/threats/points").await;
        assert!(body["points"].is_array(), "points muss ein Array sein, nicht null: {body}");
        assert_eq!(body["points"].as_array().unwrap().len(), 0);
        assert_eq!(body["blocked_total"], 0);
    }

    /// 39.90/116.40 und 39.91/116.44 runden beide auf 39.9/116.4 — ein Punkt, count=2.
    #[sqlx::test(migrations = "../../migrations")]
    async fn nearby_points_collapse_into_one(pool: sqlx::PgPool) {
        insert(&pool, 2, 1, "1.1.1.1", Some(39.90), Some(116.40), Some("CN"), Some(10)).await;
        insert(&pool, 2, 1, "2.2.2.2", Some(39.91), Some(116.44), Some("CN"), Some(20)).await;

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/threats/points").await;
        let points = body["points"].as_array().unwrap();
        assert_eq!(points.len(), 1, "beide Zeilen müssen zu einem Punkt verschmelzen: {points:?}");
        assert_eq!(points[0]["lat"].as_f64(), Some(39.9));
        assert_eq!(points[0]["lon"].as_f64(), Some(116.4));
        assert_eq!(points[0]["count"], 2);
    }

    /// Zeilen ohne Koordinaten dürfen nie als (0, 0) auftauchen — sie fehlen einfach.
    /// `blocked_total` zählt sie trotzdem: das ist der Unterschied zwischen "keine
    /// Treffer" und "Treffer, aber noch nicht angereichert".
    #[sqlx::test(migrations = "../../migrations")]
    async fn rows_without_coordinates_are_absent(pool: sqlx::PgPool) {
        insert(&pool, 2, 1, "3.3.3.3", None, None, None, None).await;
        insert(&pool, 2, 1, "4.4.4.4", Some(10.0), None, Some("XX"), None).await;

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/threats/points").await;
        assert_eq!(body["points"].as_array().unwrap().len(), 0);
        assert_eq!(body["blocked_total"], 2, "beide Zeilen sind blockierter Firewall-Verkehr, nur ohne Ort");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn allowed_traffic_and_non_firewall_rows_are_excluded(pool: sqlx::PgPool) {
        // erlaubt, mit Koordinaten
        insert(&pool, 1, 1, "5.5.5.5", Some(48.1), Some(11.5), Some("DE"), None).await;
        // dns, "blockiert" ergibt für dns keinen Sinn, aber selbst mit Aktion 2 zählt nur firewall
        insert(&pool, 2, 2, "6.6.6.6", Some(48.1), Some(11.5), Some("DE"), None).await;

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/threats/points").await;
        assert_eq!(body["points"].as_array().unwrap().len(), 0);
    }

    /// max_threat ist das Maximum am Ort, nicht der erste oder der Durchschnitt.
    #[sqlx::test(migrations = "../../migrations")]
    async fn max_threat_reports_the_highest_score_at_a_location(pool: sqlx::PgPool) {
        insert(&pool, 2, 1, "7.7.7.7", Some(1.0), Some(1.0), Some("XX"), Some(10)).await;
        insert(&pool, 2, 1, "8.8.8.8", Some(1.0), Some(1.0), Some("XX"), Some(90)).await;
        insert(&pool, 2, 1, "9.9.9.9", Some(1.0), Some(1.0), Some("XX"), Some(30)).await;

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/threats/points").await;
        let points = body["points"].as_array().unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0]["max_threat"], 90, "nicht der erste (10) und nicht der Durchschnitt (~43)");
        assert_eq!(points[0]["count"], 3);
    }

    /// Punkte kommen absteigend nach Häufigkeit.
    #[sqlx::test(migrations = "../../migrations")]
    async fn points_are_ordered_by_count_descending(pool: sqlx::PgPool) {
        for ip in ["1.0.0.1", "1.0.0.2", "1.0.0.3"] {
            insert(&pool, 2, 1, ip, Some(10.0), Some(10.0), Some("XX"), None).await;
        }
        insert(&pool, 2, 1, "2.0.0.1", Some(20.0), Some(20.0), Some("YY"), None).await;

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/threats/points").await;
        let points = body["points"].as_array().unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0]["count"], 3, "der belebtere Ort steht vorne: {points:?}");
        assert_eq!(points[1]["count"], 1);
    }

    /// Der geteilte Filter wirkt auch hier: ein Länderfilter schneidet die Menge.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_shared_filter_narrows_the_points(pool: sqlx::PgPool) {
        insert(&pool, 2, 1, "1.2.3.4", Some(39.9), Some(116.4), Some("CN"), None).await;
        insert(&pool, 2, 1, "5.6.7.8", Some(52.5), Some(13.4), Some("DE"), None).await;

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/threats/points?country=DE").await;
        let points = body["points"].as_array().unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0]["country"], "DE");
    }

    /// Eine tote Datenbank muss als Fehler ankommen, nicht als leere Karte.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_dead_database_is_reported_not_hidden(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/threats/points").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
