//! An honest total for the log table's footer.
//!
//! A `COUNT(*)` over the `logs` hypertable is fine when there's a WHERE
//! clause narrow enough to hit an index, but with no filters at all it's a
//! full scan of every chunk — TimescaleDB's `approximate_row_count` answers
//! that case from chunk-level statistics instead, near-instantly, at the
//! cost of being an estimate. Reported as `exact: false` so the caller can
//! render it as "~N" rather than implying precision that isn't there.
//!
//! With filters, we run a real count but cap the work: `LIMIT 100_000`
//! inside the counted subquery means the query can never scan more than
//! 100k matching rows, so a filter that matches nothing near that size
//! answers exactly (`exact: true`), and one that matches more says "at
//! least 100,000" (`exact: false`) rather than paying for the full scan.

use crate::error::ApiError;
use crate::filters::LogFilter;
use axum::extract::{Query, State};
use axum::Json;
use serde_json::{json, Value};
use sqlx::PgPool;

/// Matching rows beyond this are reported as "100,000+", not counted exactly.
const CAP: i64 = 100_000;

pub async fn get_count(
    State(pool): State<PgPool>,
    Query(filter): Query<LogFilter>,
) -> Result<Json<Value>, ApiError> {
    if filter.is_unfiltered() {
        let total: i64 = sqlx::query_scalar("SELECT approximate_row_count('logs')")
            .fetch_one(&pool)
            .await?;
        return Ok(Json(json!({ "total": total, "exact": false })));
    }

    let mut qb = sqlx::QueryBuilder::new("SELECT count(*) FROM (SELECT 1 FROM logs l ");
    filter.push_joins(&mut qb);
    filter.push_where(&mut qb);
    qb.push(" LIMIT ").push_bind(CAP).push(") t");
    let capped: i64 = qb.build_query_scalar().fetch_one(&pool).await?;

    Ok(Json(json!({ "total": capped, "exact": capped < CAP })))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get_json(app: &axum::Router, uri: &str) -> serde_json::Value {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "at {uri}");
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap()
    }

    async fn seed(pool: &sqlx::PgPool, n: i32, action_id: i16) {
        for i in 0..n {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_port)
                 VALUES (NOW() - make_interval(secs => $1::int), 1, $2, '1.2.3.4', 443)",
            ).bind(i).bind(action_id).execute(pool).await.unwrap();
        }
    }

    /// No filters: cheap estimate, honestly labeled as inexact.
    #[sqlx::test(migrations = "../../migrations")]
    async fn unfiltered_count_is_approximate(pool: sqlx::PgPool) {
        seed(&pool, 5, 1).await;
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/logs/count").await;
        assert_eq!(body["exact"], false);
        assert!(body["total"].as_i64().is_some(), "total must be a number: {body}");
    }

    /// A filter under the cap: the real count, honestly labeled exact.
    #[sqlx::test(migrations = "../../migrations")]
    async fn filtered_count_under_cap_is_exact(pool: sqlx::PgPool) {
        seed(&pool, 3, 2).await; // block
        seed(&pool, 4, 1).await; // allow
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let body = get_json(&app, "/api/logs/count?action=block").await;
        assert_eq!(body["total"].as_i64(), Some(3));
        assert_eq!(body["exact"], true);
    }

    /// A dead database must surface as a 500, not a fabricated zero.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_dead_database_is_reported_not_hidden(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app.oneshot(Request::get("/api/logs/count").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Same for the filtered path — a closed pool must not read as "0 matches".
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_dead_database_is_reported_not_hidden_when_filtered(pool: sqlx::PgPool) {
        let app = crate::router(pool.clone(), tokio::sync::broadcast::channel(8).0);
        pool.close().await;
        let res = app
            .oneshot(Request::get("/api/logs/count?action=block").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
