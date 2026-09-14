//! Dashboard-Aggregate. Kennzahlen, Zeitreihe und Top-Listen teilen sich den
//! `LogFilter` der Log-Ansicht: was dort gefiltert ist, gilt auch hier.

use axum::extract::{Query, State};
use axum::Json;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::filters::LogFilter;

pub async fn get_stats(State(_pool): State<PgPool>, Query(_f): Query<LogFilter>) -> Json<Value> {
    Json(json!({ "total": 0, "blocked": 0, "allowed": 0, "by_type": {}, "unique_sources": 0, "threats": 0 }))
}

pub async fn get_series(State(_pool): State<PgPool>, Query(_f): Query<LogFilter>) -> Json<Value> {
    Json(json!({ "bucket": "15 minutes", "points": [] }))
}

pub async fn get_top(State(_pool): State<PgPool>, Query(_f): Query<LogFilter>) -> Json<Value> {
    Json(json!({ "rows": [] }))
}
