//! Threat Map. Blockierter Verkehr, gruppiert nach Ort.

use axum::extract::{Query, State};
use axum::Json;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::filters::LogFilter;

pub async fn get_points(State(_pool): State<PgPool>, Query(_f): Query<LogFilter>) -> Json<Value> {
    Json(json!({ "points": [] }))
}
