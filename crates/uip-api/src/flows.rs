//! Flow View. Verkehr als Fluss (Quelle → Dienst → Ziel) und als Zonenmatrix.

use axum::extract::{Query, State};
use axum::Json;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::filters::LogFilter;

pub async fn get_sankey(State(_pool): State<PgPool>, Query(_f): Query<LogFilter>) -> Json<Value> {
    Json(json!({ "nodes": [], "links": [] }))
}

pub async fn get_zones(State(_pool): State<PgPool>, Query(_f): Query<LogFilter>) -> Json<Value> {
    Json(json!({ "zones": [], "cells": [] }))
}
