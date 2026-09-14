pub mod export;
pub mod filters;
pub mod logs;
pub mod search;
pub mod static_files;
pub mod stream;

use axum::routing::get;
use axum::Router;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;
use uip_core::LiveRow;

#[derive(Clone)]
pub struct ApiState {
    pub pool: PgPool,
    pub events: broadcast::Sender<Arc<LiveRow>>,
}

impl axum::extract::FromRef<ApiState> for PgPool {
    fn from_ref(s: &ApiState) -> PgPool { s.pool.clone() }
}
impl axum::extract::FromRef<ApiState> for broadcast::Sender<Arc<LiveRow>> {
    fn from_ref(s: &ApiState) -> broadcast::Sender<Arc<LiveRow>> { s.events.clone() }
}

pub fn router(pool: PgPool, events: broadcast::Sender<Arc<LiveRow>>) -> Router {
    Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/logs", get(logs::get_logs))
        .route("/api/stream", get(stream::sse_stream))
        .route("/api/export", get(export::export_csv))
        .fallback(static_files::serve)
        .with_state(ApiState { pool, events })
}
