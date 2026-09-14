pub mod logs;
pub mod search;
pub mod static_files;
pub mod stream;

use axum::routing::get;
use axum::Router;
use sqlx::PgPool;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct ApiState {
    pub pool: PgPool,
    pub events: broadcast::Sender<String>,
}

impl axum::extract::FromRef<ApiState> for PgPool {
    fn from_ref(s: &ApiState) -> PgPool { s.pool.clone() }
}
impl axum::extract::FromRef<ApiState> for broadcast::Sender<String> {
    fn from_ref(s: &ApiState) -> broadcast::Sender<String> { s.events.clone() }
}

pub fn router(pool: PgPool, events: broadcast::Sender<String>) -> Router {
    Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/logs", get(logs::get_logs))
        .route("/api/stream", get(stream::sse_stream))
        .fallback(static_files::serve)
        .with_state(ApiState { pool, events })
}
