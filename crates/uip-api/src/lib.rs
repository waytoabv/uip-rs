pub mod count;
pub mod dashboard;
pub mod error;
pub mod export;
pub mod flows;
pub mod hostdetail;
pub mod filters;
pub mod logs;
pub mod search;
pub mod settings;
pub mod services;
pub mod static_files;
pub mod threats;
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
        .route("/api/settings", get(settings::get_settings).put(settings::put_settings))
        .route("/api/settings/pihole/test", get(settings::test_pihole))
        .route("/api/settings/unifi/test", get(settings::test_unifi))
        .route("/api/logs", get(logs::get_logs))
        .route("/api/logs/count", get(count::get_count))
        .route("/api/stream", get(stream::sse_stream))
        .route("/api/export", get(export::export_csv))
        .route("/api/stats", get(dashboard::get_stats))
        .route("/api/stats/series", get(dashboard::get_series))
        .route("/api/stats/top", get(dashboard::get_top))
        .route("/api/stats/ip-pairs", get(dashboard::get_ip_pairs))
        .route("/api/threats/points", get(threats::get_points))
        .route("/api/flows/sankey", get(flows::get_sankey))
        .route("/api/flows/zones", get(flows::get_zones))
        .route("/api/flows/host-detail", get(hostdetail::get_host_detail))
        .fallback(static_files::serve)
        .with_state(ApiState { pool, events })
}
