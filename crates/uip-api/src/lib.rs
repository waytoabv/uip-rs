pub mod cache;
pub mod count;
pub mod dashboard;
pub mod devices;
pub mod error;
pub mod export;
pub mod flows;
pub mod hostdetail;
pub mod filters;
pub mod firewall_rules;
pub mod logs;
pub mod networks;
pub mod search;
pub mod settings;
pub mod status;
pub mod services;
pub mod static_files;
pub mod threats;
pub mod stream;

use axum::routing::get;
use axum::Router;
use sqlx::PgPool;
use tokio::sync::broadcast;
use uip_core::LiveEvent;

#[derive(Clone)]
pub struct ApiState {
    pub pool: PgPool,
    pub events: broadcast::Sender<LiveEvent>,
    /// Die zuletzt gegebenen Antworten der Aggregat-Endpunkte (siehe `cache`).
    pub cache: std::sync::Arc<cache::ResponseCache>,
}

impl axum::extract::FromRef<ApiState> for PgPool {
    fn from_ref(s: &ApiState) -> PgPool { s.pool.clone() }
}
impl axum::extract::FromRef<ApiState> for broadcast::Sender<LiveEvent> {
    fn from_ref(s: &ApiState) -> broadcast::Sender<LiveEvent> { s.events.clone() }
}
impl axum::extract::FromRef<ApiState> for std::sync::Arc<cache::ResponseCache> {
    fn from_ref(s: &ApiState) -> std::sync::Arc<cache::ResponseCache> { s.cache.clone() }
}

pub fn router(pool: PgPool, events: broadcast::Sender<LiveEvent>) -> Router {
    let state = ApiState { pool, events, cache: cache::ResponseCache::new() };
    Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/status", get(status::get_status))
        .route("/api/devices", get(devices::get_devices))
        .route("/api/networks", get(networks::get_networks))
        .route("/api/networks/names", axum::routing::put(networks::put_names))
        .route("/api/firewall-rules", get(firewall_rules::get_firewall_rules))
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
        .layer(axum::middleware::from_fn_with_state(state.clone(), cache::layer))
        .with_state(state)
}
