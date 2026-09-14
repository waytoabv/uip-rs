use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::IpAddr;

/// Eine gerade geschriebene Zeile, wie sie an offene Streams geht.
/// Angereicherte Felder fehlen absichtlich: zu diesem Zeitpunkt gibt es sie
/// noch nicht.
#[derive(Debug, Clone, Serialize)]
pub struct LiveRow {
    pub timestamp: DateTime<Utc>,
    pub log_type: &'static str,
    pub direction: Option<&'static str>,
    pub rule_action: Option<&'static str>,
    pub rule_name: Option<String>,
    pub protocol: Option<String>,
    pub iface_in: Option<String>,
    pub iface_out: Option<String>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub dns_query: Option<String>,
    pub dns_type: Option<String>,
    pub dns_answer: Option<String>,
    pub dhcp_event: Option<String>,
    pub wifi_event: Option<String>,
    pub raw_log: Option<String>,
}
