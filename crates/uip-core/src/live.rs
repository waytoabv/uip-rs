use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::IpAddr;

/// Eine gerade geschriebene Zeile, wie sie an offene Streams geht.
///
/// Die angereicherten Felder sind gefüllt, wenn die Gegenstelle schon einmal
/// nachgeschlagen wurde — und das ist der Regelfall, denn dieselben Ziele
/// kommen immer wieder. Nur eine wirklich neue Adresse erscheint zunächst
/// ohne; die trägt der Worker anschließend als `Enrichment` nach.
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

    // Aus dem Adress-Cache, sofern die Gegenstelle bekannt ist.
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_lat: Option<f64>,
    pub geo_lon: Option<f64>,
    pub asn_number: Option<i32>,
    pub asn_name: Option<String>,
    pub rdns: Option<String>,
    pub threat_score: Option<i32>,
    pub threat_categories: Option<Vec<String>>,
    pub abuse_is_tor: Option<bool>,
}

/// Was die Anreicherung über eine Adresse herausgefunden hat.
///
/// Nachgereicht, weil es die Zeile beim Schreiben noch nicht gab: Land, ASN
/// und rDNS stehen erst fest, wenn der Worker die Adresse nachgeschlagen hat.
/// Bezugspunkt ist die Adresse, nicht die Zeile — dieselbe Auskunft gilt für
/// jede Zeile, in der sie vorkommt, auch für die, die schon auf dem Schirm
/// stehen.
#[derive(Debug, Clone, Serialize)]
pub struct Enrichment {
    pub ip: IpAddr,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_lat: Option<f64>,
    pub geo_lon: Option<f64>,
    pub asn_number: Option<i32>,
    pub asn_name: Option<String>,
    pub rdns: Option<String>,
    pub threat_score: Option<i32>,
    pub threat_categories: Option<Vec<String>>,
    pub abuse_is_tor: Option<bool>,
}

/// Was über den Live-Strom geht.
#[derive(Debug, Clone)]
pub enum LiveEvent {
    /// Eine gerade geschriebene Zeile.
    Row(std::sync::Arc<LiveRow>),
    /// Ein Nachtrag zu einer Adresse, die inzwischen nachgeschlagen wurde.
    Enriched(std::sync::Arc<Enrichment>),
}
