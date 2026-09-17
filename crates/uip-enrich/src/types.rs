use chrono::{DateTime, Utc};
use std::net::IpAddr;

/// Alles, was wir über eine Adresse wissen können. Jede Quelle füllt ihren Teil.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IpFacts {
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_lat: Option<f64>,
    pub geo_lon: Option<f64>,
    pub asn_number: Option<i32>,
    pub asn_name: Option<String>,
    pub rdns: Option<String>,
    pub threat_score: Option<i32>,
    pub threat_categories: Option<Vec<String>>,
    pub abuse_total_reports: Option<i32>,
    pub abuse_last_reported: Option<DateTime<Utc>>,
    pub abuse_is_tor: Option<bool>,
    pub abuse_usage_type: Option<String>,
}

impl IpFacts {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Übernimmt aus `other` nur, was hier noch fehlt.
    pub fn merge(&mut self, other: IpFacts) {
        macro_rules! fill { ($($f:ident),* $(,)?) => { $(
            if self.$f.is_none() { self.$f = other.$f; }
        )* } }
        fill!(
            geo_country, geo_city, geo_lat, geo_lon, asn_number, asn_name, rdns,
            threat_score, threat_categories, abuse_total_reports,
            abuse_last_reported, abuse_is_tor, abuse_usage_type,
        );
    }
}

/// Ergebnis einer Threat-Abfrage. `QuotaExhausted` ist kein Fehler, sondern
/// der Auftrag, die Zeile später erneut anzufassen.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ThreatOutcome {
    Found(IpFacts),
    NotFound,
    QuotaExhausted,
    Disabled,
}

#[async_trait::async_trait]
pub trait GeoSource: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> IpFacts;
}

#[async_trait::async_trait]
pub trait RdnsSource: Send + Sync {
    async fn lookup(&self, ip: IpAddr) -> Option<String>;
}

/// Was von einem Tageskontingent noch übrig ist.
///
/// Getrennt von `ThreatOutcome`, weil es die Quelle beschreibt und nicht eine
/// einzelne Abfrage: die Oberfläche zeigt es an, ohne selbst zu fragen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub remaining: i64,
    /// Das Kontingent, aus dem `remaining` übrig ist. -1 = unbekannt.
    pub limit: i64,
    /// Unix-Sekunden, zu denen das Kontingent wieder voll ist. 0 = unbekannt.
    pub reset_at: i64,
    /// Unix-Sekunden, bis zu denen nach einem 429 pausiert wird. 0 = keine Pause.
    pub paused_until: i64,
}

#[async_trait::async_trait]
pub trait ThreatSource: Send + Sync {
    async fn lookup(&self, ip: IpAddr) -> ThreatOutcome;

    /// Nimmt einen neuen Schlüssel an, ohne dass der Dienst neu startet.
    ///
    /// Ein leerer Schlüssel schaltet die Quelle ab. Standardmäßig folgenlos:
    /// Quellen ohne Zugangsdaten haben nichts zu wechseln.
    fn set_api_key(&self, _key: &str) {}

    /// Der Stand des Kontingents, falls die Quelle eines führt.
    ///
    /// `None` heißt „unbekannt" — vor der ersten Antwort, oder weil die Quelle
    /// gar keins kennt. Ausdrücklich nicht dasselbe wie `Some(0)`.
    fn quota(&self) -> Option<Quota> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_fills_only_empty_fields() {
        let mut facts = IpFacts { geo_country: Some("DE".into()), ..Default::default() };
        facts.merge(IpFacts {
            geo_country: Some("US".into()),
            rdns: Some("host.example.com".into()),
            ..Default::default()
        });
        // Was schon da ist, bleibt: die erste Quelle gewinnt.
        assert_eq!(facts.geo_country.as_deref(), Some("DE"));
        assert_eq!(facts.rdns.as_deref(), Some("host.example.com"));
    }

    #[test]
    fn empty_facts_carry_nothing() {
        assert!(IpFacts::default().is_empty());
        assert!(!IpFacts { rdns: Some("x".into()), ..Default::default() }.is_empty());
    }
}
