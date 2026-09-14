use crate::types::{IpFacts, ThreatOutcome, ThreatSource};
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

const API_URL: &str = "https://api.abuseipdb.com/api/v2/check";
const MAX_AGE_DAYS: &str = "90";

pub struct AbuseIpDb {
    api_key: String,
    url: String,
    http: reqwest::Client,
    /// Verbleibendes Kontingent laut letztem Antwort-Header. -1 = unbekannt.
    remaining: AtomicI64,
    /// Unix-Sekunden, bis zu denen nach einem 429 pausiert wird.
    paused_until: AtomicI64,
}

impl AbuseIpDb {
    pub fn new(api_key: String) -> Self {
        Self::with_url(api_key, API_URL.to_string())
    }

    pub fn with_url(api_key: String, url: String) -> Self {
        Self {
            api_key,
            url,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            remaining: AtomicI64::new(-1),
            paused_until: AtomicI64::new(0),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.api_key.is_empty()
    }

    fn paused(&self) -> bool {
        self.paused_until.load(Ordering::Relaxed) > Utc::now().timestamp()
    }
}

#[async_trait::async_trait]
impl ThreatSource for AbuseIpDb {
    async fn lookup(&self, ip: IpAddr) -> ThreatOutcome {
        if !self.enabled() {
            return ThreatOutcome::Disabled;
        }
        // Kontingent aufgebraucht oder Pause läuft noch: gar nicht erst fragen.
        if self.paused() || self.remaining.load(Ordering::Relaxed) == 0 {
            return ThreatOutcome::QuotaExhausted;
        }

        let res = self
            .http
            .get(&self.url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[
                ("ipAddress", ip.to_string().as_str()),
                ("maxAgeInDays", MAX_AGE_DAYS),
                ("verbose", ""),
            ])
            .send()
            .await;

        let res = match res {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, %ip, "abuseipdb request failed");
                return ThreatOutcome::NotFound;
            }
        };

        if let Some(v) = res.headers().get("X-RateLimit-Remaining") {
            if let Some(n) = v.to_str().ok().and_then(|s| s.parse::<i64>().ok()) {
                self.remaining.store(n, Ordering::Relaxed);
            }
        }

        if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // Reset-Zeitpunkt, sonst eine Stunde Ruhe.
            let reset = res
                .headers()
                .get("X-RateLimit-Reset")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or_else(|| Utc::now().timestamp() + 3600);
            self.paused_until.store(reset, Ordering::Relaxed);
            tracing::warn!(reset, "abuseipdb quota exhausted, pausing");
            return ThreatOutcome::QuotaExhausted;
        }

        if !res.status().is_success() {
            tracing::warn!(status = %res.status(), %ip, "abuseipdb returned an error");
            return ThreatOutcome::NotFound;
        }

        let body: serde_json::Value = match res.json().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "abuseipdb sent something unreadable");
                return ThreatOutcome::NotFound;
            }
        };
        let Some(data) = body.get("data") else {
            return ThreatOutcome::NotFound;
        };

        // Kategorien stecken in den einzelnen Meldungen; uns interessiert die
        // Menge der vorkommenden, nicht ihre Häufigkeit.
        let mut cats: Vec<String> = data
            .get("reports")
            .and_then(|r| r.as_array())
            .map(|reports| {
                let mut seen: Vec<String> = reports
                    .iter()
                    .filter_map(|r| r.get("categories")?.as_array())
                    .flatten()
                    .filter_map(|c| c.as_i64())
                    .map(|c| c.to_string())
                    .collect();
                seen.sort();
                seen.dedup();
                seen
            })
            .unwrap_or_default();
        cats.shrink_to_fit();

        ThreatOutcome::Found(IpFacts {
            threat_score: data.get("abuseConfidenceScore").and_then(|v| v.as_i64()).map(|n| n as i32),
            threat_categories: (!cats.is_empty()).then_some(cats),
            abuse_total_reports: data.get("totalReports").and_then(|v| v.as_i64()).map(|n| n as i32),
            abuse_is_tor: data.get("isTor").and_then(|v| v.as_bool()),
            abuse_usage_type: data.get("usageType").and_then(|v| v.as_str()).map(str::to_string),
            abuse_last_reported: data
                .get("lastReportedAt")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
            ..Default::default()
        })
    }
}

/// Quelle, die nie etwas findet — für den Betrieb ohne API-Key.
pub struct NoThreatSource;

#[async_trait::async_trait]
impl ThreatSource for NoThreatSource {
    async fn lookup(&self, _ip: IpAddr) -> ThreatOutcome {
        ThreatOutcome::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::http::HeaderMap;
    use axum::routing::get;
    use axum::Json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Startet einen Stub und liefert seine Basis-URL plus einen Zähler.
    async fn stub(status_code: u16, remaining: &'static str) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = axum::Router::new().route(
            "/check",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let h = h.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    let mut headers = HeaderMap::new();
                    headers.insert("X-RateLimit-Remaining", remaining.parse().unwrap());
                    headers.insert("X-RateLimit-Limit", "1000".parse().unwrap());
                    let body = serde_json::json!({"data": {
                        "ipAddress": q.get("ipAddress").cloned().unwrap_or_default(),
                        "abuseConfidenceScore": 42,
                        "totalReports": 7,
                        "isTor": false,
                        "usageType": "Data Center/Web Hosting/Transit",
                        "lastReportedAt": "2026-09-01T10:00:00+00:00",
                        "reports": [{"categories": [18, 22]}]
                    }});
                    (axum::http::StatusCode::from_u16(status_code).unwrap(), headers, Json(body))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/check"), hits)
    }

    #[tokio::test]
    async fn reads_a_score_and_its_details() {
        let (url, _) = stub(200, "900").await;
        let c = AbuseIpDb::with_url("key".into(), url);
        match c.lookup("8.8.8.8".parse().unwrap()).await {
            ThreatOutcome::Found(f) => {
                assert_eq!(f.threat_score, Some(42));
                assert_eq!(f.abuse_total_reports, Some(7));
                assert_eq!(f.abuse_is_tor, Some(false));
                assert!(f.abuse_last_reported.is_some());
                assert_eq!(f.threat_categories.as_deref(), Some(&["18".to_string(), "22".to_string()][..]));
            }
            other => panic!("erwartet Found, war {other:?}"),
        }
    }

    #[tokio::test]
    async fn without_a_key_the_source_is_simply_off() {
        let c = AbuseIpDb::with_url(String::new(), "http://127.0.0.1:1/check".into());
        assert_eq!(c.lookup("8.8.8.8".parse().unwrap()).await, ThreatOutcome::Disabled);
    }

    #[tokio::test]
    async fn a_429_pauses_all_further_lookups() {
        let (url, hits) = stub(429, "0").await;
        let c = AbuseIpDb::with_url("key".into(), url);
        assert_eq!(c.lookup("8.8.8.8".parse().unwrap()).await, ThreatOutcome::QuotaExhausted);
        // Der zweite Aufruf darf den Server gar nicht mehr behelligen.
        assert_eq!(c.lookup("1.1.1.1".parse().unwrap()).await, ThreatOutcome::QuotaExhausted);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_exhausted_remaining_header_stops_the_next_call() {
        let (url, hits) = stub(200, "0").await;
        let c = AbuseIpDb::with_url("key".into(), url);
        assert!(matches!(c.lookup("8.8.8.8".parse().unwrap()).await, ThreatOutcome::Found(_)));
        assert_eq!(c.lookup("1.1.1.1".parse().unwrap()).await, ThreatOutcome::QuotaExhausted);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
