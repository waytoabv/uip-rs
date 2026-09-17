use crate::types::{IpFacts, Quota, ThreatOutcome, ThreatSource};
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

const API_URL: &str = "https://api.abuseipdb.com/api/v2/check";

/// Der nächste Tageswechsel in UTC — wann AbuseIPDB das Kontingent auffüllt.
fn next_utc_midnight() -> i64 {
    (Utc::now() + chrono::Duration::days(1))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("Mitternacht gibt es")
        .and_utc()
        .timestamp()
}
const MAX_AGE_DAYS: &str = "90";

pub struct AbuseIpDb {
    api_key: String,
    url: String,
    http: reqwest::Client,
    /// Verbleibendes Kontingent laut letztem Antwort-Header. -1 = unbekannt.
    remaining: AtomicI64,
    /// Das Tageskontingent insgesamt, laut `X-RateLimit-Limit`. -1 = unbekannt.
    limit: AtomicI64,
    /// Unix-Sekunden, zu denen das Kontingent wieder voll ist. 0 = unbekannt.
    reset_at: AtomicI64,
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
            limit: AtomicI64::new(-1),
            reset_at: AtomicI64::new(0),
            paused_until: AtomicI64::new(0),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.api_key.is_empty()
    }

    fn paused(&self) -> bool {
        self.paused_until.load(Ordering::Relaxed) > Utc::now().timestamp()
    }

    /// Nach dem Reset ist das Kontingent wieder *unbekannt* — nicht null.
    ///
    /// Ohne diesen Schritt blieb `remaining == 0` für immer stehen: die
    /// Abfrage, aus deren Antwort-Header sich der Zähler erneuert hätte, wurde
    /// genau wegen der Null nie gestellt. Ein einmal erschöpftes Kontingent
    /// erholte sich erst durch einen Neustart des Dienstes — auf dem Container
    /// stand es deshalb seit dem 15. September auf 0, obwohl der Reset
    /// jede Nacht um Mitternacht UTC läuft.
    fn clear_after_reset(&self) {
        let now = Utc::now().timestamp();
        // Der spätere der beiden Zeitpunkte gilt: `reset_at` ist der Reset des
        // Tageskontingents, `paused_until` die Ruhe nach einer 429. Ist der
        // Reset unbekannt (0), zählt allein die Pause.
        let until = self.reset_at.load(Ordering::Relaxed).max(self.paused_until.load(Ordering::Relaxed));
        if until != 0 && until <= now {
            self.remaining.store(-1, Ordering::Relaxed);
            self.reset_at.store(0, Ordering::Relaxed);
            self.paused_until.store(0, Ordering::Relaxed);
            tracing::info!("abuseipdb quota window passed, trying again");
        }
    }
}

#[async_trait::async_trait]
impl ThreatSource for AbuseIpDb {
    fn quota(&self) -> Option<Quota> {
        // -1 ist der Anfangswert: es gab noch keine Antwort, aus der ein
        // Kontingent hervorginge. Ohne Schlüssel fragen wir nie, also auch
        // dann nichts zu melden.
        let remaining = self.remaining.load(Ordering::Relaxed);
        if !self.enabled() || remaining < 0 {
            return None;
        }
        Some(Quota {
            remaining,
            limit: self.limit.load(Ordering::Relaxed),
            reset_at: self.reset_at.load(Ordering::Relaxed),
            paused_until: self.paused_until.load(Ordering::Relaxed),
        })
    }

    async fn lookup(&self, ip: IpAddr) -> ThreatOutcome {
        if !self.enabled() {
            return ThreatOutcome::Disabled;
        }
        self.clear_after_reset();
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

        // Alle drei Zähler aus jeder Antwort, nicht nur aus einer 429: die
        // Statusleiste soll „987 von 1000, wieder voll um 02:00" zeigen können,
        // solange noch Kontingent da ist — und nicht erst, wenn keines mehr da
        // ist.
        let header_num = |name: &str| -> Option<i64> {
            res.headers().get(name)?.to_str().ok()?.parse::<i64>().ok()
        };
        if let Some(n) = header_num("X-RateLimit-Remaining") {
            self.remaining.store(n, Ordering::Relaxed);
        }
        if let Some(n) = header_num("X-RateLimit-Limit") {
            self.limit.store(n, Ordering::Relaxed);
        }
        if let Some(n) = header_num("X-RateLimit-Reset") {
            self.reset_at.store(n, Ordering::Relaxed);
        }
        // Ein leeres Kontingent ohne Reset-Zeitpunkt wäre endgültig: die Null
        // sperrt jede weitere Abfrage, und nur eine Abfrage könnte sie
        // aufheben. Die Doku nennt das Kontingent täglich, also ist die
        // nächste Mitternacht UTC die belegbare Untergrenze.
        if self.remaining.load(Ordering::Relaxed) == 0 && self.reset_at.load(Ordering::Relaxed) == 0 {
            self.reset_at.store(next_utc_midnight(), Ordering::Relaxed);
        }

        if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // `X-RateLimit-Reset` ist ein Zeitpunkt, `Retry-After` eine Dauer;
            // die Doku nennt beide. Der Zeitpunkt zuerst, weil er den Reset des
            // Tageskontingents benennt statt nur „gleich nochmal".
            let reset = header_num("X-RateLimit-Reset")
                .or_else(|| header_num("Retry-After").map(|s| Utc::now().timestamp() + s))
                .unwrap_or_else(|| Utc::now().timestamp() + 3600);
            self.reset_at.store(reset, Ordering::Relaxed);
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
        stub_with_reset(status_code, remaining, None).await
    }

    /// Wie `stub`, setzt aber zusätzlich `X-RateLimit-Reset`.
    async fn stub_with_reset(
        status_code: u16,
        remaining: &'static str,
        reset: Option<i64>,
    ) -> (String, Arc<AtomicUsize>) {
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
                    if let Some(r) = reset {
                        headers.insert("X-RateLimit-Reset", r.to_string().parse().unwrap());
                    }
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

    /// Der Fall, der den Dienst auf dem Container stillgelegt hat: ist das
    /// Kontingent einmal auf 0, wird keine Abfrage mehr gestellt — und ohne
    /// Abfrage erneuert sich der Zähler nie. Nach dem Reset-Zeitpunkt muss er
    /// wieder auf „unbekannt" stehen und es erneut versuchen.
    #[tokio::test]
    async fn a_passed_reset_lets_it_try_again() {
        let past = Utc::now().timestamp() - 60;
        let (url, hits) = stub_with_reset(200, "0", Some(past)).await;
        let c = AbuseIpDb::with_url("key".into(), url);

        assert!(matches!(c.lookup("8.8.8.8".parse().unwrap()).await, ThreatOutcome::Found(_)));
        assert_eq!(c.quota().map(|q| q.remaining), Some(0), "Kontingent leer");

        // Der Reset liegt hinter uns — die nächste Abfrage geht wieder raus.
        assert!(matches!(c.lookup("1.1.1.1".parse().unwrap()).await, ThreatOutcome::Found(_)));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    /// Ohne Reset-Kopfzeile darf ein leeres Kontingent nicht endgültig sein:
    /// AbuseIPDB füllt es täglich um Mitternacht UTC wieder auf, und darauf
    /// wartet die Quelle dann eben.
    #[tokio::test]
    async fn an_exhausted_quota_without_a_reset_header_waits_for_midnight() {
        let (url, _) = stub(200, "0").await;
        let c = AbuseIpDb::with_url("key".into(), url);
        c.lookup("8.8.8.8".parse().unwrap()).await;

        let reset = c.quota().and_then(|q| (q.reset_at != 0).then_some(q.reset_at));
        let reset = reset.expect("ein Reset-Zeitpunkt muss gesetzt sein");
        let midnight = (Utc::now() + chrono::Duration::days(1))
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        assert_eq!(reset, midnight, "die naechste Mitternacht UTC");
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
