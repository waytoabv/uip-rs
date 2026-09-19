//! Pi-hole als zweite Quelle für DNS-Abfragen.
//!
//! Der Gateway-Syslog kennt nur, was über ihn läuft; wer seinen DNS über
//! Pi-hole schickt, sieht dort die Auflösungen. Die abgeholten Abfragen gehen
//! in denselben Writer-Kanal wie die Syslog-Zeilen — für alles dahinter sind
//! es gewöhnliche DNS-Zeilen, und Filter, Suche und Anreicherung greifen
//! ohne Sonderfall.

use chrono::{DateTime, TimeZone, Utc};
use std::sync::Mutex;
use std::time::Duration;
use sqlx::PgPool;
use tokio::sync::mpsc;
use uip_core::types::{LogType, RuleAction};
use uip_core::ParsedLog;

const POLL_EVERY: Duration = Duration::from_secs(30);
/// Solange Pi-hole aus oder unvollständig eingerichtet ist, wird nur
/// nachgesehen, ob sich daran etwas geändert hat.
const UNCONFIGURED_POLL: Duration = Duration::from_secs(60);
/// Wie viele Abfragen ein Abruf höchstens holt.
const FETCH_LIMIT: u32 = 5000;

pub struct Pihole {
    base: String,
    password: String,
    http: reqwest::Client,
    /// Session-Id und ihre Gültigkeit. Pi-hole v6 verlangt sie in jedem Aufruf.
    session: Mutex<Option<String>>,
}

#[derive(Debug, PartialEq)]
pub enum TestOutcome {
    Ok { version: Option<String> },
    BadCredentials,
    Unreachable(String),
}

impl Pihole {
    pub fn new(base: String, password: String) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            password,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                // Selbstsignierte Zertifikate sind bei einem Pi-hole im
                // eigenen Netz die Regel, nicht die Ausnahme.
                .danger_accept_invalid_certs(true)
                .build()
                .expect("reqwest client"),
            session: Mutex::new(None),
        }
    }

    /// Holt eine Session-Id. Pi-hole gibt sie unter `session.sid` zurück.
    async fn authenticate(&self) -> Result<String, String> {
        let res = self
            .http
            .post(format!("{}/api/auth", self.base))
            .json(&serde_json::json!({ "password": self.password }))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err("unauthorized".into());
        }
        let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        let sid = body
            .get("session")
            .and_then(|s| s.get("sid"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "no sid in response".to_string())?
            .to_string();
        *self.session.lock().unwrap() = Some(sid.clone());
        Ok(sid)
    }

    fn cached_sid(&self) -> Option<String> {
        self.session.lock().unwrap().clone()
    }

    /// Prüft Erreichbarkeit und Passwort — für die Einstellungen.
    pub async fn test(&self) -> TestOutcome {
        match self.authenticate().await {
            Ok(_) => {
                let version = self
                    .http
                    .get(format!("{}/api/info/version", self.base))
                    .send()
                    .await
                    .ok()
                    .and_then(|r| r.error_for_status().ok());
                let version = match version {
                    Some(r) => r
                        .json::<serde_json::Value>()
                        .await
                        .ok()
                        .and_then(|v| v.pointer("/version/core/local/version").and_then(|s| s.as_str().map(str::to_string))),
                    None => None,
                };
                TestOutcome::Ok { version }
            }
            Err(e) if e == "unauthorized" => TestOutcome::BadCredentials,
            Err(e) => TestOutcome::Unreachable(e),
        }
    }

    /// Holt Abfragen ab einem Zeitpunkt. Gibt die Zeilen und die größte
    /// gesehene Id zurück, damit der nächste Abruf dort weitermacht.
    pub async fn fetch(&self, since: i64, after_id: i64) -> Result<(Vec<ParsedLog>, i64), String> {
        let sid = match self.cached_sid() {
            Some(s) => s,
            None => self.authenticate().await?,
        };
        let url = format!("{}/api/queries", self.base);
        let mut res = self
            .http
            .get(&url)
            .header("sid", &sid)
            .query(&[("from", since.to_string()), ("length", FETCH_LIMIT.to_string())])
            .send()
            .await
            .map_err(|e| e.to_string())?;

        // Eine abgelaufene Session ist der Normalfall, kein Fehler.
        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            let sid = self.authenticate().await?;
            res = self
                .http
                .get(&url)
                .header("sid", &sid)
                .query(&[("from", since.to_string()), ("length", FETCH_LIMIT.to_string())])
                .send()
                .await
                .map_err(|e| e.to_string())?;
        }

        let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        let queries = body.get("queries").and_then(|q| q.as_array()).cloned().unwrap_or_default();

        let mut highest = after_id;
        let mut out = Vec::new();
        for q in queries {
            let id = q.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
            // Nur, was wir noch nicht hatten — der Zeitfilter ist grob.
            if id <= after_id {
                continue;
            }
            highest = highest.max(id);
            if let Some(row) = to_log(&q) {
                out.push(row);
            }
        }
        Ok((out, highest))
    }
}

/// Ob dieser Status eine Blockade ist.
///
/// Pi-hole kennt neunzehn Zustände, neun davon heißen „geblockt": aus der
/// Gravity-Liste, über einen regulären Ausdruck, über die Sperrliste, jeweils
/// auch bei der Prüfung von CNAME-Ketten, dazu die Fälle, in denen der
/// Upstream selbst sperrt. Der Rest ist durchgelassen, aus dem Zwischenspeicher
/// beantwortet oder weitergeleitet.
fn blocked(status: &str) -> Option<RuleAction> {
    let s = status.to_ascii_uppercase();
    if s.is_empty() || s == "UNKNOWN" {
        return None;
    }
    let is_block = s.starts_with("GRAVITY")
        || s.starts_with("DENYLIST")
        || s.starts_with("BLACKLIST")
        || s.starts_with("REGEX")
        || s.starts_with("EXTERNAL_BLOCKED")
        || s == "SPECIAL_DOMAIN"
        || s == "DBBUSY";
    Some(if is_block { RuleAction::Block } else { RuleAction::Allow })
}

/// Eine Pi-hole-Abfrage als DNS-Logzeile.
///
/// Die Antwort ist die Antwort, nicht der Status: früher stand in der Spalte
/// „Antwort" das Wort `GRAVITY`, und wohin die Abfrage ging oder was
/// zurückkam, ging verloren. Jetzt trägt die Zeile eine Aktion wie jede
/// Firewall-Zeile — geblockt ist geblockt —, das Ziel ist der befragte
/// Upstream, und der Grund steht bei den Details.
pub fn to_log(q: &serde_json::Value) -> Option<ParsedLog> {
    let domain = q.get("domain").and_then(|v| v.as_str())?;
    if domain.is_empty() {
        return None;
    }
    let ts = q
        .get("time")
        .and_then(|v| v.as_f64())
        .and_then(|secs| Utc.timestamp_opt(secs as i64, 0).single())
        .unwrap_or_else(Utc::now);

    // Der Client kommt je nach Version als Objekt oder als blanke Adresse.
    let client = q.get("client");
    let src_ip = client
        .and_then(|c| c.get("ip").and_then(|v| v.as_str()).or_else(|| c.as_str()))
        .and_then(|s| s.parse().ok());
    let hostname = client
        .and_then(|c| c.get("name"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let status = q.get("status").and_then(|v| v.as_str()).unwrap_or_default().to_uppercase();

    // Der Upstream steht als „10.10.10.1#53" — die Adresse davor ist das
    // Ziel, die Zahl dahinter der Port.
    let upstream = q.get("upstream").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let (dst_ip, dst_port) = match upstream {
        Some(u) => {
            let (host, port) = u.split_once('#').unwrap_or((u, "53"));
            (host.parse().ok(), port.parse().ok())
        }
        None => (None, None),
    };

    let reply = q.get("reply");
    let reply_type = reply.and_then(|r| r.get("type")).and_then(|v| v.as_str());

    let mut details = serde_json::Map::new();
    details.insert("status".into(), serde_json::Value::String(status.clone()));
    for (key, from) in [("reply_type", "type"), ("reply_time", "time")] {
        if let Some(v) = reply.and_then(|r| r.get(from)) {
            details.insert(key.into(), v.clone());
        }
    }
    for key in ["upstream", "dnssec", "cname", "ttl"] {
        if let Some(v) = q.get(key).filter(|v| !v.is_null()) {
            details.insert(key.into(), v.clone());
        }
    }

    Some(ParsedLog {
        timestamp: Some(ts),
        log_type: Some(LogType::Dns),
        dns_query: Some(domain.to_string()),
        dns_type: q.get("type").and_then(|v| v.as_str()).map(|s| s.to_uppercase()),
        // Was wirklich zurückkam. Bei einer Blockade ist das die Art der
        // Antwort (NXDOMAIN, NODATA, IP der Sperrseite) — die sagt mehr als
        // die Wiederholung des Status.
        dns_answer: reply_type.map(|s| s.to_uppercase()).or_else(|| Some(status.clone())),
        rule_action: blocked(&status),
        src_ip,
        dst_ip,
        dst_port,
        hostname,
        details: Some(serde_json::Value::Object(details)),
        raw_log: String::new(),
        ..Default::default()
    })
}

/// Dauerläufer: alle 30 Sekunden abholen und in den Writer schieben.
/// Hält fest, wie der letzte Abruf ausging.
///
/// Zugleich Herzschlag: der Zeitstempel wird bei jedem Durchlauf neu gesetzt,
/// auch wenn nichts zu holen war. Bleibt er stehen, läuft die Schleife nicht
/// mehr — und genau das soll der Punkt in der Kopfzeile zeigen können.
async fn record(pool: &PgPool, ok: bool, error: Option<String>) {
    uip_core::settings::put_config(
        pool,
        "pihole_status",
        serde_json::json!({ "ok": ok, "at": Utc::now().to_rfc3339(), "error": error }),
    )
    .await;
}

/// Adresse und Passwort, wie sie gerade eingestellt sind — oder nichts,
/// solange Pi-hole abgeschaltet oder unvollständig eingerichtet ist.
async fn config(pool: &PgPool) -> Option<(String, String)> {
    let enabled = uip_core::settings::get_config(pool, "pihole_enabled")
        .await
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    let text = |v: Option<serde_json::Value>| {
        v.and_then(|v| v.as_str().map(str::to_string)).filter(|s| !s.is_empty())
    };
    let url = text(uip_core::settings::get_config(pool, "pihole_url").await)?;
    let password = text(uip_core::settings::get_config(pool, "pihole_password").await)
        .unwrap_or_default();
    Some((url, password))
}

pub async fn run_pihole(tx: mpsc::Sender<ParsedLog>, pool: PgPool) {
    // Beim ersten Lauf nur die letzten fünf Minuten — sonst spült ein frisch
    // eingerichtetes Pi-hole seine gesamte Historie in die Datenbank.
    let mut since = Utc::now().timestamp() - 300;
    let mut cursor: i64 = 0;
    // Der aktive Client samt der Einstellung, aus der er gebaut wurde. Nicht
    // bei jedem Durchlauf neu: der Client hält eine Sitzung, und die jedes Mal
    // wegzuwerfen hieße, sich alle dreißig Sekunden neu anzumelden.
    let mut current: Option<((String, String), Pihole)> = None;

    loop {
        let Some(cfg) = config(&pool).await else {
            current = None;
            tokio::time::sleep(UNCONFIGURED_POLL).await;
            continue;
        };
        if current.as_ref().map(|(c, _)| c) != Some(&cfg) {
            tracing::info!(url = %cfg.0, "pihole settings changed");
            current = Some((cfg.clone(), Pihole::new(cfg.0.clone(), cfg.1.clone())));
            // Die Kennungen gehören der alten Instanz; an einem anderen
            // Pi-hole bedeuten sie etwas anderes.
            cursor = 0;
            since = Utc::now().timestamp() - 300;
        }
        let client = &current.as_ref().expect("gerade gesetzt").1;

        match client.fetch(since, cursor).await {
            Ok((rows, highest)) => {
                let n = rows.len();
                for row in rows {
                    if tx.try_send(row).is_err() {
                        tracing::warn!("writer channel full, dropping pihole query");
                    }
                }
                cursor = highest;
                since = Utc::now().timestamp() - 60;
                if n > 0 {
                    tracing::debug!(rows = n, "pulled queries from pihole");
                }
                record(&pool, true, None).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "pihole poll failed");
                record(&pool, false, Some(e.to_string())).await;
            }
        }
        tokio::time::sleep(POLL_EVERY).await;
    }
}

/// Nur zum Testen gedacht: erlaubt eine andere Basis-Adresse.
#[allow(dead_code)]
fn _unused(_: DateTime<Utc>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_becomes_a_dns_row() {
        let q = serde_json::json!({
            "id": 42, "time": 1_700_000_000.5, "type": "a",
            "domain": "example.com", "status": "GRAVITY",
            "reply": { "type": "NXDOMAIN", "time": 0.0012 },
            "client": { "ip": "10.0.0.5", "name": "laptop" }
        });
        let row = to_log(&q).unwrap();
        assert_eq!(row.dns_query.as_deref(), Some("example.com"));
        assert_eq!(row.dns_type.as_deref(), Some("A"));
        // Die Antwort ist, was zurückkam — nicht die Wiederholung des Status.
        assert_eq!(row.dns_answer.as_deref(), Some("NXDOMAIN"));
        // Geblockt ist geblockt: dieselbe Aktion wie bei einer Firewall-Zeile,
        // also greifen dieselbe Spalte und dieselben Filter.
        assert_eq!(row.rule_action, Some(RuleAction::Block));
        assert_eq!(row.src_ip.map(|i| i.to_string()).as_deref(), Some("10.0.0.5"));
        assert_eq!(row.hostname.as_deref(), Some("laptop"));
        assert!(row.timestamp.is_some());
        let d = row.details.unwrap();
        assert_eq!(d["status"], "GRAVITY", "der Grund bleibt erhalten");
        assert_eq!(d["reply_type"], "NXDOMAIN");
    }

    /// Eine weitergeleitete Abfrage ist erlaubt, und sie ging irgendwohin —
    /// beides stand vorher nirgends.
    #[test]
    fn a_forwarded_query_keeps_its_upstream() {
        let q = serde_json::json!({
            "id": 43, "time": 1_700_000_001.0, "type": "aaaa",
            "domain": "example.org", "status": "FORWARDED",
            "upstream": "10.10.10.1#53",
            "reply": { "type": "IP", "time": 0.021 },
            "client": "10.0.0.6"
        });
        let row = to_log(&q).unwrap();
        assert_eq!(row.rule_action, Some(RuleAction::Allow));
        assert_eq!(row.dst_ip.map(|i| i.to_string()).as_deref(), Some("10.10.10.1"));
        assert_eq!(row.dst_port, Some(53));
        assert_eq!(row.dns_answer.as_deref(), Some("IP"));
    }

    /// Neun der neunzehn Zustände heißen „geblockt", und sie heißen nicht
    /// alle gleich.
    #[test]
    fn every_blocking_status_counts_as_a_block() {
        for s in ["GRAVITY", "DENYLIST", "REGEX", "GRAVITY_CNAME", "REGEX_CNAME", "EXTERNAL_BLOCKED_IP", "SPECIAL_DOMAIN"] {
            assert_eq!(blocked(s), Some(RuleAction::Block), "{s}");
        }
        for s in ["FORWARDED", "CACHE", "CACHE_STALE", "RETRIED"] {
            assert_eq!(blocked(s), Some(RuleAction::Allow), "{s}");
        }
        // „noch nicht bekannt" ist keine Entscheidung.
        assert_eq!(blocked("UNKNOWN"), None);
    }

    /// Je nach Pi-hole-Version steht der Client als Objekt oder blank da.
    #[test]
    fn a_bare_client_address_also_works() {
        let q = serde_json::json!({ "id": 1, "domain": "x.test", "client": "10.0.0.9" });
        let row = to_log(&q).unwrap();
        assert_eq!(row.src_ip.map(|i| i.to_string()).as_deref(), Some("10.0.0.9"));
        assert_eq!(row.hostname, None);
    }

    #[test]
    fn a_query_without_a_domain_is_no_row() {
        assert!(to_log(&serde_json::json!({ "id": 1 })).is_none());
        assert!(to_log(&serde_json::json!({ "id": 1, "domain": "" })).is_none());
    }

    /// Der Stub antwortet wie Pi-hole v6: erst Anmeldung, dann Abfragen.
    async fn stub(unauthorized: bool) -> String {
        use axum::routing::{get, post};
        use axum::Json;

        let app = axum::Router::new()
            .route(
                "/api/auth",
                post(move || async move {
                    if unauthorized {
                        (axum::http::StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({ "session": { "sid": "abc", "validity": 1800 } })),
                        )
                    }
                }),
            )
            .route(
                "/api/queries",
                get(|| async {
                    Json(serde_json::json!({ "queries": [
                        { "id": 1, "time": 1_700_000_000.0, "type": "a", "domain": "one.test",
                          "status": "FORWARDED", "client": { "ip": "10.0.0.1" } },
                        { "id": 2, "time": 1_700_000_001.0, "type": "aaaa", "domain": "two.test",
                          "status": "GRAVITY", "client": { "ip": "10.0.0.2" } }
                    ]}))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetches_queries_and_advances_the_cursor() {
        let base = stub(false).await;
        let c = Pihole::new(base, "pw".into());
        let (rows, highest) = c.fetch(0, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(highest, 2);

        // Ein zweiter Abruf ab derselben Id liefert nichts Neues — sonst
        // schriebe jeder Durchlauf dieselben Zeilen erneut in die Datenbank.
        let (rows, highest) = c.fetch(0, 2).await.unwrap();
        assert!(rows.is_empty());
        assert_eq!(highest, 2);
    }

    #[tokio::test]
    async fn a_wrong_password_is_reported_as_such() {
        let base = stub(true).await;
        let c = Pihole::new(base, "falsch".into());
        assert_eq!(c.test().await, TestOutcome::BadCredentials);
    }

    #[tokio::test]
    async fn an_unreachable_host_is_not_a_credentials_problem() {
        let c = Pihole::new("http://127.0.0.1:1".into(), "pw".into());
        assert!(matches!(c.test().await, TestOutcome::Unreachable(_)));
    }
}
