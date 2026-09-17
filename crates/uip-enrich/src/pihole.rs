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
use uip_core::types::LogType;
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

/// Eine Pi-hole-Abfrage als DNS-Logzeile.
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

    Some(ParsedLog {
        timestamp: Some(ts),
        log_type: Some(LogType::Dns),
        dns_query: Some(domain.to_string()),
        dns_type: q.get("type").and_then(|v| v.as_str()).map(|s| s.to_uppercase()),
        // Der Status sagt, ob geblockt wurde — als Antwort festgehalten, weil
        // unser Schema für DNS keine Aktion kennt.
        dns_answer: q.get("status").and_then(|v| v.as_str()).map(|s| s.to_uppercase()),
        src_ip,
        hostname,
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
            "client": { "ip": "10.0.0.5", "name": "laptop" }
        });
        let row = to_log(&q).unwrap();
        assert_eq!(row.dns_query.as_deref(), Some("example.com"));
        assert_eq!(row.dns_type.as_deref(), Some("A"));
        assert_eq!(row.dns_answer.as_deref(), Some("GRAVITY"));
        assert_eq!(row.src_ip.map(|i| i.to_string()).as_deref(), Some("10.0.0.5"));
        assert_eq!(row.hostname.as_deref(), Some("laptop"));
        assert!(row.timestamp.is_some());
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
