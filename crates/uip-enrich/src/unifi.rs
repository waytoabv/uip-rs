//! Gerätenamen aus dem UniFi-Controller.
//!
//! In einer Log-Zeile steht eine Adresse. Wer sein Netz kennt, weiß, dass
//! 10.10.20.196 der Fernseher ist — aber niemand sollte das auswendig können
//! müssen. Der Controller weiß es, also holen wir es von dort.
//!
//! Aufgelöst wird beim **Lesen** über einen Join auf die Adresse, nicht beim
//! Schreiben. Das kostet einen Join pro Abfrage, hat aber zwei Vorteile, die
//! schwerer wiegen: die Namen gelten rückwirkend für alles, was schon in der
//! Datenbank liegt, und eine Umbenennung im Controller wirkt sofort, ohne dass
//! Millionen Zeilen angefasst werden müssen.

use serde_json::Value;
use sqlx::PgPool;
use std::time::Duration;

const SYNC_EVERY: Duration = Duration::from_secs(300);

pub struct Unifi {
    base: String,
    api_key: String,
    site: String,
    http: reqwest::Client,
}

#[derive(Debug, PartialEq)]
pub enum TestOutcome {
    Ok { clients: usize, devices: usize },
    BadCredentials,
    Unreachable(String),
}

impl Unifi {
    pub fn new(base: String, api_key: String, site: String) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            api_key,
            site: if site.is_empty() { "default".into() } else { site },
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                // Controller im eigenen Netz tragen fast immer ein
                // selbstsigniertes Zertifikat.
                .danger_accept_invalid_certs(true)
                .build()
                .expect("reqwest client"),
        }
    }

    /// UniFi OS schiebt die Netzwerk-API hinter `/proxy/network`; ein
    /// selbst gehosteter Controller nicht. Wir versuchen erst den Proxy-Pfad
    /// und fallen auf den direkten zurück — das erspart eine Einstellung,
    /// die ohnehin niemand sicher beantworten kann.
    fn urls(&self, path: &str) -> [String; 2] {
        [
            format!("{}/proxy/network/api/s/{}/{}", self.base, self.site, path),
            format!("{}/api/s/{}/{}", self.base, self.site, path),
        ]
    }

    async fn get(&self, path: &str) -> Result<Vec<Value>, String> {
        let mut last = String::from("no attempt");
        for url in self.urls(path) {
            let res = self
                .http
                .get(&url)
                .header("X-API-KEY", &self.api_key)
                .header("Accept", "application/json")
                .send()
                .await;
            match res {
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED
                    || r.status() == reqwest::StatusCode::FORBIDDEN =>
                {
                    return Err("unauthorized".into());
                }
                Ok(r) if r.status().is_success() => {
                    let body: Value = r.json().await.map_err(|e| e.to_string())?;
                    return Ok(body
                        .get("data")
                        .and_then(|d| d.as_array())
                        .cloned()
                        .unwrap_or_default());
                }
                Ok(r) => last = format!("status {}", r.status()),
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }

    pub async fn test(&self) -> TestOutcome {
        match (self.get("stat/sta").await, self.get("stat/device").await) {
            (Ok(c), Ok(d)) => TestOutcome::Ok { clients: c.len(), devices: d.len() },
            (Err(e), _) | (_, Err(e)) if e == "unauthorized" => TestOutcome::BadCredentials,
            (Err(e), _) | (_, Err(e)) => TestOutcome::Unreachable(e),
        }
    }

    pub async fn sync(&self, pool: &PgPool) -> Result<(usize, usize), String> {
        let clients = self.get("stat/sta").await?;
        let devices = self.get("stat/device").await?;

        let mut n_clients = 0;
        for c in &clients {
            if store_client(pool, c).await {
                n_clients += 1;
            }
        }
        let mut n_devices = 0;
        for d in &devices {
            if store_device(pool, d).await {
                n_devices += 1;
            }
        }
        Ok((n_clients, n_devices))
    }
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Der angezeigte Name in der Reihenfolge, in der ein Mensch ihn erwartet:
/// der selbst vergebene Name vor dem gemeldeten Hostnamen vor dem Hersteller.
pub fn display_name(v: &Value) -> Option<String> {
    text(v, "name").or_else(|| text(v, "hostname")).or_else(|| text(v, "oui"))
}

async fn store_client(pool: &PgPool, c: &Value) -> bool {
    let Some(mac) = text(c, "mac") else { return false };
    let res = sqlx::query(
        "INSERT INTO unifi_clients (mac, ip, name, hostname, oui, network, is_wired, last_seen, updated_at)
         VALUES ($1::text::macaddr, $2::text::inet, $3, $4, $5, $6, $7, to_timestamp($8), NOW())
         ON CONFLICT (mac) DO UPDATE SET
            ip = EXCLUDED.ip, name = EXCLUDED.name, hostname = EXCLUDED.hostname,
            oui = EXCLUDED.oui, network = EXCLUDED.network, is_wired = EXCLUDED.is_wired,
            last_seen = EXCLUDED.last_seen, updated_at = NOW()",
    )
    .bind(mac.to_lowercase())
    .bind(text(c, "ip"))
    .bind(text(c, "name"))
    .bind(text(c, "hostname"))
    .bind(text(c, "oui"))
    .bind(text(c, "network"))
    .bind(c.get("is_wired").and_then(|v| v.as_bool()))
    .bind(c.get("last_seen").and_then(|v| v.as_f64()).unwrap_or(0.0))
    .execute(pool)
    .await;
    if let Err(e) = &res {
        tracing::debug!(error = %e, %mac, "could not store unifi client");
    }
    res.is_ok()
}

async fn store_device(pool: &PgPool, d: &Value) -> bool {
    let Some(mac) = text(d, "mac") else { return false };
    let res = sqlx::query(
        "INSERT INTO unifi_devices (mac, ip, name, model, device_type, firmware, updated_at)
         VALUES ($1::text::macaddr, $2::text::inet, $3, $4, $5, $6, NOW())
         ON CONFLICT (mac) DO UPDATE SET
            ip = EXCLUDED.ip, name = EXCLUDED.name, model = EXCLUDED.model,
            device_type = EXCLUDED.device_type, firmware = EXCLUDED.firmware, updated_at = NOW()",
    )
    .bind(mac.to_lowercase())
    .bind(text(d, "ip"))
    .bind(display_name(d))
    .bind(text(d, "model"))
    .bind(text(d, "type"))
    .bind(text(d, "version"))
    .execute(pool)
    .await;
    res.is_ok()
}

/// Dauerläufer: alle fünf Minuten abgleichen. Gerätenamen ändern sich selten,
/// und ein Controller ist kein Dienst, den man im Sekundentakt befragen sollte.
pub async fn run_unifi(client: Unifi, pool: PgPool) {
    loop {
        match client.sync(&pool).await {
            Ok((c, d)) => tracing::info!(clients = c, devices = d, "synced unifi inventory"),
            Err(e) => tracing::warn!(error = %e, "unifi sync failed"),
        }
        tokio::time::sleep(SYNC_EVERY).await;
    }
}
