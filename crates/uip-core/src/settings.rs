use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

/// Laufzeit-Einstellungen. Die DB ist die Wahrheit; Env überschreibt sie und
/// wird dabei zurückgeschrieben, damit der nächste Start ohne Env auskommt.
#[derive(Debug, Clone)]
pub struct Settings {
    pub wan_ips: HashSet<IpAddr>,
    pub gateway_ips: HashSet<IpAddr>,
    pub rdns_enabled: bool,
    pub abuseipdb_key: Option<String>,
    pub geoip_dir: PathBuf,
}

async fn get(pool: &PgPool, key: &str) -> Option<Value> {
    sqlx::query_scalar::<_, Value>("SELECT value FROM system_config WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

async fn put(pool: &PgPool, key: &str, value: Value) {
    let res = sqlx::query(
        "INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, key, "could not persist setting");
    }
}

fn parse_ips(s: &str) -> HashSet<IpAddr> {
    s.split(',').filter_map(|p| p.trim().parse().ok()).collect()
}

impl Settings {
    pub async fn load(
        pool: &PgPool,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, sqlx::Error> {
        /// Env gewinnt und wird zurückgeschrieben; sonst zählt die DB, sonst der Default.
        async fn text(
            pool: &PgPool,
            key: &str,
            from_env: Option<String>,
            default: &str,
        ) -> String {
            match from_env.filter(|v| !v.is_empty()) {
                Some(v) => {
                    put(pool, key, Value::from(v.clone())).await;
                    v
                }
                None => get(pool, key)
                    .await
                    .and_then(|v| v.as_str().map(str::to_string))
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| default.to_string()),
            }
        }

        let wan_ips = parse_ips(&text(pool, "wan_ips", env("UIP_WAN_IPS"), "").await);
        let gateway_ips = get(pool, "gateway_ips")
            .await
            .and_then(|v| v.as_str().map(parse_ips))
            .unwrap_or_default();

        let rdns_enabled = match env("UIP_RDNS_ENABLED") {
            Some(raw) => {
                let on = !matches!(raw.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no");
                put(pool, "rdns_enabled", Value::Bool(on)).await;
                on
            }
            None => get(pool, "rdns_enabled").await.and_then(|v| v.as_bool()).unwrap_or(true),
        };

        let abuseipdb_key =
            text(pool, "abuseipdb_api_key", env("UIP_ABUSEIPDB_KEY"), "").await;
        let geoip_dir =
            text(pool, "geoip_dir", env("UIP_GEOIP_DIR"), "/var/lib/uip/geoip").await;

        Ok(Self {
            wan_ips,
            gateway_ips,
            rdns_enabled,
            abuseipdb_key: Some(abuseipdb_key).filter(|k| !k.is_empty()),
            geoip_dir: PathBuf::from(geoip_dir),
        })
    }

    /// Alles, was nicht angereichert werden muss, weil es uns selbst gehört.
    pub fn exclusions(&self) -> HashSet<IpAddr> {
        self.wan_ips.union(&self.gateway_ips).copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn env_seeds_the_database_once(pool: sqlx::PgPool) {
        let s = Settings::load(&pool, |k| match k {
            "UIP_WAN_IPS" => Some("203.0.113.7, 198.51.100.4".into()),
            "UIP_ABUSEIPDB_KEY" => Some("secret".into()),
            _ => None,
        }).await.unwrap();

        assert_eq!(s.wan_ips.len(), 2);
        assert!(s.wan_ips.contains(&"203.0.113.7".parse().unwrap()));
        assert_eq!(s.abuseipdb_key.as_deref(), Some("secret"));
        assert!(s.rdns_enabled, "Default ist an");

        // Der zweite Start ohne Env liest dieselben Werte aus der DB.
        let again = Settings::load(&pool, |_| None).await.unwrap();
        assert_eq!(again.wan_ips, s.wan_ips);
        assert_eq!(again.abuseipdb_key.as_deref(), Some("secret"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn env_wins_over_a_stored_value(pool: sqlx::PgPool) {
        Settings::load(&pool, |k| (k == "UIP_WAN_IPS").then(|| "203.0.113.7".into())).await.unwrap();
        let s = Settings::load(&pool, |k| (k == "UIP_WAN_IPS").then(|| "1.2.3.4".into())).await.unwrap();
        assert_eq!(s.wan_ips, ["1.2.3.4".parse().unwrap()].into_iter().collect());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rdns_can_be_turned_off(pool: sqlx::PgPool) {
        let s = Settings::load(&pool, |k| (k == "UIP_RDNS_ENABLED").then(|| "false".into())).await.unwrap();
        assert!(!s.rdns_enabled);
    }

    /// Wie `env_seeds_the_database_once`, aber für `geoip_dir`: einmal mit Env
    /// gesetzt, dann ohne Env erneut geladen — derselbe Pfad muss zurückkommen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn geoip_dir_is_persisted_and_reread(pool: sqlx::PgPool) {
        let s = Settings::load(&pool, |k| {
            (k == "UIP_GEOIP_DIR").then(|| "/opt/uip/geoip-custom".into())
        })
        .await
        .unwrap();
        assert_eq!(s.geoip_dir, PathBuf::from("/opt/uip/geoip-custom"));

        let again = Settings::load(&pool, |_| None).await.unwrap();
        assert_eq!(again.geoip_dir, s.geoip_dir);
    }
}
