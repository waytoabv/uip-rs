use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub http_addr: String,
    pub syslog_addr: String,
    pub wan_interfaces: HashSet<String>,
}

impl Config {
    /// Injizierbare Env-Quelle, damit Tests keine Prozess-Env anfassen.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Self {
        let wan = get("UIP_WAN_IFACES").unwrap_or_else(|| "ppp0".into());
        Self {
            database_url: get("UIP_DB_URL")
                .or_else(|| get("DATABASE_URL"))
                .unwrap_or_else(|| "postgres://localhost/uip_dev".into()),
            http_addr: get("UIP_HTTP_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into()),
            syslog_addr: get("UIP_SYSLOG_ADDR").unwrap_or_else(|| "0.0.0.0:514".into()),
            wan_interfaces: wan
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    pub fn from_env() -> Self {
        Self::from_vars(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_env_missing() {
        let c = Config::from_vars(|_| None);
        assert_eq!(c.http_addr, "0.0.0.0:8080");
        assert_eq!(c.syslog_addr, "0.0.0.0:514");
        assert_eq!(c.wan_interfaces, ["ppp0".to_string()].into_iter().collect::<std::collections::HashSet<_>>());
        assert!(c.database_url.contains("uip"));
    }

    #[test]
    fn reads_env_overrides() {
        let c = Config::from_vars(|k| match k {
            "UIP_DB_URL" => Some("postgres://x/y".into()),
            "UIP_HTTP_ADDR" => Some("127.0.0.1:9999".into()),
            "UIP_SYSLOG_ADDR" => Some("0.0.0.0:5514".into()),
            "UIP_WAN_IFACES" => Some("eth8, ppp0".into()),
            _ => None,
        });
        assert_eq!(c.database_url, "postgres://x/y");
        assert_eq!(c.http_addr, "127.0.0.1:9999");
        assert_eq!(c.syslog_addr, "0.0.0.0:5514");
        assert!(c.wan_interfaces.contains("eth8") && c.wan_interfaces.contains("ppp0"));
    }
}
