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
/// Solange der Controller aus oder unvollständig eingerichtet ist, wird nur
/// nachgesehen, ob sich daran etwas geändert hat.
const UNCONFIGURED_POLL: Duration = Duration::from_secs(60);

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

        // Die Netz-Konfiguration ist die Nebensache, nicht der Zweck des
        // Abgleichs: fehlt sie, bleiben die Schnittstellen eben bei ihren
        // rohen Namen, statt dass der ganze Durchlauf scheitert.
        match self.get("rest/networkconf").await {
            Ok(networks) => store_networks(pool, &networks, &devices).await,
            Err(e) => tracing::debug!(error = %e, "could not read the network configuration"),
        }
        store_wan_addresses(pool, &devices).await;

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

/// Die Schnittstelle, auf der ein Netz im Log erscheint.
///
/// UniFi bildet VLAN *n* auf die Bridge `brn` ab; das Vorgabenetz ohne eigenes
/// VLAN liegt auf `br0`. Dieselbe Regel wie im Vorgänger — sie steht nirgends
/// in der API, sondern ergibt sich daraus, wie das Gateway die Bridges
/// benennt.
fn bridge_for(net: &Value) -> Option<String> {
    let purpose = text(net, "purpose").unwrap_or_default();
    if !matches!(purpose.as_str(), "corporate" | "guest" | "vlan-only") {
        return None;
    }
    if !net.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) {
        return None;
    }
    // UniFi gibt Zahlen je nach Version mal als Zahl, mal als Zeichenkette
    // zurück — `vlan` ist eine davon. Ein `as_i64` allein läse die Zeichenkette
    // als „kein VLAN" und legte jedes Netz auf br0.
    let vlan = number(net, "vlan");
    // Fehlt `vlan_enabled` ganz, entscheidet die VLAN-Nummer selbst: ein Netz
    // mit VLAN 15 liegt auf br15, ob das Feld nun mitgeschickt wurde oder nicht.
    let enabled = net
        .get("vlan_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| vlan.is_some_and(|v| v > 1));
    let vlan = vlan.filter(|_| enabled).unwrap_or(1);
    Some(if vlan == 1 { "br0".to_string() } else { format!("br{vlan}") })
}

/// Eine Zahl, die auch als Zeichenkette ankommen darf.
fn number(v: &Value, key: &str) -> Option<i64> {
    let field = v.get(key)?;
    field.as_i64().or_else(|| field.as_str()?.trim().parse().ok())
}

/// Die WAN-Schnittstellen, wie das Gateway sie meldet.
///
/// Anders als bei den Bridges lässt sich der Name nicht aus der Netz-Definition
/// ableiten — `eth4` oder `ppp0` steht nur am Gerät selbst. Die Zuordnung ist
/// deshalb absichtlich zurückhaltend: findet sich nichts Passendes, bleibt es
/// beim rohen Namen, statt einen zu erfinden.
fn wan_interfaces(devices: &[Value], networks: &[Value]) -> Vec<(String, String)> {
    let name_for = |group: &str| -> String {
        networks
            .iter()
            .find(|n| {
                text(n, "purpose").as_deref() == Some("wan")
                    && text(n, "wan_networkgroup").as_deref() == Some(group)
            })
            .and_then(|n| text(n, "name"))
            .unwrap_or_else(|| group.to_string())
    };

    let mut out = Vec::new();
    for device in devices {
        for (key, group) in [("wan1", "WAN"), ("wan2", "WAN2")] {
            if let Some(iface) = device.get(key).and_then(|w| text(w, "ifname")) {
                out.push((iface, name_for(group)));
            }
        }
    }
    out
}

async fn store_networks(pool: &PgPool, networks: &[Value], devices: &[Value]) {
    let mut seen: Vec<String> = Vec::new();

    for net in networks {
        let (Some(iface), Some(name)) = (bridge_for(net), text(net, "name")) else {
            continue;
        };
        let vlan = number(net, "vlan").map(|v| v as i32);
        upsert_network(pool, &iface, &name, vlan, text(net, "purpose").as_deref()).await;
        seen.push(iface);
    }

    for (iface, name) in wan_interfaces(devices, networks) {
        upsert_network(pool, &iface, &name, None, Some("wan")).await;
        seen.push(iface);
    }

    // Ein gelöschtes oder abgeschaltetes Netz soll seinen Namen verlieren,
    // sonst trägt eine Schnittstelle für immer die Beschriftung von gestern.
    if !seen.is_empty() {
        let res = sqlx::query("DELETE FROM unifi_networks WHERE interface <> ALL($1)")
            .bind(&seen)
            .execute(pool)
            .await;
        if let Err(e) = res {
            tracing::warn!(error = %e, "could not prune the network list");
        }
    }
}

/// Die eigenen WAN-Adressen, wie das Gateway sie meldet.
///
/// Sie stand bisher als Pflichtfeld in den Einstellungen — eine Angabe, die
/// jeder von Hand nachtragen musste und die sich bei einer dynamischen
/// Adresse hinter seinem Rücken änderte. Das Gerät kennt sie, also fragen wir
/// es. Getrennt von der eingetippten Fassung abgelegt, damit eine bewusste
/// Angabe nicht bei jedem Abgleich überschrieben wird.
async fn store_wan_addresses(pool: &PgPool, devices: &[Value]) {
    let mut found: Vec<String> = Vec::new();
    for device in devices {
        for key in ["wan1", "wan2"] {
            if let Some(ip) = device.get(key).and_then(|w| text(w, "ip")) {
                if ip.parse::<std::net::IpAddr>().is_ok() && !found.contains(&ip) {
                    found.push(ip);
                }
            }
        }
    }
    if found.is_empty() {
        return;
    }
    uip_core::settings::put_config(pool, "wan_ips_detected", found.join(",").into()).await;
}

async fn upsert_network(pool: &PgPool, iface: &str, name: &str, vlan: Option<i32>, purpose: Option<&str>) {
    let res = sqlx::query(
        "INSERT INTO unifi_networks (interface, name, vlan, purpose, updated_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (interface) DO UPDATE SET
            name = EXCLUDED.name, vlan = EXCLUDED.vlan,
            purpose = EXCLUDED.purpose, updated_at = NOW()",
    )
    .bind(iface)
    .bind(name)
    .bind(vlan)
    .bind(purpose)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, iface, "could not store the network name");
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
/// Hält fest, wie der letzte Abgleich ausging — zugleich Herzschlag, damit
/// eine stehengebliebene Schleife von einer stillen zu unterscheiden ist.
async fn record(pool: &PgPool, ok: bool, error: Option<String>, counts: Option<(usize, usize)>) {
    uip_core::settings::put_config(
        pool,
        "unifi_status",
        serde_json::json!({
            "ok": ok,
            "at": chrono::Utc::now().to_rfc3339(),
            "error": error,
            "clients": counts.map(|c| c.0),
            "devices": counts.map(|c| c.1),
        }),
    )
    .await;
}

/// Controller, Schlüssel und Standort, wie sie gerade eingestellt sind.
async fn config(pool: &PgPool) -> Option<(String, String, String)> {
    let enabled = uip_core::settings::get_config(pool, "unifi_enabled")
        .await
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    let text = |v: Option<serde_json::Value>| {
        v.and_then(|v| v.as_str().map(str::to_string)).filter(|s| !s.is_empty())
    };
    let url = text(uip_core::settings::get_config(pool, "unifi_url").await)?;
    let key = text(uip_core::settings::get_config(pool, "unifi_api_key").await).unwrap_or_default();
    let site = text(uip_core::settings::get_config(pool, "unifi_site").await).unwrap_or_default();
    Some((url, key, site))
}

pub async fn run_unifi(pool: PgPool) {
    let mut current: Option<((String, String, String), Unifi)> = None;

    loop {
        let Some(cfg) = config(&pool).await else {
            current = None;
            tokio::time::sleep(UNCONFIGURED_POLL).await;
            continue;
        };
        if current.as_ref().map(|(c, _)| c) != Some(&cfg) {
            tracing::info!(url = %cfg.0, "unifi settings changed");
            current = Some((cfg.clone(), Unifi::new(cfg.0.clone(), cfg.1.clone(), cfg.2.clone())));
        }
        let client = &current.as_ref().expect("gerade gesetzt").1;

        match client.sync(&pool).await {
            Ok((c, d)) => {
                tracing::info!(clients = c, devices = d, "synced unifi inventory");
                record(&pool, true, None, Some((c, d))).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "unifi sync failed");
                record(&pool, false, Some(e), None).await;
            }
        }
        tokio::time::sleep(SYNC_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// VLAN 15 liegt auf br15, das ungetaggte Vorgabenetz auf br0. Die Regel
    /// steht nirgends in der API — sie ergibt sich daraus, wie das Gateway
    /// seine Bridges benennt.
    #[test]
    fn a_network_maps_to_the_bridge_it_appears_on() {
        let vlan15 = json!({"purpose": "corporate", "name": "IoT", "vlan": 15, "vlan_enabled": true});
        assert_eq!(bridge_for(&vlan15).as_deref(), Some("br15"));

        let default = json!({"purpose": "corporate", "name": "LAN", "vlan_enabled": false});
        assert_eq!(bridge_for(&default).as_deref(), Some("br0"));

        // Zahlen kommen je nach Version als Zeichenkette.
        let as_text = json!({"purpose": "corporate", "name": "IoT", "vlan": "15", "vlan_enabled": true});
        assert_eq!(bridge_for(&as_text).as_deref(), Some("br15"));

        // Ohne `vlan_enabled` entscheidet die Nummer selbst.
        let implied = json!({"purpose": "guest", "name": "Gast", "vlan": 20});
        assert_eq!(bridge_for(&implied).as_deref(), Some("br20"));
    }

    /// WAN-Netze und abgeschaltete haben keine Bridge — und ein WAN-Eintrag
    /// darf auf keinen Fall als br0 durchgehen, sonst trüge das LAN den Namen
    /// der Internetverbindung.
    #[test]
    fn only_real_lan_segments_get_a_bridge() {
        assert_eq!(bridge_for(&json!({"purpose": "wan", "name": "WAN"})), None);
        assert_eq!(
            bridge_for(&json!({"purpose": "corporate", "name": "Alt", "enabled": false})),
            None
        );
        assert_eq!(bridge_for(&json!({"purpose": "remote-user-vpn", "name": "VPN"})), None);
    }

    /// Ein vollständiger Satz, wie ihn ein echtes Gateway liefert — die Formen
    /// sind aus einer laufenden Anlage übernommen, die Namen ersetzt.
    ///
    /// Der lehrreiche Fall ist das Vorgabenetz: `vlan: null` bei
    /// `vlan_enabled: false`. Es liegt auf br0, und keine der anderen Zeilen
    /// darf dort mit landen — sonst trügen alle Netze denselben Namen.
    #[test]
    fn a_whole_controller_config_maps_without_collisions() {
        let networks = vec![
            json!({"name": "WAN", "purpose": "wan", "vlan": null, "vlan_enabled": null,
                   "enabled": true, "wan_networkgroup": "WAN"}),
            json!({"name": "Management", "purpose": "corporate", "vlan": null,
                   "vlan_enabled": false, "enabled": true}),
            json!({"name": "#0 - Server", "purpose": "corporate", "vlan": 10,
                   "vlan_enabled": true, "enabled": true}),
            json!({"name": "#2 - Guests", "purpose": "corporate", "vlan": 20,
                   "vlan_enabled": true, "enabled": true}),
            json!({"name": "#1 - Internal", "purpose": "corporate", "vlan": 15,
                   "vlan_enabled": true, "enabled": true}),
            json!({"name": "Wireguard Server", "purpose": "remote-user-vpn", "vlan": null,
                   "vlan_enabled": null, "enabled": true}),
            json!({"name": "VPN Provider", "purpose": "vpn-client", "vlan": null,
                   "vlan_enabled": null, "enabled": true}),
        ];

        let bridges: Vec<_> = networks
            .iter()
            .filter_map(|n| bridge_for(n).map(|b| (b, text(n, "name").unwrap_or_default())))
            .collect();

        assert_eq!(
            bridges,
            [
                ("br0".to_string(), "Management".to_string()),
                ("br10".to_string(), "#0 - Server".to_string()),
                ("br20".to_string(), "#2 - Guests".to_string()),
                ("br15".to_string(), "#1 - Internal".to_string()),
            ],
            "WAN und beide VPN-Netze haben keine Bridge, das Vorgabenetz genau eine"
        );

        // Und das WAN findet seinen Namen über die Gruppe.
        let devices = vec![json!({"wan1": {"ifname": "eth1"}})];
        assert_eq!(
            wan_interfaces(&devices, &networks),
            [("eth1".to_string(), "WAN".to_string())]
        );
    }

    /// Die WAN-Schnittstelle steht nur am Gerät. Genau diese Form meldet das
    /// Gateway (`wan1.ifname`).
    #[test]
    fn the_wan_interface_comes_from_the_device() {
        let devices = vec![
            json!({}),
            json!({"wan1": {"ifname": "eth1", "uplink_ifname": "eth1", "up": true}}),
        ];
        let networks = vec![json!({"purpose": "wan", "name": "Internet", "wan_networkgroup": "WAN"})];
        assert_eq!(
            wan_interfaces(&devices, &networks),
            [("eth1".to_string(), "Internet".to_string())]
        );

        // Ohne passenden Netz-Eintrag bleibt die Gruppe als Name stehen —
        // besser als gar keine Beschriftung und besser als eine erfundene.
        assert_eq!(wan_interfaces(&devices, &[]), [("eth1".to_string(), "WAN".to_string())]);

        // Ein Gerät ohne WAN-Angabe liefert nichts, statt zu raten.
        assert!(wan_interfaces(&[json!({"name": "switch"})], &networks).is_empty());
    }
}
