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
use sqlx::{PgPool, Row};
use std::collections::HashMap;
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

    /// Die Zonen-Firewall spricht die v2-API: andere Pfade, und die Antwort
    /// ist ein nacktes Array statt `{"data": […]}`.
    fn v2_urls(&self, path: &str) -> [String; 2] {
        [
            format!("{}/proxy/network/v2/api/site/{}/{}", self.base, self.site, path),
            format!("{}/v2/api/site/{}/{}", self.base, self.site, path),
        ]
    }

    async fn get(&self, path: &str) -> Result<Vec<Value>, String> {
        let body = self.fetch(self.urls(path)).await?;
        Ok(body.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default())
    }

    /// Dasselbe über die v2-API. Sie antwortet mit dem Array selbst; das
    /// `data`-Feld bleibt als Rückfall stehen, weil einzelne Endpunkte es
    /// weiterhin verwenden.
    async fn get_v2(&self, path: &str) -> Result<Vec<Value>, String> {
        let body = self.fetch(self.v2_urls(path)).await?;
        if let Some(arr) = body.as_array() {
            return Ok(arr.clone());
        }
        Ok(body.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default())
    }

    async fn fetch(&self, urls: [String; 2]) -> Result<Value, String> {
        let mut last = String::from("no attempt");
        for url in urls {
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
                    return r.json::<Value>().await.map_err(|e| e.to_string());
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
        // `stat/sta` kennt nur, was gerade verbunden ist. Ein Gerät, das einen
        // Namen im Controller trägt und gerade schläft, stünde damit nie im
        // Log. `stat/alluser` kennt alle je gesehenen, mit `last_ip` statt
        // `ip` und ohne die reicheren Felder — deshalb zuerst geschrieben,
        // damit ein aktiver Eintrag darüber gewinnt.
        let known = self.get("stat/alluser").await.unwrap_or_else(|e| {
            tracing::debug!(error = %e, "no historical client list");
            Vec::new()
        });

        // Die Netz-Konfiguration ist die Nebensache, nicht der Zweck des
        // Abgleichs: fehlt sie, bleiben die Schnittstellen eben bei ihren
        // rohen Namen, statt dass der ganze Durchlauf scheitert.
        let networks = match self.get("rest/networkconf").await {
            Ok(networks) => {
                store_networks(pool, &networks, &devices).await;
                networks
            }
            Err(e) => {
                tracing::debug!(error = %e, "could not read the network configuration");
                Vec::new()
            }
        };
        store_wan_addresses(pool, &devices).await;

        // Ebenfalls Beiwerk: ein Controller ohne Zonen-Firewall kennt diese
        // Endpunkte nicht, und dann bleibt es bei dem, was im Log steht.
        match (self.get_v2("firewall/zone").await, self.get_v2("firewall-policies").await) {
            (Ok(zones), Ok(policies)) => store_firewall_policies(pool, &zones, &policies).await,
            (Err(e), _) | (_, Err(e)) => {
                tracing::debug!(error = %e, "could not read the firewall policies")
            }
        }

        let mut n_clients = 0;
        // Nach `last_seen` aufsteigend: wer eine Adresse zuletzt hatte, wird
        // zuletzt geschrieben und behält sie (siehe `store_client`).
        for c in by_last_seen(&known) {
            store_client(pool, c).await;
        }
        for c in by_last_seen(&clients) {
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

        store_device_addresses(pool, &devices, &networks).await;
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

/// Das Kürzel, unter dem eine Zone im Regelnamen einer Log-Zeile steht.
///
/// Der Regelname ist gebaut, nicht vergeben: `CUSTOM2_CUSTOM1-A-10008` nennt
/// Quellzone, Zielzone, Aktion und den Index der Regel innerhalb dieses
/// Zonenpaars. Die Vorgabezonen tragen ihr `zone_key` — drei davon heißen im
/// Log anders, als sie im Controller heißen. Selbst angelegte Zonen haben kein
/// `zone_key`; sie werden durchnummeriert, in der Reihenfolge ihrer
/// Erstellung. Die trägt die Kennung in sich: eine MongoDB-`_id` beginnt mit
/// dem Zeitstempel, aufsteigend sortiert ergibt sich die Reihenfolge, in der
/// das Gateway sie zählt.
fn zone_tokens(zones: &[Value]) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    let mut customs: Vec<&Value> = Vec::new();

    for zone in zones {
        let (Some(id), Some(name)) = (text(zone, "_id"), text(zone, "name")) else {
            continue;
        };
        match text(zone, "zone_key").as_deref() {
            Some("internal") => drop(out.insert(id, ("LAN".to_string(), name))),
            Some("external") => drop(out.insert(id, ("WAN".to_string(), name))),
            Some("gateway") => drop(out.insert(id, ("LOCAL".to_string(), name))),
            Some(key) => drop(out.insert(id, (key.to_uppercase(), name))),
            None => customs.push(zone),
        }
    }

    customs.sort_by_key(|z| text(z, "_id").unwrap_or_default());
    for (n, zone) in customs.iter().enumerate() {
        let (Some(id), Some(name)) = (text(zone, "_id"), text(zone, "name")) else {
            continue;
        };
        out.insert(id, (format!("CUSTOM{}", n + 1), name));
    }
    out
}

/// Der Buchstabe, den die Firewall für diese Aktion in den Regelnamen schreibt.
fn action_letter(action: &str) -> &'static str {
    match action.to_ascii_uppercase().as_str() {
        "ALLOW" | "ACCEPT" => "A",
        "BLOCK" | "DROP" | "REJECT" => "D",
        _ => "R",
    }
}

/// Der Regelname, wie er in der Log-Zeile stehen wird — oder nichts, wenn die
/// Regel auf eine Zone zeigt, die es nicht mehr gibt.
fn policy_key(policy: &Value, tokens: &HashMap<String, (String, String)>) -> Option<String> {
    let zone = |side: &str| -> Option<&(String, String)> {
        tokens.get(&text(policy.get(side)?, "zone_id")?)
    };
    let src = zone("source")?;
    let dst = zone("destination")?;
    let index = number(policy, "index")?;
    let action = text(policy, "action").unwrap_or_default();
    Some(format!("{}_{}-{}-{index}", src.0, dst.0, action_letter(&action)))
}

async fn store_firewall_policies(pool: &PgPool, zones: &[Value], policies: &[Value]) {
    let tokens = zone_tokens(zones);
    let mut seen: Vec<String> = Vec::new();

    for policy in policies {
        let (Some(key), Some(name)) = (policy_key(policy, &tokens), text(policy, "name")) else {
            continue;
        };
        let zone_name = |side: &str| -> Option<String> {
            let id = text(policy.get(side)?, "zone_id")?;
            tokens.get(&id).map(|(_, name)| name.clone())
        };
        let res = sqlx::query(
            "INSERT INTO unifi_firewall_policies
                (rule_key, name, src_zone, dst_zone, predefined, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             ON CONFLICT (rule_key) DO UPDATE SET
                name = EXCLUDED.name, src_zone = EXCLUDED.src_zone,
                dst_zone = EXCLUDED.dst_zone, predefined = EXCLUDED.predefined,
                updated_at = NOW()",
        )
        .bind(&key)
        .bind(&name)
        .bind(zone_name("source"))
        .bind(zone_name("destination"))
        .bind(policy.get("predefined").and_then(|v| v.as_bool()).unwrap_or(false))
        .execute(pool)
        .await;
        match res {
            Ok(_) => seen.push(key),
            Err(e) => tracing::warn!(error = %e, key, "could not store the firewall policy"),
        }
    }

    // Eine gelöschte Regel soll ihren Namen verlieren — sonst beschriftet sie
    // weiter Zeilen, die inzwischen eine andere Regel gezogen haben, denn der
    // Index wird wiederverwendet.
    if !seen.is_empty() {
        let res = sqlx::query("DELETE FROM unifi_firewall_policies WHERE rule_key <> ALL($1)")
            .bind(&seen)
            .execute(pool)
            .await;
        if let Err(e) = res {
            tracing::warn!(error = %e, "could not prune the firewall policies");
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
    if !found.is_empty() {
        uip_core::settings::put_config(pool, "wan_ips_detected", found.join(",").into()).await;
    }

    // Und der Name der Schnittstelle. Ohne ihn hält der Parser jede
    // Internetverbindung für Verkehr zwischen zwei VLANs: „WAN" ist keine
    // Eigenschaft der Zeile, sondern die Frage, ob diese Schnittstelle zum
    // Anbieter zeigt — und das weiß nur das Gerät.
    let ifaces: Vec<String> = devices
        .iter()
        .flat_map(|d| ["wan1", "wan2"].map(|k| d.get(k).and_then(|w| text(w, "ifname"))))
        .flatten()
        .collect();
    if !ifaces.is_empty() {
        uip_core::settings::put_config(pool, "wan_interfaces_detected", ifaces.join(",").into())
            .await;
    }
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

/// Die Adresse, unter der das Gateway in einem Netz erreichbar ist.
///
/// `ip_subnet` ist die Netzangabe mitsamt der eigenen Adresse darin —
/// „10.10.15.1/24" heißt: das Gateway ist die .1. Unter `stat/device` steht
/// von ihm nur die WAN-Adresse; in den Log-Zeilen taucht es aber unter seiner
/// Adresse im jeweiligen VLAN auf, und die stand bisher nirgends.
fn gateway_ip(net: &Value) -> Option<String> {
    let purpose = text(net, "purpose").unwrap_or_default();
    if !matches!(purpose.as_str(), "corporate" | "guest" | "vlan-only" | "remote-user-vpn") {
        return None;
    }
    let subnet = text(net, "ip_subnet")?;
    let addr = subnet.split('/').next()?.trim();
    addr.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

/// Der Name des Gateways, wie ihn der Controller führt.
fn gateway_name(devices: &[Value]) -> Option<String> {
    devices
        .iter()
        .find(|d| matches!(text(d, "type").as_deref(), Some("udm") | Some("ugw")))
        .and_then(display_name)
}

/// Baut die Zuordnung Adresse → Gerätename neu auf.
///
/// Absichtlich vollständig neu und nicht fortgeschrieben: die Tabelle ist
/// klein, und ein Gerät, das seine Adresse abgegeben hat, soll seinen Namen
/// dort nicht behalten. Geschrieben wird in der Rangfolge Client, Gateway,
/// Gerät — das Letzte gewinnt, und ein Gerät des Controllers weiß besser, wer
/// es ist, als ein DHCP-Eintrag derselben Adresse.
async fn store_device_addresses(pool: &PgPool, devices: &[Value], networks: &[Value]) {
    let mut entries: Vec<(String, String, &str)> = Vec::new();

    let clients = sqlx::query("SELECT host(ip) AS ip, COALESCE(name, hostname, oui) AS name FROM unifi_clients WHERE ip IS NOT NULL")
        .fetch_all(pool)
        .await;
    match clients {
        Ok(rows) => {
            for r in &rows {
                let (Some(ip), Some(name)) =
                    (r.get::<Option<String>, _>("ip"), r.get::<Option<String>, _>("name"))
                else {
                    continue;
                };
                entries.push((ip, name, "client"));
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not read the client addresses");
            return;
        }
    }

    if let Some(name) = gateway_name(devices) {
        for net in networks {
            if let Some(ip) = gateway_ip(net) {
                entries.push((ip, name.clone(), "gateway"));
            }
        }
    }

    for d in devices {
        if let (Some(ip), Some(name)) = (text(d, "ip"), display_name(d)) {
            entries.push((ip, name, "device"));
        }
    }

    if entries.is_empty() {
        return;
    }

    let mut seen: Vec<String> = Vec::new();
    for (ip, name, kind) in &entries {
        let res = sqlx::query(
            "INSERT INTO device_addresses (ip, name, kind, updated_at)
             VALUES ($1::text::inet, $2, $3, NOW())
             ON CONFLICT (ip) DO UPDATE SET
                name = EXCLUDED.name, kind = EXCLUDED.kind, updated_at = NOW()",
        )
        .bind(ip)
        .bind(name)
        .bind(kind)
        .execute(pool)
        .await;
        match res {
            Ok(_) => seen.push(ip.clone()),
            Err(e) => tracing::debug!(error = %e, ip, "could not store the device address"),
        }
    }

    let res = sqlx::query("DELETE FROM device_addresses WHERE host(ip) <> ALL($1)")
        .bind(&seen)
        .execute(pool)
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "could not prune the device addresses");
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

/// Dieselben Einträge, älteste zuerst.
fn by_last_seen(clients: &[Value]) -> Vec<&Value> {
    let mut out: Vec<&Value> = clients.iter().collect();
    out.sort_by_key(|c| c.get("last_seen").and_then(|v| v.as_f64()).unwrap_or(0.0) as i64);
    out
}

async fn store_client(pool: &PgPool, c: &Value) -> bool {
    let Some(mac) = text(c, "mac") else { return false };
    // `stat/alluser` nennt die Adresse `last_ip`.
    let ip = text(c, "ip").or_else(|| text(c, "last_ip"));

    // Eine Adresse gehört immer nur einem Gerät. Ohne das trüge ein alter
    // Eintrag, dessen Adresse die DHCP-Vergabe inzwischen weitergereicht hat,
    // seinen Namen an fremden Verkehr — und schlimmer: der Join beim Lesen
    // fände zwei Zeilen und zeigte jede Log-Zeile doppelt.
    if let Some(ip) = &ip {
        let _ = sqlx::query("UPDATE unifi_clients SET ip = NULL WHERE ip = $1::text::inet AND mac <> $2::text::macaddr")
            .bind(ip)
            .bind(mac.to_lowercase())
            .execute(pool)
            .await;
    }

    let res = sqlx::query(
        "INSERT INTO unifi_clients (mac, ip, name, hostname, oui, network, is_wired, last_seen, updated_at)
         VALUES ($1::text::macaddr, $2::text::inet, $3, $4, $5, $6, $7, to_timestamp($8), NOW())
         ON CONFLICT (mac) DO UPDATE SET
            ip = EXCLUDED.ip, name = EXCLUDED.name, hostname = EXCLUDED.hostname,
            oui = EXCLUDED.oui, network = EXCLUDED.network, is_wired = EXCLUDED.is_wired,
            last_seen = EXCLUDED.last_seen, updated_at = NOW()",
    )
    .bind(mac.to_lowercase())
    .bind(ip)
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

    /// Der Weg über einen wirklichen Controller — nur auf Zuruf, weil er
    /// Netz und Zugangsdaten braucht:
    ///
    /// ```text
    /// UNIFI_URL=https://10.0.0.1 UNIFI_API_KEY=… \
    ///   cargo test -p uip-enrich -- --ignored --nocapture live_controller
    /// ```
    #[sqlx::test(migrations = "../../migrations")]
    #[ignore = "braucht einen erreichbaren Controller"]
    async fn live_controller_fills_the_policy_table(pool: PgPool) {
        let (Ok(url), Ok(key)) = (std::env::var("UNIFI_URL"), std::env::var("UNIFI_API_KEY"))
        else {
            panic!("UNIFI_URL und UNIFI_API_KEY setzen");
        };
        let site = std::env::var("UNIFI_SITE").unwrap_or_default();
        let client = Unifi::new(url, key, site);

        let zones = client.get_v2("firewall/zone").await.expect("zones");
        let policies = client.get_v2("firewall-policies").await.expect("policies");
        store_firewall_policies(&pool, &zones, &policies).await;

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT rule_key, name FROM unifi_firewall_policies ORDER BY rule_key")
                .fetch_all(&pool)
                .await
                .unwrap();
        for (key, name) in rows.iter().take(10) {
            println!("{key} → {name}");
        }
        assert_eq!(rows.len(), policies.len(), "jede Regel bekommt genau einen Schlüssel");
    }

    /// Die Tabelle, aus der beide Wege ihre Gerätenamen nehmen: die
    /// Zeilenliste beim Lesen, der Live-Strom über `/api/devices`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn device_addresses_gather_every_name_there_is(pool: PgPool) {
        // Ein Client mit eigenem Namen, einer nur mit gemeldetem Hostnamen.
        sqlx::query(
            "INSERT INTO unifi_clients (mac, ip, name, hostname) VALUES
             ('11:22:33:44:55:66'::macaddr, '10.10.15.56'::inet, 'MacBook Pro', 'macbook'),
             ('11:22:33:44:55:77'::macaddr, '10.10.15.93'::inet, NULL, 'HP1234')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let devices = vec![
            json!({"type": "udm", "name": "Express 7", "ip": "31.16.242.153"}),
            json!({"type": "uap", "name": "U7 Pro", "ip": "10.10.0.2"}),
        ];
        let networks = vec![
            json!({"purpose": "corporate", "name": "#1 - VLAN15 - Intern", "ip_subnet": "10.10.15.1/24"}),
            json!({"purpose": "wan", "name": "WAN"}),
        ];
        store_device_addresses(&pool, &devices, &networks).await;

        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT host(ip), name, kind FROM device_addresses ORDER BY ip")
                .fetch_all(&pool)
                .await
                .unwrap();
        let name_of = |ip: &str| {
            rows.iter().find(|(a, _, _)| a == ip).map(|(_, n, _)| n.clone())
        };

        assert_eq!(name_of("10.10.15.56").as_deref(), Some("MacBook Pro"));
        // Der selbst vergebene Name fehlt — dann der gemeldete.
        assert_eq!(name_of("10.10.15.93").as_deref(), Some("HP1234"));
        assert_eq!(name_of("10.10.0.2").as_deref(), Some("U7 Pro"));
        // Das Gateway meldet nur seine WAN-Adresse; unter welcher Adresse es
        // im VLAN steht, weiß nur die Netz-Konfiguration.
        assert_eq!(name_of("10.10.15.1").as_deref(), Some("Express 7"));
        assert_eq!(name_of("31.16.242.153").as_deref(), Some("Express 7"));
        // Das WAN hat keine Gateway-Adresse in diesem Sinn.
        assert_eq!(rows.len(), 5, "{rows:?}");

        // Ein Gerät, das seine Adresse abgegeben hat, behält seinen Namen
        // dort nicht: die Tabelle wird bei jedem Abgleich neu gebaut.
        sqlx::query("DELETE FROM unifi_clients WHERE ip = '10.10.15.93'::inet")
            .execute(&pool)
            .await
            .unwrap();
        store_device_addresses(&pool, &devices, &networks).await;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM device_addresses")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 4);
    }

    fn zones() -> Vec<Value> {
        vec![
            json!({"_id": "6977a4f61a33a3dda51d6e92", "zone_key": "internal", "name": "Internal"}),
            json!({"_id": "6977a4f61a33a3dda51d6e93", "zone_key": "external", "name": "External"}),
            json!({"_id": "6977a4f61a33a3dda51d6e94", "zone_key": "gateway", "name": "Gateway"}),
            json!({"_id": "6977a4f61a33a3dda51d6e97", "zone_key": "dmz", "name": "Dmz"}),
            // Selbst angelegt, absichtlich in der falschen Reihenfolge: die
            // Nummer hängt an der Kennung, nicht an der Stelle in der Liste.
            json!({"_id": "697cd15e123a22a82ec58c85", "name": "#1 - Internes Netzwerk"}),
            json!({"_id": "697bc376123a22a82ec5572b", "name": "#0 - Servernetzwerk"}),
        ]
    }

    /// Drei Vorgabezonen heißen im Log anders als im Controller, und die
    /// selbst angelegten heißen dort überhaupt nicht — sie werden gezählt.
    #[test]
    fn zones_carry_the_token_the_log_uses() {
        let tokens = zone_tokens(&zones());
        let token = |id: &str| tokens.get(id).map(|(t, _)| t.clone()).unwrap();
        assert_eq!(token("6977a4f61a33a3dda51d6e92"), "LAN");
        assert_eq!(token("6977a4f61a33a3dda51d6e93"), "WAN");
        assert_eq!(token("6977a4f61a33a3dda51d6e94"), "LOCAL");
        assert_eq!(token("6977a4f61a33a3dda51d6e97"), "DMZ");
        assert_eq!(token("697bc376123a22a82ec5572b"), "CUSTOM1");
        assert_eq!(token("697cd15e123a22a82ec58c85"), "CUSTOM2");
    }

    /// Der Regelname der Log-Zeile, aus der Regel selbst gebaut. Die Beispiele
    /// stammen aus einer laufenden Anlage: `CUSTOM2_CUSTOM1-A-10008` ist dort
    /// „VL15 -> VL10 - Allow Pihole DNS and WebUI".
    #[test]
    fn a_policy_knows_the_rule_name_it_will_log_under() {
        let tokens = zone_tokens(&zones());
        let key = |src: &str, dst: &str, action: &str, index: i64| {
            policy_key(
                &json!({
                    "source": {"zone_id": src},
                    "destination": {"zone_id": dst},
                    "action": action,
                    "index": index,
                }),
                &tokens,
            )
        };
        assert_eq!(
            key("697cd15e123a22a82ec58c85", "697bc376123a22a82ec5572b", "ALLOW", 10008).as_deref(),
            Some("CUSTOM2_CUSTOM1-A-10008")
        );
        assert_eq!(
            key("6977a4f61a33a3dda51d6e97", "6977a4f61a33a3dda51d6e94", "BLOCK", 10002).as_deref(),
            Some("DMZ_LOCAL-D-10002")
        );
        // Die vordefinierte Vorgabe am Ende jeder Kette.
        assert_eq!(
            key("6977a4f61a33a3dda51d6e94", "6977a4f61a33a3dda51d6e93", "ALLOW", 2147483647).as_deref(),
            Some("LOCAL_WAN-A-2147483647")
        );
        // Eine Regel auf eine gelöschte Zone lässt sich keiner Zeile zuordnen.
        assert_eq!(key("weg", "6977a4f61a33a3dda51d6e93", "ALLOW", 10000), None);
    }

    /// Die Zahl kommt je nach Version als Zahl oder als Zeichenkette — beim
    /// Index entschiede das sonst über einen Treffer oder keinen.
    #[test]
    fn the_index_may_arrive_as_text() {
        let tokens = zone_tokens(&zones());
        let p = json!({
            "source": {"zone_id": "6977a4f61a33a3dda51d6e92"},
            "destination": {"zone_id": "6977a4f61a33a3dda51d6e94"},
            "action": "allow",
            "index": "10000",
        });
        assert_eq!(policy_key(&p, &tokens).as_deref(), Some("LAN_LOCAL-A-10000"));
    }

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

    /// Eine Adresse gehört immer nur einem Gerät. Reicht DHCP sie weiter,
    /// muss der alte Eintrag sie abgeben — sonst fände der Join beim Lesen
    /// zwei Zeilen und zeigte jede Log-Zeile doppelt.
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_address_belongs_to_one_client_at_a_time(pool: sqlx::PgPool) {
        let old = json!({"mac": "aa:bb:cc:dd:ee:01", "last_ip": "10.0.0.5",
                         "name": "Alter Drucker", "last_seen": 1_700_000_000.0});
        let new = json!({"mac": "aa:bb:cc:dd:ee:02", "ip": "10.0.0.5",
                         "name": "Neues Notebook", "last_seen": 1_800_000_000.0});

        let both = [old, new];
        for c in by_last_seen(&both) {
            assert!(store_client(&pool, c).await);
        }

        let holders: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT name, host(ip) FROM unifi_clients ORDER BY name",
        )
        .fetch_all(&pool).await.unwrap();
        assert_eq!(
            holders,
            [("Alter Drucker".to_string(), None), ("Neues Notebook".to_string(), Some("10.0.0.5".into()))],
            "der zuletzt gesehene behält die Adresse, der andere gibt sie ab"
        );
    }

    /// `stat/alluser` nennt die Adresse `last_ip`. Nur nach `ip` zu greifen
    /// hieße, dass jedes gerade nicht verbundene Gerät namenlos bleibt — und
    /// das sind die meisten, wenn man abends ins Log schaut.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_historical_client_is_stored_under_its_last_address(pool: sqlx::PgPool) {
        let sleeping = json!({"mac": "aa:bb:cc:dd:ee:03", "last_ip": "10.0.0.9",
                              "hostname": "nas", "last_seen": 1_700_000_000.0});
        assert!(store_client(&pool, &sleeping).await);

        let (host, ip): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT hostname, host(ip) FROM unifi_clients")
                .fetch_one(&pool).await.unwrap();
        assert_eq!((host.as_deref(), ip.as_deref()), (Some("nas"), Some("10.0.0.9")));
    }

    /// Ältester zuerst — sonst entscheidet die Reihenfolge der Antwort, wer
    /// eine geteilte Adresse behält.
    #[test]
    fn clients_are_written_oldest_first() {
        let a = json!({"mac": "a", "last_seen": 300.0});
        let b = json!({"mac": "b", "last_seen": 100.0});
        let c = json!({"mac": "c"}); // ohne Angabe: ganz nach vorn
        let all = [a, b, c];
        let order: Vec<&str> = by_last_seen(&all)
            .iter()
            .map(|v| v.get("mac").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(order, ["c", "b", "a"]);
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
