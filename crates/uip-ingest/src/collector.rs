//! Der eigene Syslog-Verkehr — gezählt statt gespeichert.
//!
//! Das Gateway meldet jede Firewall-Entscheidung per Syslog hierher. Diese
//! Meldungen laufen selbst über das Netz, also schreibt das Gateway auch
//! darüber eine Firewall-Zeile: „10.10.15.1:56369 → 10.10.15.56:514". Bei
//! einigen tausend Zeilen pro Minute ist das der lauteste Absender überhaupt,
//! und er sagt nichts, was man nicht schon weiß.
//!
//! Also: nicht schreiben. Was davon bleibt, ist die einzige Aussage, die
//! darin steckt — dass die Verbindung steht. Die steht als Zähler in den
//! Einstellungen.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use uip_core::types::LogType;
use uip_core::ParsedLog;

/// Wie oft der Zählerstand festgehalten wird.
const PERSIST_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// Was der Empfänger über sich selbst weiß.
#[derive(Clone)]
pub struct Collector {
    /// Der Port, auf dem wir lauschen.
    port: i32,
    /// Unsere eigenen Adressen, wie die Geräte sie sehen. Wird gelernt, nicht
    /// eingestellt — siehe `learn_local_address`.
    local: Arc<Mutex<HashSet<IpAddr>>>,
    /// Ob der eigene Verkehr verworfen wird. Vorgabe: ja.
    drop_own: Arc<AtomicBool>,
    /// Empfangene Meldungen, seit dem Start.
    received: Arc<AtomicU64>,
    /// Davon verworfene Firewall-Zeilen über den eigenen Verkehr.
    dropped: Arc<AtomicU64>,
}

impl Collector {
    pub fn new(port: i32) -> Self {
        Self {
            port,
            local: Arc::new(Mutex::new(HashSet::new())),
            drop_own: Arc::new(AtomicBool::new(true)),
            received: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_drop_own(&self, on: bool) {
        self.drop_own.store(on, Ordering::Relaxed);
    }

    pub fn count_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    /// Merkt sich, unter welcher Adresse uns dieser Absender erreicht.
    ///
    /// Gelernt statt eingestellt: der Empfänger lauscht auf `0.0.0.0`, und
    /// `local_addr` verrät dann nichts. Ein verbundener UDP-Socket lässt den
    /// Kernel die Quelladresse wählen, die er für genau diesen Weg nähme —
    /// das ist die Adresse, an die das Gerät sendet. Es wird dabei nichts
    /// verschickt.
    pub fn learn_local_address(&self, peer: SocketAddr) {
        let Ok(probe) = std::net::UdpSocket::bind(match peer {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        }) else {
            return;
        };
        if probe.connect(peer).is_err() {
            return;
        }
        let Ok(addr) = probe.local_addr() else { return };
        if let Ok(mut set) = self.local.lock() {
            if set.insert(addr.ip()) {
                tracing::info!(address = %addr.ip(), %peer, "collector reachable at");
            }
        }
    }

    /// Ob diese Zeile den Weg der Log-Meldungen selbst beschreibt.
    ///
    /// Nur Firewall-Zeilen, nur der eingestellte Port, und nur wenn eine der
    /// beiden Seiten wir selbst sind: Syslog zwischen zwei anderen Rechnern
    /// ist gewöhnlicher Verkehr und bleibt sichtbar.
    pub fn is_own_syslog(&self, p: &ParsedLog) -> bool {
        if p.log_type != Some(LogType::Firewall) {
            return false;
        }
        let Ok(local) = self.local.lock() else { return false };
        let to_us = p.dst_port == Some(self.port) && p.dst_ip.is_some_and(|ip| local.contains(&ip));
        let from_us = p.src_port == Some(self.port) && p.src_ip.is_some_and(|ip| local.contains(&ip));
        to_us || from_us
    }

    /// Wahr, wenn die Zeile verworfen werden soll — und zählt sie dabei.
    pub fn should_drop(&self, p: &ParsedLog) -> bool {
        if !self.drop_own.load(Ordering::Relaxed) || !self.is_own_syslog(p) {
            return false;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn snapshot(&self) -> serde_json::Value {
        let addresses: Vec<String> = self
            .local
            .lock()
            .map(|s| s.iter().map(|ip| ip.to_string()).collect())
            .unwrap_or_default();
        serde_json::json!({
            "received": self.received.load(Ordering::Relaxed),
            "dropped": self.dropped.load(Ordering::Relaxed),
            "port": self.port,
            "addresses": addresses,
            "at": chrono::Utc::now().to_rfc3339(),
        })
    }
}

/// Die WAN-Adressen, die gerade gelten.
///
/// Die eingetippte Angabe gewinnt, wenn es eine gibt — wer sie setzt, meint
/// sie. Sonst gilt, was der Controller gemeldet hat. Vereinigt statt
/// ausgewählt wäre falsch: eine alte, von Hand eingetragene Adresse bliebe
/// dann für immer gültig.
async fn effective_wan_ips(pool: &PgPool) -> HashSet<IpAddr> {
    let parse = |v: Option<serde_json::Value>| -> HashSet<IpAddr> {
        v.and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    };
    let manual = parse(uip_core::settings::get_config(pool, "wan_ips").await);
    if !manual.is_empty() {
        return manual;
    }
    parse(uip_core::settings::get_config(pool, "wan_ips_detected").await)
}

/// Die WAN-Schnittstellen, die gerade gelten.
///
/// Anders als bei den Adressen gewinnt hier die *erkannte* Fassung vor dem
/// Startwert: `UIP_WAN_IFACES` steht mit „ppp0" in jeder frisch erzeugten
/// Umgebungsdatei, ohne dass es jemand so gewählt hätte. Ein Gateway mit
/// `eth1` am Anbieter bekäme damit für immer die falsche Richtung. Nur eine
/// ausdrücklich gesetzte Einstellung schlägt die Beobachtung.
async fn effective_wan_interfaces(pool: &PgPool, fallback: &HashSet<String>) -> HashSet<String> {
    let parse = |v: Option<serde_json::Value>| -> HashSet<String> {
        v.and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    };
    let manual = parse(uip_core::settings::get_config(pool, "wan_interfaces").await);
    if !manual.is_empty() {
        return manual;
    }
    let detected = parse(uip_core::settings::get_config(pool, "wan_interfaces_detected").await);
    if !detected.is_empty() {
        return detected;
    }
    fallback.clone()
}

/// Bringt die Richtung schon gespeicherter Zeilen mit den WAN-Schnittstellen
/// in Übereinstimmung.
///
/// Solange die falsche Schnittstelle als WAN galt, war keine Seite je „WAN",
/// und `derive_direction` fiel auf `inter_vlan` oder `local` zurück. Das
/// betrifft die gesamte Historie, nicht nur die nächste Zeile — ein Filter auf
/// „inbound" fand deshalb nichts.
///
/// Angefasst wird ausschließlich, was genau daran krankt: Zeilen mit `local`
/// oder `inter_vlan`, bei denen heute genau eine Seite ans WAN zeigt. Alles
/// mit eigener Begründung — `nat` aus dem Regelnamen, `vpn` aus dem Präfix —
/// bleibt, wie es ist.
async fn correct_directions(pool: &PgPool, wan: &HashSet<String>) {
    if wan.is_empty() {
        return;
    }
    let names: Vec<String> = wan.iter().map(|s| s.to_lowercase()).collect();
    // `lower(name) = ANY(...)` ist NULL, sobald die Seite fehlt — und NULL <>
    // FALSE ist wieder NULL, die Zeile fiele stumm durch. COALESCE macht aus
    // „keine Schnittstelle" ein ehrliches „kein WAN", damit `IN=- OUT=eth1`
    // als ausgehend erkannt wird statt übersprungen.
    let res = sqlx::query(
        "UPDATE logs l SET direction_id = d.dir
         FROM (
            SELECT src.timestamp, src.id,
                   CASE WHEN COALESCE(lower(ii.name) = ANY($1), FALSE)
                        THEN 1::smallint ELSE 2::smallint END AS dir
            FROM logs src
            LEFT JOIN interfaces ii ON ii.id = src.iface_in_id
            LEFT JOIN interfaces io ON io.id = src.iface_out_id
            WHERE src.log_type_id = 1
              AND src.direction_id IN (3, 4)
              AND COALESCE(lower(ii.name) = ANY($1), FALSE)
                  <> COALESCE(lower(io.name) = ANY($1), FALSE)
         ) d
         WHERE l.timestamp = d.timestamp AND l.id = d.id",
    )
    .bind(&names)
    .execute(pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            tracing::info!(rows = r.rows_affected(), "corrected the direction of stored rows")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "could not correct stored directions"),
    }
}

/// Hält den Zählerstand fest und liest die Einstellung nach.
///
/// Der Zählerstand ist zugleich der Herzschlag: er wird auch dann neu
/// geschrieben, wenn nichts ankam. Bleibt der Zeitstempel stehen, läuft der
/// Empfänger nicht mehr — und das sieht von außen sonst genauso aus wie ein
/// stilles Netz.
pub async fn run_bookkeeping(collector: Collector, ctx: crate::firewall::FirewallCtx, pool: PgPool) {
    let startup_ifaces: HashSet<String> = ctx.wan_interfaces.load().as_ref().clone();
    loop {
        let on = uip_core::settings::get_config(&pool, "drop_syslog_traffic")
            .await
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        collector.set_drop_own(on);
        ctx.set_wan_ips(effective_wan_ips(&pool).await);

        // Ändert sich, was als WAN gilt, stimmt auch die Richtung der bereits
        // gespeicherten Zeilen nicht mehr. Einmal je Änderung, nicht je Runde.
        let wan = effective_wan_interfaces(&pool, &startup_ifaces).await;
        if ctx.set_wan_interfaces(wan.clone()) {
            correct_directions(&pool, &wan).await;
        }

        uip_core::settings::put_config(&pool, "syslog_stats", collector.snapshot()).await;
        tokio::time::sleep(PERSIST_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uip_core::types::LogType;

    fn row(src: &str, sport: i32, dst: &str, dport: i32, kind: LogType) -> ParsedLog {
        ParsedLog {
            log_type: Some(kind),
            src_ip: src.parse().ok(),
            dst_ip: dst.parse().ok(),
            src_port: Some(sport),
            dst_port: Some(dport),
            ..Default::default()
        }
    }

    fn collector_at(addr: &str) -> Collector {
        let c = Collector::new(514);
        c.local.lock().unwrap().insert(addr.parse().unwrap());
        c
    }

    #[test]
    fn traffic_to_our_own_syslog_port_is_dropped() {
        let c = collector_at("10.10.15.56");
        let own = row("10.10.15.1", 56369, "10.10.15.56", 514, LogType::Firewall);
        assert!(c.should_drop(&own));
        assert_eq!(c.snapshot()["dropped"], 1);
    }

    /// Syslog zwischen zwei anderen Rechnern ist gewöhnlicher Verkehr. Ihn
    /// mitzuverwerfen hieße, dem Betreiber genau das zu verbergen, wofür er
    /// mitliest.
    #[test]
    fn syslog_between_other_hosts_stays() {
        let c = collector_at("10.10.15.56");
        let elsewhere = row("10.10.20.5", 45000, "10.10.20.9", 514, LogType::Firewall);
        assert!(!c.should_drop(&elsewhere));
    }

    /// Eine DNS- oder System-Zeile über Port 514 ist keine Beschreibung des
    /// Transportwegs, sondern Inhalt.
    #[test]
    fn only_firewall_rows_describe_the_transport() {
        let c = collector_at("10.10.15.56");
        let dns = row("10.10.15.1", 56369, "10.10.15.56", 514, LogType::Dns);
        assert!(!c.should_drop(&dns));
    }

    #[test]
    fn a_switched_off_filter_keeps_everything() {
        let c = collector_at("10.10.15.56");
        c.set_drop_own(false);
        let own = row("10.10.15.1", 56369, "10.10.15.56", 514, LogType::Firewall);
        assert!(!c.should_drop(&own));
        assert_eq!(c.snapshot()["dropped"], 0, "was bleibt, wird nicht gezählt");
    }

    /// Ohne gelernte Adresse darf nichts verworfen werden — sonst verschwände
    /// beim Start fremder Syslog-Verkehr, nur weil der Port stimmt.
    #[test]
    fn nothing_is_dropped_before_we_know_our_address() {
        let c = Collector::new(514);
        let own = row("10.10.15.1", 56369, "10.10.15.56", 514, LogType::Firewall);
        assert!(!c.should_drop(&own));
    }

    /// Die Gegenrichtung zählt auch: „von uns, Quellport 514".
    #[test]
    fn the_other_direction_counts_too() {
        let c = collector_at("10.10.15.56");
        let from_us = row("10.10.15.56", 514, "10.10.15.1", 33333, LogType::Firewall);
        assert!(c.should_drop(&from_us));
    }

    /// Die Historie muss mit: solange die falsche Schnittstelle als WAN galt,
    /// war keine Seite „WAN", und alles landete bei `inter_vlan` oder `local`.
    /// Ein Filter auf „inbound" fand deshalb nichts.
    #[sqlx::test(migrations = "../../migrations")]
    async fn stored_rows_follow_a_corrected_wan_interface(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO interfaces (name) VALUES ('eth1'), ('br10'), ('br15')")
            .execute(&pool).await.unwrap();
        // 1=eth1, 2=br10, 3=br15
        let rows: [(i16, Option<i16>, Option<i16>); 5] = [
            (4, Some(2), Some(1)), // br10 → eth1: in Wahrheit ausgehend
            (4, Some(1), Some(2)), // eth1 → br10: eingehend
            (4, Some(2), Some(3)), // br10 → br15: bleibt zwischen VLANs
            (3, None, Some(1)),    // - → eth1: ausgehend, obwohl eine Seite fehlt
            (3, Some(2), None),    // br10 → -: bleibt lokal
        ];
        for (dir, i, o) in rows {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, direction_id, iface_in_id, iface_out_id, src_ip)
                 VALUES (NOW(), 1, $1, $2, $3, '10.0.0.1')",
            )
            .bind(dir).bind(i).bind(o)
            .execute(&pool).await.unwrap();
        }

        let wan: HashSet<String> = ["eth1".to_string()].into_iter().collect();
        correct_directions(&pool, &wan).await;

        let out: Vec<Option<i16>> = sqlx::query_scalar(
            "SELECT direction_id FROM logs ORDER BY iface_in_id NULLS LAST, iface_out_id NULLS LAST",
        )
        .fetch_all(&pool).await.unwrap();
        // eth1→br10 eingehend, br10→eth1 ausgehend, br10→br15 unverändert,
        // br10→- unverändert lokal, -→eth1 ausgehend.
        assert_eq!(out, [Some(1), Some(2), Some(4), Some(3), Some(2)]);

        // Ein zweiter Lauf ändert nichts mehr.
        correct_directions(&pool, &wan).await;
        let again: Vec<Option<i16>> = sqlx::query_scalar(
            "SELECT direction_id FROM logs ORDER BY iface_in_id NULLS LAST, iface_out_id NULLS LAST",
        )
        .fetch_all(&pool).await.unwrap();
        assert_eq!(again, out, "die Korrektur ist wiederholbar");
    }

    /// Ohne bekanntes WAN wird nichts angefasst — sonst schriebe ein leerer
    /// Satz die ganze Historie auf „ausgehend".
    #[sqlx::test(migrations = "../../migrations")]
    async fn nothing_is_corrected_without_a_wan_interface(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO interfaces (name) VALUES ('eth1')").execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, direction_id, iface_out_id, src_ip)
             VALUES (NOW(), 1, 4, 1, '10.0.0.1')",
        ).execute(&pool).await.unwrap();

        correct_directions(&pool, &HashSet::new()).await;
        let dir: Option<i16> = sqlx::query_scalar("SELECT direction_id FROM logs")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(dir, Some(4));
    }

    /// Die Adresse wird gelernt, nicht eingestellt.
    #[test]
    fn the_local_address_is_learned_from_the_sender() {
        let c = Collector::new(514);
        c.learn_local_address("127.0.0.1:514".parse().unwrap());
        let loopback = row("127.0.0.1", 40000, "127.0.0.1", 514, LogType::Firewall);
        assert!(c.should_drop(&loopback), "über die Rückschleife sind wir 127.0.0.1");
    }
}
