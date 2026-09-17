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

/// Hält den Zählerstand fest und liest die Einstellung nach.
///
/// Der Zählerstand ist zugleich der Herzschlag: er wird auch dann neu
/// geschrieben, wenn nichts ankam. Bleibt der Zeitstempel stehen, läuft der
/// Empfänger nicht mehr — und das sieht von außen sonst genauso aus wie ein
/// stilles Netz.
pub async fn run_bookkeeping(collector: Collector, ctx: crate::firewall::FirewallCtx, pool: PgPool) {
    loop {
        let on = uip_core::settings::get_config(&pool, "drop_syslog_traffic")
            .await
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        collector.set_drop_own(on);
        ctx.set_wan_ips(effective_wan_ips(&pool).await);

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

    /// Die Adresse wird gelernt, nicht eingestellt.
    #[test]
    fn the_local_address_is_learned_from_the_sender() {
        let c = Collector::new(514);
        c.learn_local_address("127.0.0.1:514".parse().unwrap());
        let loopback = row("127.0.0.1", 40000, "127.0.0.1", 514, LogType::Firewall);
        assert!(c.should_drop(&loopback), "über die Rückschleife sind wir 127.0.0.1");
    }
}
