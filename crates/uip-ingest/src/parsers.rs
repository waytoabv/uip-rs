use crate::firewall::{parse_firewall, FirewallCtx};
use crate::syslog::parse_header;
use chrono::{DateTime, Utc};
use uip_core::types::LogType;
use uip_core::ParsedLog;

pub fn detect_log_type(body: &str) -> LogType {
    if (body.contains("SRC=") && body.contains("DST=") && body.contains("PROTO="))
        || (body.starts_with('[') && body.contains("DESCR=")) {
        return LogType::Firewall;
    }
    if body.contains("dnsmasq-dhcp") || DHCP_EVENTS.iter().any(|ev| body.contains(ev)) {
        return LogType::Dhcp;
    }
    if body.contains("dnsmasq")
        && (body.contains("query[") || body.contains("reply ") || body.contains("forwarded ") || body.contains("cached ")) {
        return LogType::Dns;
    }
    if body.contains("stamgr") || body.contains("hostapd") || body.contains("stahtd")
        || (body.contains("STA ") && (body.contains("associated") || body.contains("authenticated"))) {
        return LogType::Wifi;
    }
    LogType::System
}

/// Die Ereignisse, die dnsmasq schreibt. `RELEASE`, `NAK`, `DECLINE` und
/// `INFORM` fehlten bisher — Zeilen darüber wurden nicht als DHCP erkannt und
/// landeten stumm im System-Topf, obwohl gerade sie die interessanten sind:
/// eine abgelehnte Anfrage oder eine zurückgegebene Adresse sagt mehr als die
/// tausendste Verlängerung.
const DHCP_EVENTS: [&str; 8] = [
    "DHCPACK",
    "DHCPREQUEST",
    "DHCPOFFER",
    "DHCPDISCOVER",
    "DHCPRELEASE",
    "DHCPNAK",
    "DHCPDECLINE",
    "DHCPINFORM",
];

/// Das Programm, das die Zeile geschrieben hat.
///
/// Der Körper einer Zeile fängt mit dem Programmnamen an, gefolgt von seiner
/// Prozessnummer in eckigen Klammern: `systemd[1]: …`. Manche Absender
/// wiederholen davor den Hostnamen („Express-7 Express-7 systemd[1]") — der
/// fällt weg, sonst hieße das Programm hier „Express-7".
fn program_of<'a>(body: &'a str, host: &str) -> Option<&'a str> {
    let rest = body.strip_prefix(host).map(str::trim_start).unwrap_or(body);
    let head = rest.split(':').next()?.trim();
    let name = head.split('[').next()?.trim();
    // Ein Programmname ist ein Wort. Steht dort ein Satz, war es keins.
    if name.is_empty() || name.len() > 64 || name.contains(' ') {
        return None;
    }
    Some(name)
}

fn word_after<'a>(body: &'a str, marker: &str) -> Option<&'a str> {
    let i = body.find(marker)? + marker.len();
    let rest = body[i..].trim_start();
    let end = rest.find(' ').unwrap_or(rest.len());
    let w = &rest[..end];
    if w.is_empty() { None } else { Some(w) }
}

pub fn parse_dns(body: &str) -> ParsedLog {
    let mut p = ParsedLog { log_type: Some(LogType::Dns), ..Default::default() };
    if let Some(i) = body.find("query[") {
        let rest = &body[i + 6..];
        if let Some(close) = rest.find(']') {
            p.dns_type = Some(rest[..close].to_string());
            let mut it = rest[close + 1..].split_whitespace();
            p.dns_query = it.next().map(str::to_string);
            if it.next() == Some("from") {
                p.src_ip = it.next().and_then(|s| s.parse().ok());
            }
            return p;
        }
    }
    for (marker, is_answer) in [("reply ", true), ("cached ", true), ("forwarded ", false)] {
        if let Some(i) = body.find(marker) {
            let mut it = body[i + marker.len()..].split_whitespace();
            p.dns_query = it.next().map(str::to_string);
            let link = it.next(); // "is" / "to"
            let val = it.next();
            match (is_answer, link, val) {
                (true, Some("is"), Some(v)) => p.dns_answer = Some(v.to_string()),
                (false, Some("to"), Some(v)) => p.dst_ip = v.parse().ok(),
                _ => { p.dns_query = None; }
            }
            return p;
        }
    }
    p
}

pub fn parse_dhcp(body: &str) -> ParsedLog {
    let mut p = ParsedLog { log_type: Some(LogType::Dhcp), ..Default::default() };
    for ev in DHCP_EVENTS {
        let Some(i) = body.find(ev) else { continue };
        let rest = &body[i + ev.len()..];
        let Some(rest) = rest.strip_prefix('(') else { continue };
        let Some(close) = rest.find(')') else { continue };
        p.dhcp_event = Some(ev.to_string());
        p.interface_in = Some(rest[..close].to_string());
        let mut it = rest[close + 1..].split_whitespace().peekable();
        // optionale IP, dann MAC, dann optionaler Hostname (nur ACK)
        if let Some(w) = it.peek() {
            if w.parse::<std::net::IpAddr>().is_ok() {
                p.src_ip = it.next().and_then(|s| s.parse().ok());
            }
        }
        p.mac_address = it.next().map(str::to_string);
        // Den Namen schreibt dnsmasq hinter die MAC, wenn das Gerät einen
        // gemeldet hat — nicht nur beim ACK.
        p.hostname = it.next().map(str::to_string).filter(|h| !h.starts_with('<'));
        return p;
    }
    p
}

/// Die Ereignisse, die ein Access Point über eine Station schreibt.
///
/// Die Reihenfolge ist die Lesereihenfolge, nicht das Alphabet: `disassoc`
/// vor `assoc`, weil das eine im anderen steckt und sonst jede Trennung als
/// Verbindung gälte.
const WIFI_EVENTS: [&str; 8] = [
    "disassociated",
    "deauthenticated",
    "associated",
    "authenticated",
    "disconnected",
    "connected",
    "key handshake completed",
    "roamed",
];

pub fn parse_wifi(body: &str) -> ParsedLog {
    let mut p = ParsedLog { log_type: Some(LogType::Wifi), ..Default::default() };
    if body.contains("stahtd") {
        if let Some(i) = body.find('{') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body[i..]) {
                p.mac_address = v.get("mac").and_then(|m| m.as_str()).map(str::to_string);
                p.wifi_event = v.get("event_type").or_else(|| v.get("message_type"))
                    .and_then(|e| e.as_str()).map(str::to_string)
                    .or_else(|| Some("stahtd".into()));
                // Was der Access Point sonst noch mitschickt — Kanal,
                // Signalstärke, Grund einer Trennung —, steht in derselben
                // Struktur und ging bisher verloren.
                p.details = Some(v);
                return p;
            }
        }
        p.wifi_event = Some("stahtd".into());
        return p;
    }
    // `hostapd: ath0: STA aa:bb:… IEEE 802.11: associated`
    if let Some(iface) = body.split_once(": ").and_then(|(_, rest)| rest.split_once(": ")) {
        let name = iface.0.trim();
        if !name.is_empty() && !name.contains(' ') && name.len() <= 20 {
            p.interface_in = Some(name.to_string());
        }
    }
    if let Some(mac) = word_after(body, "STA ") {
        p.mac_address = Some(mac.to_string());
    }
    for ev in WIFI_EVENTS {
        if body.contains(ev) {
            p.wifi_event = Some(ev.to_string());
            break;
        }
    }
    // Kein bekanntes Wort: dann das, was hinter dem letzten Doppelpunkt
    // steht. Eine Zeile, deren Ereignis wir nicht kennen, ist immer noch
    // besser als eine leere Spalte — und der Rohtext steht daneben.
    if p.wifi_event.is_none() {
        if let Some((_, tail)) = body.rsplit_once(": ") {
            let tail = tail.trim();
            if !tail.is_empty() && tail.len() <= 60 {
                p.wifi_event = Some(tail.to_string());
            }
        }
    }
    p
}

fn valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Komplette Zeile → ParsedLog. None, wenn schon der Header nicht passt;
/// der Aufrufer persistiert die Zeile dann als System-Log mit raw.
pub fn parse_log(raw: &str, now: DateTime<Utc>, ctx: &FirewallCtx) -> Option<ParsedLog> {
    let h = parse_header(raw, now)?;
    // Die Ereignisse des Gateways kommen über dasselbe Syslog, tragen aber
    // ihr eigenes Format — und deutlich mehr Information als die Zeile, in
    // der sie stecken.
    let mut p = if crate::cef::is_cef(h.body) {
        crate::cef::parse_cef(h.body)
            .unwrap_or_else(|| ParsedLog { log_type: Some(LogType::System), ..Default::default() })
    } else {
        let mut p = match detect_log_type(h.body) {
            LogType::Firewall => parse_firewall(h.body, ctx),
            LogType::Dns => parse_dns(h.body),
            LogType::Dhcp => parse_dhcp(h.body),
            LogType::Wifi => parse_wifi(h.body),
            LogType::System => ParsedLog { log_type: Some(LogType::System), ..Default::default() },
        };
        p.program = program_of(h.body, h.host).map(str::to_string);
        p.severity = h.priority.map(crate::syslog::severity_of);
        p
    };
    p.timestamp = Some(h.timestamp);
    p.raw_log = raw.to_string();
    if let Some(m) = &p.mac_address {
        if !valid_mac(m) { p.mac_address = None; }
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallCtx;
    use chrono::{TimeZone, Utc};
    use uip_core::types::LogType;

    fn now() -> chrono::DateTime<Utc> { Utc.with_ymd_and_hms(2026, 9, 13, 12, 0, 0).unwrap() }
    fn ctx() -> FirewallCtx { FirewallCtx::default() }

    #[test]
    fn detect_types() {
        assert_eq!(detect_log_type("kernel: [X]IN=a OUT=b SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP"), LogType::Firewall);
        assert_eq!(detect_log_type("dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff host1"), LogType::Dhcp);
        assert_eq!(detect_log_type("dnsmasq[1234]: query[A] example.com from 192.168.1.5"), LogType::Dns);
        assert_eq!(detect_log_type("hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated"), LogType::Wifi);
        assert_eq!(detect_log_type("systemd[1]: Started thing."), LogType::System);
    }

    #[test]
    fn dns_query_reply_forward_cached() {
        let p = parse_dns("dnsmasq[1234]: query[A] example.com from 192.168.1.5");
        assert_eq!(p.dns_type.as_deref(), Some("A"));
        assert_eq!(p.dns_query.as_deref(), Some("example.com"));
        assert_eq!(p.src_ip.unwrap().to_string(), "192.168.1.5");
        let p = parse_dns("dnsmasq[1234]: reply example.com is 1.2.3.4");
        assert_eq!(p.dns_answer.as_deref(), Some("1.2.3.4"));
        let p = parse_dns("dnsmasq[1234]: forwarded example.com to 8.8.8.8");
        assert_eq!(p.dst_ip.unwrap().to_string(), "8.8.8.8");
        let p = parse_dns("dnsmasq[1234]: cached example.com is 1.2.3.4");
        assert_eq!(p.dns_answer.as_deref(), Some("1.2.3.4"));
        let p = parse_dns("dnsmasq[1234]: some unknown line");
        assert_eq!(p.dns_query, None);
    }

    #[test]
    fn dhcp_events() {
        let p = parse_dhcp("dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff myhost");
        assert_eq!(p.dhcp_event.as_deref(), Some("DHCPACK"));
        assert_eq!(p.interface_in.as_deref(), Some("br0"));
        assert_eq!(p.src_ip.unwrap().to_string(), "192.168.1.100");
        assert_eq!(p.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(p.hostname.as_deref(), Some("myhost"));
        let p = parse_dhcp("dnsmasq-dhcp[1234]: DHCPDISCOVER(br0) aa:bb:cc:dd:ee:ff");
        assert_eq!(p.dhcp_event.as_deref(), Some("DHCPDISCOVER"));
        assert_eq!(p.src_ip, None);
        let p = parse_dhcp("dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff");
        assert_eq!(p.hostname, None);
    }

    #[test]
    fn wifi_assoc() {
        let p = parse_wifi("hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated");
        assert_eq!(p.wifi_event.as_deref(), Some("associated"));
        assert_eq!(p.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        let p = parse_wifi(r#"stahtd[999]: stahtd: {"mac":"aa:bb:cc:dd:ee:ff","event_type":"probe"}"#);
        assert_eq!(p.wifi_event.as_deref(), Some("probe"));
    }

    /// Die WLAN-Spalte zeigte bisher fast immer nichts: erkannt wurden vier
    /// Wörter, alles andere blieb leer — und der Rohtext wurde nicht einmal
    /// gespeichert.
    #[test]
    fn wifi_lines_say_what_happened() {
        let p = parse_wifi("hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated");
        assert_eq!(p.wifi_event.as_deref(), Some("associated"));
        assert_eq!(p.interface_in.as_deref(), Some("ath0"));

        // „disassociated" enthält „associated" — die Reihenfolge entscheidet.
        let p = parse_wifi("hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: disassociated");
        assert_eq!(p.wifi_event.as_deref(), Some("disassociated"));

        // Unbekanntes Ereignis: lieber der Satz als gar nichts.
        let p = parse_wifi("hostapd: ath0: STA aa:bb:cc:dd:ee:ff WPA: group key handshake completed");
        assert_eq!(p.wifi_event.as_deref(), Some("key handshake completed"));

        let p = parse_wifi(r#"stahtd[999]: stahtd: {"mac":"aa:bb:cc:dd:ee:ff","event_type":"probe","rssi":-61}"#);
        assert_eq!(p.wifi_event.as_deref(), Some("probe"));
        assert_eq!(p.details.unwrap()["rssi"], -61);
    }

    #[test]
    fn dhcp_events_beyond_the_common_four() {
        // Eine zurückgegebene Adresse war bisher keine DHCP-Zeile, sondern
        // eine namenlose System-Zeile.
        assert_eq!(
            detect_log_type("dnsmasq-dhcp[123]: DHCPRELEASE(br15) 10.10.15.93 ac:df:a1:08:fc:26"),
            LogType::Dhcp
        );
        let p = parse_dhcp("dnsmasq-dhcp[123]: DHCPRELEASE(br15) 10.10.15.93 ac:df:a1:08:fc:26");
        assert_eq!(p.dhcp_event.as_deref(), Some("DHCPRELEASE"));
        assert_eq!(p.src_ip.unwrap().to_string(), "10.10.15.93");
        let p = parse_dhcp("dnsmasq-dhcp[123]: DHCPNAK(br15) 10.10.15.93 ac:df:a1:08:fc:26 wrong network");
        assert_eq!(p.dhcp_event.as_deref(), Some("DHCPNAK"));
    }

    /// Der Name des Geräts steht hinter der MAC — auch bei REQUEST, nicht nur
    /// beim ACK. Ihn dort wegzulassen hieß, eine Zeile ohne Not namenlos zu
    /// lassen.
    #[test]
    fn dhcp_takes_the_name_wherever_it_stands() {
        let p = parse_dhcp("dnsmasq-dhcp[123]: DHCPREQUEST(br15) 10.10.15.93 ac:df:a1:08:fc:26 Annas-iPhone");
        assert_eq!(p.hostname.as_deref(), Some("Annas-iPhone"));
    }

    /// Programm und Schweregrad stehen in jeder Zeile und wurden bisher
    /// weggeworfen. Ohne sie sind siebenundzwanzigtausend System-Zeilen am Tag
    /// nicht zu sortieren.
    #[test]
    fn a_system_line_knows_its_program_and_severity() {
        let p = parse_log(
            "<30>Sep 19 08:14:32 Express-7 Express-7 systemd[1]: systemd-timedated.service: Succeeded.",
            now(),
            &ctx(),
        )
        .unwrap();
        assert_eq!(p.log_type, Some(LogType::System));
        assert_eq!(p.program.as_deref(), Some("systemd"), "der doppelte Hostname zählt nicht");
        assert_eq!(p.severity, Some(6));

        let p = parse_log("<11>Sep 19 07:49:50 Express-7 Express-7 mca-ctrl[2020070]: fail", now(), &ctx()).unwrap();
        assert_eq!(p.program.as_deref(), Some("mca-ctrl"));
        assert_eq!(p.severity, Some(3), "11 = Facility 1, Severity 3 (error)");

        // Ohne Priorität keine Behauptung über die Dringlichkeit.
        let p = parse_log("Sep 19 07:49:50 UDR kernel: x", now(), &ctx()).unwrap();
        assert_eq!(p.severity, None);
        assert_eq!(p.program.as_deref(), Some("kernel"));
    }

    /// Die Ereignisse des Gateways kommen über dasselbe Syslog und wurden
    /// bisher als Rohtext abgelegt.
    #[test]
    fn a_cef_event_from_the_gateway_is_parsed() {
        let p = parse_log(
            "Sep 19 08:04:24 Express-7 CEF:0|Ubiquiti|UniFi Network|10.6.106|400|WiFi Client Connected|1|UNIFIclientAlias=iPhone Air UNIFIclientMac=70:13:84:65:dc:3a UNIFIclientIp=10.10.15.98 UNIFIwifiName=#1 msg=iPhone Air connected to #1 on U7 Pro.",
            now(),
            &ctx(),
        )
        .unwrap();
        assert_eq!(p.log_type, Some(LogType::Wifi));
        assert_eq!(p.wifi_event.as_deref(), Some("connected"));
        assert_eq!(p.program.as_deref(), Some("unifi"));
        assert_eq!(p.details.unwrap()["wifiName"], "#1");
    }

    #[test]
    fn full_line_dispatch_and_invalid_mac_dropped() {
        let p = parse_log("Feb  8 16:43:49 UDR dnsmasq[1234]: query[A] example.com from 192.168.1.5", now(), &ctx()).unwrap();
        assert_eq!(p.log_type, Some(LogType::Dns));
        assert!(p.timestamp.is_some());
        assert_eq!(p.raw_log, "Feb  8 16:43:49 UDR dnsmasq[1234]: query[A] example.com from 192.168.1.5");
        // Fork-Fixture: verkürzte MAC wird verworfen statt DB-Fehler
        let p = parse_log("Feb  8 16:43:49 UDR hostapd: ath0: STA aa:bb:cc IEEE 802.11: associated", now(), &ctx()).unwrap();
        assert_eq!(p.mac_address, None);
        // Header kaputt → None (Aufrufer speichert raw als System-Zeile)
        assert!(parse_log("garbage", now(), &ctx()).is_none());
    }
}
