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
    if body.contains("dnsmasq-dhcp") || body.contains("DHCPACK") || body.contains("DHCPDISCOVER")
        || body.contains("DHCPREQUEST") || body.contains("DHCPOFFER") {
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
    for ev in ["DHCPACK", "DHCPREQUEST", "DHCPOFFER", "DHCPDISCOVER"] {
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
        if ev == "DHCPACK" {
            p.hostname = it.next().map(str::to_string);
        }
        return p;
    }
    p
}

pub fn parse_wifi(body: &str) -> ParsedLog {
    let mut p = ParsedLog { log_type: Some(LogType::Wifi), ..Default::default() };
    if body.contains("stahtd") {
        if let Some(i) = body.find('{') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body[i..]) {
                p.mac_address = v.get("mac").and_then(|m| m.as_str()).map(str::to_string);
                p.wifi_event = v.get("event_type").or_else(|| v.get("message_type"))
                    .and_then(|e| e.as_str()).map(str::to_string)
                    .or_else(|| Some("stahtd".into()));
                return p;
            }
        }
        p.wifi_event = Some("stahtd".into());
        return p;
    }
    if let Some(mac) = word_after(body, "STA ") {
        p.mac_address = Some(mac.to_string());
        for ev in ["disassociated", "deauthenticated", "associated", "authenticated"] {
            if body.contains(ev) {
                p.wifi_event = Some(ev.to_string());
                break;
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
    let mut p = match detect_log_type(h.body) {
        LogType::Firewall => parse_firewall(h.body, ctx),
        LogType::Dns => parse_dns(h.body),
        LogType::Dhcp => parse_dhcp(h.body),
        LogType::Wifi => parse_wifi(h.body),
        LogType::System => ParsedLog { log_type: Some(LogType::System), ..Default::default() },
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
