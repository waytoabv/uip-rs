//! Die Ereignisse des Gateways, im Common Event Format.
//!
//! Über dasselbe Syslog, aus dem die Firewall-Zeilen kommen, schickt der
//! Controller seine eigenen Ereignisse — und die wissen Dinge, die in keiner
//! iptables-Zeile stehen: zu welchem Access Point ein Gerät sich verbunden
//! hat, auf welchem Kanal, mit welcher Signalstärke; welche Domain hinter der
//! blockierten Adresse steckt und als welche Anwendung der Verkehr erkannt
//! wurde; wer wann welche Einstellung geändert hat.
//!
//! Bisher landete das alles als Rohtext im System-Topf. Eine dieser Zeilen,
//! ungekürzt:
//!
//! ```text
//! CEF:0|Ubiquiti|UniFi Network|10.6.106|400|WiFi Client Connected|1|
//!   UNIFIconnectedToDeviceName=U7 Pro UNIFIclientAlias=iPhone Air
//!   UNIFIclientIp=10.10.15.98 UNIFIwifiChannel=37 UNIFIwifiName=#1
//!   UNIFIWiFiRssi=-60 msg=iPhone Air connected to #1 on U7 Pro. …
//! ```
//!
//! Das Format ist einfach: sieben Kopffelder, durch `|` getrennt, danach
//! Schlüssel-Wert-Paare. Die Werte dürfen Leerzeichen enthalten — „U7 Pro",
//! „VL10 -> WAN - Drop All" —, ein Paar endet also erst dort, wo der nächste
//! Schlüssel anfängt.

use serde_json::{Map, Value};
use uip_core::types::{LogType, RuleAction};
use uip_core::ParsedLog;

/// Ob diese Zeile ein CEF-Ereignis ist.
pub fn is_cef(body: &str) -> bool {
    body.starts_with("CEF:")
}

/// Die Kopffelder: Version, Hersteller, Produkt, Produktversion,
/// Signatur-Id, Name, Schweregrad.
struct Header<'a> {
    signature: &'a str,
    name: &'a str,
    severity: &'a str,
    extension: &'a str,
}

fn split_header(body: &str) -> Option<Header<'_>> {
    let mut parts = body.splitn(8, '|');
    let _version = parts.next()?;
    let _vendor = parts.next()?;
    let _product = parts.next()?;
    let _product_version = parts.next()?;
    let signature = parts.next()?;
    let name = parts.next()?;
    let severity = parts.next()?;
    let extension = parts.next().unwrap_or("");
    Some(Header { signature, name, severity, extension })
}

/// Wo im Text ein neues Schlüssel-Wert-Paar beginnt.
///
/// Ein Schlüssel steht am Anfang oder hinter einem Leerzeichen, besteht aus
/// Buchstaben und Ziffern und endet auf `=`. Alles andere gehört zum Wert des
/// vorigen Schlüssels — sonst zerfiele „VL10 -> WAN - Drop All" in Bruchstücke.
fn key_starts(ext: &str) -> Vec<(usize, usize)> {
    let bytes = ext.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let at_start = i == 0 || bytes[i - 1] == b' ';
        if at_start && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' && j > i {
                out.push((i, j));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Die Erweiterung als Schlüssel-Wert-Paare. Das Präfix `UNIFI` fällt weg —
/// es steht vor fast jedem Schlüssel und sagt nichts, was der Rest nicht
/// schon sagt.
pub fn extension(ext: &str) -> Map<String, Value> {
    let keys = key_starts(ext);
    let mut out = Map::new();
    for (n, &(start, eq)) in keys.iter().enumerate() {
        let end = keys.get(n + 1).map(|&(next, _)| next).unwrap_or(ext.len());
        let key = &ext[start..eq];
        let key = key.strip_prefix("UNIFI").unwrap_or(key);
        let value = ext[eq + 1..end].trim();
        if value.is_empty() || value == "null" {
            continue;
        }
        let mut key = key.to_string();
        // Die Schreibweise der Schlüssel ist uneinheitlich (`clientIp`,
        // `WiFiRssi`, `dst`) — der erste Buchstabe wird klein, damit sie in
        // der Detailzeile nicht wie zwei verschiedene Sorten aussehen.
        if let Some(first) = key.get_mut(..1) {
            first.make_ascii_lowercase();
        }
        out.insert(key, Value::String(value.to_string()));
    }
    out
}

fn text(fields: &Map<String, Value>, key: &str) -> Option<String> {
    fields.get(key)?.as_str().map(str::to_string)
}

fn ip(fields: &Map<String, Value>, key: &str) -> Option<std::net::IpAddr> {
    text(fields, key)?.parse().ok()
}

fn port(fields: &Map<String, Value>, key: &str) -> Option<i32> {
    text(fields, key)?.parse().ok()
}

/// Der CEF-Schweregrad (0–10) auf die Syslog-Skala (0–7, kleiner ist
/// dringender). Grob, aber in derselben Richtung — und nur so lassen sich
/// System-Zeilen und Ereignisse gemeinsam nach Dringlichkeit sortieren.
fn severity_from_cef(raw: &str) -> Option<i16> {
    let n: i16 = raw.trim().parse().ok()?;
    Some(match n {
        0..=3 => 6,  // info
        4..=6 => 4,  // warning
        7..=8 => 3,  // error
        _ => 2,      // critical
    })
}

/// Ein CEF-Ereignis als Log-Zeile.
///
/// WLAN-Ereignisse werden zu `wifi`-Zeilen — dort gehören sie hin, und bisher
/// stand in dieser Spalte nichts als eine MAC-Adresse. Alles andere bleibt
/// `system`, bekommt aber Namen, Schweregrad und seine Felder; die Adressen
/// werden übernommen, damit ein Filter nach einer Adresse diese Ereignisse
/// mitfindet.
pub fn parse_cef(body: &str) -> Option<ParsedLog> {
    let h = split_header(body)?;
    let mut fields = extension(h.extension);
    fields.insert("event".into(), Value::String(h.name.to_string()));
    fields.insert("signature".into(), Value::String(h.signature.to_string()));

    let mut p = ParsedLog {
        log_type: Some(LogType::System),
        severity: severity_from_cef(h.severity),
        program: Some("unifi".into()),
        ..Default::default()
    };

    // Die Adressen: bei Client-Ereignissen heißt die Quelle `clientIp`, bei
    // Firewall-Ereignissen `srcClientIp`, und das Ziel steht schlicht als
    // `dst`.
    p.src_ip = ip(&fields, "clientIp")
        .or_else(|| ip(&fields, "srcClientIp"))
        .or_else(|| ip(&fields, "src"));
    p.dst_ip = ip(&fields, "dst").or_else(|| ip(&fields, "dstClientIp"));
    p.src_port = port(&fields, "spt");
    p.dst_port = port(&fields, "dpt");
    p.protocol = text(&fields, "proto");
    p.mac_address = text(&fields, "clientMac").or_else(|| text(&fields, "srcClientMac"));
    p.hostname = text(&fields, "clientAlias").or_else(|| text(&fields, "clientHostname"));

    match h.signature {
        // WLAN: verbunden, getrennt, gewechselt.
        "400" | "401" | "402" => {
            p.log_type = Some(LogType::Wifi);
            p.wifi_event = Some(
                match h.signature {
                    "400" => "connected",
                    "401" => "disconnected",
                    _ => "roamed",
                }
                .to_string(),
            );
            p.interface_in = text(&fields, "networkName");
        }
        // Von der Firewall blockiert — dieselbe Blockade steht auch als
        // iptables-Zeile im Log, aber ohne Domain, Anwendung und Regelnamen.
        "203" => {
            p.rule_action = Some(RuleAction::Block);
            p.rule_name = text(&fields, "policyName").or_else(|| text(&fields, "firewallPolicy"));
        }
        _ => {}
    }

    p.details = Some(Value::Object(fields));
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIFI: &str = "CEF:0|Ubiquiti|UniFi Network|10.6.106|400|WiFi Client Connected|1|UNIFIcategory=Client Devices UNIFIhost=Express 7 UNIFIconnectedToDeviceName=U7 Pro UNIFIclientAlias=iPhone Air UNIFIclientHostname=iPhone-Air UNIFIclientIp=10.10.15.98 UNIFIclientMac=70:13:84:65:dc:3a UNIFIwifiChannel=37 UNIFIwifiName=#1 UNIFIwifiBand=6e UNIFIWiFiRssi=-60 UNIFInetworkName=#1 - VLAN15 - Intern UNIFInetworkVlan=15 msg=iPhone Air connected to #1 on U7 Pro. Connection Info: Ch. 37 (6 GHz, 160 MHz), -60 dBm. IP: 10.10.15.98";

    const BLOCK: &str = "CEF:0|Ubiquiti|UniFi Network|10.6.106|203|Blocked by Firewall|4|UNIFIcategory=Security UNIFIhost=Express 7 proto=TCP spt=48742 dpt=25 act=blocked app=SMTP UNIFIrisk=low UNIFIpolicyName=VL10 -> WAN - Drop All UNIFIdirection=outgoing dst=80.241.60.215 UNIFIsrcClientAlias=Proxmox Backup Server UNIFIsrcClientIp=10.10.10.9 UNIFIsrcClientMac=bc:24:11:63:4c:59 UNIFIdstDomain=mxext2.mailbox.org UNIFIflowId=null msg=Proxmox Backup Server was blocked from accessing 80.241.60.215 by the VL10 -> WAN - Drop All Firewall Policy.";

    #[test]
    fn a_wifi_event_becomes_a_wifi_row() {
        let p = parse_cef(WIFI).unwrap();
        assert_eq!(p.log_type, Some(LogType::Wifi));
        assert_eq!(p.wifi_event.as_deref(), Some("connected"));
        assert_eq!(p.mac_address.as_deref(), Some("70:13:84:65:dc:3a"));
        assert_eq!(p.src_ip.map(|i| i.to_string()).as_deref(), Some("10.10.15.98"));
        assert_eq!(p.hostname.as_deref(), Some("iPhone Air"));
        // Das Netz steht im Ereignis, nicht in einer Bridge-Kennung.
        assert_eq!(p.interface_in.as_deref(), Some("#1 - VLAN15 - Intern"));
        assert_eq!(p.severity, Some(6));

        let d = p.details.unwrap();
        assert_eq!(d["event"], "WiFi Client Connected");
        assert_eq!(d["connectedToDeviceName"], "U7 Pro", "der Access Point");
        assert_eq!(d["wifiName"], "#1", "die SSID");
        assert_eq!(d["wiFiRssi"], "-60");
        assert_eq!(d["wifiChannel"], "37");
        assert!(d["msg"].as_str().unwrap().starts_with("iPhone Air connected to #1"));
    }

    #[test]
    fn a_blocked_flow_keeps_what_the_kernel_line_does_not_know() {
        let p = parse_cef(BLOCK).unwrap();
        assert_eq!(p.log_type, Some(LogType::System));
        assert_eq!(p.rule_action, Some(RuleAction::Block));
        assert_eq!(p.rule_name.as_deref(), Some("VL10 -> WAN - Drop All"));
        assert_eq!(p.src_ip.map(|i| i.to_string()).as_deref(), Some("10.10.10.9"));
        assert_eq!(p.dst_ip.map(|i| i.to_string()).as_deref(), Some("80.241.60.215"));
        assert_eq!(p.dst_port, Some(25));
        assert_eq!(p.protocol.as_deref(), Some("TCP"));
        assert_eq!(p.severity, Some(4));

        let d = p.details.unwrap();
        assert_eq!(d["dstDomain"], "mxext2.mailbox.org");
        assert_eq!(d["app"], "SMTP");
        assert_eq!(d["risk"], "low");
        // `null` als Wert ist kein Wert.
        assert!(d.get("flowId").is_none());
    }

    /// Werte dürfen Leerzeichen enthalten, Schlüssel nicht — daran entlang
    /// wird getrennt. Ohne diese Regel zerfiele jeder Gerätename.
    #[test]
    fn values_may_contain_spaces_and_dashes() {
        let f = extension("UNIFIpolicyName=VL10 -> WAN - Drop All UNIFIdirection=outgoing dst=1.2.3.4");
        assert_eq!(f["policyName"], "VL10 -> WAN - Drop All");
        assert_eq!(f["direction"], "outgoing");
        assert_eq!(f["dst"], "1.2.3.4");
    }

    /// Der letzte Schlüssel ist fast immer `msg` mit einem ganzen Satz darin,
    /// Punkte und Doppelpunkte eingeschlossen.
    #[test]
    fn the_message_runs_to_the_end_of_the_line() {
        let f = extension("a=1 msg=Ein Satz mit Ch. 37 (6 GHz), -60 dBm. IP: 10.10.15.98");
        assert_eq!(f["msg"], "Ein Satz mit Ch. 37 (6 GHz), -60 dBm. IP: 10.10.15.98");
    }

    #[test]
    fn a_line_that_is_not_cef_is_not_parsed() {
        assert!(!is_cef("systemd[1]: Started thing."));
        assert!(is_cef(BLOCK));
        assert!(parse_cef("CEF:0|zu wenig Felder").is_none());
    }
}
