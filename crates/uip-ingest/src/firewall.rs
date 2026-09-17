use std::collections::HashSet;
use std::net::IpAddr;
use uip_core::{Direction, ParsedLog, RuleAction};
use uip_core::types::LogType;

pub const VPN_PREFIXES: [&str; 9] =
    ["wgsrv", "wgclt", "wgsts", "tlprt", "vti", "tunovpnc", "tun", "vtun", "l2tp"];

/// Was der Parser über das eigene Netz wissen muss.
///
/// `wan_ips` liegt hinter einem `ArcSwap`, weil die Adresse sich ändert, ohne
/// dass jemand etwas tut: bei einer dynamischen Verbindung vergibt der
/// Anbieter regelmäßig eine neue. Einmal beim Start zu lesen hieße, dass die
/// Richtungserkennung ab dem nächsten Wechsel danebenliegt, bis jemand den
/// Dienst neu startet.
#[derive(Debug, Clone, Default)]
pub struct FirewallCtx {
    pub wan_interfaces: std::sync::Arc<arc_swap::ArcSwap<HashSet<String>>>,
    pub wan_ips: std::sync::Arc<arc_swap::ArcSwap<HashSet<IpAddr>>>,
}

impl FirewallCtx {
    /// Nimmt einen neuen Satz WAN-Adressen an.
    pub fn set_wan_ips(&self, ips: HashSet<IpAddr>) {
        if **self.wan_ips.load() != ips {
            tracing::info!(count = ips.len(), "wan addresses changed");
            self.wan_ips.store(std::sync::Arc::new(ips));
        }
    }

    /// Nimmt einen neuen Satz WAN-Schnittstellen an. `true`, wenn er sich
    /// geändert hat — dann stimmt die bisher abgeleitete Richtung nicht mehr.
    pub fn set_wan_interfaces(&self, names: HashSet<String>) -> bool {
        if **self.wan_interfaces.load() == names {
            return false;
        }
        tracing::info!(?names, "wan interfaces changed");
        self.wan_interfaces.store(std::sync::Arc::new(names));
        true
    }
}

fn is_vpn_iface(name: &str) -> bool {
    VPN_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn is_broadcast_or_multicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// Source-MAC aus dem 14-Byte-iptables-MAC-Feld (dest:src:ethertype).
fn extract_src_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() >= 12 { Some(parts[6..12].join(":")) } else { Some(raw.to_string()) }
}

fn derive_action(rule_name: Option<&str>, rule_desc: Option<&str>) -> Option<RuleAction> {
    let name = rule_name?;
    // Der Buchstabe ist ein eigenes Segment, aber nicht zwangsläufig das
    // letzte: die zonenbasierte Firewall hängt ihren Index dahinter
    // (`DMZ_LOCAL-D-10002`), der ältere Stil nicht (`WAN_IN-B-1-D`). Von
    // rechts suchen trifft beide; nur das letzte Segment zu lesen fand ihn im
    // ersten Fall nie und machte aus jedem Block ein Allow.
    if let Some(letter) = name.rsplit('-').find(|seg| matches!(*seg, "A" | "D" | "R")) {
        return Some(match letter {
            "A" => RuleAction::Allow,
            "D" => RuleAction::Block,
            _ => RuleAction::Redirect,
        });
    }
    if let Some(d) = rule_desc {
        // UniFi stellt der Beschreibung oft die Zone voran
        // (`[WAN_LOCAL]Block All Traffic`) — der Hinweis fängt erst dahinter
        // an, also fällt die Klammer weg, bevor gelesen wird.
        let d = d.to_ascii_lowercase();
        let d = d.split_once(']').map_or(d.as_str(), |(_, after)| after).trim_start();
        if d.starts_with("block") || d.starts_with("deny") || d.starts_with("drop") {
            return Some(RuleAction::Block);
        }
        if d.starts_with("allow") || d.starts_with("accept") {
            return Some(RuleAction::Allow);
        }
    }
    Some(RuleAction::Allow) // unbekannt → allow (wie Fork-Verhalten)
}

fn derive_direction(
    iface_in: Option<&str>, iface_out: Option<&str>, rule_name: Option<&str>,
    src_ip: Option<&IpAddr>, dst_ip: Option<&IpAddr>, ctx: &FirewallCtx,
) -> Option<Direction> {
    if iface_in.is_none() && iface_out.is_none() { return None; }
    if let Some(d) = dst_ip {
        if is_broadcast_or_multicast(d) { return Some(Direction::Local); }
    }
    let wan = ctx.wan_interfaces.load();
    let wan_out = iface_out.map(|i| wan.contains(i)).unwrap_or(false);
    if let Some(s) = src_ip {
        if ctx.wan_ips.load().contains(s) && !wan_out { return Some(Direction::Local); }
    }
    if let Some(r) = rule_name {
        if r.contains("DNAT") || r.contains("PREROUTING") { return Some(Direction::Nat); }
    }
    let wan_in = iface_in.map(|i| wan.contains(i)).unwrap_or(false);
    let Some(out) = iface_out else {
        return Some(if wan_in { Direction::Inbound } else { Direction::Local });
    };
    match (wan_in, wan_out) {
        (true, false) => Some(Direction::Inbound),
        (false, true) => Some(Direction::Outbound),
        (false, false) if iface_in != Some(out) => {
            let vpn = iface_in.map(is_vpn_iface).unwrap_or(false) || is_vpn_iface(out);
            Some(if vpn { Direction::Vpn } else { Direction::InterVlan })
        }
        _ => Some(Direction::Local),
    }
}

pub fn parse_firewall(body: &str, ctx: &FirewallCtx) -> ParsedLog {
    let mut p = ParsedLog { log_type: Some(LogType::Firewall), ..Default::default() };

    // Rule-Name: erster [..]-Block
    if let Some(start) = body.find('[') {
        if let Some(len) = body[start + 1..].find(']') {
            p.rule_name = Some(body[start + 1..start + 1 + len].to_string());
        }
    }

    // KEY=VALUE-Scanner. DESCR="…" trägt Spaces → gesondert.
    let mut rest = body;
    while let Some(eq) = rest.find('=') {
        let key_start = rest[..eq].rfind([' ', ']']).map(|i| i + 1).unwrap_or(0);
        let key = &rest[key_start..eq];
        let after = &rest[eq + 1..];
        let (value, next): (&str, &str) = if let Some(quoted) = after.strip_prefix('"') {
            match quoted.find('"') {
                Some(end) => (&quoted[..end], &quoted[end + 1..]),
                None => (quoted, ""),
            }
        } else {
            match after.find(' ') {
                Some(end) => (&after[..end], &after[end + 1..]),
                None => (after, ""),
            }
        };
        match key {
            "IN" if !value.is_empty() => p.interface_in = Some(value.to_string()),
            "OUT" if !value.is_empty() => p.interface_out = Some(value.to_string()),
            "SRC" => p.src_ip = value.parse().ok(),
            "DST" => p.dst_ip = value.parse().ok(),
            "PROTO" => p.protocol = Some(value.to_ascii_lowercase()),
            "SPT" => p.src_port = value.parse().ok(),
            "DPT" => p.dst_port = value.parse().ok(),
            "MAC" => p.mac_address = extract_src_mac(value),
            "DESCR" => p.rule_desc = Some(value.to_string()),
            _ => {}
        }
        rest = next;
    }

    p.rule_action = derive_action(p.rule_name.as_deref(), p.rule_desc.as_deref());
    p.direction = derive_direction(
        p.interface_in.as_deref(), p.interface_out.as_deref(), p.rule_name.as_deref(),
        p.src_ip.as_ref(), p.dst_ip.as_ref(), ctx,
    );
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use uip_core::{Direction, RuleAction};
    use std::collections::HashSet;

    fn ctx() -> FirewallCtx {
        FirewallCtx {
            wan_interfaces: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                HashSet::from(["ppp0".to_string()]),
            )),
            wan_ips: Default::default(),
        }
    }

    #[test]
    fn parses_zone_rule_inbound() {
        let p = parse_firewall("kernel: [WAN_IN-B-4000000003-D]IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=443", &ctx());
        assert_eq!(p.rule_name.as_deref(), Some("WAN_IN-B-4000000003-D"));
        assert_eq!(p.src_ip.unwrap().to_string(), "1.2.3.4");
        assert_eq!(p.dst_ip.unwrap().to_string(), "10.0.0.5");
        assert_eq!(p.protocol.as_deref(), Some("tcp"));
        assert_eq!((p.src_port, p.dst_port), (Some(54321), Some(443)));
        assert_eq!(p.direction, Some(Direction::Inbound));
        assert_eq!(p.rule_action, Some(RuleAction::Block));
    }

    #[test]
    fn parses_ipv6_and_router_destined() {
        let p = parse_firewall("kernel: [RULE1]IN=ppp0 OUT= SRC=2001:db8::1 DST=fd00::2 PROTO=TCP SPT=80 DPT=8080", &ctx());
        assert_eq!(p.src_ip.unwrap().to_string(), "2001:db8::1");
        assert_eq!(p.interface_out, None);
        assert_eq!(p.direction, Some(Direction::Inbound)); // kein OUT + WAN-IN → an den Router
    }

    #[test]
    fn descr_and_mac_extraction() {
        let p = parse_firewall(r#"kernel: [LAN_OUT-A]IN=br20 OUT=ppp0 MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC=10.0.20.5 DST=8.8.8.8 PROTO=UDP SPT=5353 DPT=53 DESCR="Allow DNS""#, &ctx());
        assert_eq!(p.mac_address.as_deref(), Some("11:22:33:44:55:66"));
        assert_eq!(p.rule_desc.as_deref(), Some("Allow DNS"));
        assert_eq!(p.direction, Some(Direction::Outbound));
        assert_eq!(p.rule_action, Some(RuleAction::Allow));
    }

    #[test]
    fn inter_vlan_vs_vpn() {
        let p = parse_firewall("kernel: [X-A]IN=br20 OUT=br30 SRC=10.0.20.5 DST=10.0.30.5 PROTO=TCP SPT=1 DPT=2", &ctx());
        assert_eq!(p.direction, Some(Direction::InterVlan));
        let p = parse_firewall("kernel: [X-A]IN=wgsrv0 OUT=br20 SRC=10.6.0.2 DST=10.0.20.5 PROTO=TCP SPT=1 DPT=2", &ctx());
        assert_eq!(p.direction, Some(Direction::Vpn));
    }

    #[test]
    fn broadcast_is_local_and_invalid_ip_dropped() {
        let p = parse_firewall("kernel: [X-A]IN=ppp0 OUT=br0 SRC=1.2.3.4 DST=255.255.255.255 PROTO=UDP", &ctx());
        assert_eq!(p.direction, Some(Direction::Local));
        let p = parse_firewall("kernel: SRC=not_ip DST=10.0.0.1 PROTO=TCP", &ctx());
        assert_eq!(p.src_ip, None);
        assert_eq!(p.dst_ip.unwrap().to_string(), "10.0.0.1");
    }

    /// Die zonenbasierte Firewall schreibt den Aktionsbuchstaben in die
    /// MITTE des Regelnamens: `<ZONE>_<ZONE>-<A|D|R>-<index>`. Nur das letzte
    /// Segment zu lesen fand ihn dort nie, und der Rückfall machte aus jeder
    /// geblockten Zeile eine erlaubte.
    #[test]
    fn action_letter_sits_in_the_middle_of_a_zone_rule_name() {
        let block = parse_firewall(
            r#"kernel: [DMZ_LOCAL-D-10002]IN=br30 OUT=br0 SRC=10.0.30.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=22 DESCR="DMZ To GW - Drop all Traffic""#,
            &ctx(),
        );
        assert_eq!(block.rule_action, Some(RuleAction::Block));

        let allow = parse_firewall(
            r#"kernel: [CUSTOM1_WAN-A-10004]IN=br10 OUT=ppp0 SRC=10.0.10.5 DST=1.1.1.1 PROTO=UDP SPT=1 DPT=53 DESCR="VL10 -> WAN - Pihole Allow DNS""#,
            &ctx(),
        );
        assert_eq!(allow.rule_action, Some(RuleAction::Allow));

        let redirect = parse_firewall(
            "kernel: [LAN_LOCAL-R-10001]IN=br0 OUT=br0 SRC=10.0.0.5 DST=1.1.1.1 PROTO=UDP SPT=1 DPT=53",
            &ctx(),
        );
        assert_eq!(redirect.rule_action, Some(RuleAction::Redirect));
    }

    /// Der alte Namensstil trägt ihn am Ende — der muss weiter treffen.
    #[test]
    fn action_letter_at_the_end_still_wins() {
        let p = parse_firewall("kernel: [WAN_IN-B-4000000003-D]IN=ppp0 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP", &ctx());
        assert_eq!(p.rule_action, Some(RuleAction::Block));
    }

    /// Ohne Buchstaben im Namen bleibt die Beschreibung — und die trägt bei
    /// UniFi ein `[ZONE]`-Präfix, hinter dem der Hinweis erst anfängt.
    #[test]
    fn descr_hint_is_read_behind_a_zone_tag() {
        let p = parse_firewall(
            r#"kernel: [UBIOS_WAN_IN_USER]IN=ppp0 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP DESCR="[WAN_LOCAL]Block All Traffic""#,
            &ctx(),
        );
        assert_eq!(p.rule_action, Some(RuleAction::Block));
    }

    #[test]
    fn descr_block_hint_when_no_suffix() {
        let p = parse_firewall(r#"kernel: [MYRULE]IN=br20 OUT=ppp0 SRC=10.0.20.5 DST=1.2.3.4 PROTO=TCP DESCR="Block Unauthorized""#, &ctx());
        assert_eq!(p.rule_action, Some(RuleAction::Block));
    }
}
