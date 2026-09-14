use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i16)]
pub enum LogType { Firewall = 1, Dns = 2, Dhcp = 3, Wifi = 4, System = 5 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i16)]
pub enum RuleAction { Allow = 1, Block = 2, Redirect = 3 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(i16)]
pub enum Direction { Inbound = 1, Outbound = 2, Local = 3, InterVlan = 4, Vpn = 5, Nat = 6 }

impl LogType {
    pub fn as_str(self) -> &'static str {
        match self { Self::Firewall => "firewall", Self::Dns => "dns", Self::Dhcp => "dhcp", Self::Wifi => "wifi", Self::System => "system" }
    }
}
impl RuleAction {
    pub fn as_str(self) -> &'static str {
        match self { Self::Allow => "allow", Self::Block => "block", Self::Redirect => "redirect" }
    }
}
impl Direction {
    pub fn as_str(self) -> &'static str {
        match self { Self::Inbound => "inbound", Self::Outbound => "outbound", Self::Local => "local", Self::InterVlan => "inter_vlan", Self::Vpn => "vpn", Self::Nat => "nat" }
    }
}

/// Ergebnis eines Parsers — noch ohne Lookup-Ids, reine Werte.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedLog {
    pub timestamp: Option<DateTime<Utc>>,
    pub log_type: Option<LogType>,
    pub rule_name: Option<String>,
    pub rule_desc: Option<String>,
    pub rule_action: Option<RuleAction>,
    pub direction: Option<Direction>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub protocol: Option<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub dns_query: Option<String>,
    pub dns_type: Option<String>,
    pub dns_answer: Option<String>,
    pub dhcp_event: Option<String>,
    pub wifi_event: Option<String>,
    pub raw_log: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable() {
        assert_eq!(LogType::Firewall as i16, 1);
        assert_eq!(LogType::Dns as i16, 2);
        assert_eq!(LogType::Dhcp as i16, 3);
        assert_eq!(LogType::Wifi as i16, 4);
        assert_eq!(LogType::System as i16, 5);
        assert_eq!(RuleAction::Allow as i16, 1);
        assert_eq!(RuleAction::Block as i16, 2);
        assert_eq!(RuleAction::Redirect as i16, 3);
        assert_eq!(Direction::Inbound as i16, 1);
        assert_eq!(Direction::Outbound as i16, 2);
        assert_eq!(Direction::Local as i16, 3);
        assert_eq!(Direction::InterVlan as i16, 4);
        assert_eq!(Direction::Vpn as i16, 5);
        assert_eq!(Direction::Nat as i16, 6);
    }

    #[test]
    fn str_roundtrip() {
        assert_eq!(LogType::Firewall.as_str(), "firewall");
        assert_eq!(Direction::InterVlan.as_str(), "inter_vlan");
        assert_eq!(RuleAction::Block.as_str(), "block");
    }
}
