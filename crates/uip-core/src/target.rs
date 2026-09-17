use std::collections::HashSet;
use std::net::IpAddr;

/// Öffentlich im Sinne der Anreicherung: alles, was nicht offensichtlich
/// aus dem eigenen Netz oder gar keine Gegenstelle ist.
pub fn is_enrichable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // 100.64.0.0/10 (CGNAT) und 0.0.0.0/8
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // fc00::/7 unique local, fe80::/10 link local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Welche der beiden Adressen einer Zeile ist die Gegenstelle?
///
/// `log_type_id`/`direction_id` sind die numerischen Ids aus uip-core
/// (firewall=1, dns=2 … / inbound=1, outbound=2 …).
pub fn remote_ip(
    log_type_id: i16,
    direction_id: Option<i16>,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    excluded: &HashSet<IpAddr>,
) -> Option<IpAddr> {
    let usable = |ip: Option<IpAddr>| -> Option<IpAddr> {
        ip.filter(is_enrichable).filter(|i| !excluded.contains(i))
    };
    match log_type_id {
        1 => match direction_id {
            Some(1) => usable(src_ip),            // inbound
            Some(2) => usable(dst_ip),            // outbound
            _ => usable(src_ip).or_else(|| usable(dst_ip)),
        },
        2 => usable(src_ip).or_else(|| usable(dst_ip)), // dns
        _ => None,                                       // dhcp, wifi, system
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    fn excl() -> HashSet<IpAddr> { HashSet::from([ip("203.0.113.7")]) }

    #[test]
    fn inbound_takes_the_source() {
        let r = remote_ip(1, Some(1), Some(ip("8.8.8.8")), Some(ip("10.0.0.5")), &excl());
        assert_eq!(r, Some(ip("8.8.8.8")));
    }

    #[test]
    fn outbound_takes_the_destination() {
        let r = remote_ip(1, Some(2), Some(ip("10.0.0.5")), Some(ip("1.1.1.1")), &excl());
        assert_eq!(r, Some(ip("1.1.1.1")));
    }

    #[test]
    fn private_addresses_are_not_enrichable() {
        assert_eq!(remote_ip(1, Some(4), Some(ip("10.0.0.1")), Some(ip("192.168.1.1")), &excl()), None);
        assert_eq!(remote_ip(1, Some(3), Some(ip("127.0.0.1")), None, &excl()), None);
        assert_eq!(remote_ip(1, Some(1), Some(ip("224.0.0.1")), None, &excl()), None);
    }

    #[test]
    fn our_own_wan_address_is_excluded() {
        assert_eq!(remote_ip(1, Some(1), Some(ip("203.0.113.7")), Some(ip("10.0.0.5")), &excl()), None);
    }

    #[test]
    fn falls_back_to_whichever_side_is_public() {
        // local/inter_vlan: keine feste Seite, nimm die öffentliche
        let r = remote_ip(1, Some(3), Some(ip("10.0.0.5")), Some(ip("9.9.9.9")), &excl());
        assert_eq!(r, Some(ip("9.9.9.9")));
    }

    #[test]
    fn only_firewall_and_dns_carry_remote_addresses() {
        // dhcp (3), wifi (4), system (5) → nie
        assert_eq!(remote_ip(3, None, Some(ip("8.8.8.8")), None, &excl()), None);
        assert_eq!(remote_ip(5, None, Some(ip("8.8.8.8")), None, &excl()), None);
        // dns (2) → nur eine öffentliche Quelle
        assert_eq!(remote_ip(2, None, Some(ip("8.8.8.8")), None, &excl()), Some(ip("8.8.8.8")));
    }
}
