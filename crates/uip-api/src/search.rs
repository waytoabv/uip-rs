//! Ein Feld nimmt, was man weiß, und findet heraus, was es ist.
//!
//! Als Textvergleich gebaut fand eine Suche nach 10.10.10.10 auch
//! 10.10.10.100, und die Adressspalten lagen außerhalb der Reichweite ihres
//! Index. Den Typ zu erkennen macht daraus einen exakten, indizierten
//! Vergleich.

use ipnetwork::IpNetwork;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    SrcIp, DstIp, AnyIp, Port, SrcPort, DstPort, Rule, Country,
    Asn, Protocol, Interface, Host, Action, LogType,
}

fn field_from_prefix(p: &str) -> Option<Field> {
    Some(match p {
        "src" | "source" => Field::SrcIp,
        "dst" | "dest" => Field::DstIp,
        "ip" => Field::AnyIp,
        "port" => Field::Port,
        "sport" => Field::SrcPort,
        "dport" => Field::DstPort,
        "rule" => Field::Rule,
        "country" => Field::Country,
        "asn" => Field::Asn,
        "proto" | "protocol" => Field::Protocol,
        "iface" | "interface" => Field::Interface,
        "host" | "hostname" => Field::Host,
        "action" => Field::Action,
        "type" => Field::LogType,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Ip(IpAddr),
    Cidr(IpNetwork),
    Port(i32),
    /// Eine AS-Nummer. Eigener Fall, weil sie sonst als Port gelesen würde —
    /// die meisten AS-Nummern liegen im Portbereich.
    Asn(i32),
    Mac(String),
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Term {
    pub value: Value,
    pub field: Option<Field>,
    pub negated: bool,
    /// Der Text enthält '*' und wird als Muster verglichen.
    pub glob: bool,
}

/// Zerlegt einen Suchausdruck. Wirft nie.
pub fn parse_search(query: &str) -> Vec<Term> {
    if query.trim().is_empty() {
        return Vec::new();
    }
    split_tokens(query).into_iter().filter_map(classify).collect()
}

/// Trennt an Leerzeichen, hält aber "…" zusammen. Eine offene Anführung ist
/// kein Fehler — da tippt jemand noch.
fn split_tokens(query: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in query.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn classify(token: String) -> Option<Term> {
    let mut negated = false;
    let mut token = token;
    if token.starts_with('!') || token.starts_with('-') {
        let rest = token[1..].to_string();
        if rest.is_empty() {
            return None; // ein blankes Zeichen ist kein Begriff
        }
        negated = true;
        token = rest;
    }

    let mut field = None;
    if let Some((prefix, remainder)) = token.split_once(':') {
        // Nur ein bekanntes Präfix beschränkt: Doppelpunkte stehen auch in
        // MACs, IPv6-Adressen und gewöhnlichem Text.
        if let Some(f) = field_from_prefix(&prefix.trim().to_lowercase()) {
            if !remainder.is_empty() {
                field = Some(f);
                token = remainder.to_string();
            }
        }
    }
    if token.is_empty() {
        return None;
    }

    let glob = token.contains('*');
    let value = typed_for(&token, field);
    Some(Term { value, field, negated, glob })
}

/// Erkennt den Typ eines Werts — aber nur so weit, wie das Feld es zulässt.
///
/// Ohne diese Einschränkung entscheidet allein der Inhalt, und dann wird
/// `asn:15169` zur Portsuche und `rule:443` ebenfalls: beides sind Zahlen im
/// Portbereich. Sagt jemand ausdrücklich, welches Feld gemeint ist, hat das
/// Vorrang vor dem Raten.
fn typed_for(token: &str, field: Option<Field>) -> Value {
    match field {
        // Diese Felder tragen immer Text, egal wie der Wert aussieht.
        Some(
            Field::Rule
            | Field::Host
            | Field::Country
            | Field::Protocol
            | Field::Interface
            | Field::Action
            | Field::LogType,
        ) => Value::Text(token.to_string()),

        // Eine Zahl ist die AS-Nummer, alles andere der Name des Betreibers.
        Some(Field::Asn) => match token.parse::<i32>() {
            Ok(n) if n > 0 => Value::Asn(n),
            _ => Value::Text(token.to_string()),
        },

        // Portfelder nehmen nur Zahlen; alles andere trifft nichts.
        Some(Field::Port | Field::SrcPort | Field::DstPort) => match token.parse::<i32>() {
            Ok(p) if (1..=65535).contains(&p) => Value::Port(p),
            _ => Value::Text(token.to_string()),
        },

        // Adressfelder nehmen Adressen und Netze. Die Adresse wird zuerst
        // geprüft: "10.0.0.5" parst auch als Netz (/32), und daraus würde ein
        // Präfixvergleich statt der exakten, indizierten Gleichheit.
        Some(Field::SrcIp | Field::DstIp | Field::AnyIp) => {
            if let Ok(ip) = token.parse::<IpAddr>() {
                Value::Ip(ip)
            } else if token.contains('/') {
                match token.parse::<IpNetwork>() {
                    Ok(net) => Value::Cidr(net),
                    Err(_) => Value::Text(token.to_string()),
                }
            } else if let Some(net) = prefix_to_network(token) {
                Value::Cidr(net)
            } else {
                Value::Text(token.to_string())
            }
        }

        // Ohne Feldangabe entscheidet der Inhalt.
        None => typed(token),
    }
}

fn typed(token: &str) -> Value {
    if token.contains('/') {
        if let Ok(net) = token.parse::<IpNetwork>() {
            return Value::Cidr(net);
        }
    }
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Value::Ip(ip);
    }
    if let Some(net) = prefix_to_network(token) {
        return Value::Cidr(net);
    }
    if is_mac(token) {
        return Value::Mac(token.to_lowercase());
    }
    if let Ok(port) = token.parse::<i32>() {
        if (1..=65535).contains(&port) {
            return Value::Port(port);
        }
    }
    Value::Text(token.to_string())
}

fn is_mac(t: &str) -> bool {
    let parts: Vec<&str> = t.split([':', '-']).collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// '10.10.30.*', '10.10.30.' oder '10.10.30' → 10.10.30.0/24
fn prefix_to_network(token: &str) -> Option<IpNetwork> {
    let trimmed = token.trim_end_matches('*').trim_end_matches('.');
    let octets: Vec<&str> = trimmed.split('.').collect();
    // Ein einzelnes Oktett ohne Punkt oder Stern ist eine Zahl, kein Netz.
    if octets.len() < 2 || octets.len() > 3 {
        return None;
    }
    let parsed: Option<Vec<u8>> = octets.iter().map(|o| o.parse::<u8>().ok()).collect();
    let parsed = parsed?;
    let mut full = parsed.clone();
    full.resize(4, 0);
    let addr = std::net::Ipv4Addr::new(full[0], full[1], full[2], full[3]);
    IpNetwork::new(IpAddr::V4(addr), (8 * parsed.len()) as u8).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(q: &str) -> Term {
        let terms = parse_search(q);
        assert_eq!(terms.len(), 1, "erwartet genau einen Begriff aus {q:?}");
        terms.into_iter().next().unwrap()
    }

    #[test]
    fn a_full_address_is_an_address() {
        let t = one("10.0.0.5");
        assert_eq!(t.value, Value::Ip("10.0.0.5".parse().unwrap()));
        assert!(!t.negated);
        assert_eq!(t.field, None);
    }

    /// Der Grund, warum es diesen Parser gibt: als Text verglichen fand
    /// 10.10.10.10 auch 10.10.10.100.
    #[test]
    fn an_address_does_not_match_a_longer_one() {
        assert_eq!(one("10.10.10.10").value, Value::Ip("10.10.10.10".parse().unwrap()));
    }

    #[test]
    fn a_partial_address_becomes_a_network() {
        for q in ["10.10.30.", "10.10.30.*", "10.10.30"] {
            assert_eq!(one(q).value, Value::Cidr("10.10.30.0/24".parse().unwrap()), "bei {q:?}");
        }
    }

    #[test]
    fn an_explicit_network_stays_one() {
        assert_eq!(one("10.10.30.0/24").value, Value::Cidr("10.10.30.0/24".parse().unwrap()));
    }

    /// Ein einzelnes Oktett ohne Punkt ist eine Zahl, kein Netz.
    #[test]
    fn a_bare_number_is_a_port() {
        assert_eq!(one("443").value, Value::Port(443));
        assert_eq!(one("10").value, Value::Port(10));
        // Jenseits des Portbereichs ist es wieder Text.
        assert_eq!(one("70000").value, Value::Text("70000".into()));
    }

    #[test]
    fn a_mac_is_a_mac() {
        assert_eq!(one("AA:BB:CC:DD:EE:FF").value, Value::Mac("aa:bb:cc:dd:ee:ff".into()));
    }

    #[test]
    fn a_prefix_scopes_a_term() {
        let t = one("src:10.0.0.5");
        assert_eq!(t.field, Some(Field::SrcIp));
        assert_eq!(t.value, Value::Ip("10.0.0.5".parse().unwrap()));
    }

    /// Doppelpunkte stehen auch in MACs, IPv6 und gewöhnlichem Text.
    #[test]
    fn an_unknown_prefix_is_not_a_scope() {
        let t = one("foo:bar");
        assert_eq!(t.field, None);
        assert_eq!(t.value, Value::Text("foo:bar".into()));
    }

    #[test]
    fn terms_can_be_negated_both_ways() {
        assert!(one("!tcp").negated);
        assert!(one("-tcp").negated);
        assert_eq!(one("!tcp").value, Value::Text("tcp".into()));
        // Ein Bindestrich mitten im Wort negiert nicht.
        assert!(!one("a-b").negated);
        // Ein blankes Zeichen ist kein Begriff.
        assert!(parse_search("!").is_empty());
        assert!(parse_search("-").is_empty());
    }

    #[test]
    fn quoted_values_stay_together() {
        let t = one(r#"rule:"LAN to WAN""#);
        assert_eq!(t.field, Some(Field::Rule));
        assert_eq!(t.value, Value::Text("LAN to WAN".into()));
    }

    /// Jemand tippt noch. Das darf nichts kaputt machen.
    #[test]
    fn an_unbalanced_quote_still_parses() {
        let terms = parse_search(r#"nas "denied"#);
        assert_eq!(terms.len(), 2);
        assert_eq!(terms[0].value, Value::Text("nas".into()));
    }

    #[test]
    fn several_terms_all_apply() {
        let terms = parse_search("10.10.30.0/24 443 !tcp");
        assert_eq!(terms.len(), 3);
        assert!(matches!(terms[0].value, Value::Cidr(_)));
        assert_eq!(terms[1].value, Value::Port(443));
        assert!(terms[2].negated);
    }

    #[test]
    fn a_star_makes_text_a_pattern() {
        let t = one("nas*");
        assert_eq!(t.value, Value::Text("nas*".into()));
        assert!(t.glob);
    }


    /// Gefunden beim Bau der Filterleiste: `typed()` entschied allein nach
    /// dem Inhalt, also wurde eine AS-Nummer zur Portsuche — und `rule:443`
    /// ebenfalls. Eine ausdrückliche Feldangabe hat Vorrang vor dem Raten.
    #[test]
    fn an_explicit_field_beats_content_guessing() {
        // AS-Nummern liegen fast alle im Portbereich.
        assert_eq!(one("asn:15169").value, Value::Asn(15169));
        assert_eq!(one("asn:Google").value, Value::Text("Google".into()));

        // Ein Regelname darf eine Zahl sein.
        assert_eq!(one("rule:443").value, Value::Text("443".into()));
        // Ein Hostname ebenso.
        assert_eq!(one("host:12345").value, Value::Text("12345".into()));
        // Und ein Land, das wie eine MAC aussieht, gibt es zwar nicht —
        // aber der Text bleibt Text.
        assert_eq!(one("country:DE").value, Value::Text("DE".into()));
        assert_eq!(one("proto:6").value, Value::Text("6".into()));
        assert_eq!(one("iface:10").value, Value::Text("10".into()));
    }

    #[test]
    fn scoped_address_and_port_fields_stay_typed() {
        assert_eq!(one("src:10.0.0.5").value, Value::Ip("10.0.0.5".parse().unwrap()));
        assert_eq!(one("dst:10.10.30.0/24").value, Value::Cidr("10.10.30.0/24".parse().unwrap()));
        assert_eq!(one("dport:443").value, Value::Port(443));
        // Unsinn in einem Portfeld trifft nichts, statt zu einem Textvergleich
        // über alle Spalten zu entarten.
        assert_eq!(one("dport:nonsense").value, Value::Text("nonsense".into()));
    }

    #[test]
    fn without_a_field_the_content_still_decides() {
        assert_eq!(one("15169").value, Value::Port(15169));
        assert_eq!(one("10.0.0.5").value, Value::Ip("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn nothing_in_nothing_out() {
        assert!(parse_search("").is_empty());
        assert!(parse_search("   ").is_empty());
    }
}
