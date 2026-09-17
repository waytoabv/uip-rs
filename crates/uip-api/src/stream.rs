//! Der Live-Stream sendet, was gerade geschrieben wurde — bevor die
//! Anreicherung (Land, Threat-Score, rdns, ASN) dazu etwas weiß. Ein Filter,
//! der nach diesen Feldern fragt, kann also nicht ehrlich beantwortet werden:
//! `Unknowable` sagt das, statt die Zeile stillschweigend zu verwerfen.

use crate::filters::LogFilter;
use crate::search::{parse_search, Field, Term, Value};
use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use std::net::IpAddr;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uip_core::{LiveEvent, LiveRow};

/// Was der Stream mit einer Zeile tun soll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Reject,
    /// Der Filter fragt nach etwas, das erst die Anreicherung weiß.
    Unknowable,
}

/// Kombiniert mehrere Verdicts nach dreiwertiger UND-Logik: ein sicheres
/// `Reject` gewinnt immer (die Zeile fällt so oder so raus), sonst gewinnt
/// `Unknowable` (wir wissen es nicht besser), sonst `Pass`.
fn combine(verdicts: impl IntoIterator<Item = Verdict>) -> Verdict {
    let mut unknowable = false;
    for v in verdicts {
        match v {
            Verdict::Reject => return Verdict::Reject,
            Verdict::Unknowable => unknowable = true,
            Verdict::Pass => {}
        }
    }
    if unknowable {
        Verdict::Unknowable
    } else {
        Verdict::Pass
    }
}

/// Prüft eine der `Vec<String>`-Filterlisten (log_type/action/direction/proto)
/// gegen einen einzelnen Wert der Zeile.
fn list_verdict(active: &[String], value: Option<&str>) -> Verdict {
    if active.is_empty() {
        return Verdict::Pass;
    }
    match value {
        Some(v) if active.iter().any(|a| a.eq_ignore_ascii_case(v)) => Verdict::Pass,
        _ => Verdict::Reject,
    }
}

fn iface_verdict(active: &[String], iface_in: Option<&str>, iface_out: Option<&str>) -> Verdict {
    if active.is_empty() {
        return Verdict::Pass;
    }
    let hit = [iface_in, iface_out]
        .into_iter()
        .flatten()
        .any(|v| active.iter().any(|a| a.eq_ignore_ascii_case(v)));
    if hit {
        Verdict::Pass
    } else {
        Verdict::Reject
    }
}

/// Genau eine Seite, anders als `iface_verdict`: ein Zonenpaar ist gerichtet.
fn exact_iface_verdict(want: Option<&str>, have: Option<&str>) -> Verdict {
    match want.filter(|s| !s.is_empty()) {
        None => Verdict::Pass,
        Some(w) if have.is_some_and(|h| h.eq_ignore_ascii_case(w)) => Verdict::Pass,
        Some(_) => Verdict::Reject,
    }
}

fn port_verdict(port: Option<i32>, src: Option<i32>, dst: Option<i32>) -> Verdict {
    match port {
        None => Verdict::Pass,
        Some(p) if src == Some(p) || dst == Some(p) => Verdict::Pass,
        Some(_) => Verdict::Reject,
    }
}

/// `country`/`threat_min` fragen nach Spalten, die eine frisch geschriebene
/// Zeile noch nicht hat.
fn enriched_verdict(f: &LogFilter) -> Verdict {
    if !f.country.is_empty() || f.threat_min.is_some() {
        Verdict::Unknowable
    } else {
        Verdict::Pass
    }
}

fn glob_match(haystack: &str, pattern: &str) -> bool {
    let haystack = haystack.to_lowercase();
    let pattern = pattern.to_lowercase();
    let mut pos = 0usize;
    let mut parts = pattern.split('*').peekable();
    if let Some(first) = parts.next() {
        if !haystack[pos..].starts_with(first) {
            return false;
        }
        pos += first.len();
    }
    for part in parts {
        if part.is_empty() {
            continue;
        }
        match haystack[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }
    true
}

fn text_hit(hay: &str, needle: &str, glob: bool) -> bool {
    if glob {
        glob_match(hay, needle)
    } else {
        hay.to_lowercase().contains(&needle.to_lowercase())
    }
}

/// Ob genau dieser Suchbegriff auf die Zeile passt — ohne Berücksichtigung
/// der Negation, die ruft den Aufrufer danach an.
fn term_hit(row: &LiveRow, term: &Term) -> Verdict {
    match (&term.value, term.field) {
        (Value::Ip(ip), field) => {
            let hit = match field {
                Some(Field::SrcIp) => row.src_ip == Some(*ip),
                Some(Field::DstIp) => row.dst_ip == Some(*ip),
                _ => row.src_ip == Some(*ip) || row.dst_ip == Some(*ip),
            };
            if hit { Verdict::Pass } else { Verdict::Reject }
        }
        (Value::Cidr(net), field) => {
            let in_net = |ip: Option<IpAddr>| ip.is_some_and(|ip| net.contains(ip));
            let hit = match field {
                Some(Field::SrcIp) => in_net(row.src_ip),
                Some(Field::DstIp) => in_net(row.dst_ip),
                _ => in_net(row.src_ip) || in_net(row.dst_ip),
            };
            if hit { Verdict::Pass } else { Verdict::Reject }
        }
        (Value::Port(p), field) => {
            let hit = match field {
                Some(Field::SrcPort) => row.src_port == Some(*p),
                Some(Field::DstPort) => row.dst_port == Some(*p),
                _ => row.src_port == Some(*p) || row.dst_port == Some(*p),
            };
            if hit { Verdict::Pass } else { Verdict::Reject }
        }
        (Value::Mac(m), _) => {
            let hit = row.mac_address.as_deref().map(|s| s.to_lowercase()).as_deref() == Some(m.as_str());
            if hit { Verdict::Pass } else { Verdict::Reject }
        }
        // Land und ASN kennt eine frische Zeile noch nicht — nur die
        // Anreicherung weiß es. Das gilt für den AS-Namen wie für die Nummer.
        (Value::Text(_), Some(Field::Country))
        | (Value::Text(_), Some(Field::Asn))
        | (Value::Asn(_), _) => Verdict::Unknowable,
        (Value::Text(t), Some(Field::Action)) => {
            if row.rule_action.is_some_and(|a| a.eq_ignore_ascii_case(t)) {
                Verdict::Pass
            } else {
                Verdict::Reject
            }
        }
        (Value::Text(t), Some(Field::LogType)) => {
            if row.log_type.eq_ignore_ascii_case(t) {
                Verdict::Pass
            } else {
                Verdict::Reject
            }
        }
        (Value::Text(t), Some(Field::Rule)) => {
            if row.rule_name.as_deref().is_some_and(|s| text_hit(s, t, term.glob)) {
                Verdict::Pass
            } else {
                Verdict::Reject
            }
        }
        (Value::Text(t), Some(Field::Protocol)) => {
            if row.protocol.as_deref().is_some_and(|s| text_hit(s, t, term.glob)) {
                Verdict::Pass
            } else {
                Verdict::Reject
            }
        }
        (Value::Text(t), Some(Field::Interface)) => {
            let hit = row.iface_in.as_deref().is_some_and(|s| text_hit(s, t, term.glob))
                || row.iface_out.as_deref().is_some_and(|s| text_hit(s, t, term.glob));
            if hit { Verdict::Pass } else { Verdict::Reject }
        }
        (Value::Text(t), Some(Field::Host)) => {
            // rdns kennt die Zeile noch nicht — nur der Gerätename, falls per
            // DHCP schon bekannt, ist hier prüfbar.
            if row.hostname.as_deref().is_some_and(|s| text_hit(s, t, term.glob)) {
                Verdict::Pass
            } else {
                Verdict::Reject
            }
        }
        (Value::Text(t), _) => {
            // Freier Text: nur gegen die Felder, die LiveRow tatsächlich hat.
            let hit = [
                row.rule_name.as_deref(),
                row.protocol.as_deref(),
                row.iface_in.as_deref(),
                row.iface_out.as_deref(),
                row.hostname.as_deref(),
                row.dns_query.as_deref(),
                row.dns_type.as_deref(),
                row.dns_answer.as_deref(),
                row.dhcp_event.as_deref(),
                row.wifi_event.as_deref(),
                row.raw_log.as_deref(),
                row.mac_address.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|s| text_hit(s, t, term.glob));
            if hit { Verdict::Pass } else { Verdict::Reject }
        }
    }
}

fn search_verdict(row: &LiveRow, q: Option<&str>) -> Verdict {
    let Some(q) = q else { return Verdict::Pass };
    combine(parse_search(q).into_iter().map(|term| {
        match term_hit(row, &term) {
            Verdict::Unknowable => Verdict::Unknowable,
            Verdict::Pass if term.negated => Verdict::Reject,
            Verdict::Pass => Verdict::Pass,
            Verdict::Reject if term.negated => Verdict::Pass,
            Verdict::Reject => Verdict::Reject,
        }
    }))
}

/// Wendet denselben Filter an, der auch `/api/logs` filtert — auf eine Zeile,
/// die gerade erst geschrieben wurde. Zeitfilter (`from`/`to`/`range`) werden
/// hier bewusst ignoriert: eine Zeile, die gerade ankommt, liegt per
/// Definition am oberen Ende.
pub fn matches_live(row: &LiveRow, f: &LogFilter) -> Verdict {
    combine([
        list_verdict(&f.log_type, Some(row.log_type)),
        list_verdict(&f.action, row.rule_action),
        list_verdict(&f.direction, row.direction),
        iface_verdict(&f.iface, row.iface_in.as_deref(), row.iface_out.as_deref()),
        exact_iface_verdict(f.iface_in.as_deref(), row.iface_in.as_deref()),
        exact_iface_verdict(f.iface_out.as_deref(), row.iface_out.as_deref()),
        list_verdict(&f.proto, row.protocol.as_deref()),
        port_verdict(f.port, row.src_port, row.dst_port),
        enriched_verdict(f),
        search_verdict(row, f.q.as_deref()),
    ])
}

pub async fn sse_stream(
    State(events): State<tokio::sync::broadcast::Sender<LiveEvent>>,
    Query(filter): Query<LogFilter>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = events.subscribe();
    // Ob wir dieser Verbindung schon einmal `suspended` geschickt haben —
    // sonst würde jede weitere unbeantwortbare Zeile den Client erneut
    // benachrichtigen.
    let mut suspended_sent = false;
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        // Ein Nachtrag beschreibt eine Adresse, keine Zeile. Er geht ungefiltert
        // durch: die Oberfläche trägt ihn nur in Zeilen ein, die sie ohnehin
        // schon zeigt, und was sie nicht zeigt, geht ihn nichts an.
        Ok(LiveEvent::Enriched(facts)) => {
            let data = serde_json::to_string(&*facts).unwrap_or_default();
            Some(Ok(Event::default().event("enriched").data(data)))
        }
        Ok(LiveEvent::Row(row)) => match matches_live(&row, &filter) {
            Verdict::Pass => {
                let data = serde_json::to_string(&*row).unwrap_or_default();
                Some(Ok(Event::default().event("log").data(data)))
            }
            Verdict::Reject => None,
            Verdict::Unknowable => {
                if suspended_sent {
                    None
                } else {
                    suspended_sent = true;
                    Some(Ok(Event::default().event("suspended").data("")))
                }
            }
        },
        Err(BroadcastStreamRecvError::Lagged(n)) => {
            Some(Ok(Event::default().event("lagged").data(n.to_string())))
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uip_core::LiveRow;

    fn row() -> LiveRow {
        LiveRow {
            timestamp: Utc::now(),
            log_type: "firewall",
            direction: Some("inbound"),
            rule_action: Some("block"),
            rule_name: Some("WAN_IN-D".into()),
            protocol: Some("tcp".into()),
            iface_in: Some("ppp0".into()),
            iface_out: Some("br20".into()),
            src_ip: Some("1.2.3.4".parse().unwrap()),
            dst_ip: Some("10.0.0.5".parse().unwrap()),
            src_port: Some(5000),
            dst_port: Some(443),
            mac_address: None, hostname: None, dns_query: None, dns_type: None,
            dns_answer: None, dhcp_event: None, wifi_event: None, raw_log: None,
        }
    }

    fn f(query: &str) -> LogFilter {
        serde_urlencoded::from_str(query).unwrap()
    }

    #[test]
    fn an_empty_filter_lets_everything_through() {
        assert_eq!(matches_live(&row(), &LogFilter::default()), Verdict::Pass);
    }

    #[test]
    fn type_action_direction_and_interface_are_checked() {
        assert_eq!(matches_live(&row(), &f("log_type=firewall")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("log_type=dns")), Verdict::Reject);
        assert_eq!(matches_live(&row(), &f("action=block")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("action=allow")), Verdict::Reject);
        assert_eq!(matches_live(&row(), &f("direction=inbound")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("iface=ppp0")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("iface=br99")), Verdict::Reject);
        assert_eq!(matches_live(&row(), &f("proto=tcp")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("port=443")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("port=22")), Verdict::Reject);
    }

    /// `iface` trifft beide Seiten; ein Zonenpaar ist gerichtet. Ohne eigene
    /// Prüfung liefe jede frische Zeile am Zonenfilter vorbei in die Liste.
    #[test]
    fn the_directed_interfaces_are_checked_separately() {
        assert_eq!(matches_live(&row(), &f("iface_in=ppp0")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("iface_in=br20")), Verdict::Reject, "das ist die Gegenrichtung");
        assert_eq!(matches_live(&row(), &f("iface_out=br20")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("iface_in=ppp0&iface_out=br20")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("iface_in=ppp0&iface_out=br99")), Verdict::Reject);
    }

    #[test]
    fn search_terms_apply_to_the_stream_too() {
        assert_eq!(matches_live(&row(), &f("q=1.2.3.4")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("q=10.10.10.0%2F24")), Verdict::Reject);
        assert_eq!(matches_live(&row(), &f("q=WAN_IN")), Verdict::Pass);
        assert_eq!(matches_live(&row(), &f("q=%21WAN_IN")), Verdict::Reject);
    }

    /// Eine frisch geschriebene Zeile ist noch nicht angereichert. Nach Land
    /// zu filtern hieße, sie immer zu verwerfen — also sagen wir es lieber.
    #[test]
    fn filtering_on_enriched_fields_suspends_the_stream() {
        assert_eq!(matches_live(&row(), &f("country=DE")), Verdict::Unknowable);
        assert_eq!(matches_live(&row(), &f("threat_min=50")), Verdict::Unknowable);
        assert_eq!(matches_live(&row(), &f("q=country%3ADE")), Verdict::Unknowable);
    }
}
