use crate::search::{parse_search, Field, Term, Value};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sqlx::{Postgres, QueryBuilder};

/// Alle Filter der Log-Ansicht. Leere Felder filtern nicht.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LogFilter {
    #[serde(deserialize_with = "comma_list")]
    pub log_type: Vec<String>,
    #[serde(deserialize_with = "comma_list")]
    pub action: Vec<String>,
    #[serde(deserialize_with = "comma_list")]
    pub direction: Vec<String>,
    #[serde(deserialize_with = "comma_list")]
    pub iface: Vec<String>,
    #[serde(deserialize_with = "comma_list")]
    pub proto: Vec<String>,
    #[serde(deserialize_with = "comma_list")]
    pub country: Vec<String>,
    pub port: Option<i32>,
    pub threat_min: Option<i32>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub range: Option<String>,
    pub q: Option<String>,
}

fn comma_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let raw = Option::<String>::deserialize(d)?;
    Ok(raw
        .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default())
}

fn log_type_id(name: &str) -> Option<i16> {
    Some(match name { "firewall" => 1, "dns" => 2, "dhcp" => 3, "wifi" => 4, "system" => 5, _ => return None })
}
fn action_id(name: &str) -> Option<i16> {
    Some(match name { "allow" => 1, "block" => 2, "redirect" => 3, _ => return None })
}
fn direction_id(name: &str) -> Option<i16> {
    Some(match name {
        "inbound" => 1, "outbound" => 2, "local" => 3,
        "inter_vlan" => 4, "vpn" => 5, "nat" => 6, _ => return None,
    })
}

fn ids(names: &[String], map: fn(&str) -> Option<i16>) -> Vec<i16> {
    names.iter().filter_map(|n| map(n)).collect()
}

/// Wandelt '7d' in einen Zeitpunkt. Unbekanntes ergibt None statt eines Fehlers.
fn range_start(range: &str) -> Option<DateTime<Utc>> {
    let (value, unit) = range.split_at(range.len().checked_sub(1)?);
    let n: i64 = value.parse().ok()?;
    let d = match unit {
        "h" => Duration::try_hours(n)?,
        "d" => Duration::try_days(n)?,
        "m" => Duration::try_minutes(n)?,
        _ => return None,
    };
    Some(Utc::now() - d)
}

impl LogFilter {
    /// True wenn kein einziges Feld gesetzt ist — der Fall, in dem
    /// `/api/logs/count` auf `approximate_row_count` statt auf ein echtes
    /// `COUNT(*)` ausweichen darf, weil `push_where` ohnehin nur `WHERE TRUE`
    /// ergäbe.
    pub fn is_unfiltered(&self) -> bool {
        self.log_type.is_empty()
            && self.action.is_empty()
            && self.direction.is_empty()
            && self.iface.is_empty()
            && self.proto.is_empty()
            && self.country.is_empty()
            && self.port.is_none()
            && self.threat_min.is_none()
            && self.from.is_none()
            && self.to.is_none()
            && self.range.is_none()
            && self.q.is_none()
    }

    /// Die Joins, die Filter und Ausgabe gemeinsam brauchen.
    pub fn push_joins(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        qb.push(
            " LEFT JOIN rules r ON r.id = l.rule_id \
              LEFT JOIN interfaces ii ON ii.id = l.iface_in_id \
              LEFT JOIN interfaces io ON io.id = l.iface_out_id \
              LEFT JOIN protocols pr ON pr.id = l.protocol_id \
              LEFT JOIN device_names dn ON dn.id = l.hostname_id ",
        );
    }

    pub fn push_where(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        qb.push(" WHERE TRUE");

        let types = ids(&self.log_type, log_type_id);
        if !types.is_empty() {
            qb.push(" AND l.log_type_id = ANY(").push_bind(types).push(")");
        }
        // "unknown" ist keine Id, sondern das Fehlen einer: Zeilen ohne
        // erkannte Aktion. Ohne diesen Fall verschwände die Pille wirkungslos,
        // weil `ids` den Namen zu keiner Id auflöst und die Liste leer bliebe.
        let wants_unknown = self.action.iter().any(|a| a == "unknown");
        let actions = ids(&self.action, action_id);
        if !actions.is_empty() || wants_unknown {
            qb.push(" AND (");
            if !actions.is_empty() {
                qb.push("l.rule_action_id = ANY(").push_bind(actions).push(")");
                if wants_unknown {
                    qb.push(" OR ");
                }
            }
            if wants_unknown {
                qb.push("l.rule_action_id IS NULL");
            }
            qb.push(")");
        }
        let directions = ids(&self.direction, direction_id);
        if !directions.is_empty() {
            qb.push(" AND l.direction_id = ANY(").push_bind(directions).push(")");
        }
        if !self.iface.is_empty() {
            let names: Vec<String> = self.iface.iter().map(|s| s.to_lowercase()).collect();
            qb.push(" AND (lower(ii.name) = ANY(").push_bind(names.clone())
              .push(") OR lower(io.name) = ANY(").push_bind(names).push("))");
        }
        if !self.proto.is_empty() {
            let names: Vec<String> = self.proto.iter().map(|s| s.to_lowercase()).collect();
            qb.push(" AND lower(pr.name) = ANY(").push_bind(names).push(")");
        }
        if !self.country.is_empty() {
            let codes: Vec<String> = self.country.iter().map(|s| s.to_uppercase()).collect();
            qb.push(" AND l.geo_country = ANY(").push_bind(codes).push(")");
        }
        if let Some(port) = self.port {
            qb.push(" AND (l.src_port = ").push_bind(port)
              .push(" OR l.dst_port = ").push_bind(port).push(")");
        }
        if let Some(min) = self.threat_min {
            qb.push(" AND l.threat_score >= ").push_bind(min);
        }
        let from = self.from.or_else(|| self.range.as_deref().and_then(range_start));
        if let Some(from) = from {
            qb.push(" AND l.timestamp >= ").push_bind(from);
        }
        if let Some(to) = self.to {
            qb.push(" AND l.timestamp <= ").push_bind(to);
        }
        for term in self.q.as_deref().map(parse_search).unwrap_or_default() {
            push_term(qb, &term);
        }
    }
}

fn push_term(qb: &mut QueryBuilder<'_, Postgres>, term: &Term) {
    // NOT(a OR b) is NULL, not TRUE, once a or b is NULL (e.g. an absent
    // dst_ip on a DNS row) — COALESCE to FALSE first so negation of an
    // unknown column reads as "doesn't match" rather than "drop the row".
    qb.push(if term.negated { " AND NOT COALESCE((" } else { " AND (" });
    match (&term.value, term.field) {
        (Value::Ip(ip), field) => {
            let net = ipnetwork::IpNetwork::from(*ip);
            match field {
                Some(Field::SrcIp) => { qb.push("l.src_ip = ").push_bind(net); }
                Some(Field::DstIp) => { qb.push("l.dst_ip = ").push_bind(net); }
                _ => {
                    qb.push("l.src_ip = ").push_bind(net)
                      .push(" OR l.dst_ip = ").push_bind(net);
                }
            }
        }
        (Value::Cidr(net), field) => match field {
            Some(Field::SrcIp) => { qb.push("l.src_ip <<= ").push_bind(*net); }
            Some(Field::DstIp) => { qb.push("l.dst_ip <<= ").push_bind(*net); }
            _ => {
                qb.push("l.src_ip <<= ").push_bind(*net)
                  .push(" OR l.dst_ip <<= ").push_bind(*net);
            }
        },
        (Value::Port(p), field) => match field {
            Some(Field::SrcPort) => { qb.push("l.src_port = ").push_bind(*p); }
            Some(Field::DstPort) => { qb.push("l.dst_port = ").push_bind(*p); }
            _ => {
                qb.push("l.src_port = ").push_bind(*p)
                  .push(" OR l.dst_port = ").push_bind(*p);
            }
        },
        (Value::Mac(m), _) => {
            qb.push("l.mac_address::text = ").push_bind(m.clone());
        }
        // Entsteht nur aus `asn:<zahl>` und vergleicht die AS-Nummer exakt.
        // Ohne eigenen Fall läse der Parser sie als Port — die meisten
        // AS-Nummern liegen im Portbereich.
        (Value::Asn(n), _) => {
            qb.push("l.asn_number = ").push_bind(*n);
        }
        (Value::Text(t), field @ (Some(Field::Action) | Some(Field::LogType))) => {
            // action:<name> / type:<name> beschränken über die Id, nicht als
            // Text — sonst passt der Begriff auf nichts Sinnvolles.
            let id = match field {
                Some(Field::Action) => action_id(t),
                Some(Field::LogType) => log_type_id(t),
                _ => unreachable!(),
            };
            let column = match field {
                Some(Field::Action) => "l.rule_action_id",
                Some(Field::LogType) => "l.log_type_id",
                _ => unreachable!(),
            };
            match id {
                Some(id) => { qb.push(column).push(" = ").push_bind(id); }
                // Der Name passt zu keiner Id — der Begriff soll nichts treffen.
                None => { qb.push("FALSE"); }
            }
        }
        (Value::Text(t), field) => {
            // '*' ist das Muster, das Leute tippen; SQL will '%'.
            let pattern = if term.glob { t.replace('*', "%") } else { format!("%{t}%") };
            let columns: &[&str] = match field {
                Some(Field::Rule) => &["r.name", "r.descr"],
                Some(Field::Country) => &["l.geo_country"],
                Some(Field::Asn) => &["l.asn_name"],
                Some(Field::Protocol) => &["pr.name"],
                Some(Field::Interface) => &["ii.name", "io.name"],
                Some(Field::Host) => &["dn.name", "l.rdns"],
                _ => &[
                    "r.name", "r.descr", "ii.name", "io.name", "pr.name", "dn.name",
                    "l.dns_query", "l.rdns", "l.asn_name", "l.geo_country", "l.geo_city",
                    "l.dhcp_event", "l.wifi_event", "l.raw_log",
                ],
            };
            for (i, col) in columns.iter().enumerate() {
                if i > 0 {
                    qb.push(" OR ");
                }
                qb.push(*col).push(" ILIKE ").push_bind(pattern.clone());
            }
        }
    }
    qb.push(if term.negated { "), FALSE)" } else { ")" });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Legt eine überschaubare, bekannte Menge an Zeilen an.
    async fn seed(pool: &sqlx::PgPool) {
        // iface/proto/rule über die Lookup-Tabellen
        sqlx::query("INSERT INTO interfaces (name) VALUES ('ppp0'), ('br20')").execute(pool).await.unwrap();
        sqlx::query("INSERT INTO protocols (name) VALUES ('tcp'), ('udp')").execute(pool).await.unwrap();
        sqlx::query("INSERT INTO rules (name, descr) VALUES ('WAN_IN-D', 'Block Bad')").execute(pool).await.unwrap();

        // firewall/block/inbound, 1.2.3.4 → 10.0.0.5:443, tcp, ppp0, DE
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, direction_id, rule_action_id, rule_id,
                 protocol_id, iface_in_id, src_ip, dst_ip, src_port, dst_port, geo_country, threat_score)
             VALUES (NOW(), 1, 1, 2, 1, 1, 1, '1.2.3.4', '10.0.0.5', 5000, 443, 'DE', 80)",
        ).execute(pool).await.unwrap();

        // firewall/allow/outbound, 10.10.30.7 → 8.8.8.8:53, udp, br20
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, direction_id, rule_action_id,
                 protocol_id, iface_in_id, src_ip, dst_ip, src_port, dst_port, geo_country)
             VALUES (NOW() - INTERVAL '2 hours', 1, 2, 1, 2, 2, '10.10.30.7', '8.8.8.8', 5001, 53, 'US')",
        ).execute(pool).await.unwrap();

        // dns-Zeile, drei Tage alt
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, dns_query)
             VALUES (NOW() - INTERVAL '3 days', 2, '10.10.30.100', 'example.com')",
        ).execute(pool).await.unwrap();
    }

    /// Wendet einen Filter an und gibt die Quell-Adressen der Treffer zurück.
    async fn matching(pool: &sqlx::PgPool, f: &LogFilter) -> Vec<String> {
        let mut qb = sqlx::QueryBuilder::new("SELECT host(l.src_ip) AS src FROM logs l ");
        f.push_joins(&mut qb);
        f.push_where(&mut qb);
        qb.push(" ORDER BY l.timestamp DESC");
        qb.build_query_scalar::<Option<String>>()
            .fetch_all(pool).await.unwrap()
            .into_iter().flatten().collect()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn no_filter_returns_everything(pool: sqlx::PgPool) {
        seed(&pool).await;
        assert_eq!(matching(&pool, &LogFilter::default()).await.len(), 3);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn filters_by_type_action_and_direction(pool: sqlx::PgPool) {
        seed(&pool).await;
        let f = LogFilter { log_type: vec!["firewall".into()], ..Default::default() };
        assert_eq!(matching(&pool, &f).await.len(), 2);

        let f = LogFilter { action: vec!["block".into()], ..Default::default() };
        assert_eq!(matching(&pool, &f).await, ["1.2.3.4"]);

        let f = LogFilter { direction: vec!["outbound".into()], ..Default::default() };
        assert_eq!(matching(&pool, &f).await, ["10.10.30.7"]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn filters_by_interface_protocol_country_and_port(pool: sqlx::PgPool) {
        seed(&pool).await;
        assert_eq!(matching(&pool, &LogFilter { iface: vec!["ppp0".into()], ..Default::default() }).await, ["1.2.3.4"]);
        assert_eq!(matching(&pool, &LogFilter { proto: vec!["udp".into()], ..Default::default() }).await, ["10.10.30.7"]);
        assert_eq!(matching(&pool, &LogFilter { country: vec!["DE".into()], ..Default::default() }).await, ["1.2.3.4"]);
        // Port trifft Quelle oder Ziel
        assert_eq!(matching(&pool, &LogFilter { port: Some(443), ..Default::default() }).await, ["1.2.3.4"]);
        assert_eq!(matching(&pool, &LogFilter { port: Some(5001), ..Default::default() }).await, ["10.10.30.7"]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn filters_by_threat_and_time(pool: sqlx::PgPool) {
        seed(&pool).await;
        assert_eq!(matching(&pool, &LogFilter { threat_min: Some(50), ..Default::default() }).await, ["1.2.3.4"]);

        let f = LogFilter { from: Some(chrono::Utc::now() - chrono::Duration::hours(1)), ..Default::default() };
        assert_eq!(matching(&pool, &f).await, ["1.2.3.4"]);

        let f = LogFilter { range: Some("24h".into()), ..Default::default() };
        assert_eq!(matching(&pool, &f).await.len(), 2, "die drei Tage alte Zeile fällt raus");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn search_terms_are_typed_not_textual(pool: sqlx::PgPool) {
        seed(&pool).await;
        // exakte Adresse
        assert_eq!(matching(&pool, &LogFilter { q: Some("1.2.3.4".into()), ..Default::default() }).await, ["1.2.3.4"]);
        // Netz trifft beide 10.10.30.x-Zeilen
        assert_eq!(matching(&pool, &LogFilter { q: Some("10.10.30.0/24".into()), ..Default::default() }).await.len(), 2);
        // Port
        assert_eq!(matching(&pool, &LogFilter { q: Some("443".into()), ..Default::default() }).await, ["1.2.3.4"]);
        // Text trifft den Regelnamen
        assert_eq!(matching(&pool, &LogFilter { q: Some("WAN_IN".into()), ..Default::default() }).await, ["1.2.3.4"]);
        // Feld-Beschränkung
        assert_eq!(matching(&pool, &LogFilter { q: Some("dst:8.8.8.8".into()), ..Default::default() }).await, ["10.10.30.7"]);
        // Negation
        let out = matching(&pool, &LogFilter { q: Some("!1.2.3.4".into()), ..Default::default() }).await;
        assert!(!out.contains(&"1.2.3.4".to_string()) && out.len() == 2);
    }

    /// Der Grund für den typisierten Parser.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_shorter_address_does_not_match_a_longer_one(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO logs (timestamp, log_type_id, src_ip) VALUES (NOW(), 1, '10.10.10.100')")
            .execute(&pool).await.unwrap();
        let f = LogFilter { q: Some("10.10.10.10".into()), ..Default::default() };
        assert!(matching(&pool, &f).await.is_empty(), "10.10.10.10 darf 10.10.10.100 nicht treffen");
    }


    /// `unknown` ist die vierte Aktions-Pille des Forks und meint Zeilen ohne
    /// erkannte Aktion — etwa DNS. Ohne eigenen Fall löste `ids` den Namen zu
    /// keiner Id auf, die Liste blieb leer und der Filter wirkte gar nicht.
    #[sqlx::test(migrations = "../../migrations")]
    async fn unknown_action_matches_rows_without_one(pool: sqlx::PgPool) {
        seed(&pool).await;
        let f = LogFilter { action: vec!["unknown".into()], ..Default::default() };
        assert_eq!(matching(&pool, &f).await, ["10.10.30.100"], "nur die DNS-Zeile");

        // Zusammen mit einer echten Aktion gilt die Vereinigung.
        let f = LogFilter { action: vec!["block".into(), "unknown".into()], ..Default::default() };
        let out = matching(&pool, &f).await;
        assert_eq!(out.len(), 2);
        assert!(out.contains(&"1.2.3.4".to_string()));
        assert!(out.contains(&"10.10.30.100".to_string()));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn filters_combine_with_and(pool: sqlx::PgPool) {
        seed(&pool).await;
        let f = LogFilter {
            log_type: vec!["firewall".into()],
            action: vec!["allow".into()],
            q: Some("53".into()),
            ..Default::default()
        };
        assert_eq!(matching(&pool, &f).await, ["10.10.30.7"]);
    }

    #[test]
    fn is_unfiltered_is_true_only_for_a_bare_default() {
        assert!(LogFilter::default().is_unfiltered());
        assert!(!LogFilter { q: Some("x".into()), ..Default::default() }.is_unfiltered());
        assert!(!LogFilter { action: vec!["block".into()], ..Default::default() }.is_unfiltered());
        assert!(!LogFilter { port: Some(443), ..Default::default() }.is_unfiltered());
    }

    /// action:<name> muss über die Id filtern, nicht als Text durchfallen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn search_action_field_matches_by_id_not_text(pool: sqlx::PgPool) {
        seed(&pool).await;
        assert_eq!(matching(&pool, &LogFilter { q: Some("action:block".into()), ..Default::default() }).await, ["1.2.3.4"]);
        assert_eq!(matching(&pool, &LogFilter { q: Some("action:allow".into()), ..Default::default() }).await, ["10.10.30.7"]);
        // Unbekannter Name trifft nichts.
        assert!(matching(&pool, &LogFilter { q: Some("action:bogus".into()), ..Default::default() }).await.is_empty());
    }

    /// type:<name> ebenso.
    #[sqlx::test(migrations = "../../migrations")]
    async fn search_log_type_field_matches_by_id_not_text(pool: sqlx::PgPool) {
        seed(&pool).await;
        assert_eq!(matching(&pool, &LogFilter { q: Some("type:dns".into()), ..Default::default() }).await, ["10.10.30.100"]);
        assert_eq!(matching(&pool, &LogFilter { q: Some("type:firewall".into()), ..Default::default() }).await.len(), 2);
        // Unbekannter Name trifft nichts.
        assert!(matching(&pool, &LogFilter { q: Some("type:bogus".into()), ..Default::default() }).await.is_empty());
    }
}
