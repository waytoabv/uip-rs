# Phase 3a "Filter, Suche und Export" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Die Log-Ansicht wird benutzbar — typisierte Suche, explizite Filter, ein Live-Stream der demselben Filter folgt, CSV-Export und Theming.

**Architecture:** Ein Suchparser klassifiziert Begriffe (Adresse, Netz, Port, MAC, Text) statt alles als Text zu vergleichen. Filter und Suchbegriffe bauen über `sqlx::QueryBuilder` dieselbe WHERE-Klausel für `/api/logs` und `/api/export`. Der Writer sendet an SSE künftig einen typisierten `LiveRow` statt eines JSON-Strings, damit derselbe Filter auch auf den Stream passt.

**Tech Stack:** bestehender Stack; neu nur `csv` (Export) und `tokio-stream` (schon vorhanden).

**Referenz-Spec:** `docs/superpowers/specs/2026-09-14-phase3a-filters-search-export-design.md`

**Umgebung:** Dev-DB `postgres://lukas@localhost/uip_dev` (expliziter Benutzer ist Pflicht). Tests via `#[sqlx::test(migrations = "../../migrations")]`.

---

### Task 1: Der Suchparser

Reine Funktion, kein SQL, kein Zustand. Die Tests sind die Spezifikation.

**Files:**
- Create: `crates/uip-api/src/search.rs`
- Modify: `crates/uip-api/src/lib.rs`

- [ ] **Step 1: Failing Tests**

```rust
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

    #[test]
    fn nothing_in_nothing_out() {
        assert!(parse_search("").is_empty());
        assert!(parse_search("   ").is_empty());
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-api search`
Expected: FAIL — `parse_search` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-api/src/search.rs`:

```rust
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
    let value = typed(&token);
    Some(Term { value, field, negated, glob })
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
```

`lib.rs` ergänzen: `pub mod search;`

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-api`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): typed search term parser"
```

---

### Task 2: Filter und WHERE-Aufbau

**Files:**
- Create: `crates/uip-api/src/filters.rs`
- Modify: `crates/uip-api/src/lib.rs`

- [ ] **Step 1: Failing Tests** (gegen eine echte DB — geprüft wird, welche Zeilen zurückkommen, nicht welcher SQL-String entsteht)

```rust
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
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-api filters`
Expected: FAIL — `LogFilter` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-api/src/filters.rs`:

```rust
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
        let actions = ids(&self.action, action_id);
        if !actions.is_empty() {
            qb.push(" AND l.rule_action_id = ANY(").push_bind(actions).push(")");
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
    qb.push(if term.negated { " AND NOT (" } else { " AND (" });
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
    qb.push(")");
}
```

`lib.rs` ergänzen: `pub mod filters;`

**Hinweis zu `Action`/`LogType` als Textbegriff:** `action:block` und
`type:dns` landen im Text-Zweig und treffen dort nichts Sinnvolles. Ergänze
für `Some(Field::Action)` und `Some(Field::LogType)` je einen Zweig, der den
Text über `action_id`/`log_type_id` in eine Id übersetzt und gegen
`l.rule_action_id` bzw. `l.log_type_id` vergleicht; passt der Name zu keiner
Id, soll der Begriff nichts treffen (`FALSE`). Schreibe dafür zwei Tests
analog zu `search_terms_are_typed_not_textual`.

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-api`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): log filters and search into one where clause"
```

### Task 3: /api/logs nutzt die Filter

**Files:**
- Modify: `crates/uip-api/src/logs.rs`

- [ ] **Step 1: Failing Test**

```rust
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_endpoint_applies_filters_and_keeps_paging(pool: sqlx::PgPool) {
        for i in 0..4 {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, rule_action_id, src_ip, dst_port)
                 VALUES (NOW() - make_interval(secs => $1::int), $2, $3, '1.2.3.4', 443)",
            )
            .bind(i)
            .bind(if i % 2 == 0 { 1i16 } else { 2i16 })   // firewall / dns
            .bind(if i % 2 == 0 { Some(2i16) } else { None }) // block / -
            .execute(&pool).await.unwrap();
        }
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);

        let body = get_json(&app, "/api/logs?log_type=firewall").await;
        assert_eq!(body["rows"].as_array().unwrap().len(), 2);
        assert!(body["rows"].as_array().unwrap().iter().all(|r| r["log_type"] == "firewall"));

        // Filter und Cursor zusammen: Seite 1 und 2 überschneiden sich nicht.
        let first = get_json(&app, "/api/logs?log_type=firewall&limit=1").await;
        let cursor = first["next_cursor"].as_str().unwrap();
        let second = get_json(&app, &format!("/api/logs?log_type=firewall&limit=1&before={cursor}")).await;
        assert_eq!(second["rows"].as_array().unwrap().len(), 1);
        assert_ne!(first["rows"][0]["id"], second["rows"][0]["id"]);

        // Suche
        let body = get_json(&app, "/api/logs?q=443").await;
        assert_eq!(body["rows"].as_array().unwrap().len(), 4);
        let body = get_json(&app, "/api/logs?q=9.9.9.9").await;
        assert!(body["rows"].as_array().unwrap().is_empty());
    }
```

Dazu einen Helfer bei den bestehenden Tests ergänzen:

```rust
    async fn get_json(app: &axum::Router, uri: &str) -> serde_json::Value {
        let res = app.clone().oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "bei {uri}");
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap()).unwrap()
    }
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-api the_endpoint_applies_filters`
Expected: FAIL — Filter werden ignoriert.

- [ ] **Step 3: `get_logs` auf QueryBuilder umstellen**

`LogsQuery` wird zu `{ limit, before, #[serde(flatten)] filter: LogFilter }`. Die
handgeschriebene Query weicht einem `QueryBuilder`, der dieselbe SELECT-Liste
wie bisher benutzt (inklusive der Enrichment-Spalten aus Phase 2), dann
`filter.push_joins`, `filter.push_where`, dann die Cursor-Bedingung, Sortierung
und Limit:

```rust
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT l.id, l.timestamp, l.log_type_id, l.direction_id, l.rule_action_id,
                host(l.src_ip) AS src_ip, host(l.dst_ip) AS dst_ip,
                l.src_port, l.dst_port, l.mac_address::text AS mac_address,
                l.dns_query, l.dns_type, l.dns_answer, l.dhcp_event, l.wifi_event, l.raw_log,
                l.geo_country, l.geo_city, l.geo_lat::float8 AS geo_lat,
                l.geo_lon::float8 AS geo_lon, l.asn_number, l.asn_name,
                l.rdns, l.threat_score, l.threat_categories, l.abuse_is_tor,
                r.name AS rule_name, r.descr AS rule_desc,
                ii.name AS iface_in, io.name AS iface_out,
                pr.name AS protocol, dn.name AS hostname
         FROM logs l ",
    );
    q.filter.push_joins(&mut qb);
    q.filter.push_where(&mut qb);
    if let Some((ts, id)) = cursor {
        qb.push(" AND (l.timestamp, l.id) < (").push_bind(ts).push(", ").push_bind(id).push(")");
    }
    qb.push(" ORDER BY l.timestamp DESC, l.id DESC LIMIT ").push_bind(limit);
    let rows = qb.build().fetch_all(&pool).await.unwrap_or_default();
```

Die Zeilen-zu-JSON-Schleife bleibt unverändert. `push_where` beginnt mit
`WHERE TRUE`, deshalb dürfen alle weiteren Bedingungen mit `AND` anfangen.

- [ ] **Step 4: Alle API-Tests grün**

Run: `cargo test -p uip-api`
Expected: PASS — auch die bestehenden Tests aus Phase 1 und 2.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): filter and search on /api/logs"
```

---

### Task 4: Der Live-Stream folgt dem Filter

Der Writer sendet künftig einen typisierten Datensatz statt eines fertigen
JSON-Strings, damit Stream und Abfrage denselben Filter benutzen.

**Files:**
- Create: `crates/uip-core/src/live.rs`
- Modify: `crates/uip-core/src/lib.rs`, `crates/uip-ingest/src/writer.rs`, `crates/uip-api/src/lib.rs`, `crates/uip-api/src/stream.rs`, `crates/uip/src/main.rs`

- [ ] **Step 1: `LiveRow` in uip-core**

```rust
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::IpAddr;

/// Eine gerade geschriebene Zeile, wie sie an offene Streams geht.
/// Angereicherte Felder fehlen absichtlich: zu diesem Zeitpunkt gibt es sie
/// noch nicht.
#[derive(Debug, Clone, Serialize)]
pub struct LiveRow {
    pub timestamp: DateTime<Utc>,
    pub log_type: &'static str,
    pub direction: Option<&'static str>,
    pub rule_action: Option<&'static str>,
    pub rule_name: Option<String>,
    pub protocol: Option<String>,
    pub iface_in: Option<String>,
    pub iface_out: Option<String>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub dns_query: Option<String>,
    pub dns_type: Option<String>,
    pub dns_answer: Option<String>,
    pub dhcp_event: Option<String>,
    pub wifi_event: Option<String>,
    pub raw_log: Option<String>,
}
```

`lib.rs`: `pub mod live; pub use live::LiveRow;`

- [ ] **Step 2: Writer sendet LiveRow**

In `writer.rs` wird aus `broadcast::Sender<String>` ein
`broadcast::Sender<Arc<LiveRow>>`. `Row.json: String` wird zu
`Row.live: Arc<LiveRow>`, gefüllt aus denselben Werten wie bisher das JSON.
Der bestehende Writer-Test prüft statt `evt.contains("\"src_ip\":\"1.2.3.4\"")`
jetzt `evt.src_ip == Some("1.2.3.4".parse().unwrap())`.

- [ ] **Step 3: Failing Tests für den Stream-Filter**

In `stream.rs`:

```rust
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
```

- [ ] **Step 4: Implementierung**

`Verdict` und `matches_live` in `stream.rs`:

```rust
/// Was der Stream mit einer Zeile tun soll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Reject,
    /// Der Filter fragt nach etwas, das erst die Anreicherung weiß.
    Unknowable,
}

pub fn matches_live(row: &LiveRow, f: &LogFilter) -> Verdict { … }
```

Regeln:
- `country`, `threat_min` gesetzt → `Unknowable`.
- Ein Suchbegriff mit `Field::Country`, `Field::Asn` oder einem Textbegriff,
  der nur angereicherte Spalten treffen könnte → `Unknowable`. Für den freien
  Text genügt die Prüfung gegen die Felder, die `LiveRow` hat; er gilt als
  `Reject`, wenn keines passt (das ist ehrlich: die Zeile enthält den Text
  jetzt nicht).
- Sonst jeder Filter der Reihe nach; eine Abweichung ergibt `Reject`.
- Zeitfilter (`from`/`to`/`range`) auf dem Stream ignorieren — eine Zeile, die
  gerade ankommt, liegt per Definition am oberen Ende.

Der SSE-Handler nimmt statt `StreamQuery` jetzt `Query<LogFilter>`, serialisiert
die Zeile pro Verbindung erst nach bestandenem Filter, und sendet bei
`Unknowable` **einmalig** ein Ereignis `suspended`, solange der Filter aktiv
ist (nicht pro Zeile — sonst flutet es den Client).

`serde_urlencoded` als dev-dependency in `uip-api` ergänzen, falls für die
Tests nötig.

- [ ] **Step 5: main und Tests anpassen**

`main.rs`: der Kanaltyp wird `broadcast::channel::<Arc<LiveRow>>(1024)`.
`ApiState.events` entsprechend. Die `FromRef`-Implementierung mitziehen.

- [ ] **Step 6: Alles grün**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(api): the live stream follows the same filter"
```

---

### Task 5: CSV-Export

**Files:**
- Create: `crates/uip-api/src/export.rs`
- Modify: `crates/uip-api/src/lib.rs`, `crates/uip-api/Cargo.toml`

- [ ] **Step 1: Failing Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[sqlx::test(migrations = "../../migrations")]
    async fn exports_filtered_rows_as_csv(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO rules (name, descr) VALUES ('A,B', 'mit, Komma')").execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, rule_action_id, rule_id, src_ip, dst_port, geo_country)
             VALUES (NOW(), 1, 2, 1, '1.2.3.4', 443, 'DE')",
        ).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO logs (timestamp, log_type_id, src_ip) VALUES (NOW(), 2, '10.0.0.9')")
            .execute(&pool).await.unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get("/api/export?log_type=firewall").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["content-type"], "text/csv; charset=utf-8");
        assert!(res.headers()["content-disposition"].to_str().unwrap().contains("attachment"));

        let body = String::from_utf8(
            axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec()
        ).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[0].starts_with("timestamp,log_type,"), "Kopfzeile fehlt: {:?}", lines[0]);
        assert_eq!(lines.len(), 2, "nur die Firewall-Zeile, plus Kopf");
        assert!(lines[1].contains("1.2.3.4"));
        // Ein Komma im Regelnamen darf die Spalten nicht verschieben.
        assert!(lines[1].contains("\"A,B\""), "Regelname nicht maskiert: {:?}", lines[1]);
        assert!(!lines[1].contains("10.0.0.9"));
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-api export`
Expected: FAIL — Route fehlt (404).

- [ ] **Step 3: Implementierung**

`csv = "1"` als Dependency in `crates/uip-api/Cargo.toml`.

`export.rs` baut dieselbe Abfrage wie `get_logs` (Filter, aber ohne Cursor,
`LIMIT 100000`), holt die Zeilen und schreibt sie mit `csv::Writer` in einen
`Vec<u8>`, der als Body zurückgeht. Header: `Content-Type: text/csv;
charset=utf-8`, `Content-Disposition: attachment; filename="uip-logs.csv"`.

Spalten (aufgelöste Namen, keine Ids): `timestamp, log_type, direction, action,
rule_name, iface_in, iface_out, protocol, src_ip, src_port, dst_ip, dst_port,
mac_address, hostname, geo_country, geo_city, asn_name, rdns, threat_score,
dns_query, dhcp_event, wifi_event`.

**Zur Spec:** dort steht, der Export solle gestreamt werden. Für 100 000 Zeilen
à ~200 Byte sind das rund 20 MB im Speicher — auf einem 2-GB-LXC vertretbar,
aber unschön. Baue ihn zuerst so (einfach, testbar), und hinterlasse einen
Kommentar, dass `Body::from_stream` mit einem `sqlx`-Cursor der nächste Schritt
ist, sobald das Limit steigt. Nicht vorzeitig optimieren, aber die Stelle
benennen.

Route in `lib.rs`: `.route("/api/export", get(export::export_csv))`.

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-api`

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): csv export of the filtered view"
```

---

### Task 6: Filterleiste, Suchfeld und Chips

**Files:**
- Create: `ui/src/FilterBar.tsx`, `ui/src/filters.ts`
- Modify: `ui/src/App.tsx`, `ui/src/api.ts`

- [ ] **Step 1: Filterzustand**

`ui/src/filters.ts`: ein `FilterState`-Objekt (dieselben Felder wie
`LogFilter`), eine Funktion `toQuery(state): string`, die daraus einen
Query-String baut (leere Werte weglassen), und `describe(state): Chip[]`, die
für die aktiven Filter je ein `{ key, label, clear }` liefert.

- [ ] **Step 2: Die Leiste**

`FilterBar.tsx` zeigt:
- ein Suchfeld (`q`), das **bei Enter** übernimmt, nicht bei jedem Tastendruck
  — sonst schickt jeder Buchstabe eine Abfrage los und die Ergebnisse springen;
- Auswahlfelder für Zeitraum (`range`: 1h/6h/24h/7d/30d), Log-Typ, Aktion und
  Richtung;
- Eingabefelder für Schnittstelle, Protokoll, Land, Port, Mindest-Threat;
- die aktiven Filter als Chips mit einem ×, das genau diesen Filter löscht;
- einen Knopf „CSV" der `/api/export?…` mit demselben Query-String öffnet.

- [ ] **Step 3: App verbindet beides**

`App.tsx` hält den Filterzustand als Signal. Ändert er sich: `/api/logs?…` neu
laden **und** die SSE-Verbindung mit dem neuen Query-String neu aufbauen
(`EventSource` kennt keine nachträgliche Parameteränderung). Auf ein
`suspended`-Ereignis hin zeigt die Tabelle einen Hinweis, dass der Live-Stream
bei diesem Filter pausiert, weil die Felder erst nach der Anreicherung
feststehen.

`api.ts`: `fetchLogs(query: string)` statt `fetchLogs(limit)`.

- [ ] **Step 4: Bauen und ansehen**

Run: `cd ui && npm run build`
Dann Backend starten, ein paar Zeilen einspeisen, im Browser filtern.
Expected: Filter wirken, Chips erscheinen und lassen sich einzeln entfernen,
CSV lädt herunter.

- [ ] **Step 5: Commit**

```bash
git add ui && git commit -m "feat(ui): filter bar, search box and active filter chips"
```

---

### Task 7: Theming

**Files:**
- Modify: `ui/src/index.css`, `ui/src/App.tsx`

- [ ] **Step 1: Farben als Variablen**

`index.css` definiert die Palette als Custom Properties auf `:root` (hell) und
überschreibt sie unter `:root[data-theme="dark"]` sowie unter
`@media (prefers-color-scheme: dark)` — Letzteres eingeschränkt auf
`:root:not([data-theme="light"])`, damit eine getroffene Wahl gewinnt.
Alle bisherigen festen Farben in der Tabelle auf die Variablen umstellen.

- [ ] **Step 2: Umschalter**

In `App.tsx` ein Knopf, der `data-theme` auf `document.documentElement` setzt
und die Wahl in `localStorage` ablegt; beim Start wird sie von dort gelesen.
Ohne gespeicherte Wahl bleibt das Attribut weg, dann gilt die
Systemeinstellung.

- [ ] **Step 3: Bauen und beide Themes ansehen**

Run: `cd ui && npm run build`

- [ ] **Step 4: Commit**

```bash
git add ui && git commit -m "feat(ui): light and dark theme"
```

---

## Abschluss Phase 3a

- [ ] `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cd ui && npm run build`
- [ ] End-to-End: Zeilen einspeisen, filtern, suchen, CSV laden, Theme wechseln
- [ ] README: kurzer Abschnitt zur Suchsyntax
- [ ] Merge nach `main`

**Bewusst nicht in 3a:** Dashboard-Aggregate, Threat Map, Flow View (3b/3c),
gespeicherte Ansichten, Volltextindex.

