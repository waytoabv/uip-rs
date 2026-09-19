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
    /// Genau die eingehende Schnittstelle. `iface` trifft beide Seiten und
    /// taugt deshalb nicht, um ein Zonenpaar (von X nach Y) zu beschreiben.
    pub iface_in: Option<String>,
    /// Genau die ausgehende Schnittstelle.
    pub iface_out: Option<String>,
    #[serde(deserialize_with = "opt_i32")]
    pub port: Option<i32>,
    #[serde(deserialize_with = "opt_i32")]
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

/// Liest eine Zahl, die auch als Zeichenkette ankommen darf.
///
/// Nötig, weil vier Endpunkte den Filter mit `#[serde(flatten)]` einbetten.
/// serde puffert dabei jeden Wert erst als `Content` — und aus einem
/// Query-String ist das immer `Str`, denn serde_urlencoded kennt keine Typen.
/// Ein schlichtes `Option<i32>` sieht dort nie eine Zahl und lässt den ganzen
/// Request mit 400 scheitern, statt zu filtern.
fn opt_i32<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i32>, D::Error> {
    use serde::de::{Error, Visitor};
    use std::fmt;

    struct Outer;
    impl<'de> Visitor<'de> for Outer {
        type Value = Option<i32>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a whole number, or a string holding one")
        }
        fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_any(Inner)
        }
    }

    struct Inner;
    impl<'de> Visitor<'de> for Inner {
        type Value = Option<i32>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a whole number, or a string holding one")
        }
        fn visit_i64<E: Error>(self, v: i64) -> Result<Self::Value, E> {
            i32::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
            i32::try_from(v).map(Some).map_err(E::custom)
        }
        fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
            // Ein leer gelassenes Feld ist kein Filter, kein Fehler.
            match v.trim() {
                "" => Ok(None),
                n => n.parse().map(Some).map_err(E::custom),
            }
        }
    }

    d.deserialize_option(Outer)
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

/// Welche Nachschlagetabellen eine Abfrage braucht.
///
/// Die Log-Zeile trägt Fremdschlüssel statt Namen — wer `r.name` oder
/// `ii.name` auswählt, braucht den Join dazu. Wer nur zählt, braucht keinen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Joins {
    pub rules: bool,
    /// Die Tabelle der Programmnamen — gebraucht von der Zeilenliste und von
    /// einem Filter auf `prog:`.
    pub programs: bool,
    pub interfaces: bool,
    pub protocols: bool,
    pub hostnames: bool,
    /// Gerätenamen aus dem Controller. Seit 0008 stehen sie in
    /// `device_addresses`, und die Zeilenliste hängt sie sich selbst an — hier
    /// bleibt das Feld, weil ein Filter auf einen Gerätenamen denkbar ist.
    pub devices: bool,
}

impl Joins {
    pub const NONE: Self = Self {
        rules: false,
        programs: false,
        interfaces: false,
        protocols: false,
        hostnames: false,
        devices: false,
    };
    pub const ALL: Self = Self {
        rules: true,
        programs: true,
        interfaces: true,
        protocols: true,
        hostnames: true,
        devices: true,
    };

    pub const fn rules(mut self) -> Self {
        self.rules = true;
        self
    }
    pub const fn programs(mut self) -> Self {
        self.programs = true;
        self
    }
    pub const fn interfaces(mut self) -> Self {
        self.interfaces = true;
        self
    }
    pub const fn protocols(mut self) -> Self {
        self.protocols = true;
        self
    }
    pub const fn hostnames(mut self) -> Self {
        self.hostnames = true;
        self
    }

    fn or(self, other: Self) -> Self {
        Self {
            rules: self.rules || other.rules,
            programs: self.programs || other.programs,
            interfaces: self.interfaces || other.interfaces,
            protocols: self.protocols || other.protocols,
            hostnames: self.hostnames || other.hostnames,
            devices: self.devices || other.devices,
        }
    }
}

/// Die Tabellen, die ein Suchbegriff anfasst. Ein Begriff ohne Feldangabe
/// sucht in allem, was Text ist — und das steht zum Teil in den
/// Nachschlagetabellen.
fn term_joins(term: &Term) -> Joins {
    match (&term.value, term.field) {
        (Value::Text(_), Some(Field::Action) | Some(Field::LogType)) => Joins::NONE,
        (Value::Text(_), Some(Field::Rule)) => Joins::NONE.rules(),
        (Value::Text(_), Some(Field::Program)) => Joins::NONE.programs(),
        (Value::Text(_), Some(Field::Severity)) => Joins::NONE,
        (Value::Text(_), Some(Field::Protocol)) => Joins::NONE.protocols(),
        (Value::Text(_), Some(Field::Interface)) => Joins::NONE.interfaces(),
        (Value::Text(_), Some(Field::Host)) => Joins::NONE.hostnames(),
        (Value::Text(_), Some(Field::Country) | Some(Field::Asn)) => Joins::NONE,
        // Ohne Feldangabe wird überall gesucht.
        (Value::Text(_), None) => {
            Joins::NONE.rules().interfaces().protocols().hostnames().programs()
        }
        _ => Joins::NONE,
    }
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
            && self.iface_in.is_none()
            && self.iface_out.is_none()
            && self.port.is_none()
            && self.threat_min.is_none()
            && self.from.is_none()
            && self.to.is_none()
            && self.range.is_none()
            && self.q.is_none()
    }

    /// Welche Nachschlagetabellen dieser Filter selbst braucht.
    ///
    /// Ein Filter auf `proto:udp` vergleicht `pr.name` — ohne den Join stünde
    /// dort kein Name. Umgekehrt braucht ein Zählen nach Richtung keine
    /// einzige davon.
    fn needed_joins(&self) -> Joins {
        let mut needs = Joins::NONE;
        if !self.iface.is_empty() || self.iface_in.is_some() || self.iface_out.is_some() {
            needs.interfaces = true;
        }
        if !self.proto.is_empty() {
            needs.protocols = true;
        }
        for term in self.q.as_deref().map(parse_search).unwrap_or_default() {
            needs = needs.or(term_joins(&term));
        }
        needs
    }

    /// Die Joins für diese Abfrage: was der Filter braucht, dazu was die
    /// Ausgabe verlangt.
    ///
    /// Früher standen hier immer alle neun — auch unter einem `COUNT(*)`, das
    /// keine einzige Spalte daraus liest. Vier davon verbinden über
    /// IP-Adressen (`unifi_clients`, `unifi_devices`); über drei Millionen
    /// Zeilen kostet das ein Vielfaches der Zählung selbst. Gemessen an einer
    /// Kopie des Bestands: `COUNT(DISTINCT src_ip)` fiel von 530 auf 90
    /// Millisekunden, die Top-Listen etwa auf die Hälfte.
    pub fn push_joins(&self, qb: &mut QueryBuilder<'_, Postgres>, extra: Joins) {
        let needs = self.needed_joins().or(extra);
        if needs.rules {
            qb.push(" LEFT JOIN rules r ON r.id = l.rule_id ");
        }
        if needs.programs {
            qb.push(" LEFT JOIN programs pg ON pg.id = l.program_id ");
        }
        if needs.interfaces {
            qb.push(
                " LEFT JOIN interfaces ii ON ii.id = l.iface_in_id \
                  LEFT JOIN interfaces io ON io.id = l.iface_out_id ",
            );
        }
        if needs.protocols {
            qb.push(" LEFT JOIN protocols pr ON pr.id = l.protocol_id ");
        }
        if needs.hostnames {
            qb.push(" LEFT JOIN device_names dn ON dn.id = l.hostname_id ");
        }
        // `devices` verlangt heute keinen Join mehr: die Zeilenliste verbindet
        // `device_addresses` selbst, und kein Filter liest daraus.

    }

    /// Die ausdrücklich gewählten Log-Arten, deren Zeilen keine Aktion
    /// tragen — für sie darf die Aktions-Pille nicht gelten.
    ///
    /// `None`, wenn keine Art gewählt ist: dann fragt niemand nach einer
    /// bestimmten Sorte, und „geblockt" soll geblockt heißen.
    fn actionless_types(&self) -> Option<Vec<i16>> {
        let chosen: Vec<i16> = ids(&self.log_type, log_type_id)
            .into_iter()
            // Firewall-Zeilen tragen immer eine Aktion; für sie gilt die
            // Pille unverändert, samt „unknown". Bei den übrigen Arten trägt
            // sie mal eine (eine von Pi-hole geblockte Abfrage) und meistens
            // keine — und eine Pille, die eine ganze Log-Art verschwinden
            // lässt, ist eine Falle. Wer gezielt nur die geblockten sehen
            // will, schreibt `action:block` in die Suche; der Begriff bleibt
            // streng.
            .filter(|id| *id != 1)
            .collect();
        (!chosen.is_empty()).then_some(chosen)
    }

    /// Dasselbe für die Richtung: die gibt es nur bei Firewall-Zeilen.
    fn directionless_types(&self) -> Option<Vec<i16>> {
        let chosen: Vec<i16> =
            ids(&self.log_type, log_type_id).into_iter().filter(|id| *id != 1).collect();
        (!chosen.is_empty()).then_some(chosen)
    }

    pub fn push_where(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        qb.push(" WHERE TRUE");

        let types = ids(&self.log_type, log_type_id);
        if !types.is_empty() {
            // Logisch überflüssig, für den Planner aber der ganze Punkt:
            // `= ANY($1)` mit gebundenem Array beweist ihm nicht, dass die
            // Firewall-Zeilen ausgeschlossen sind, und ohne diesen Beweis
            // bleibt der partielle `idx_logs_type_time_rare` unberührt
            // liegen. Mit dem Zusatz deckt er genau die seltenen Arten ab,
            // für die er angelegt wurde.
            if !types.contains(&1) {
                qb.push(" AND l.log_type_id <> 1");
            }
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
            // Eine WLAN-Verbindung wird weder erlaubt noch geblockt, eine
            // DHCP-Anfrage auch nicht. Wer ausdrücklich nach einer solchen
            // Log-Art fragt, soll sie sehen — sonst bleibt die Liste leer,
            // und die Pille, die das bewirkt, steht am anderen Ende der
            // Leiste. Ohne Typ-Auswahl bleibt es streng: „geblockt" heißt
            // dann geblockt und nicht „alles, was nicht blockbar ist".
            if let Some(ids) = self.actionless_types() {
                qb.push(" OR (l.rule_action_id IS NULL AND l.log_type_id = ANY(")
                  .push_bind(ids)
                  .push("))");
            }
            qb.push(")");
        }
        let directions = ids(&self.direction, direction_id);
        if !directions.is_empty() {
            qb.push(" AND (l.direction_id = ANY(").push_bind(directions).push(")");
            // Dasselbe für die Richtung — die kennt nur die Firewall.
            if let Some(ids) = self.directionless_types() {
                qb.push(" OR l.log_type_id = ANY(").push_bind(ids).push(")");
            }
            qb.push(")");
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
        if let Some(name) = self.iface_in.as_deref().filter(|s| !s.is_empty()) {
            qb.push(" AND lower(ii.name) = ").push_bind(name.to_lowercase());
        }
        if let Some(name) = self.iface_out.as_deref().filter(|s| !s.is_empty()) {
            qb.push(" AND lower(io.name) = ").push_bind(name.to_lowercase());
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

/// Ein Schweregrad, wie Menschen ihn schreiben: als Zahl oder als Name.
///
/// Die Namen sind die von Syslog, dazu die Kurzformen, die jeder tippt.
fn severity_level(s: &str) -> Option<i16> {
    let s = s.trim().to_ascii_lowercase();
    if let Ok(n) = s.parse::<i16>() {
        return (0..=7).contains(&n).then_some(n);
    }
    Some(match s.as_str() {
        "emerg" | "emergency" | "panic" => 0,
        "alert" => 1,
        "crit" | "critical" => 2,
        "err" | "error" => 3,
        "warn" | "warning" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => return None,
    })
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
        // Der Schweregrad wird als Schwelle gelesen: kleiner ist dringender,
        // `sev:warn` liefert also Warnungen, Fehler und Schlimmeres.
        (Value::Text(t), Some(Field::Severity)) => match severity_level(t) {
            Some(n) => { qb.push("l.severity <= ").push_bind(n); }
            None => { qb.push("FALSE"); }
        },
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
                Some(Field::Program) => &["pg.name"],
                _ => &[
                    "r.name", "r.descr", "ii.name", "io.name", "pr.name", "dn.name", "pg.name",
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
        f.push_joins(&mut qb, Joins::ALL);
        f.push_where(&mut qb);
        qb.push(" ORDER BY l.timestamp DESC");
        qb.build_query_scalar::<Option<String>>()
            .fetch_all(pool).await.unwrap()
            .into_iter().flatten().collect()
    }

    /// Der Schweregrad wird als Schwelle gelesen, das Programm als Name —
    /// beides erst möglich, seit die Zeilen beides überhaupt tragen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn severity_and_program_are_searchable(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO programs (name) VALUES ('systemd'), ('mca-ctrl')")
            .execute(&pool)
            .await
            .unwrap();
        // Eine Warnung von mca-ctrl, eine Info von systemd.
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, severity, program_id, src_ip)
             VALUES (NOW(), 5, 4, 2, '10.0.0.1'), (NOW(), 5, 6, 1, '10.0.0.2')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let q = |s: &str| LogFilter { q: Some(s.to_string()), ..Default::default() };
        // „Warnung und dringender" trifft die eine, nicht die andere.
        assert_eq!(matching(&pool, &q("sev:warn")).await, ["10.0.0.1"]);
        assert_eq!(matching(&pool, &q("sev:info")).await.len(), 2, "Info schließt Warnungen ein");
        assert!(matching(&pool, &q("sev:3")).await.is_empty(), "nichts ist ein Fehler");
        assert_eq!(matching(&pool, &q("prog:mca")).await, ["10.0.0.1"]);
        assert_eq!(matching(&pool, &q("prog:systemd")).await, ["10.0.0.2"]);
        // Ein Wort, das kein Schweregrad ist, trifft nichts — statt alles.
        assert!(matching(&pool, &q("sev:unsinn")).await.is_empty());
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

    /// Wer nach DNS, DHCP, WLAN oder System fragt, bekommt sie auch — die
    /// Pillen für Aktion und Richtung beschreiben Firewall-Verkehr, und diese
    /// Zeilen haben weder das eine noch das andere. Genau das war der Grund,
    /// warum vier von fünf Log-Arten in der Vorauswahl leer aussahen.
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_firewall_pills_do_not_empty_the_other_log_kinds(pool: sqlx::PgPool) {
        seed(&pool).await;
        // Die Vorauswahl der Oberfläche, nur mit einer anderen Art.
        let f = LogFilter {
            log_type: vec!["dns".into()],
            action: vec!["allow".into(), "block".into()],
            direction: vec!["inbound".into(), "outbound".into(), "inter_vlan".into()],
            ..Default::default()
        };
        assert_eq!(matching(&pool, &f).await, ["10.10.30.100"]);

        // Ohne gewählte Art bleibt es streng: „geblockt" heißt geblockt.
        let f = LogFilter { action: vec!["block".into()], ..Default::default() };
        assert_eq!(matching(&pool, &f).await, ["1.2.3.4"]);

        // Und innerhalb der Firewall gilt die Pille weiter.
        let f = LogFilter {
            log_type: vec!["firewall".into()],
            action: vec!["block".into()],
            ..Default::default()
        };
        assert_eq!(matching(&pool, &f).await, ["1.2.3.4"]);

        // Wer gezielt nur die geblockten DNS-Abfragen sehen will, sagt es in
        // der Suche — der Begriff bleibt streng, auch bei gewählter Art.
        let f = LogFilter {
            log_type: vec!["dns".into()],
            q: Some("action:block".into()),
            ..Default::default()
        };
        assert!(matching(&pool, &f).await.is_empty(), "die DNS-Zeile war nicht geblockt");
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

    /// `/api/logs`, `/api/stats/top`, `/api/flows/sankey` und
    /// `/api/flows/host-detail` betten den Filter mit `#[serde(flatten)]` ein.
    /// Dabei puffert serde jeden Wert als Zeichenkette — serde_urlencoded
    /// kennt keine Typen —, und ein schlichtes `Option<i32>` sieht dort nie
    /// eine Zahl: der Request scheiterte mit 400, statt zu filtern.
    #[test]
    fn numeric_fields_survive_a_flattened_query() {
        #[derive(Deserialize)]
        struct Wrapper {
            limit: Option<i64>,
            #[serde(flatten)]
            filter: LogFilter,
        }
        let w: Wrapper =
            serde_urlencoded::from_str("limit=50&port=443&threat_min=80&action=block").unwrap();
        assert_eq!(w.limit, Some(50));
        assert_eq!(w.filter.port, Some(443));
        assert_eq!(w.filter.threat_min, Some(80));
        assert_eq!(w.filter.action, ["block"]);

        // Ohne Flatten muss es weiter gehen — so liest `/api/logs/count`.
        let f: LogFilter = serde_urlencoded::from_str("port=443&threat_min=80").unwrap();
        assert_eq!((f.port, f.threat_min), (Some(443), Some(80)));

        // Ein leeres Feld ist kein Filter, kein Fehler.
        let f: LogFilter = serde_urlencoded::from_str("port=&threat_min=").unwrap();
        assert_eq!((f.port, f.threat_min), (None, None));

        // Die übrigen nicht-textlichen Felder gehen denselben Weg.
        let w: Wrapper =
            serde_urlencoded::from_str("from=2026-09-01T00:00:00Z&to=2026-09-02T00:00:00Z").unwrap();
        assert!(w.filter.from.is_some() && w.filter.to.is_some());
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
