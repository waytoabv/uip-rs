# Phase 2 "Enrichment" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ein Worker reichert die in Phase 1 geschriebenen Log-Zeilen asynchron an — GeoIP, ASN, Reverse DNS und AbuseIPDB-Threat-Score — ohne die Ingest-Latenz anzufassen.

**Architecture:** Neues Crate `uip-enrich`. Die Log-Tabelle ist die Queue: der Worker claimt Batches (`enrich_status 0 → 3`, sofort committet), arbeitet außerhalb jeder Transaktion, schreibt per UNNEST-UPDATE zurück (`→ 1`). Drei Quellen hinter Traits (GeoIP lokal, rDNS, AbuseIPDB), damit der Worker gegen Fakes testbar ist. IP-Fakten liegen zusätzlich in `ip_enrichment` als Cache.

**Tech Stack:** maxminddb, hickory-resolver, reqwest (rustls), arc-swap, async-trait; PostgreSQL + TimescaleDB; bestehender Stack aus Phase 1.

**Referenz-Spec:** `docs/superpowers/specs/2026-09-14-phase2-enrichment-design.md`

**Umgebung:** Dev-DB `postgres://lukas@localhost/uip_dev` (der explizite Benutzer ist in dieser Sandbox Pflicht). `~/.cargo/bin/sqlx` für Migrationen. Tests laufen mit `#[sqlx::test(migrations = "../../migrations")]`.

**Wichtige API-Fakten** (geprüft, nicht aus dem Gedächtnis):
- maxminddb: `Reader::open_readfile(path)?`, dann `reader.lookup(ip)?.decode::<geoip2::City>()?` → `Option<City>`. Ältere Beispiele mit `lookup::<City>(ip)` sind veraltet.
- hickory-resolver: `Resolver::builder_tokio()?.build()?`, Reverse-Lookup über `resolver.reverse_lookup(ip).await`.

---

### Task 1: Migration 0002 — IP-Cache und fehlende Log-Spalten

**Files:**
- Create: `migrations/0002_enrichment.sql`

- [ ] **Step 1: Migration schreiben**

```sql
-- IP-Fakten als Cache und Wahrheit. logs behält seine denormalisierten
-- Spalten: das Land, das zum Zeitpunkt des Logs galt, bleibt historisch
-- korrekt, auch wenn die Adresse später jemand anderem gehört.
CREATE TABLE ip_enrichment (
    ip                   INET PRIMARY KEY,
    geo_country          VARCHAR(2),
    geo_city             VARCHAR(100),
    geo_lat              DOUBLE PRECISION,
    geo_lon              DOUBLE PRECISION,
    asn_number           INTEGER,
    asn_name             VARCHAR(255),
    rdns                 VARCHAR(255),
    threat_score         INTEGER,
    threat_categories    TEXT[],
    abuse_total_reports  INTEGER,
    abuse_last_reported  TIMESTAMPTZ,
    abuse_is_tor         BOOLEAN,
    abuse_usage_type     TEXT,
    geo_looked_up_at     TIMESTAMPTZ,
    rdns_looked_up_at    TIMESTAMPTZ,
    abuse_looked_up_at   TIMESTAMPTZ
);

-- Kandidaten für eine Auffrischung: alles, was älter als vier Tage ist.
CREATE INDEX idx_ip_enrichment_abuse_age ON ip_enrichment (abuse_looked_up_at)
    WHERE threat_score IS NOT NULL;

-- Die in Phase 1 noch fehlenden AbuseIPDB-Spalten.
ALTER TABLE logs
    ADD COLUMN threat_categories   TEXT[],
    ADD COLUMN abuse_total_reports INTEGER,
    ADD COLUMN abuse_last_reported TIMESTAMPTZ,
    ADD COLUMN abuse_is_tor        BOOLEAN,
    ADD COLUMN abuse_usage_type    TEXT;

CREATE INDEX idx_logs_threat_score ON logs (threat_score, timestamp DESC)
    WHERE threat_score IS NOT NULL;
```

- [ ] **Step 2: Anwenden und prüfen**

Run: `~/.cargo/bin/sqlx migrate run`
Expected: `Applied 2/migrate enrichment`.

Run: `/opt/homebrew/opt/postgresql@18/bin/psql uip_dev -c "\d ip_enrichment"`
Expected: die Tabelle mit allen Spalten.

Falls `ALTER TABLE logs ADD COLUMN` an der Kompression scheitert (`cannot
change ... compressed hypertable`): Kompression vorher lösen ist FALSCH —
melde stattdessen den genauen Fehler, das Schema muss dann anders geschnitten
werden.

- [ ] **Step 3: Commit**

```bash
git add migrations && git commit -m "feat(db): ip enrichment cache and threat columns"
```

---

### Task 2: Crate `uip-enrich` — Typen und Traits

**Files:**
- Create: `crates/uip-enrich/Cargo.toml`, `crates/uip-enrich/src/lib.rs`, `crates/uip-enrich/src/types.rs`
- Modify: `Cargo.toml` (workspace members + deps)

- [ ] **Step 1: Workspace erweitern**

In der Root-`Cargo.toml` `members` um `"crates/uip-enrich"` ergänzen und unter `[workspace.dependencies]` anfügen:

```toml
async-trait = "0.1"
arc-swap = "1"
maxminddb = "0.26"
hickory-resolver = "0.25"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
```

`crates/uip-enrich/Cargo.toml`:

```toml
[package]
name = "uip-enrich"
version.workspace = true
edition.workspace = true

[dependencies]
uip-core = { path = "../uip-core" }
tokio.workspace = true
sqlx.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
anyhow.workspace = true
ipnetwork.workspace = true
async-trait.workspace = true
arc-swap.workspace = true
maxminddb.workspace = true
hickory-resolver.workspace = true
reqwest.workspace = true
```

Sollte eine der Versionen nicht auflösen, nimm die neueste kompatible und melde welche.

- [ ] **Step 2: Failing Test für die Zusammenführung**

`crates/uip-enrich/src/types.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_fills_only_empty_fields() {
        let mut facts = IpFacts { geo_country: Some("DE".into()), ..Default::default() };
        facts.merge(IpFacts {
            geo_country: Some("US".into()),
            rdns: Some("host.example.com".into()),
            ..Default::default()
        });
        // Was schon da ist, bleibt: die erste Quelle gewinnt.
        assert_eq!(facts.geo_country.as_deref(), Some("DE"));
        assert_eq!(facts.rdns.as_deref(), Some("host.example.com"));
    }

    #[test]
    fn empty_facts_carry_nothing() {
        assert!(IpFacts::default().is_empty());
        assert!(!IpFacts { rdns: Some("x".into()), ..Default::default() }.is_empty());
    }
}
```

- [ ] **Step 3: FAIL bestätigen**

Run: `cargo test -p uip-enrich`
Expected: FAIL — `IpFacts` fehlt.

- [ ] **Step 4: Implementierung**

`crates/uip-enrich/src/types.rs` (über dem Testmodul):

```rust
use chrono::{DateTime, Utc};
use std::net::IpAddr;

/// Alles, was wir über eine Adresse wissen können. Jede Quelle füllt ihren Teil.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IpFacts {
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_lat: Option<f64>,
    pub geo_lon: Option<f64>,
    pub asn_number: Option<i32>,
    pub asn_name: Option<String>,
    pub rdns: Option<String>,
    pub threat_score: Option<i32>,
    pub threat_categories: Option<Vec<String>>,
    pub abuse_total_reports: Option<i32>,
    pub abuse_last_reported: Option<DateTime<Utc>>,
    pub abuse_is_tor: Option<bool>,
    pub abuse_usage_type: Option<String>,
}

impl IpFacts {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Übernimmt aus `other` nur, was hier noch fehlt.
    pub fn merge(&mut self, other: IpFacts) {
        macro_rules! fill { ($($f:ident),* $(,)?) => { $(
            if self.$f.is_none() { self.$f = other.$f; }
        )* } }
        fill!(
            geo_country, geo_city, geo_lat, geo_lon, asn_number, asn_name, rdns,
            threat_score, threat_categories, abuse_total_reports,
            abuse_last_reported, abuse_is_tor, abuse_usage_type,
        );
    }
}

/// Ergebnis einer Threat-Abfrage. `QuotaExhausted` ist kein Fehler, sondern
/// der Auftrag, die Zeile später erneut anzufassen.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatOutcome {
    Found(IpFacts),
    NotFound,
    QuotaExhausted,
    Disabled,
}

#[async_trait::async_trait]
pub trait GeoSource: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> IpFacts;
}

#[async_trait::async_trait]
pub trait RdnsSource: Send + Sync {
    async fn lookup(&self, ip: IpAddr) -> Option<String>;
}

#[async_trait::async_trait]
pub trait ThreatSource: Send + Sync {
    async fn lookup(&self, ip: IpAddr) -> ThreatOutcome;
}
```

`crates/uip-enrich/src/lib.rs`:

```rust
pub mod types;
pub use types::{GeoSource, IpFacts, RdnsSource, ThreatOutcome, ThreatSource};
```

- [ ] **Step 5: Tests grün**

Run: `cargo test -p uip-enrich`
Expected: PASS (2 Tests).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(enrich): crate scaffold with fact types and source traits"
```

---

### Task 3: Auswahl der Remote-IP

Nicht jede Zeile hat eine anreicherbare Adresse. Diese Logik ist rein und wird
ohne DB getestet.

**Files:**
- Create: `crates/uip-enrich/src/target.rs`
- Modify: `crates/uip-enrich/src/lib.rs`

- [ ] **Step 1: Failing Tests**

```rust
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
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-enrich target`
Expected: FAIL — `remote_ip` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-enrich/src/target.rs`:

```rust
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
```

`lib.rs` ergänzen: `pub mod target;` und `pub use target::{is_enrichable, remote_ip};`

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-enrich`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(enrich): pick the remote address of a log row"
```

### Task 4: Der Worker — Claim, Anreicherung, Rückschreiben

Das Herzstück. Wird gegen **Fake-Quellen** getestet, nie gegen ein Netz.

**Files:**
- Create: `crates/uip-enrich/src/worker.rs`
- Modify: `crates/uip-enrich/src/lib.rs`

- [ ] **Step 1: Failing Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GeoSource, IpFacts, RdnsSource, ThreatOutcome, ThreatSource};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct FakeGeo { calls: AtomicUsize }
    #[async_trait::async_trait]
    impl GeoSource for FakeGeo {
        fn lookup(&self, _ip: IpAddr) -> IpFacts {
            self.calls.fetch_add(1, Ordering::SeqCst);
            IpFacts { geo_country: Some("US".into()), asn_number: Some(15169), ..Default::default() }
        }
    }

    struct FakeRdns;
    #[async_trait::async_trait]
    impl RdnsSource for FakeRdns {
        async fn lookup(&self, _ip: IpAddr) -> Option<String> { Some("dns.example.".into()) }
    }

    struct FakeThreat { outcome: ThreatOutcome }
    #[async_trait::async_trait]
    impl ThreatSource for FakeThreat {
        async fn lookup(&self, _ip: IpAddr) -> ThreatOutcome { self.outcome.clone() }
    }

    fn sources(threat: ThreatOutcome) -> (Arc<FakeGeo>, Sources) {
        let geo = Arc::new(FakeGeo { calls: AtomicUsize::new(0) });
        let s = Sources {
            geo: geo.clone(),
            rdns: Some(Arc::new(FakeRdns)),
            threat: Arc::new(FakeThreat { outcome: threat }),
        };
        (geo, s)
    }

    async fn insert_row(pool: &sqlx::PgPool, log_type: i16, direction: Option<i16>, action: Option<i16>, src: &str) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, direction_id, rule_action_id, src_ip, dst_ip)
             VALUES (NOW(), $1, $2, $3, $4::text::inet, '10.0.0.5')",
        ).bind(log_type).bind(direction).bind(action).bind(src)
        .execute(pool).await.unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn enriches_a_pending_row(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        let (_, s) = sources(ThreatOutcome::Found(IpFacts { threat_score: Some(77), ..Default::default() }));

        let n = run_once(&pool, &s, &Default::default(), 100).await.unwrap();
        assert_eq!(n, 1);

        let (status, country, rdns, score): (i16, Option<String>, Option<String>, Option<i32>) =
            sqlx::query_as("SELECT enrich_status, geo_country, rdns, threat_score FROM logs LIMIT 1")
                .fetch_one(&pool).await.unwrap();
        assert_eq!(status, 1);
        assert_eq!(country.as_deref(), Some("US"));
        assert_eq!(rdns.as_deref(), Some("dns.example."));
        assert_eq!(score, Some(77));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rows_without_a_remote_address_are_done_immediately(pool: sqlx::PgPool) {
        insert_row(&pool, 3, None, None, "192.168.1.50").await; // dhcp
        let (geo, s) = sources(ThreatOutcome::NotFound);

        let n = run_once(&pool, &s, &Default::default(), 100).await.unwrap();
        assert_eq!(n, 1);

        let status: i16 = sqlx::query_scalar("SELECT enrich_status FROM logs LIMIT 1")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(status, 1);
        assert_eq!(geo.calls.load(Ordering::SeqCst), 0, "keine Quelle darf befragt worden sein");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_lookup_per_distinct_address(pool: sqlx::PgPool) {
        for _ in 0..5 { insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await; }
        insert_row(&pool, 1, Some(1), Some(2), "1.1.1.1").await;
        let (geo, s) = sources(ThreatOutcome::NotFound);

        let n = run_once(&pool, &s, &Default::default(), 100).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(geo.calls.load(Ordering::SeqCst), 2, "zwei verschiedene Adressen, zwei Lookups");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn threat_lookups_only_for_blocked_firewall_rows(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(1), "8.8.8.8").await; // allow
        let (_, s) = sources(ThreatOutcome::Found(IpFacts { threat_score: Some(99), ..Default::default() }));

        run_once(&pool, &s, &Default::default(), 100).await.unwrap();

        let score: Option<i32> = sqlx::query_scalar("SELECT threat_score FROM logs LIMIT 1")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(score, None, "erlaubter Traffic kostet kein Kontingent");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn exhausted_quota_leaves_the_row_pending(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        let (_, s) = sources(ThreatOutcome::QuotaExhausted);

        run_once(&pool, &s, &Default::default(), 100).await.unwrap();

        let (status, country): (i16, Option<String>) =
            sqlx::query_as("SELECT enrich_status, geo_country FROM logs LIMIT 1")
                .fetch_one(&pool).await.unwrap();
        assert_eq!(status, 0, "zurück in die Queue, damit der Score nachgereicht wird");
        assert_eq!(country.as_deref(), Some("US"), "das Übrige wird trotzdem geschrieben");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn startup_releases_stale_claims(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        sqlx::query("UPDATE logs SET enrich_status = 3").execute(&pool).await.unwrap();

        release_stale_claims(&pool).await.unwrap();

        let status: i16 = sqlx::query_scalar("SELECT enrich_status FROM logs LIMIT 1")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(status, 0);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn facts_land_in_the_ip_cache(pool: sqlx::PgPool) {
        insert_row(&pool, 1, Some(1), Some(2), "8.8.8.8").await;
        let (_, s) = sources(ThreatOutcome::NotFound);

        run_once(&pool, &s, &Default::default(), 100).await.unwrap();

        let country: Option<String> = sqlx::query_scalar(
            "SELECT geo_country FROM ip_enrichment WHERE ip = '8.8.8.8'",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(country.as_deref(), Some("US"));
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-enrich worker`
Expected: FAIL — `run_once`, `Sources`, `release_stale_claims` fehlen.

- [ ] **Step 3: Implementierung**

`crates/uip-enrich/src/worker.rs`:

```rust
use crate::target::remote_ip;
use crate::types::{GeoSource, IpFacts, RdnsSource, ThreatOutcome, ThreatSource};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Wie viele Zeilen ein Durchlauf höchstens anfasst.
pub const BATCH_SIZE: i64 = 200;
/// Auch ohne Signal wird regelmäßig nachgesehen (Backfill, verpasste Notifies).
const IDLE_POLL: Duration = Duration::from_secs(2);

pub struct Sources {
    pub geo: Arc<dyn GeoSource>,
    pub rdns: Option<Arc<dyn RdnsSource>>,
    pub threat: Arc<dyn ThreatSource>,
}

/// Adressen, die uns selbst gehören und die niemand nachschlagen muss.
#[derive(Debug, Clone, Default)]
pub struct Exclusions(pub HashSet<IpAddr>);

impl std::ops::Deref for Exclusions {
    type Target = HashSet<IpAddr>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

/// Eine geclaimte Zeile, bevor sie angereichert ist.
struct Claimed {
    timestamp: DateTime<Utc>,
    id: i64,
    remote: Option<IpAddr>,
    wants_threat: bool,
}

/// Nach einem Absturz können Zeilen auf "in progress" hängen bleiben. Das hier
/// setzt voraus, dass genau ein Prozess schreibt — so läuft das LXC-Deployment.
pub async fn release_stale_claims(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("UPDATE logs SET enrich_status = 0 WHERE enrich_status = 3")
        .execute(pool)
        .await?;
    let n = res.rows_affected();
    if n > 0 {
        tracing::warn!(rows = n, "released claims left behind by an earlier run");
    }
    Ok(n)
}

/// Claimt bis zu `limit` Zeilen. Das UPDATE committet sofort — die langsame
/// Arbeit darf keine Transaktion offen halten.
async fn claim(pool: &PgPool, excluded: &Exclusions, limit: i64) -> Result<Vec<Claimed>, sqlx::Error> {
    let rows = sqlx::query(
        r#"UPDATE logs SET enrich_status = 3
           WHERE (timestamp, id) IN (
               SELECT timestamp, id FROM logs
               WHERE enrich_status = 0
               ORDER BY timestamp DESC
               LIMIT $1
               FOR UPDATE SKIP LOCKED
           )
           RETURNING timestamp, id, log_type_id, direction_id, rule_action_id,
                     host(src_ip) AS src_ip, host(dst_ip) AS dst_ip"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .iter()
        .map(|r| {
            let src: Option<String> = r.get("src_ip");
            let dst: Option<String> = r.get("dst_ip");
            let log_type_id: i16 = r.get("log_type_id");
            let direction_id: Option<i16> = r.get("direction_id");
            let remote = remote_ip(
                log_type_id,
                direction_id,
                src.and_then(|s| s.parse().ok()),
                dst.and_then(|s| s.parse().ok()),
                excluded,
            );
            Claimed {
                timestamp: r.get("timestamp"),
                id: r.get("id"),
                remote,
                // AbuseIPDB nur für blockierte Firewall-Zeilen: das freie
                // Kontingent ist klein, erlaubter Traffic braucht keinen Score.
                wants_threat: log_type_id == 1 && r.get::<Option<i16>, _>("rule_action_id") == Some(2),
            }
        })
        .collect())
}

/// Liest bekannte Fakten aus dem Cache, damit wir nichts doppelt nachschlagen.
async fn cached_facts(pool: &PgPool, ips: &[IpAddr]) -> HashMap<IpAddr, IpFacts> {
    let nets: Vec<IpNetwork> = ips.iter().copied().map(IpNetwork::from).collect();
    let rows = sqlx::query(
        r#"SELECT host(ip) AS ip, geo_country, geo_city, geo_lat, geo_lon,
                  asn_number, asn_name, rdns, threat_score, threat_categories,
                  abuse_total_reports, abuse_last_reported, abuse_is_tor, abuse_usage_type
           FROM ip_enrichment WHERE ip = ANY($1)"#,
    )
    .bind(&nets)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rows.iter()
        .filter_map(|r| {
            let ip: String = r.get("ip");
            let ip: IpAddr = ip.parse().ok()?;
            Some((
                ip,
                IpFacts {
                    geo_country: r.get("geo_country"),
                    geo_city: r.get("geo_city"),
                    geo_lat: r.get("geo_lat"),
                    geo_lon: r.get("geo_lon"),
                    asn_number: r.get("asn_number"),
                    asn_name: r.get("asn_name"),
                    rdns: r.get("rdns"),
                    threat_score: r.get("threat_score"),
                    threat_categories: r.get("threat_categories"),
                    abuse_total_reports: r.get("abuse_total_reports"),
                    abuse_last_reported: r.get("abuse_last_reported"),
                    abuse_is_tor: r.get("abuse_is_tor"),
                    abuse_usage_type: r.get("abuse_usage_type"),
                },
            ))
        })
        .collect()
}

async fn store_facts(pool: &PgPool, ip: IpAddr, f: &IpFacts) {
    let res = sqlx::query(
        r#"INSERT INTO ip_enrichment (ip, geo_country, geo_city, geo_lat, geo_lon,
              asn_number, asn_name, rdns, threat_score, threat_categories,
              abuse_total_reports, abuse_last_reported, abuse_is_tor, abuse_usage_type,
              geo_looked_up_at, rdns_looked_up_at, abuse_looked_up_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
              CASE WHEN $2 IS NULL THEN NULL ELSE NOW() END,
              CASE WHEN $8 IS NULL THEN NULL ELSE NOW() END,
              CASE WHEN $9 IS NULL THEN NULL ELSE NOW() END)
           ON CONFLICT (ip) DO UPDATE SET
              geo_country = COALESCE(EXCLUDED.geo_country, ip_enrichment.geo_country),
              geo_city = COALESCE(EXCLUDED.geo_city, ip_enrichment.geo_city),
              geo_lat = COALESCE(EXCLUDED.geo_lat, ip_enrichment.geo_lat),
              geo_lon = COALESCE(EXCLUDED.geo_lon, ip_enrichment.geo_lon),
              asn_number = COALESCE(EXCLUDED.asn_number, ip_enrichment.asn_number),
              asn_name = COALESCE(EXCLUDED.asn_name, ip_enrichment.asn_name),
              rdns = COALESCE(EXCLUDED.rdns, ip_enrichment.rdns),
              threat_score = COALESCE(EXCLUDED.threat_score, ip_enrichment.threat_score),
              threat_categories = COALESCE(EXCLUDED.threat_categories, ip_enrichment.threat_categories),
              abuse_total_reports = COALESCE(EXCLUDED.abuse_total_reports, ip_enrichment.abuse_total_reports),
              abuse_last_reported = COALESCE(EXCLUDED.abuse_last_reported, ip_enrichment.abuse_last_reported),
              abuse_is_tor = COALESCE(EXCLUDED.abuse_is_tor, ip_enrichment.abuse_is_tor),
              abuse_usage_type = COALESCE(EXCLUDED.abuse_usage_type, ip_enrichment.abuse_usage_type),
              geo_looked_up_at = COALESCE(EXCLUDED.geo_looked_up_at, ip_enrichment.geo_looked_up_at),
              rdns_looked_up_at = COALESCE(EXCLUDED.rdns_looked_up_at, ip_enrichment.rdns_looked_up_at),
              abuse_looked_up_at = COALESCE(EXCLUDED.abuse_looked_up_at, ip_enrichment.abuse_looked_up_at)"#,
    )
    .bind(IpNetwork::from(ip))
    .bind(&f.geo_country).bind(&f.geo_city).bind(f.geo_lat).bind(f.geo_lon)
    .bind(f.asn_number).bind(&f.asn_name).bind(&f.rdns)
    .bind(f.threat_score).bind(&f.threat_categories)
    .bind(f.abuse_total_reports).bind(f.abuse_last_reported)
    .bind(f.abuse_is_tor).bind(&f.abuse_usage_type)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, %ip, "could not cache ip facts");
    }
}

/// Ein Durchlauf: claimen, anreichern, zurückschreiben. Gibt zurück, wie viele
/// Zeilen angefasst wurden — 0 heißt, die Queue ist leer.
pub async fn run_once(
    pool: &PgPool,
    sources: &Sources,
    excluded: &Exclusions,
    limit: i64,
) -> Result<usize, sqlx::Error> {
    let claimed = claim(pool, excluded, limit).await?;
    if claimed.is_empty() {
        return Ok(0);
    }

    // Eine Adresse, ein Lookup — auch wenn sie in zweihundert Zeilen steht.
    let distinct: Vec<IpAddr> = claimed
        .iter()
        .filter_map(|c| c.remote)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let wants_threat: HashSet<IpAddr> = claimed
        .iter()
        .filter(|c| c.wants_threat)
        .filter_map(|c| c.remote)
        .collect();

    let mut facts = cached_facts(pool, &distinct).await;
    let mut quota_ran_out = false;

    for ip in &distinct {
        let known = facts.entry(*ip).or_default();
        if known.geo_country.is_none() && known.asn_number.is_none() {
            known.merge(sources.geo.lookup(*ip));
        }
        if known.rdns.is_none() {
            if let Some(rdns) = &sources.rdns {
                known.rdns = rdns.lookup(*ip).await;
            }
        }
        if wants_threat.contains(ip) && known.threat_score.is_none() {
            match sources.threat.lookup(*ip).await {
                ThreatOutcome::Found(t) => known.merge(t),
                ThreatOutcome::QuotaExhausted => quota_ran_out = true,
                ThreatOutcome::NotFound | ThreatOutcome::Disabled => {}
            }
        }
        if !known.is_empty() {
            let snapshot = known.clone();
            store_facts(pool, *ip, &snapshot).await;
        }
    }

    write_back(pool, &claimed, &facts, quota_ran_out, &wants_threat).await?;
    Ok(claimed.len())
}

/// Schreibt die Ergebnisse in einem einzigen UPDATE zurück.
async fn write_back(
    pool: &PgPool,
    claimed: &[Claimed],
    facts: &HashMap<IpAddr, IpFacts>,
    quota_ran_out: bool,
    wants_threat: &HashSet<IpAddr>,
) -> Result<(), sqlx::Error> {
    let empty = IpFacts::default();
    let mut ts = Vec::with_capacity(claimed.len());
    let mut ids = Vec::with_capacity(claimed.len());
    let mut status = Vec::with_capacity(claimed.len());
    let (mut country, mut city, mut lat, mut lon) = (vec![], vec![], vec![], vec![]);
    let (mut asn_n, mut asn_name, mut rdns, mut score) = (vec![], vec![], vec![], vec![]);
    let (mut cats, mut reports, mut last_rep, mut tor, mut usage) = (vec![], vec![], vec![], vec![], vec![]);

    for c in claimed {
        let f = c.remote.and_then(|ip| facts.get(&ip)).unwrap_or(&empty);
        // Kontingent alle? Dann bleibt genau diese Zeile in der Queue, damit
        // der Score nachgereicht werden kann.
        let pending_again = quota_ran_out
            && c.wants_threat
            && c.remote.map(|ip| wants_threat.contains(&ip)).unwrap_or(false)
            && f.threat_score.is_none();
        ts.push(c.timestamp);
        ids.push(c.id);
        status.push(if pending_again { 0i16 } else { 1i16 });
        country.push(f.geo_country.clone());
        city.push(f.geo_city.clone());
        lat.push(f.geo_lat);
        lon.push(f.geo_lon);
        asn_n.push(f.asn_number);
        asn_name.push(f.asn_name.clone());
        rdns.push(f.rdns.clone());
        score.push(f.threat_score);
        cats.push(f.threat_categories.clone());
        reports.push(f.abuse_total_reports);
        last_rep.push(f.abuse_last_reported);
        tor.push(f.abuse_is_tor);
        usage.push(f.abuse_usage_type.clone());
    }

    sqlx::query(
        r#"UPDATE logs l SET
             enrich_status = u.status,
             geo_country = u.country,
             geo_city = u.city,
             geo_lat = u.lat::numeric,
             geo_lon = u.lon::numeric,
             asn_number = u.asn_number,
             asn_name = u.asn_name,
             rdns = u.rdns,
             threat_score = u.score,
             threat_categories = u.cats,
             abuse_total_reports = u.reports,
             abuse_last_reported = u.last_rep,
             abuse_is_tor = u.tor,
             abuse_usage_type = u.usage
           FROM UNNEST($1::timestamptz[], $2::bigint[], $3::smallint[], $4::text[],
                       $5::text[], $6::float8[], $7::float8[], $8::int[], $9::text[],
                       $10::text[], $11::int[], $12::text[][], $13::int[],
                       $14::timestamptz[], $15::bool[], $16::text[])
             AS u(ts, id, status, country, city, lat, lon, asn_number, asn_name,
                  rdns, score, cats, reports, last_rep, tor, usage)
           WHERE l.timestamp = u.ts AND l.id = u.id"#,
    )
    .bind(&ts).bind(&ids).bind(&status).bind(&country)
    .bind(&city).bind(&lat).bind(&lon).bind(&asn_n).bind(&asn_name)
    .bind(&rdns).bind(&score).bind(&cats).bind(&reports)
    .bind(&last_rep).bind(&tor).bind(&usage)
    .execute(pool)
    .await?;
    Ok(())
}

/// Dauerläufer: arbeitet die Queue leer, wartet dann auf ein Signal vom
/// Writer oder auf den Timer.
pub async fn run_worker(
    pool: PgPool,
    sources: Sources,
    excluded: Exclusions,
    wake: Arc<tokio::sync::Notify>,
) {
    if let Err(e) = release_stale_claims(&pool).await {
        tracing::error!(error = %e, "could not release stale claims at startup");
    }
    loop {
        match run_once(&pool, &sources, &excluded, BATCH_SIZE).await {
            Ok(0) => {
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(IDLE_POLL) => {}
                }
            }
            Ok(n) => tracing::debug!(rows = n, "enriched batch"),
            Err(e) => {
                tracing::error!(error = %e, "enrichment run failed");
                tokio::time::sleep(IDLE_POLL).await;
            }
        }
    }
}
```

`lib.rs` ergänzen: `pub mod worker;` und `pub use worker::{run_worker, Exclusions, Sources};`

**Wenn ein Bind-Typ scheitert:** `Vec<Option<Vec<String>>>` für `threat_categories`
(ein Array von Arrays) ist die wahrscheinlichste Stelle. Falls Postgres das
`text[][]`-Cast ablehnt, schreibe die Kategorien in einem zweiten, separaten
UPDATE nur für die Zeilen, die welche haben — und melde die Änderung. Nicht
die Spalte zu JSON umbauen.

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-enrich`
Expected: PASS (alle 7 Worker-Tests + die aus Task 2/3).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(enrich): queue worker with claim, dedup and write-back"
```

### Task 5: GeoIP und ASN aus den MaxMind-Dateien

**Files:**
- Create: `crates/uip-enrich/src/geoip.rs`, `crates/uip-enrich/tests/data/.gitkeep`
- Modify: `crates/uip-enrich/src/lib.rs`

- [ ] **Step 1: Testdatenbanken holen**

MaxMind veröffentlicht Testdatenbanken unter MIT-Lizenz. Holen:

```bash
cd /Users/lukas/Documents/dev/uip-rs/crates/uip-enrich/tests/data
curl -fsSLO https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoIP2-City-Test.mmdb
curl -fsSLO https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoLite2-ASN-Test.mmdb
ls -la
```

Diese Dateien werden mitcommittet (wenige hundert KB, Testfixtures). Schlägt
der Download fehl, ist das kein Blocker: der Test überspringt sich dann selbst
(siehe unten) — melde es aber.

- [ ] **Step 2: Failing Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn data_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
    }

    /// Die Testdatenbanken sind optional — ohne sie kann dieser Test nichts
    /// aussagen, aber er darf deshalb nicht die Suite rot machen.
    fn test_dbs() -> Option<MaxmindGeo> {
        let city = data_dir().join("GeoIP2-City-Test.mmdb");
        let asn = data_dir().join("GeoLite2-ASN-Test.mmdb");
        if !city.exists() || !asn.exists() { return None; }
        MaxmindGeo::load(Some(&city), Some(&asn)).ok()
    }

    #[test]
    fn reads_country_and_city_from_the_test_database() {
        let Some(geo) = test_dbs() else { eprintln!("skipped: no test mmdb"); return };
        // 2.125.160.216 liegt in MaxMinds Testdaten in GB.
        let f = geo.lookup("2.125.160.216".parse().unwrap());
        assert_eq!(f.geo_country.as_deref(), Some("GB"));
        assert!(f.geo_lat.is_some() && f.geo_lon.is_some());
    }

    #[test]
    fn unknown_addresses_yield_nothing_rather_than_an_error() {
        let Some(geo) = test_dbs() else { eprintln!("skipped: no test mmdb"); return };
        assert!(geo.lookup("10.0.0.1".parse().unwrap()).is_empty());
    }

    #[test]
    fn a_missing_database_is_not_a_failure() {
        let geo = MaxmindGeo::load(None, None).unwrap();
        assert!(geo.lookup("8.8.8.8".parse().unwrap()).is_empty());
    }
}
```

- [ ] **Step 3: FAIL bestätigen**

Run: `cargo test -p uip-enrich geoip`
Expected: FAIL — `MaxmindGeo` fehlt.

- [ ] **Step 4: Implementierung**

`crates/uip-enrich/src/geoip.rs`:

```rust
use crate::types::{GeoSource, IpFacts};
use arc_swap::ArcSwap;
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Wie oft nachgesehen wird, ob geoipupdate neue Dateien hingelegt hat.
const RELOAD_CHECK: Duration = Duration::from_secs(300);

struct Databases {
    city: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

pub struct MaxmindGeo {
    dbs: ArcSwap<Databases>,
    city_path: Option<PathBuf>,
    asn_path: Option<PathBuf>,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok()?.modified().ok()
}

impl MaxmindGeo {
    /// Fehlende oder kaputte Dateien sind kein Fehler: dann gibt es eben
    /// kein GeoIP, und alles andere reichert weiter an.
    pub fn load(city: Option<&Path>, asn: Option<&Path>) -> anyhow::Result<Self> {
        let open = |p: Option<&Path>| -> Option<Reader<Vec<u8>>> {
            let p = p?;
            match Reader::open_readfile(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "could not open mmdb");
                    None
                }
            }
        };
        Ok(Self {
            dbs: ArcSwap::from_pointee(Databases { city: open(city), asn: open(asn) }),
            city_path: city.map(Path::to_path_buf),
            asn_path: asn.map(Path::to_path_buf),
        })
    }

    /// Aus einem Verzeichnis mit den üblichen GeoLite2-Dateinamen.
    pub fn from_dir(dir: &Path) -> anyhow::Result<Self> {
        let city = dir.join("GeoLite2-City.mmdb");
        let asn = dir.join("GeoLite2-ASN.mmdb");
        Self::load(
            city.exists().then_some(city.as_path()),
            asn.exists().then_some(asn.as_path()),
        )
    }

    fn reload(&self) {
        let open = |p: &Option<PathBuf>| -> Option<Reader<Vec<u8>>> {
            Reader::open_readfile(p.as_ref()?).ok()
        };
        self.dbs.store(Arc::new(Databases {
            city: open(&self.city_path),
            asn: open(&self.asn_path),
        }));
        tracing::info!("reloaded geoip databases");
    }
}

impl GeoSource for MaxmindGeo {
    fn lookup(&self, ip: IpAddr) -> IpFacts {
        let dbs = self.dbs.load();
        let mut f = IpFacts::default();

        if let Some(reader) = &dbs.city {
            if let Ok(res) = reader.lookup(ip) {
                if let Ok(Some(city)) = res.decode::<geoip2::City>() {
                    f.geo_country = city.country.as_ref().and_then(|c| c.iso_code).map(str::to_string);
                    f.geo_city = city
                        .city
                        .as_ref()
                        .and_then(|c| c.names.as_ref())
                        .and_then(|n| n.english)
                        .map(str::to_string);
                    if let Some(loc) = &city.location {
                        f.geo_lat = loc.latitude;
                        f.geo_lon = loc.longitude;
                    }
                }
            }
        }

        if let Some(reader) = &dbs.asn {
            if let Ok(res) = reader.lookup(ip) {
                if let Ok(Some(asn)) = res.decode::<geoip2::Asn>() {
                    f.asn_number = asn.autonomous_system_number.map(|n| n as i32);
                    f.asn_name = asn.autonomous_system_organization.map(str::to_string);
                }
            }
        }
        f
    }
}

/// Wacht über die mtime der Dateien. Der Fork brauchte dafür SIGUSR1 zwischen
/// Update-Skript und Prozess; das hier funktioniert auch, wenn jemand die
/// Dateien von Hand tauscht.
pub async fn watch_for_updates(geo: Arc<MaxmindGeo>) {
    let mut seen = (
        geo.city_path.as_deref().and_then(mtime),
        geo.asn_path.as_deref().and_then(mtime),
    );
    loop {
        tokio::time::sleep(RELOAD_CHECK).await;
        let now = (
            geo.city_path.as_deref().and_then(mtime),
            geo.asn_path.as_deref().and_then(mtime),
        );
        if now != seen {
            seen = now;
            geo.reload();
        }
    }
}
```

`lib.rs` ergänzen: `pub mod geoip;`

**Zur API:** `geoip2::City`-Felder sind in maxminddb 0.26 `Option`-verpackt
(`city.country`, `city.city.names`). Weicht die installierte Version ab,
richte dich nach dem Compiler und melde die Abweichung — die Struktur der
Funktion bleibt gleich.

- [ ] **Step 5: Tests grün**

Run: `cargo test -p uip-enrich`
Expected: PASS. Falls die mmdb-Dateien fehlen, stehen zwei `skipped`-Zeilen im Output — das ist in Ordnung.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(enrich): maxmind geoip and asn with mtime hot reload"
```

---

### Task 6: Reverse DNS

**Files:**
- Create: `crates/uip-enrich/src/rdns.rs`
- Modify: `crates/uip-enrich/src/lib.rs`

- [ ] **Step 1: Failing Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn caches_hits_and_misses_alike() {
        let cache = RdnsCache::new(Duration::from_secs(60));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(cache.get(&ip).is_none());

        cache.put(ip, Some("dns.google.".into()));
        assert_eq!(cache.get(&ip), Some(Some("dns.google.".into())));

        let other: IpAddr = "1.1.1.1".parse().unwrap();
        // Auch ein Fehlschlag wird gemerkt, sonst fragen wir ihn ewig neu.
        cache.put(other, None);
        assert_eq!(cache.get(&other), Some(None));
    }

    #[tokio::test]
    async fn entries_expire() {
        let cache = RdnsCache::new(Duration::from_millis(30));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        cache.put(ip, Some("dns.google.".into()));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(cache.get(&ip).is_none());
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-enrich rdns`
Expected: FAIL — `RdnsCache` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-enrich/src/rdns.rs`:

```rust
use crate::types::RdnsSource;
use hickory_resolver::{Resolver, TokioResolver};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// PTR-Lookups sind langsam und oft erfolglos — beides wird gemerkt.
pub struct RdnsCache {
    ttl: Duration,
    entries: Mutex<HashMap<IpAddr, (Instant, Option<String>)>>,
}

impl RdnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, entries: Mutex::new(HashMap::new()) }
    }

    pub fn get(&self, ip: &IpAddr) -> Option<Option<String>> {
        let mut map = self.entries.lock().unwrap();
        match map.get(ip) {
            Some((at, value)) if at.elapsed() < self.ttl => Some(value.clone()),
            Some(_) => { map.remove(ip); None }
            None => None,
        }
    }

    pub fn put(&self, ip: IpAddr, value: Option<String>) {
        let mut map = self.entries.lock().unwrap();
        if map.len() > 10_000 {
            let ttl = self.ttl;
            map.retain(|_, (at, _)| at.elapsed() < ttl);
        }
        map.insert(ip, (Instant::now(), value));
    }
}

pub struct Rdns {
    resolver: TokioResolver,
    cache: RdnsCache,
    timeout: Duration,
}

impl Rdns {
    pub fn from_system() -> anyhow::Result<Self> {
        let resolver = Resolver::builder_tokio()?.build();
        Ok(Self {
            resolver,
            cache: RdnsCache::new(Duration::from_secs(24 * 3600)),
            timeout: Duration::from_secs(2),
        })
    }
}

#[async_trait::async_trait]
impl RdnsSource for Rdns {
    async fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let Some(hit) = self.cache.get(&ip) {
            return hit;
        }
        let found = match tokio::time::timeout(self.timeout, self.resolver.reverse_lookup(ip)).await {
            Ok(Ok(answer)) => answer.iter().next().map(|n| n.to_string()),
            _ => None, // Timeout, NXDOMAIN, Netzfehler — alles dasselbe: kein rDNS
        };
        self.cache.put(ip, found.clone());
        found
    }
}
```

`lib.rs` ergänzen: `pub mod rdns;`

**Zur API:** `Resolver::builder_tokio()` gibt in hickory-resolver 0.25 einen
Builder zurück; `build()` liefert je nach Patch-Version `TokioResolver` oder
`Result<TokioResolver, _>`. Richte dich nach dem Compiler und melde, welche
Variante gilt. Die `system-config`-Feature muss aktiv sein — falls nicht, in
`Cargo.toml` ergänzen.

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-enrich`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(enrich): reverse dns with a ttl cache"
```

### Task 7: AbuseIPDB-Client

Rate-Limit-bewusst, gegen einen lokalen HTTP-Stub getestet. **Kein Test ruft
die echte API.**

**Files:**
- Create: `crates/uip-enrich/src/abuseipdb.rs`
- Modify: `crates/uip-enrich/src/lib.rs`, `crates/uip-enrich/Cargo.toml`

- [ ] **Step 1: Dev-Dependency für den Stub**

In `crates/uip-enrich/Cargo.toml` unter `[dev-dependencies]`:

```toml
axum = { workspace = true }
tower = { version = "0.5", features = ["util"] }
```

Der Stub ist ein echter axum-Server auf `127.0.0.1:0` — kein Mocking-Framework,
damit auch die HTTP-Schicht wirklich durchlaufen wird.

- [ ] **Step 2: Failing Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::http::HeaderMap;
    use axum::routing::get;
    use axum::Json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Startet einen Stub und liefert seine Basis-URL plus einen Zähler.
    async fn stub(status_code: u16, remaining: &'static str) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = axum::Router::new().route(
            "/check",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let h = h.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    let mut headers = HeaderMap::new();
                    headers.insert("X-RateLimit-Remaining", remaining.parse().unwrap());
                    headers.insert("X-RateLimit-Limit", "1000".parse().unwrap());
                    let body = serde_json::json!({"data": {
                        "ipAddress": q.get("ipAddress").cloned().unwrap_or_default(),
                        "abuseConfidenceScore": 42,
                        "totalReports": 7,
                        "isTor": false,
                        "usageType": "Data Center/Web Hosting/Transit",
                        "lastReportedAt": "2026-09-01T10:00:00+00:00",
                        "reports": [{"categories": [18, 22]}]
                    }});
                    (axum::http::StatusCode::from_u16(status_code).unwrap(), headers, Json(body))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/check"), hits)
    }

    #[tokio::test]
    async fn reads_a_score_and_its_details() {
        let (url, _) = stub(200, "900").await;
        let c = AbuseIpDb::with_url("key".into(), url);
        match c.lookup("8.8.8.8".parse().unwrap()).await {
            ThreatOutcome::Found(f) => {
                assert_eq!(f.threat_score, Some(42));
                assert_eq!(f.abuse_total_reports, Some(7));
                assert_eq!(f.abuse_is_tor, Some(false));
                assert!(f.abuse_last_reported.is_some());
                assert_eq!(f.threat_categories.as_deref(), Some(&["18".to_string(), "22".to_string()][..]));
            }
            other => panic!("erwartet Found, war {other:?}"),
        }
    }

    #[tokio::test]
    async fn without_a_key_the_source_is_simply_off() {
        let c = AbuseIpDb::with_url(String::new(), "http://127.0.0.1:1/check".into());
        assert_eq!(c.lookup("8.8.8.8".parse().unwrap()).await, ThreatOutcome::Disabled);
    }

    #[tokio::test]
    async fn a_429_pauses_all_further_lookups() {
        let (url, hits) = stub(429, "0").await;
        let c = AbuseIpDb::with_url("key".into(), url);
        assert_eq!(c.lookup("8.8.8.8".parse().unwrap()).await, ThreatOutcome::QuotaExhausted);
        // Der zweite Aufruf darf den Server gar nicht mehr behelligen.
        assert_eq!(c.lookup("1.1.1.1".parse().unwrap()).await, ThreatOutcome::QuotaExhausted);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_exhausted_remaining_header_stops_the_next_call() {
        let (url, hits) = stub(200, "0").await;
        let c = AbuseIpDb::with_url("key".into(), url);
        assert!(matches!(c.lookup("8.8.8.8".parse().unwrap()).await, ThreatOutcome::Found(_)));
        assert_eq!(c.lookup("1.1.1.1".parse().unwrap()).await, ThreatOutcome::QuotaExhausted);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
```

- [ ] **Step 3: FAIL bestätigen**

Run: `cargo test -p uip-enrich abuseipdb`
Expected: FAIL — `AbuseIpDb` fehlt.

- [ ] **Step 4: Implementierung**

`crates/uip-enrich/src/abuseipdb.rs`:

```rust
use crate::types::{IpFacts, ThreatOutcome, ThreatSource};
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

const API_URL: &str = "https://api.abuseipdb.com/api/v2/check";
const MAX_AGE_DAYS: &str = "90";

pub struct AbuseIpDb {
    api_key: String,
    url: String,
    http: reqwest::Client,
    /// Verbleibendes Kontingent laut letztem Antwort-Header. -1 = unbekannt.
    remaining: AtomicI64,
    /// Unix-Sekunden, bis zu denen nach einem 429 pausiert wird.
    paused_until: AtomicI64,
}

impl AbuseIpDb {
    pub fn new(api_key: String) -> Self {
        Self::with_url(api_key, API_URL.to_string())
    }

    pub fn with_url(api_key: String, url: String) -> Self {
        Self {
            api_key,
            url,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            remaining: AtomicI64::new(-1),
            paused_until: AtomicI64::new(0),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.api_key.is_empty()
    }

    fn paused(&self) -> bool {
        self.paused_until.load(Ordering::Relaxed) > Utc::now().timestamp()
    }
}

#[async_trait::async_trait]
impl ThreatSource for AbuseIpDb {
    async fn lookup(&self, ip: IpAddr) -> ThreatOutcome {
        if !self.enabled() {
            return ThreatOutcome::Disabled;
        }
        // Kontingent aufgebraucht oder Pause läuft noch: gar nicht erst fragen.
        if self.paused() || self.remaining.load(Ordering::Relaxed) == 0 {
            return ThreatOutcome::QuotaExhausted;
        }

        let res = self
            .http
            .get(&self.url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[
                ("ipAddress", ip.to_string().as_str()),
                ("maxAgeInDays", MAX_AGE_DAYS),
                ("verbose", ""),
            ])
            .send()
            .await;

        let res = match res {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, %ip, "abuseipdb request failed");
                return ThreatOutcome::NotFound;
            }
        };

        if let Some(v) = res.headers().get("X-RateLimit-Remaining") {
            if let Some(n) = v.to_str().ok().and_then(|s| s.parse::<i64>().ok()) {
                self.remaining.store(n, Ordering::Relaxed);
            }
        }

        if res.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // Reset-Zeitpunkt, sonst eine Stunde Ruhe.
            let reset = res
                .headers()
                .get("X-RateLimit-Reset")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or_else(|| Utc::now().timestamp() + 3600);
            self.paused_until.store(reset, Ordering::Relaxed);
            tracing::warn!(reset, "abuseipdb quota exhausted, pausing");
            return ThreatOutcome::QuotaExhausted;
        }

        if !res.status().is_success() {
            tracing::warn!(status = %res.status(), %ip, "abuseipdb returned an error");
            return ThreatOutcome::NotFound;
        }

        let body: serde_json::Value = match res.json().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "abuseipdb sent something unreadable");
                return ThreatOutcome::NotFound;
            }
        };
        let Some(data) = body.get("data") else {
            return ThreatOutcome::NotFound;
        };

        // Kategorien stecken in den einzelnen Meldungen; uns interessiert die
        // Menge der vorkommenden, nicht ihre Häufigkeit.
        let mut cats: Vec<String> = data
            .get("reports")
            .and_then(|r| r.as_array())
            .map(|reports| {
                let mut seen: Vec<String> = reports
                    .iter()
                    .filter_map(|r| r.get("categories")?.as_array())
                    .flatten()
                    .filter_map(|c| c.as_i64())
                    .map(|c| c.to_string())
                    .collect();
                seen.sort();
                seen.dedup();
                seen
            })
            .unwrap_or_default();
        cats.shrink_to_fit();

        ThreatOutcome::Found(IpFacts {
            threat_score: data.get("abuseConfidenceScore").and_then(|v| v.as_i64()).map(|n| n as i32),
            threat_categories: (!cats.is_empty()).then_some(cats),
            abuse_total_reports: data.get("totalReports").and_then(|v| v.as_i64()).map(|n| n as i32),
            abuse_is_tor: data.get("isTor").and_then(|v| v.as_bool()),
            abuse_usage_type: data.get("usageType").and_then(|v| v.as_str()).map(str::to_string),
            abuse_last_reported: data
                .get("lastReportedAt")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
            ..Default::default()
        })
    }
}

/// Quelle, die nie etwas findet — für den Betrieb ohne API-Key.
pub struct NoThreatSource;

#[async_trait::async_trait]
impl ThreatSource for NoThreatSource {
    async fn lookup(&self, _ip: IpAddr) -> ThreatOutcome {
        ThreatOutcome::Disabled
    }
}
```

`lib.rs` ergänzen: `pub mod abuseipdb;`

- [ ] **Step 5: Tests grün**

Run: `cargo test -p uip-enrich`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(enrich): rate-limit aware abuseipdb client"
```

---

### Task 8: Konfiguration aus system_config

WAN-IPs, Gateway-Adressen und Schalter kommen aus der DB, mit Env als
Erststart-Vorgabe. Die WAN-IPs fließen außerdem in den Parser zurück — in
Phase 1 bekam er eine leere Menge, die Multi-WAN-Erkennung war damit blind.

**Files:**
- Create: `crates/uip-core/src/settings.rs`
- Modify: `crates/uip-core/src/lib.rs`, `crates/uip-core/src/config.rs`

- [ ] **Step 1: Failing Tests**

In `settings.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn env_seeds_the_database_once(pool: sqlx::PgPool) {
        let s = Settings::load(&pool, |k| match k {
            "UIP_WAN_IPS" => Some("203.0.113.7, 198.51.100.4".into()),
            "UIP_ABUSEIPDB_KEY" => Some("secret".into()),
            _ => None,
        }).await.unwrap();

        assert_eq!(s.wan_ips.len(), 2);
        assert!(s.wan_ips.contains(&"203.0.113.7".parse().unwrap()));
        assert_eq!(s.abuseipdb_key.as_deref(), Some("secret"));
        assert!(s.rdns_enabled, "Default ist an");

        // Der zweite Start ohne Env liest dieselben Werte aus der DB.
        let again = Settings::load(&pool, |_| None).await.unwrap();
        assert_eq!(again.wan_ips, s.wan_ips);
        assert_eq!(again.abuseipdb_key.as_deref(), Some("secret"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn env_wins_over_a_stored_value(pool: sqlx::PgPool) {
        Settings::load(&pool, |k| (k == "UIP_WAN_IPS").then(|| "203.0.113.7".into())).await.unwrap();
        let s = Settings::load(&pool, |k| (k == "UIP_WAN_IPS").then(|| "1.2.3.4".into())).await.unwrap();
        assert_eq!(s.wan_ips, ["1.2.3.4".parse().unwrap()].into_iter().collect());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rdns_can_be_turned_off(pool: sqlx::PgPool) {
        let s = Settings::load(&pool, |k| (k == "UIP_RDNS_ENABLED").then(|| "false".into())).await.unwrap();
        assert!(!s.rdns_enabled);
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-core settings`
Expected: FAIL — `Settings` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-core/src/settings.rs`:

```rust
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

/// Laufzeit-Einstellungen. Die DB ist die Wahrheit; Env überschreibt sie und
/// wird dabei zurückgeschrieben, damit der nächste Start ohne Env auskommt.
#[derive(Debug, Clone)]
pub struct Settings {
    pub wan_ips: HashSet<IpAddr>,
    pub gateway_ips: HashSet<IpAddr>,
    pub rdns_enabled: bool,
    pub abuseipdb_key: Option<String>,
    pub geoip_dir: PathBuf,
}

async fn get(pool: &PgPool, key: &str) -> Option<Value> {
    sqlx::query_scalar::<_, Value>("SELECT value FROM system_config WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

async fn put(pool: &PgPool, key: &str, value: Value) {
    let res = sqlx::query(
        "INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, key, "could not persist setting");
    }
}

fn parse_ips(s: &str) -> HashSet<IpAddr> {
    s.split(',').filter_map(|p| p.trim().parse().ok()).collect()
}

impl Settings {
    pub async fn load(
        pool: &PgPool,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, sqlx::Error> {
        /// Env gewinnt und wird zurückgeschrieben; sonst zählt die DB, sonst der Default.
        async fn text(
            pool: &PgPool,
            key: &str,
            from_env: Option<String>,
            default: &str,
        ) -> String {
            match from_env.filter(|v| !v.is_empty()) {
                Some(v) => {
                    put(pool, key, Value::from(v.clone())).await;
                    v
                }
                None => get(pool, key)
                    .await
                    .and_then(|v| v.as_str().map(str::to_string))
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| default.to_string()),
            }
        }

        let wan_ips = parse_ips(&text(pool, "wan_ips", env("UIP_WAN_IPS"), "").await);
        let gateway_ips = get(pool, "gateway_ips")
            .await
            .and_then(|v| v.as_str().map(parse_ips))
            .unwrap_or_default();

        let rdns_enabled = match env("UIP_RDNS_ENABLED") {
            Some(raw) => {
                let on = !matches!(raw.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no");
                put(pool, "rdns_enabled", Value::Bool(on)).await;
                on
            }
            None => get(pool, "rdns_enabled").await.and_then(|v| v.as_bool()).unwrap_or(true),
        };

        let abuseipdb_key =
            text(pool, "abuseipdb_api_key", env("UIP_ABUSEIPDB_KEY"), "").await;
        let geoip_dir =
            text(pool, "geoip_dir", env("UIP_GEOIP_DIR"), "/var/lib/uip/geoip").await;

        Ok(Self {
            wan_ips,
            gateway_ips,
            rdns_enabled,
            abuseipdb_key: Some(abuseipdb_key).filter(|k| !k.is_empty()),
            geoip_dir: PathBuf::from(geoip_dir),
        })
    }

    /// Alles, was nicht angereichert werden muss, weil es uns selbst gehört.
    pub fn exclusions(&self) -> HashSet<IpAddr> {
        self.wan_ips.union(&self.gateway_ips).copied().collect()
    }
}
```

`lib.rs` ergänzen: `pub mod settings;` und `pub use settings::Settings;`

Ergänze einen vierten Test analog zu `env_seeds_the_database_once`, der
`UIP_GEOIP_DIR` setzt und nach einem zweiten `load` ohne Env denselben Pfad
zurückbekommt.

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-core`
Expected: PASS (inklusive des selbst ergänzten geoip_dir-Tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): runtime settings from system_config"
```

### Task 9: Verdrahtung in main

Worker starten, Writer den Wecker geben, WAN-IPs in den Parser zurückführen.

**Files:**
- Modify: `crates/uip/src/main.rs`, `crates/uip/Cargo.toml`, `crates/uip-ingest/src/writer.rs`, `Cargo.toml`

- [ ] **Step 1: Writer signalisiert nach jedem Flush**

In `crates/uip-ingest/src/writer.rs` bekommt `run_writer` einen weiteren
Parameter und weckt den Worker nach einem erfolgreichen Flush:

```rust
pub async fn run_writer(
    mut rx: mpsc::Receiver<ParsedLog>,
    pool: PgPool,
    cache: Arc<LookupCache>,
    events: broadcast::Sender<String>,
    wake_enricher: Arc<tokio::sync::Notify>,
) {
```

`flush` bekommt denselben Zusatzparameter und ruft im `Ok`-Zweig, nach dem
Broadcast, `wake_enricher.notify_one();` auf. Der bestehende Writer-Test muss
entsprechend ein `Arc::new(tokio::sync::Notify::new())` mitgeben.

- [ ] **Step 2: main verdrahten**

`crates/uip/Cargo.toml` um `uip-enrich = { path = "../uip-enrich" }` ergänzen.

In `crates/uip/src/main.rs` nach dem Migrations-Aufruf und vor dem Writer:

```rust
    let settings = uip_core::Settings::load(&pool, |k| std::env::var(k).ok()).await?;
    tracing::info!(
        wan_ips = settings.wan_ips.len(),
        rdns = settings.rdns_enabled,
        threat = settings.abuseipdb_key.is_some(),
        "settings loaded"
    );

    let wake_enricher = Arc::new(tokio::sync::Notify::new());
```

Der Writer-Aufruf bekommt `wake_enricher.clone()` als fünftes Argument.

Der `FirewallCtx` nimmt jetzt die echten WAN-IPs — in Phase 1 stand hier eine
leere Menge, womit die Multi-WAN-Erkennung nichts zu arbeiten hatte:

```rust
    let fw_ctx = FirewallCtx {
        wan_interfaces: cfg.wan_interfaces.clone(),
        wan_ips: settings.wan_ips.clone(),
    };
```

Und vor dem HTTP-Server der Enrichment-Worker:

```rust
    let geo = Arc::new(uip_enrich::geoip::MaxmindGeo::from_dir(&settings.geoip_dir)?);
    tokio::spawn(uip_enrich::geoip::watch_for_updates(geo.clone()));

    let rdns: Option<Arc<dyn uip_enrich::RdnsSource>> = if settings.rdns_enabled {
        match uip_enrich::rdns::Rdns::from_system() {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                tracing::warn!(error = %e, "no system resolver, reverse dns stays off");
                None
            }
        }
    } else {
        None
    };

    let threat: Arc<dyn uip_enrich::ThreatSource> = match &settings.abuseipdb_key {
        Some(key) => Arc::new(uip_enrich::abuseipdb::AbuseIpDb::new(key.clone())),
        None => Arc::new(uip_enrich::abuseipdb::NoThreatSource),
    };

    tokio::spawn(uip_enrich::worker::run_worker(
        pool.clone(),
        uip_enrich::Sources { geo, rdns, threat },
        uip_enrich::Exclusions(settings.exclusions()),
        wake_enricher,
    ));
```

- [ ] **Step 3: End-to-End-Probe**

```bash
cd /Users/lukas/Documents/dev/uip-rs
psql -q uip_dev -c "TRUNCATE logs; TRUNCATE ip_enrichment"
UIP_DB_URL=postgres://lukas@localhost/uip_dev UIP_SYSLOG_ADDR=127.0.0.1:5514 \
  UIP_HTTP_ADDR=127.0.0.1:8080 UIP_GEOIP_DIR=/tmp/uip-geoip-missing \
  cargo run -p uip &
sleep 8
printf 'Feb  8 16:43:49 UDR kernel: [WAN_IN-D]IN=ppp0 OUT=br20 SRC=8.8.8.8 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=443' | nc -u -w1 127.0.0.1 5514
sleep 4
psql -tA uip_dev -c "SELECT enrich_status, rdns FROM logs"
```

Expected: `enrich_status` ist `1`. Ohne mmdb-Dateien bleibt GeoIP leer — genau
das ist der Punkt: eine fehlende Datenbank darf die Zeile nicht aufhalten.
`rdns` sollte bei 8.8.8.8 `dns.google.` sein, sofern der Rechner DNS hat.
Prozess danach beenden. Echte Ausgabe im Report festhalten.

- [ ] **Step 4: Alles grün**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: run the enrichment worker alongside ingest"
```

---

### Task 10: Angereicherte Felder in API und Tabelle

**Files:**
- Modify: `crates/uip-api/src/logs.rs`, `crates/uip-ingest/src/writer.rs`, `ui/src/api.ts`, `ui/src/App.tsx`

- [ ] **Step 1: Failing Test**

In `crates/uip-api/src/logs.rs` bei den bestehenden Tests:

```rust
    #[sqlx::test(migrations = "../../migrations")]
    async fn enriched_columns_reach_the_client(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO logs (timestamp, log_type_id, src_ip, geo_country, asn_name, rdns, threat_score)
             VALUES (NOW(), 1, '8.8.8.8', 'US', 'GOOGLE', 'dns.google.', 42)",
        ).execute(&pool).await.unwrap();

        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get("/api/logs?limit=1").body(Body::empty()).unwrap()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        ).unwrap();
        let row = &body["rows"][0];
        assert_eq!(row["geo_country"].as_str(), Some("US"));
        assert_eq!(row["asn_name"].as_str(), Some("GOOGLE"));
        assert_eq!(row["rdns"].as_str(), Some("dns.google."));
        assert_eq!(row["threat_score"].as_i64(), Some(42));
    }
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-api enriched`
Expected: FAIL — die Felder fehlen in der Antwort.

- [ ] **Step 3: Query und JSON erweitern**

In der SELECT-Liste von `get_logs` ergänzen:

```sql
                  l.geo_country, l.geo_city, l.geo_lat::float8 AS geo_lat,
                  l.geo_lon::float8 AS geo_lon, l.asn_number, l.asn_name,
                  l.rdns, l.threat_score, l.threat_categories, l.abuse_is_tor,
```

und im `json!`-Block:

```rust
            "geo_country": r.get::<Option<String>, _>("geo_country"),
            "geo_city": r.get::<Option<String>, _>("geo_city"),
            "geo_lat": r.get::<Option<f64>, _>("geo_lat"),
            "geo_lon": r.get::<Option<f64>, _>("geo_lon"),
            "asn_number": r.get::<Option<i32>, _>("asn_number"),
            "asn_name": r.get::<Option<String>, _>("asn_name"),
            "rdns": r.get::<Option<String>, _>("rdns"),
            "threat_score": r.get::<Option<i32>, _>("threat_score"),
            "threat_categories": r.get::<Option<Vec<String>>, _>("threat_categories"),
            "abuse_is_tor": r.get::<Option<bool>, _>("abuse_is_tor"),
```

**Der SSE-Stream sendet diese Felder bewusst nicht:** eine frisch geschriebene
Zeile ist noch gar nicht angereichert. Die Live-Tabelle zeigt sie als leer und
füllt sie beim nächsten Neuladen — das ist ehrlicher als ein Wert, den es zum
Sendezeitpunkt nicht gab. In `writer.rs` bleibt das JSON deshalb unverändert;
ergänze dort nur einen Kommentar, der das festhält.

- [ ] **Step 4: UI**

`ui/src/api.ts`: `LogRow` um `geo_country`, `geo_city`, `asn_name`, `rdns`,
`threat_score` (alle `| null`) erweitern.

`ui/src/App.tsx`: zwei Spalten ergänzen — „Herkunft" zeigt
`r.geo_country`, und „Threat" zeigt `r.threat_score`, wenn gesetzt. Die
Kopfzeile entsprechend erweitern. Adressen bekommen `title={r.rdns ?? ''}`,
damit der rDNS-Name im Tooltip steht, ohne die Zeile zu verbreitern.

- [ ] **Step 5: Grün und gebaut**

Run: `cargo test --workspace && cd ui && npm run build`
Expected: Tests grün, Build ohne TypeScript-Fehler.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(api): expose enrichment fields and show them in the table"
```

---

### Task 11: geoipupdate im LXC

**Files:**
- Modify: `lxc/install.sh`
- Create: `lxc/systemd/uip-geoip.service`, `lxc/systemd/uip-geoip.timer`

- [ ] **Step 1: Timer-Einheiten**

`lxc/systemd/uip-geoip.service`:

```ini
[Unit]
Description=Refresh MaxMind GeoLite2 databases for uip
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/geoipupdate -d /var/lib/uip/geoip -f /etc/uip/GeoIP.conf
# Der Worker bemerkt die neuen Dateien von selbst an ihrer mtime.
```

`lxc/systemd/uip-geoip.timer`:

```ini
[Unit]
Description=Weekly GeoLite2 refresh

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 2: install.sh erweitern**

Im Paket-Schritt `geoipupdate` mitinstallieren. Nach dem Service-Block
einfügen:

```bash
msg "GeoIP"
mkdir -p /var/lib/uip/geoip
chown -R uip:uip /var/lib/uip
if [ -n "${MAXMIND_ACCOUNT_ID:-}" ] && [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
  cat > /etc/uip/GeoIP.conf <<EOF
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs GeoLite2-City GeoLite2-ASN
EOF
  chmod 600 /etc/uip/GeoIP.conf
  install -m 644 "${SRC_DIR}/lxc/systemd/uip-geoip.service" /etc/systemd/system/
  install -m 644 "${SRC_DIR}/lxc/systemd/uip-geoip.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now uip-geoip.timer
  # Einmal sofort, damit nicht bis zum ersten Timer-Lauf gewartet wird.
  systemctl start uip-geoip.service || msg "GeoIP-Download fehlgeschlagen — Timer versucht es erneut"
else
  msg "Ohne MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY bleibt GeoIP leer."
  msg "Später nachrüstbar: /etc/uip/GeoIP.conf anlegen und uip-geoip.timer aktivieren."
fi
```

In den erzeugten `/etc/uip/uip.env` zusätzlich `UIP_GEOIP_DIR=/var/lib/uip/geoip`
und eine auskommentierte Zeile `#UIP_ABUSEIPDB_KEY=` schreiben.

- [ ] **Step 3: Syntax prüfen**

Run: `bash -n lxc/install.sh`
Expected: keine Ausgabe.

- [ ] **Step 4: Commit**

```bash
git add lxc && git commit -m "feat(lxc): weekly geolite2 refresh via systemd timer"
```

---

## Abschluss Phase 2

- [ ] `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
- [ ] End-to-End-Probe aus Task 9 erneut, diesmal mit echten mmdb-Dateien falls vorhanden
- [ ] README: Abschnitt zu Enrichment (welche Quellen, was ohne Keys passiert)
- [ ] Merge nach `main`

**Bewusst nicht in Phase 2:** Blacklist-Vorbefüllung und Backfill-Bedienung
(beides setzt nur `enrich_status` zurück und läuft durch denselben Worker),
Pi-hole, UniFi-Integration, Dashboard-Aggregate, Threat Map — die kommen in
Phase 3 und 4.

