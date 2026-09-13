# Phase 1 "Fundament" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lauffähige Ingest-Pipeline: UDP-Syslog → State-Machine-Parser → Batch-Writer → TimescaleDB, plus Minimal-axum-API (`/api/logs` cursor-basiert, SSE `/api/stream`), SolidJS-Shell mit Live-Log-Tabelle, LXC-Installer v0.

**Architecture:** Ein Rust-Binary (tokio). Cargo-Workspace: `uip-core` (Typen, Config, DB), `uip-ingest` (UDP, Parser, Writer), `uip-api` (axum, SSE, embedded Frontend), `uip` (main). Logs landen sofort mit `enrich_status=0` (pending) in einer Timescale-Hypertable; Enrichment kommt in Phase 2 und liest genau diesen Status. Writer broadcastet eingefügte Zeilen an SSE-Clients.

**Tech Stack:** Rust stable, tokio, axum, sqlx (postgres, chrono, ipnetwork, mac_address), chrono, serde, rust-embed, tracing; PostgreSQL 17 + TimescaleDB; SolidJS + Vite + TypeScript; Debian-13-LXC, systemd.

**Referenz:** Spec `docs/superpowers/specs/2026-09-13-uip-rs-rewrite-design.md`. Log-Format-Wissen stammt aus dem Fork (`waytoabv/UniFi-Insights-Plus`, `receiver/parsers.py`, `init.sql`) — Konzepte, kein Code-Copy.

---

## Dev-Umgebung (einmalig, vor Task 4)

Lokale DB auf macOS (kein Docker):

```bash
brew install postgresql@17
brew install timescale/tap/timescaledb   # falls Formel klemmt: Tasks 4/8/9 gegen eine Test-DB im LXC fahren (DATABASE_URL zeigt dorthin)
brew services start postgresql@17
createdb uip_dev
psql uip_dev -c "CREATE EXTENSION IF NOT EXISTS timescaledb"
cargo install sqlx-cli --no-default-features --features postgres
```

`.env` im Repo-Root (gitignored):

```
DATABASE_URL=postgres://localhost/uip_dev
```

DB-Integrationstests laufen nur, wenn `DATABASE_URL` gesetzt ist (sqlx `#[sqlx::test]` nutzt sie und legt Wegwerf-Schemata an).

## File Structure

```
Cargo.toml                      # workspace
rust-toolchain.toml
crates/
  uip-core/src/lib.rs           # re-exports
  uip-core/src/config.rs        # env config
  uip-core/src/types.rs         # LogType/Direction/RuleAction enums, ParsedLog
  uip-core/src/db.rs            # pool + lookup cache
  uip-ingest/src/lib.rs
  uip-ingest/src/syslog.rs      # RFC3164 header + timestamp
  uip-ingest/src/firewall.rs    # KV-scanner, direction/action
  uip-ingest/src/parsers.rs     # dns/dhcp/wifi/system + detect + parse_log
  uip-ingest/src/writer.rs      # batch writer + broadcast
  uip-ingest/src/udp.rs         # UDP listener task
  uip-api/src/lib.rs            # router
  uip-api/src/logs.rs           # GET /api/logs
  uip-api/src/stream.rs         # SSE /api/stream
  uip-api/src/static_files.rs   # rust-embed frontend
  uip/src/main.rs               # wiring, shutdown
migrations/0001_init.sql
ui/                             # SolidJS + Vite
lxc/install.sh  lxc/proxmox-lxc.sh  lxc/update.sh  lxc/systemd/uip.service
.github/workflows/ci.yml
```

---

### Task 1: Cargo-Workspace-Scaffold

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `crates/uip-core/Cargo.toml`, `crates/uip-core/src/lib.rs`, `crates/uip-ingest/Cargo.toml`, `crates/uip-ingest/src/lib.rs`, `crates/uip-api/Cargo.toml`, `crates/uip-api/src/lib.rs`, `crates/uip/Cargo.toml`, `crates/uip/src/main.rs`, `.github/workflows/ci.yml`

- [ ] **Step 1: Workspace anlegen**

`Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/uip-core", "crates/uip-ingest", "crates/uip-api", "crates/uip"]

[workspace.package]
version = "0.1.0"
edition = "2021"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
axum = "0.8"
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "chrono", "ipnetwork", "mac_address", "migrate"] }
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
thiserror = "2"
ipnetwork = "0.20"
mac_address = "1"
futures = "0.3"
tokio-stream = { version = "0.1", features = ["sync"] }
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
```

`crates/uip-core/Cargo.toml`:

```toml
[package]
name = "uip-core"
version.workspace = true
edition.workspace = true

[dependencies]
tokio.workspace = true
sqlx.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
ipnetwork.workspace = true
mac_address.workspace = true
tracing.workspace = true
```

`crates/uip-ingest/Cargo.toml`:

```toml
[package]
name = "uip-ingest"
version.workspace = true
edition.workspace = true

[dependencies]
uip-core = { path = "../uip-core" }
tokio.workspace = true
sqlx.workspace = true
chrono.workspace = true
serde_json.workspace = true
ipnetwork.workspace = true
mac_address.workspace = true
tracing.workspace = true
anyhow.workspace = true
```

`crates/uip-api/Cargo.toml`:

```toml
[package]
name = "uip-api"
version.workspace = true
edition.workspace = true

[dependencies]
uip-core = { path = "../uip-core" }
uip-ingest = { path = "../uip-ingest" }
axum.workspace = true
tokio.workspace = true
tokio-stream.workspace = true
futures.workspace = true
sqlx.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
rust-embed = "8"
mime_guess = "2"
```

`crates/uip/Cargo.toml`:

```toml
[package]
name = "uip"
version.workspace = true
edition.workspace = true

[dependencies]
uip-core = { path = "../uip-core" }
uip-ingest = { path = "../uip-ingest" }
uip-api = { path = "../uip-api" }
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
anyhow.workspace = true
```

Lib-Stubs: `crates/uip-core/src/lib.rs`, `crates/uip-ingest/src/lib.rs`, `crates/uip-api/src/lib.rs` je leer (`// modules follow`), `crates/uip/src/main.rs`:

```rust
fn main() {
    println!("uip");
}
```

- [ ] **Step 2: Build prüfen**

Run: `cargo build`
Expected: kompiliert ohne Fehler (erster Lauf lädt Crates).

- [ ] **Step 3: CI-Workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --workspace
      - run: cargo test --workspace
      - run: cargo clippy --workspace -- -D warnings
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "chore: cargo workspace scaffold with ci"
```

### Task 2: uip-core — Config aus Env

**Files:**
- Create: `crates/uip-core/src/config.rs`
- Modify: `crates/uip-core/src/lib.rs`

- [ ] **Step 1: Failing Test schreiben** (in `config.rs` unten als `#[cfg(test)]`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_env_missing() {
        let c = Config::from_vars(|_| None);
        assert_eq!(c.http_addr, "0.0.0.0:8080");
        assert_eq!(c.syslog_addr, "0.0.0.0:514");
        assert_eq!(c.wan_interfaces, ["ppp0".to_string()].into_iter().collect::<std::collections::HashSet<_>>());
        assert!(c.database_url.contains("uip"));
    }

    #[test]
    fn reads_env_overrides() {
        let c = Config::from_vars(|k| match k {
            "UIP_DB_URL" => Some("postgres://x/y".into()),
            "UIP_HTTP_ADDR" => Some("127.0.0.1:9999".into()),
            "UIP_SYSLOG_ADDR" => Some("0.0.0.0:5514".into()),
            "UIP_WAN_IFACES" => Some("eth8, ppp0".into()),
            _ => None,
        });
        assert_eq!(c.database_url, "postgres://x/y");
        assert_eq!(c.http_addr, "127.0.0.1:9999");
        assert_eq!(c.syslog_addr, "0.0.0.0:5514");
        assert!(c.wan_interfaces.contains("eth8") && c.wan_interfaces.contains("ppp0"));
    }
}
```

- [ ] **Step 2: Test läuft und schlägt fehl**

Run: `cargo test -p uip-core`
Expected: FAIL — `Config` nicht definiert.

- [ ] **Step 3: Implementierung**

`crates/uip-core/src/config.rs` (über dem Testmodul):

```rust
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub http_addr: String,
    pub syslog_addr: String,
    pub wan_interfaces: HashSet<String>,
}

impl Config {
    /// Injizierbare Env-Quelle, damit Tests keine Prozess-Env anfassen.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Self {
        let wan = get("UIP_WAN_IFACES").unwrap_or_else(|| "ppp0".into());
        Self {
            database_url: get("UIP_DB_URL")
                .or_else(|| get("DATABASE_URL"))
                .unwrap_or_else(|| "postgres://localhost/uip_dev".into()),
            http_addr: get("UIP_HTTP_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into()),
            syslog_addr: get("UIP_SYSLOG_ADDR").unwrap_or_else(|| "0.0.0.0:514".into()),
            wan_interfaces: wan
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    pub fn from_env() -> Self {
        Self::from_vars(|k| std::env::var(k).ok())
    }
}
```

`crates/uip-core/src/lib.rs`:

```rust
pub mod config;
pub use config::Config;
```

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-core`
Expected: PASS (2 Tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): env config"
```

---

### Task 3: uip-core — Domänentypen

Closed Sets als Enums mit fixen i16-Ids (identisch zur DB, niemals umnummerieren — die Ids stehen in Millionen Log-Zeilen).

**Files:**
- Create: `crates/uip-core/src/types.rs`
- Modify: `crates/uip-core/src/lib.rs`

- [ ] **Step 1: Failing Test**

```rust
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
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-core types`
Expected: FAIL — Typen fehlen.

- [ ] **Step 3: Implementierung**

`crates/uip-core/src/types.rs`:

```rust
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
```

In `lib.rs` ergänzen:

```rust
pub mod types;
pub use types::{Direction, LogType, ParsedLog, RuleAction};
```

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-core`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): closed-set enums and ParsedLog"
```

### Task 4: Migration 0001 — Schema + Hypertable

Konzept aus dem Fork-Schema (Lookup-Tabellen, Alignment-bewusste Spaltenreihenfolge), neu: Hypertable, `enrich_status`, Timescale-Policies statt Cleanup-Cron. Enrichment-Spalten (geo/asn/threat/rdns) sind ab Tag 1 im Schema, damit Phase 2 keine teure Hypertable-ALTER-Orgie braucht — sie bleiben in Phase 1 einfach NULL.

**Files:**
- Create: `migrations/0001_init.sql`

- [ ] **Step 1: Migration schreiben**

```sql
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Lookup-Tabellen: offene Wertemengen aus dem Netz, je einmal gespeichert.
CREATE TABLE rules (
    id    SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name  VARCHAR(100),
    descr VARCHAR(255)
);
CREATE UNIQUE INDEX idx_rules_key ON rules (COALESCE(lower(name), ''), COALESCE(lower(descr), ''));

CREATE TABLE interfaces (
    id   SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(20) NOT NULL
);
CREATE UNIQUE INDEX idx_interfaces_key ON interfaces (lower(name));

CREATE TABLE protocols (
    id   SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(10) NOT NULL
);
CREATE UNIQUE INDEX idx_protocols_key ON protocols (lower(name));

CREATE TABLE device_names (
    id   SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_device_names_key ON device_names (lower(name));

-- Logs: Hypertable, partitioniert nach timestamp. id ist NICHT global eindeutig
-- sortierbar ohne timestamp — Cursor ist immer (timestamp, id).
CREATE TABLE logs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY,
    timestamp           TIMESTAMPTZ NOT NULL,
    src_port            INTEGER,
    dst_port            INTEGER,
    asn_number          INTEGER,
    threat_score        INTEGER,
    log_type_id         SMALLINT NOT NULL,
    direction_id        SMALLINT,
    rule_id             SMALLINT,
    rule_action_id      SMALLINT,
    protocol_id         SMALLINT,
    iface_in_id         SMALLINT,
    iface_out_id        SMALLINT,
    hostname_id         SMALLINT,
    enrich_status       SMALLINT NOT NULL DEFAULT 0,  -- 0=pending 1=done 2=failed
    src_ip              INET,
    dst_ip              INET,
    mac_address         MACADDR,
    geo_country         VARCHAR(2),
    geo_city            VARCHAR(100),
    geo_lat             DECIMAL(9,6),
    geo_lon             DECIMAL(9,6),
    asn_name            VARCHAR(255),
    rdns                VARCHAR(255),
    dns_query           VARCHAR(255),
    dns_type            VARCHAR(10),
    dns_answer          VARCHAR(255),
    dhcp_event          VARCHAR(20),
    wifi_event          VARCHAR(50),
    raw_log             TEXT,
    PRIMARY KEY (timestamp, id)
);

SELECT create_hypertable('logs', 'timestamp', chunk_time_interval => INTERVAL '1 day');

CREATE INDEX idx_logs_type_time ON logs (log_type_id, timestamp DESC, id DESC);
CREATE INDEX idx_logs_src_ip ON logs (src_ip, timestamp DESC);
CREATE INDEX idx_logs_dst_ip ON logs (dst_ip, timestamp DESC);
-- Die Enrichment-Queue: Worker (Phase 2) holt pending-Zeilen. Partial → winzig.
CREATE INDEX idx_logs_enrich_pending ON logs (timestamp, id) WHERE enrich_status = 0;

-- Kompression + Retention über Timescale statt eigenem Cron.
ALTER TABLE logs SET (
    timescaledb.compress,
    timescaledb.compress_orderby = 'timestamp DESC, id DESC',
    timescaledb.compress_segmentby = 'log_type_id'
);
SELECT add_compression_policy('logs', INTERVAL '7 days');
SELECT add_retention_policy('logs', INTERVAL '60 days');

-- Dynamische Konfiguration (Setup, Labels, Retention-Overrides …)
CREATE TABLE system_config (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- [ ] **Step 2: Migration anwenden**

Run: `sqlx migrate run` (im Repo-Root, `.env` mit `DATABASE_URL` vorhanden)
Expected: `Applied 1/migrate init`. Danach `psql uip_dev -c "\d logs"` zeigt die Tabelle; `psql uip_dev -c "SELECT hypertable_name FROM timescaledb_information.hypertables"` zeigt `logs`.

- [ ] **Step 3: Commit**

```bash
git add migrations && git commit -m "feat(db): initial timescale schema"
```

---

### Task 5: uip-ingest — Syslog-Header-Parser

RFC3164 ohne Jahr: `<13>Feb  8 16:43:49 UDR-UK body…`. Priority-Präfix optional. Timestamp in lokaler TZ des Gateways (TZ-Env), als UTC gespeichert. Jahres-Rollover: nur zurückdatieren, wenn Log-Monat > 6 Monate vor jetzt liegt (Dez-Log im Januar) — ein simples `ts > now` kippt bei wenigen Sekunden Uhrenversatz.

**Files:**
- Create: `crates/uip-ingest/src/syslog.rs`
- Modify: `crates/uip-ingest/src/lib.rs`

- [ ] **Step 1: Failing Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, TimeZone, Utc};

    fn now() -> chrono::DateTime<Utc> { Utc.with_ymd_and_hms(2026, 9, 13, 12, 0, 0).unwrap() }

    #[test]
    fn parses_plain_header() {
        let h = parse_header("Feb  8 16:43:49 UDR-UK kernel: hello", now()).unwrap();
        assert_eq!(h.host, "UDR-UK");
        assert_eq!(h.body, "kernel: hello");
        assert_eq!(h.timestamp.month(), 2);
        assert_eq!(h.timestamp.year(), 2026);
    }

    #[test]
    fn strips_priority_prefix() {
        let h = parse_header("<13>Feb  8 16:43:49 UDR kernel: x", now()).unwrap();
        assert_eq!(h.host, "UDR");
    }

    #[test]
    fn year_rollover_december_log_in_january() {
        let jan = Utc.with_ymd_and_hms(2027, 1, 2, 0, 0, 0).unwrap();
        let h = parse_header("Dec 31 23:59:58 UDR kernel: x", jan).unwrap();
        assert_eq!(h.timestamp.year(), 2026);
    }

    #[test]
    fn same_month_keeps_year() {
        let h = parse_header("Sep 13 11:59:00 UDR kernel: x", now()).unwrap();
        assert_eq!(h.timestamp.year(), 2026);
    }

    #[test]
    fn garbage_returns_none() {
        assert!(parse_header("not a syslog line", now()).is_none());
        assert!(parse_header("", now()).is_none());
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-ingest`
Expected: FAIL — `parse_header` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-ingest/src/syslog.rs`:

```rust
use chrono::{DateTime, Datelike, Local, LocalResult, TimeZone, Utc};

#[derive(Debug, PartialEq)]
pub struct SyslogHeader<'a> {
    pub timestamp: DateTime<Utc>,
    pub host: &'a str,
    pub body: &'a str,
}

fn month_num(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    })
}

/// `now` wird injiziert (Tests!); Produktion ruft `parse_header(line, Utc::now())`.
pub fn parse_header(line: &str, now: DateTime<Utc>) -> Option<SyslogHeader<'_>> {
    // Priority-Präfix <NN> abstreifen
    let line = if let Some(rest) = line.strip_prefix('<') {
        let end = rest.find('>')?;
        if !rest[..end].bytes().all(|b| b.is_ascii_digit()) { return None; }
        &rest[end + 1..]
    } else {
        line
    };

    let mut it = line.splitn(2, ' ');
    let month = month_num(it.next()?)?;
    let rest = it.next()?.trim_start();

    let mut it = rest.splitn(2, ' ');
    let day: u32 = it.next()?.parse().ok()?;
    let rest = it.next()?;

    let mut it = rest.splitn(2, ' ');
    let time = it.next()?;
    let rest = it.next()?;

    let mut t = time.splitn(3, ':');
    let (h, m, s): (u32, u32, u32) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );

    let mut it = rest.splitn(2, ' ');
    let host = it.next()?;
    let body = it.next()?.trim_start();
    if host.is_empty() || body.is_empty() { return None; }

    // Syslog-Zeit ist Absender-Lokalzeit; TZ-Env muss dem Gateway entsprechen.
    let local_now = now.with_timezone(&Local);
    let mut year = local_now.year();
    if month as i32 - local_now.month() as i32 > 6 {
        year -= 1;
    }
    let ts = match Local.with_ymd_and_hms(year, month, day, h, m, s) {
        LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => t,
        LocalResult::None => return None, // DST-Lücke
    };

    Some(SyslogHeader { timestamp: ts.with_timezone(&Utc), host, body })
}
```

`crates/uip-ingest/src/lib.rs`:

```rust
pub mod syslog;
```

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-ingest`
Expected: PASS (5 Tests). Hinweis: die Jahres-Tests nehmen an, dass Host-TZ und injizierte `now` zusammenpassen — sie prüfen Monat/Jahr, nicht die exakte Stunde, genau deshalb.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ingest): rfc3164 header parser with year rollover"
```

### Task 6: uip-ingest — Firewall-Parser + Direction/Action

Hand-Scanner statt Regex. Format: `kernel: [RULE-NAME]IN=ppp0 OUT=br20 MAC=… SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=443 DPT=51234 DESCR="Block Bad"`. MAC-Feld ist dest:src:ethertype (14 Bytes hex) — wir wollen Bytes 7–12 (Source-MAC). Direction-Ableitung wie im Fork-Konzept (WAN-Iface-Mengen, VPN-Präfixe, Broadcast/Multicast → local). Action Phase-1-vereinfacht: letztes `-`-Segment des Rule-Namens (`A`→allow, `D`→block, `R`→redirect), sonst DESCR-Präfix (`Block…`/`Allow…`/`Deny…`), sonst allow. Voller Policy-Matcher kommt in Phase 4.

**Files:**
- Create: `crates/uip-ingest/src/firewall.rs`
- Modify: `crates/uip-ingest/src/lib.rs`

- [ ] **Step 1: Failing Tests** (echte Fixture-Zeilen aus dem Fork-Testbestand)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use uip_core::{Direction, RuleAction};
    use std::collections::HashSet;

    fn ctx() -> FirewallCtx {
        FirewallCtx {
            wan_interfaces: HashSet::from(["ppp0".to_string()]),
            wan_ips: HashSet::new(),
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

    #[test]
    fn descr_block_hint_when_no_suffix() {
        let p = parse_firewall(r#"kernel: [MYRULE]IN=br20 OUT=ppp0 SRC=10.0.20.5 DST=1.2.3.4 PROTO=TCP DESCR="Block Unauthorized""#, &ctx());
        assert_eq!(p.rule_action, Some(RuleAction::Block));
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-ingest firewall`
Expected: FAIL — Modul fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-ingest/src/firewall.rs`:

```rust
use std::collections::HashSet;
use std::net::IpAddr;
use uip_core::{Direction, ParsedLog, RuleAction};
use uip_core::types::LogType;

pub const VPN_PREFIXES: [&str; 9] =
    ["wgsrv", "wgclt", "wgsts", "tlprt", "vti", "tunovpnc", "tun", "vtun", "l2tp"];

#[derive(Debug, Clone, Default)]
pub struct FirewallCtx {
    pub wan_interfaces: HashSet<String>,
    pub wan_ips: HashSet<IpAddr>,
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
    if let Some(last) = name.rsplit('-').next() {
        match last {
            "A" => return Some(RuleAction::Allow),
            "D" => return Some(RuleAction::Block),
            "R" => return Some(RuleAction::Redirect),
            _ => {}
        }
    }
    if let Some(d) = rule_desc {
        let d = d.to_ascii_lowercase();
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
    let wan_out = iface_out.map(|i| ctx.wan_interfaces.contains(i)).unwrap_or(false);
    if let Some(s) = src_ip {
        if ctx.wan_ips.contains(s) && !wan_out { return Some(Direction::Local); }
    }
    if let Some(r) = rule_name {
        if r.contains("DNAT") || r.contains("PREROUTING") { return Some(Direction::Nat); }
    }
    let wan_in = iface_in.map(|i| ctx.wan_interfaces.contains(i)).unwrap_or(false);
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
        let key_start = rest[..eq].rfind(|c: char| c == ' ' || c == ']').map(|i| i + 1).unwrap_or(0);
        let key = &rest[key_start..eq];
        let after = &rest[eq + 1..];
        let (value, next): (&str, &str) = if after.starts_with('"') {
            match after[1..].find('"') {
                Some(end) => (&after[1..1 + end], &after[end + 2..]),
                None => (&after[1..], ""),
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
```

`lib.rs` ergänzen: `pub mod firewall;`

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-ingest`
Expected: PASS (alle Firewall-Tests + Syslog-Tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ingest): firewall kv-scanner with direction/action derivation"
```

### Task 7: uip-ingest — DNS/DHCP/WiFi/System-Parser + Dispatch

**Files:**
- Create: `crates/uip-ingest/src/parsers.rs`
- Modify: `crates/uip-ingest/src/lib.rs`

- [ ] **Step 1: Failing Tests** (Fixtures 1:1 aus dem Fork-Testbestand)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallCtx;
    use chrono::{TimeZone, Utc};
    use uip_core::types::LogType;

    fn now() -> chrono::DateTime<Utc> { Utc.with_ymd_and_hms(2026, 9, 13, 12, 0, 0).unwrap() }
    fn ctx() -> FirewallCtx { FirewallCtx::default() }

    #[test]
    fn detect_types() {
        assert_eq!(detect_log_type("kernel: [X]IN=a OUT=b SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP"), LogType::Firewall);
        assert_eq!(detect_log_type("dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff host1"), LogType::Dhcp);
        assert_eq!(detect_log_type("dnsmasq[1234]: query[A] example.com from 192.168.1.5"), LogType::Dns);
        assert_eq!(detect_log_type("hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated"), LogType::Wifi);
        assert_eq!(detect_log_type("systemd[1]: Started thing."), LogType::System);
    }

    #[test]
    fn dns_query_reply_forward_cached() {
        let p = parse_dns("dnsmasq[1234]: query[A] example.com from 192.168.1.5");
        assert_eq!(p.dns_type.as_deref(), Some("A"));
        assert_eq!(p.dns_query.as_deref(), Some("example.com"));
        assert_eq!(p.src_ip.unwrap().to_string(), "192.168.1.5");
        let p = parse_dns("dnsmasq[1234]: reply example.com is 1.2.3.4");
        assert_eq!(p.dns_answer.as_deref(), Some("1.2.3.4"));
        let p = parse_dns("dnsmasq[1234]: forwarded example.com to 8.8.8.8");
        assert_eq!(p.dst_ip.unwrap().to_string(), "8.8.8.8");
        let p = parse_dns("dnsmasq[1234]: cached example.com is 1.2.3.4");
        assert_eq!(p.dns_answer.as_deref(), Some("1.2.3.4"));
        let p = parse_dns("dnsmasq[1234]: some unknown line");
        assert_eq!(p.dns_query, None);
    }

    #[test]
    fn dhcp_events() {
        let p = parse_dhcp("dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff myhost");
        assert_eq!(p.dhcp_event.as_deref(), Some("DHCPACK"));
        assert_eq!(p.interface_in.as_deref(), Some("br0"));
        assert_eq!(p.src_ip.unwrap().to_string(), "192.168.1.100");
        assert_eq!(p.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(p.hostname.as_deref(), Some("myhost"));
        let p = parse_dhcp("dnsmasq-dhcp[1234]: DHCPDISCOVER(br0) aa:bb:cc:dd:ee:ff");
        assert_eq!(p.dhcp_event.as_deref(), Some("DHCPDISCOVER"));
        assert_eq!(p.src_ip, None);
        let p = parse_dhcp("dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff");
        assert_eq!(p.hostname, None);
    }

    #[test]
    fn wifi_assoc() {
        let p = parse_wifi("hostapd: ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated");
        assert_eq!(p.wifi_event.as_deref(), Some("associated"));
        assert_eq!(p.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        let p = parse_wifi(r#"stahtd[999]: stahtd: {"mac":"aa:bb:cc:dd:ee:ff","event_type":"probe"}"#);
        assert_eq!(p.wifi_event.as_deref(), Some("probe"));
    }

    #[test]
    fn full_line_dispatch_and_invalid_mac_dropped() {
        let p = parse_log("Feb  8 16:43:49 UDR dnsmasq[1234]: query[A] example.com from 192.168.1.5", now(), &ctx()).unwrap();
        assert_eq!(p.log_type, Some(LogType::Dns));
        assert!(p.timestamp.is_some());
        assert_eq!(p.raw_log, "Feb  8 16:43:49 UDR dnsmasq[1234]: query[A] example.com from 192.168.1.5");
        // Fork-Fixture: verkürzte MAC wird verworfen statt DB-Fehler
        let p = parse_log("Feb  8 16:43:49 UDR hostapd: ath0: STA aa:bb:cc IEEE 802.11: associated", now(), &ctx()).unwrap();
        assert_eq!(p.mac_address, None);
        // Header kaputt → None (Aufrufer speichert raw als System-Zeile)
        assert!(parse_log("garbage", now(), &ctx()).is_none());
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-ingest parsers`
Expected: FAIL.

- [ ] **Step 3: Implementierung**

`crates/uip-ingest/src/parsers.rs`:

```rust
use crate::firewall::{parse_firewall, FirewallCtx};
use crate::syslog::parse_header;
use chrono::{DateTime, Utc};
use uip_core::types::LogType;
use uip_core::ParsedLog;

pub fn detect_log_type(body: &str) -> LogType {
    if (body.contains("SRC=") && body.contains("DST=") && body.contains("PROTO="))
        || (body.starts_with('[') && body.contains("DESCR=")) {
        return LogType::Firewall;
    }
    if body.contains("dnsmasq-dhcp") || body.contains("DHCPACK") || body.contains("DHCPDISCOVER")
        || body.contains("DHCPREQUEST") || body.contains("DHCPOFFER") {
        return LogType::Dhcp;
    }
    if body.contains("dnsmasq")
        && (body.contains("query[") || body.contains("reply ") || body.contains("forwarded ") || body.contains("cached ")) {
        return LogType::Dns;
    }
    if body.contains("stamgr") || body.contains("hostapd") || body.contains("stahtd")
        || (body.contains("STA ") && (body.contains("associated") || body.contains("authenticated"))) {
        return LogType::Wifi;
    }
    LogType::System
}

fn word_after<'a>(body: &'a str, marker: &str) -> Option<&'a str> {
    let i = body.find(marker)? + marker.len();
    let rest = body[i..].trim_start();
    let end = rest.find(' ').unwrap_or(rest.len());
    let w = &rest[..end];
    if w.is_empty() { None } else { Some(w) }
}

pub fn parse_dns(body: &str) -> ParsedLog {
    let mut p = ParsedLog { log_type: Some(LogType::Dns), ..Default::default() };
    if let Some(i) = body.find("query[") {
        let rest = &body[i + 6..];
        if let Some(close) = rest.find(']') {
            p.dns_type = Some(rest[..close].to_string());
            let mut it = rest[close + 1..].split_whitespace();
            p.dns_query = it.next().map(str::to_string);
            if it.next() == Some("from") {
                p.src_ip = it.next().and_then(|s| s.parse().ok());
            }
            return p;
        }
    }
    for (marker, is_answer) in [("reply ", true), ("cached ", true), ("forwarded ", false)] {
        if let Some(i) = body.find(marker) {
            let mut it = body[i + marker.len()..].split_whitespace();
            p.dns_query = it.next().map(str::to_string);
            let link = it.next(); // "is" / "to"
            let val = it.next();
            match (is_answer, link, val) {
                (true, Some("is"), Some(v)) => p.dns_answer = Some(v.to_string()),
                (false, Some("to"), Some(v)) => p.dst_ip = v.parse().ok(),
                _ => { p.dns_query = None; }
            }
            return p;
        }
    }
    p
}

pub fn parse_dhcp(body: &str) -> ParsedLog {
    let mut p = ParsedLog { log_type: Some(LogType::Dhcp), ..Default::default() };
    for ev in ["DHCPACK", "DHCPREQUEST", "DHCPOFFER", "DHCPDISCOVER"] {
        let Some(i) = body.find(ev) else { continue };
        let rest = &body[i + ev.len()..];
        let Some(rest) = rest.strip_prefix('(') else { continue };
        let Some(close) = rest.find(')') else { continue };
        p.dhcp_event = Some(ev.to_string());
        p.interface_in = Some(rest[..close].to_string());
        let mut it = rest[close + 1..].split_whitespace().peekable();
        // optionale IP, dann MAC, dann optionaler Hostname (nur ACK)
        if let Some(w) = it.peek() {
            if w.parse::<std::net::IpAddr>().is_ok() {
                p.src_ip = it.next().and_then(|s| s.parse().ok());
            }
        }
        p.mac_address = it.next().map(str::to_string);
        if ev == "DHCPACK" {
            p.hostname = it.next().map(str::to_string);
        }
        return p;
    }
    p
}

pub fn parse_wifi(body: &str) -> ParsedLog {
    let mut p = ParsedLog { log_type: Some(LogType::Wifi), ..Default::default() };
    if body.contains("stahtd") {
        if let Some(i) = body.find('{') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body[i..]) {
                p.mac_address = v.get("mac").and_then(|m| m.as_str()).map(str::to_string);
                p.wifi_event = v.get("event_type").or_else(|| v.get("message_type"))
                    .and_then(|e| e.as_str()).map(str::to_string)
                    .or_else(|| Some("stahtd".into()));
                return p;
            }
        }
        p.wifi_event = Some("stahtd".into());
        return p;
    }
    if let Some(mac) = word_after(body, "STA ") {
        p.mac_address = Some(mac.to_string());
        for ev in ["disassociated", "deauthenticated", "associated", "authenticated"] {
            if body.contains(ev) {
                p.wifi_event = Some(ev.to_string());
                break;
            }
        }
    }
    p
}

fn valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Komplette Zeile → ParsedLog. None, wenn schon der Header nicht passt;
/// der Aufrufer persistiert die Zeile dann als System-Log mit raw.
pub fn parse_log(raw: &str, now: DateTime<Utc>, ctx: &FirewallCtx) -> Option<ParsedLog> {
    let h = parse_header(raw, now)?;
    let mut p = match detect_log_type(h.body) {
        LogType::Firewall => parse_firewall(h.body, ctx),
        LogType::Dns => parse_dns(h.body),
        LogType::Dhcp => parse_dhcp(h.body),
        LogType::Wifi => parse_wifi(h.body),
        LogType::System => ParsedLog { log_type: Some(LogType::System), ..Default::default() },
    };
    p.timestamp = Some(h.timestamp);
    p.raw_log = raw.to_string();
    if let Some(m) = &p.mac_address {
        if !valid_mac(m) { p.mac_address = None; }
    }
    p
}
```

`lib.rs` ergänzen: `pub mod parsers;`

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-ingest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ingest): dns/dhcp/wifi parsers and dispatch"
```

### Task 8: uip-core — DB-Pool + Lookup-Cache

Lookup-Tabellen (interfaces, protocols, rules, device_names) sind append-only. In-Memory-Cache `HashMap<Key, i16>` hinter `RwLock`; Miss → `INSERT … ON CONFLICT DO NOTHING` + `SELECT`. Keys case-insensitiv (DB-Unique-Index ist `lower(...)`).

**Files:**
- Create: `crates/uip-core/src/db.rs`
- Modify: `crates/uip-core/src/lib.rs`

- [ ] **Step 1: Failing sqlx-Test** (läuft nur mit `DATABASE_URL`; `#[sqlx::test]` legt eine Wegwerf-DB an und spielt `migrations/` ein)

In `db.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn lookup_ids_are_stable_and_case_insensitive(pool: sqlx::PgPool) {
        let cache = LookupCache::new();
        let a = cache.interface_id(&pool, "ppp0").await.unwrap();
        let b = cache.interface_id(&pool, "PPP0").await.unwrap();
        assert_eq!(a, b);
        let c = cache.interface_id(&pool, "br20").await.unwrap();
        assert_ne!(a, c);
        let p = cache.protocol_id(&pool, "tcp").await.unwrap();
        assert!(p >= 1);
        let r1 = cache.rule_id(&pool, Some("WAN_IN-D"), Some("Block x")).await.unwrap();
        let r2 = cache.rule_id(&pool, Some("wan_in-d"), Some("block x")).await.unwrap();
        assert_eq!(r1, r2);
        let h = cache.device_name_id(&pool, "myhost").await.unwrap();
        assert!(h >= 1);
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-core db`
Expected: FAIL — `LookupCache` fehlt. (Ohne `DATABASE_URL`: Test wird als Fehler wegen fehlender Env gemeldet — dann lokal `.env` prüfen.)

- [ ] **Step 3: Implementierung**

`crates/uip-core/src/db.rs`:

```rust
use sqlx::PgPool;
use std::collections::HashMap;
use tokio::sync::RwLock;

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}

#[derive(Default)]
pub struct LookupCache {
    interfaces: RwLock<HashMap<String, i16>>,
    protocols: RwLock<HashMap<String, i16>>,
    device_names: RwLock<HashMap<String, i16>>,
    rules: RwLock<HashMap<(String, String), i16>>,
}

impl LookupCache {
    pub fn new() -> Self { Self::default() }

    async fn simple_id(
        map: &RwLock<HashMap<String, i16>>, pool: &PgPool, table: &str, value: &str,
    ) -> Result<i16, sqlx::Error> {
        let key = value.to_lowercase();
        if let Some(&id) = map.read().await.get(&key) { return Ok(id); }
        // Nur whitelisted Tabellennamen landen im SQL-String.
        let insert = format!("INSERT INTO {table} (name) VALUES ($1) ON CONFLICT DO NOTHING");
        sqlx::query(&insert).bind(value).execute(pool).await?;
        let select = format!("SELECT id FROM {table} WHERE lower(name) = $1");
        let id: i16 = sqlx::query_scalar(&select).bind(&key).fetch_one(pool).await?;
        map.write().await.insert(key, id);
        Ok(id)
    }

    pub async fn interface_id(&self, pool: &PgPool, name: &str) -> Result<i16, sqlx::Error> {
        Self::simple_id(&self.interfaces, pool, "interfaces", name).await
    }
    pub async fn protocol_id(&self, pool: &PgPool, name: &str) -> Result<i16, sqlx::Error> {
        Self::simple_id(&self.protocols, pool, "protocols", name).await
    }
    pub async fn device_name_id(&self, pool: &PgPool, name: &str) -> Result<i16, sqlx::Error> {
        Self::simple_id(&self.device_names, pool, "device_names", name).await
    }

    pub async fn rule_id(
        &self, pool: &PgPool, name: Option<&str>, descr: Option<&str>,
    ) -> Result<i16, sqlx::Error> {
        let key = (
            name.unwrap_or("").to_lowercase(),
            descr.unwrap_or("").to_lowercase(),
        );
        if let Some(&id) = self.rules.read().await.get(&key) { return Ok(id); }
        sqlx::query("INSERT INTO rules (name, descr) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(name).bind(descr).execute(pool).await?;
        let id: i16 = sqlx::query_scalar(
            "SELECT id FROM rules WHERE COALESCE(lower(name), '') = $1 AND COALESCE(lower(descr), '') = $2",
        ).bind(&key.0).bind(&key.1).fetch_one(pool).await?;
        self.rules.write().await.insert(key, id);
        Ok(id)
    }
}
```

`lib.rs` ergänzen:

```rust
pub mod db;
pub use db::{connect, LookupCache};
```

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-core`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): pg pool and lookup cache"
```

---

### Task 9: uip-ingest — Batch-Writer + Broadcast

mpsc-Kanal (Receiver-Task → Writer). Flush bei 200 Zeilen oder 200 ms. Multi-Row-INSERT via UNNEST-Arrays. Nach erfolgreichem Insert: Zeilen als JSON an `tokio::sync::broadcast` für SSE. Unparsebare Zeilen kommen als System-Log mit `raw_log` an (macht der UDP-Task, Task 10).

**Files:**
- Create: `crates/uip-ingest/src/writer.rs`
- Modify: `crates/uip-ingest/src/lib.rs`

- [ ] **Step 1: Failing sqlx-Test**

In `writer.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallCtx;
    use crate::parsers::parse_log;
    use chrono::Utc;
    use uip_core::LookupCache;

    #[sqlx::test(migrations = "../../migrations")]
    async fn writes_batch_and_broadcasts(pool: sqlx::PgPool) {
        let cache = std::sync::Arc::new(LookupCache::new());
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let (btx, mut brx) = tokio::sync::broadcast::channel(256);
        let writer = tokio::spawn(run_writer(rx, pool.clone(), cache, btx));

        let ctx = FirewallCtx { wan_interfaces: ["ppp0".to_string()].into_iter().collect(), wan_ips: Default::default() };
        let p = parse_log(
            "Feb  8 16:43:49 UDR kernel: [WAN_IN-D]IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=443",
            Utc::now(), &ctx,
        ).unwrap();
        tx.send(p).await.unwrap();
        drop(tx); // Kanal zu → Writer flusht und endet

        writer.await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM logs").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 1);
        let (status, lt): (i16, i16) = sqlx::query_as(
            "SELECT enrich_status, log_type_id FROM logs LIMIT 1",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(status, 0); // pending für Phase-2-Worker
        assert_eq!(lt, 1);
        let evt = brx.recv().await.unwrap();
        assert!(evt.contains("\"src_ip\":\"1.2.3.4\""));
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-ingest writer`
Expected: FAIL — `run_writer` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-ingest/src/writer.rs`:

```rust
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use uip_core::{LookupCache, ParsedLog};

const BATCH_MAX: usize = 200;
const FLUSH_EVERY: Duration = Duration::from_millis(200);

/// Eine Zeile, fertig aufgelöst für den UNNEST-Insert.
struct Row {
    timestamp: DateTime<Utc>,
    log_type_id: i16,
    direction_id: Option<i16>,
    rule_id: Option<i16>,
    rule_action_id: Option<i16>,
    protocol_id: Option<i16>,
    iface_in_id: Option<i16>,
    iface_out_id: Option<i16>,
    hostname_id: Option<i16>,
    src_ip: Option<IpNetwork>,
    dst_ip: Option<IpNetwork>,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    mac_address: Option<MacAddress>,
    dns_query: Option<String>,
    dns_type: Option<String>,
    dns_answer: Option<String>,
    dhcp_event: Option<String>,
    wifi_event: Option<String>,
    raw_log: Option<String>,
    json: String,
}

async fn resolve(p: ParsedLog, pool: &PgPool, cache: &LookupCache) -> Result<Row, sqlx::Error> {
    let log_type = p.log_type.expect("parse_log always sets log_type");
    let rule_id = match (&p.rule_name, &p.rule_desc) {
        (None, None) => None,
        (n, d) => Some(cache.rule_id(pool, n.as_deref(), d.as_deref()).await?),
    };
    let mut iface_in_id = None;
    if let Some(i) = &p.interface_in { iface_in_id = Some(cache.interface_id(pool, i).await?); }
    let mut iface_out_id = None;
    if let Some(i) = &p.interface_out { iface_out_id = Some(cache.interface_id(pool, i).await?); }
    let mut protocol_id = None;
    if let Some(pr) = &p.protocol { protocol_id = Some(cache.protocol_id(pool, pr).await?); }
    let mut hostname_id = None;
    if let Some(h) = &p.hostname { hostname_id = Some(cache.device_name_id(pool, h).await?); }

    let timestamp = p.timestamp.unwrap_or_else(Utc::now);
    // System-Logs tragen raw immer (einzige Information); andere nur zur Diagnose nicht nötig → NULL spart Platz.
    let keep_raw = matches!(log_type, uip_core::types::LogType::System);

    let json = serde_json::json!({
        "timestamp": timestamp.to_rfc3339(),
        "log_type": log_type.as_str(),
        "direction": p.direction.map(|d| d.as_str()),
        "rule_name": p.rule_name,
        "rule_action": p.rule_action.map(|a| a.as_str()),
        "protocol": p.protocol,
        "iface_in": p.interface_in,
        "iface_out": p.interface_out,
        "src_ip": p.src_ip.map(|i| i.to_string()),
        "dst_ip": p.dst_ip.map(|i| i.to_string()),
        "src_port": p.src_port,
        "dst_port": p.dst_port,
        "mac_address": p.mac_address,
        "hostname": p.hostname,
        "dns_query": p.dns_query,
        "dns_type": p.dns_type,
        "dns_answer": p.dns_answer,
        "dhcp_event": p.dhcp_event,
        "wifi_event": p.wifi_event,
    }).to_string();

    Ok(Row {
        timestamp,
        log_type_id: log_type as i16,
        direction_id: p.direction.map(|d| d as i16),
        rule_id,
        rule_action_id: p.rule_action.map(|a| a as i16),
        protocol_id,
        iface_in_id,
        iface_out_id,
        hostname_id,
        src_ip: p.src_ip.map(IpNetwork::from),
        dst_ip: p.dst_ip.map(IpNetwork::from),
        src_port: p.src_port,
        dst_port: p.dst_port,
        mac_address: p.mac_address.as_deref().and_then(|m| MacAddress::from_str(m).ok()),
        dns_query: p.dns_query,
        dns_type: p.dns_type,
        dns_answer: p.dns_answer,
        dhcp_event: p.dhcp_event,
        wifi_event: p.wifi_event,
        raw_log: keep_raw.then_some(p.raw_log),
        json,
    })
}

async fn flush(rows: &mut Vec<Row>, pool: &PgPool, events: &broadcast::Sender<String>) {
    if rows.is_empty() { return; }
    let n = rows.len();
    macro_rules! col { ($f:ident) => { rows.iter().map(|r| r.$f.clone()).collect::<Vec<_>>() } }
    let res = sqlx::query(
        r#"INSERT INTO logs (timestamp, log_type_id, direction_id, rule_id, rule_action_id,
             protocol_id, iface_in_id, iface_out_id, hostname_id, src_ip, dst_ip,
             src_port, dst_port, mac_address, dns_query, dns_type, dns_answer,
             dhcp_event, wifi_event, raw_log)
           SELECT * FROM UNNEST(
             $1::timestamptz[], $2::smallint[], $3::smallint[], $4::smallint[], $5::smallint[],
             $6::smallint[], $7::smallint[], $8::smallint[], $9::smallint[], $10::inet[], $11::inet[],
             $12::int[], $13::int[], $14::macaddr[], $15::text[], $16::text[], $17::text[],
             $18::text[], $19::text[], $20::text[])"#,
    )
    .bind(col!(timestamp)).bind(col!(log_type_id)).bind(col!(direction_id))
    .bind(col!(rule_id)).bind(col!(rule_action_id)).bind(col!(protocol_id))
    .bind(col!(iface_in_id)).bind(col!(iface_out_id)).bind(col!(hostname_id))
    .bind(col!(src_ip)).bind(col!(dst_ip)).bind(col!(src_port)).bind(col!(dst_port))
    .bind(col!(mac_address)).bind(col!(dns_query)).bind(col!(dns_type))
    .bind(col!(dns_answer)).bind(col!(dhcp_event)).bind(col!(wifi_event)).bind(col!(raw_log))
    .execute(pool)
    .await;
    match res {
        Ok(_) => {
            for r in rows.drain(..) {
                let _ = events.send(r.json); // niemand hört zu → egal
            }
            tracing::debug!(rows = n, "flushed batch");
        }
        Err(e) => {
            tracing::error!(error = %e, rows = n, "batch insert failed, dropping batch");
            rows.clear();
        }
    }
}

pub async fn run_writer(
    mut rx: mpsc::Receiver<ParsedLog>,
    pool: PgPool,
    cache: Arc<LookupCache>,
    events: broadcast::Sender<String>,
) {
    let mut buf: Vec<Row> = Vec::with_capacity(BATCH_MAX);
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(p) => {
                    match resolve(p, &pool, &cache).await {
                        Ok(row) => buf.push(row),
                        Err(e) => tracing::error!(error = %e, "lookup resolve failed, dropping row"),
                    }
                    if buf.len() >= BATCH_MAX { flush(&mut buf, &pool, &events).await; }
                }
                None => { flush(&mut buf, &pool, &events).await; return; }
            },
            _ = tick.tick() => flush(&mut buf, &pool, &events).await,
        }
    }
}
```

`lib.rs` ergänzen: `pub mod writer;`

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-ingest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ingest): batched unnest writer with sse broadcast"
```

### Task 10: uip-ingest — UDP-Listener

Empfängt Datagramme, parst, schickt in den Writer-Kanal. Header-Fehlschlag → System-Log mit `raw_log` (nichts verwerfen). Kanal voll → Zeile droppen und zählen (Backpressure darf den UDP-Read nie blockieren, sonst füllt der Kernel-Buffer und es droppt sowieso — nur unsichtbar).

**Files:**
- Create: `crates/uip-ingest/src/udp.rs`
- Modify: `crates/uip-ingest/src/lib.rs`

- [ ] **Step 1: Failing Test**

In `udp.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallCtx;
    use uip_core::types::LogType;

    #[tokio::test]
    async fn receives_and_parses_datagrams() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(run_udp(sock, tx, FirewallCtx::default()));

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"Feb  8 16:43:49 UDR dnsmasq[1]: query[A] example.com from 192.168.1.5", addr).await.unwrap();
        client.send_to(b"complete garbage", addr).await.unwrap();

        let p1 = rx.recv().await.unwrap();
        assert_eq!(p1.log_type, Some(LogType::Dns));
        let p2 = rx.recv().await.unwrap();
        assert_eq!(p2.log_type, Some(LogType::System));
        assert_eq!(p2.raw_log, "complete garbage");
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-ingest udp`
Expected: FAIL — `run_udp` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-ingest/src/udp.rs`:

```rust
use crate::firewall::FirewallCtx;
use crate::parsers::parse_log;
use chrono::Utc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use uip_core::types::LogType;
use uip_core::ParsedLog;

pub async fn run_udp(sock: UdpSocket, tx: mpsc::Sender<ParsedLog>, ctx: FirewallCtx) {
    let mut buf = vec![0u8; 65536];
    let mut dropped: u64 = 0;
    loop {
        let Ok((n, _peer)) = sock.recv_from(&mut buf).await else { continue };
        let line = String::from_utf8_lossy(&buf[..n]);
        let line = line.trim_end_matches(['\r', '\n', '\0']);
        if line.is_empty() { continue; }
        let parsed = parse_log(line, Utc::now(), &ctx).unwrap_or_else(|| ParsedLog {
            log_type: Some(LogType::System),
            timestamp: Some(Utc::now()),
            raw_log: line.to_string(),
            ..Default::default()
        });
        if tx.try_send(parsed).is_err() {
            dropped += 1;
            if dropped.is_power_of_two() {
                tracing::warn!(dropped, "writer channel full, dropping log lines");
            }
        }
    }
}
```

`lib.rs` ergänzen: `pub mod udp;`

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-ingest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ingest): udp listener task"
```

---

### Task 11: uip-api — Router, /api/health, /api/logs

Cursor-Pagination `(timestamp, id)` absteigend. Antwortzeilen mit aufgelösten Lookup-Namen (LEFT JOINs — dangling id degradiert zu NULL). Filter Phase 1: `log_type`, `limit`, `before` (Cursor `"<ts_micros>:<id>"`).

**Files:**
- Create: `crates/uip-api/src/logs.rs`, `crates/uip-api/src/lib.rs` (ersetzen)

- [ ] **Step 1: Failing sqlx-Test**

In `logs.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // axum dev-dependency: tower = "0.5" in uip-api [dev-dependencies]

    async fn seed(pool: &sqlx::PgPool, n: i32) {
        for i in 0..n {
            sqlx::query(
                "INSERT INTO logs (timestamp, log_type_id, src_ip, dst_port)
                 VALUES (NOW() - make_interval(secs => $1::int), 1, '1.2.3.4', 443)",
            ).bind(i).execute(pool).await.unwrap();
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn health_ok(pool: sqlx::PgPool) {
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.oneshot(Request::get("/api/health").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn logs_pagination_walks_without_gaps(pool: sqlx::PgPool) {
        seed(&pool, 5).await;
        let app = crate::router(pool, tokio::sync::broadcast::channel(8).0);
        let res = app.clone().oneshot(Request::get("/api/logs?limit=3").body(Body::empty()).unwrap()).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        ).unwrap();
        assert_eq!(body["rows"].as_array().unwrap().len(), 3);
        let cursor = body["next_cursor"].as_str().unwrap().to_string();

        let res = app.oneshot(Request::get(format!("/api/logs?limit=3&before={cursor}")).body(Body::empty()).unwrap()).await.unwrap();
        let body2: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap(),
        ).unwrap();
        assert_eq!(body2["rows"].as_array().unwrap().len(), 2);
        // keine Überschneidung
        let ids1: Vec<i64> = body["rows"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        let ids2: Vec<i64> = body2["rows"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        assert!(ids1.iter().all(|i| !ids2.contains(i)));
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-api` (vorher in `crates/uip-api/Cargo.toml` unter `[dev-dependencies]` eintragen: `tower = { version = "0.5", features = ["util"] }`)
Expected: FAIL — `router` fehlt.

- [ ] **Step 3: Implementierung**

`crates/uip-api/src/logs.rs`:

```rust
use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

#[derive(Deserialize)]
pub struct LogsQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
    pub log_type: Option<String>,
}

fn parse_cursor(s: &str) -> Option<(DateTime<Utc>, i64)> {
    let (ts, id) = s.split_once(':')?;
    let micros: i64 = ts.parse().ok()?;
    Some((Utc.timestamp_micros(micros).single()?, id.parse().ok()?))
}

fn log_type_id(name: &str) -> Option<i16> {
    Some(match name { "firewall" => 1, "dns" => 2, "dhcp" => 3, "wifi" => 4, "system" => 5, _ => return None })
}

pub async fn get_logs(State(pool): State<PgPool>, Query(q): Query<LogsQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let cursor = q.before.as_deref().and_then(parse_cursor);
    let type_filter = q.log_type.as_deref().and_then(log_type_id);

    let rows = sqlx::query(
        r#"SELECT l.id, l.timestamp, l.log_type_id, l.direction_id, l.rule_action_id,
                  l.src_ip::text AS src_ip, l.dst_ip::text AS dst_ip,
                  l.src_port, l.dst_port, l.mac_address::text AS mac_address,
                  l.dns_query, l.dns_type, l.dns_answer, l.dhcp_event, l.wifi_event, l.raw_log,
                  r.name AS rule_name, r.descr AS rule_desc,
                  ii.name AS iface_in, io.name AS iface_out,
                  pr.name AS protocol, dn.name AS hostname
           FROM logs l
           LEFT JOIN rules r ON r.id = l.rule_id
           LEFT JOIN interfaces ii ON ii.id = l.iface_in_id
           LEFT JOIN interfaces io ON io.id = l.iface_out_id
           LEFT JOIN protocols pr ON pr.id = l.protocol_id
           LEFT JOIN device_names dn ON dn.id = l.hostname_id
           WHERE ($1::timestamptz IS NULL OR (l.timestamp, l.id) < ($1, $2))
             AND ($3::smallint IS NULL OR l.log_type_id = $3)
           ORDER BY l.timestamp DESC, l.id DESC
           LIMIT $4"#,
    )
    .bind(cursor.map(|c| c.0)).bind(cursor.map(|c| c.1).unwrap_or(0))
    .bind(type_filter).bind(limit)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    const LOG_TYPES: [&str; 5] = ["firewall", "dns", "dhcp", "wifi", "system"];
    const DIRECTIONS: [&str; 6] = ["inbound", "outbound", "local", "inter_vlan", "vpn", "nat"];
    const ACTIONS: [&str; 3] = ["allow", "block", "redirect"];
    fn name(table: &[&str], id: Option<i16>) -> Option<&'static str> {
        id.and_then(|i| table.get((i as usize).checked_sub(1)?).copied())
    }

    let mut out = Vec::with_capacity(rows.len());
    let mut next_cursor = None;
    for r in &rows {
        let ts: DateTime<Utc> = r.get("timestamp");
        let id: i64 = r.get("id");
        next_cursor = Some(format!("{}:{}", ts.timestamp_micros(), id));
        out.push(json!({
            "id": id,
            "timestamp": ts.to_rfc3339(),
            "log_type": name(&LOG_TYPES, r.get("log_type_id")),
            "direction": name(&DIRECTIONS, r.get("direction_id")),
            "rule_action": name(&ACTIONS, r.get("rule_action_id")),
            "rule_name": r.get::<Option<String>, _>("rule_name"),
            "rule_desc": r.get::<Option<String>, _>("rule_desc"),
            "iface_in": r.get::<Option<String>, _>("iface_in"),
            "iface_out": r.get::<Option<String>, _>("iface_out"),
            "protocol": r.get::<Option<String>, _>("protocol"),
            "hostname": r.get::<Option<String>, _>("hostname"),
            "src_ip": r.get::<Option<String>, _>("src_ip"),
            "dst_ip": r.get::<Option<String>, _>("dst_ip"),
            "src_port": r.get::<Option<i32>, _>("src_port"),
            "dst_port": r.get::<Option<i32>, _>("dst_port"),
            "mac_address": r.get::<Option<String>, _>("mac_address"),
            "dns_query": r.get::<Option<String>, _>("dns_query"),
            "dns_type": r.get::<Option<String>, _>("dns_type"),
            "dns_answer": r.get::<Option<String>, _>("dns_answer"),
            "dhcp_event": r.get::<Option<String>, _>("dhcp_event"),
            "wifi_event": r.get::<Option<String>, _>("wifi_event"),
            "raw_log": r.get::<Option<String>, _>("raw_log"),
        }));
    }
    Json(json!({ "rows": out, "next_cursor": next_cursor }))
}
```

`crates/uip-api/src/lib.rs` (ersetzt Stub):

```rust
pub mod logs;
pub mod stream;
pub mod static_files;

use axum::routing::get;
use axum::Router;
use sqlx::PgPool;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct ApiState {
    pub pool: PgPool,
    pub events: broadcast::Sender<String>,
}

impl axum::extract::FromRef<ApiState> for PgPool {
    fn from_ref(s: &ApiState) -> PgPool { s.pool.clone() }
}
impl axum::extract::FromRef<ApiState> for broadcast::Sender<String> {
    fn from_ref(s: &ApiState) -> broadcast::Sender<String> { s.events.clone() }
}

pub fn router(pool: PgPool, events: broadcast::Sender<String>) -> Router {
    Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/logs", get(logs::get_logs))
        .route("/api/stream", get(stream::sse_stream))
        .fallback(static_files::serve)
        .with_state(ApiState { pool, events })
}
```

(`stream.rs` und `static_files.rs` entstehen in Task 12/14 — für diesen Task Stubs anlegen: `stream.rs` mit einem Handler, der `501` liefert, `static_files.rs` mit einem Handler, der `404` liefert; beide werden in ihren Tasks ersetzt. Stub `stream.rs`:

```rust
use axum::http::StatusCode;
pub async fn sse_stream() -> StatusCode { StatusCode::NOT_IMPLEMENTED }
```

Stub `static_files.rs`:

```rust
use axum::http::StatusCode;
pub async fn serve() -> StatusCode { StatusCode::NOT_FOUND }
```
)

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-api`
Expected: PASS (health + pagination).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): router with cursor-paginated /api/logs"
```

### Task 12: uip-api — SSE /api/stream

Broadcast-Receiver → `Sse`. Client-Filter Phase 1: optional `log_type` als Query-Param, serverseitig auf dem JSON-String geprüft (Zeile enthält `"log_type":"…"`; billiger als Re-Parse, korrekt weil der Writer das Feld immer setzt). Lagged Receiver (Client zu langsam) → Lücke akzeptieren und weiter — der Client sieht die Lücke am `id`-Sprung und kann per `/api/logs` nachladen.

**Files:**
- Modify: `crates/uip-api/src/stream.rs` (Stub ersetzen)

- [ ] **Step 1: Failing Test**

In `stream.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_filter_matches_json_line() {
        let fw = r#"{"timestamp":"t","log_type":"firewall","src_ip":"1.2.3.4"}"#;
        assert!(passes_filter(fw, Some("firewall")));
        assert!(!passes_filter(fw, Some("dns")));
        assert!(passes_filter(fw, None));
    }
}
```

- [ ] **Step 2: FAIL bestätigen**

Run: `cargo test -p uip-api stream`
Expected: FAIL — `passes_filter` fehlt.

- [ ] **Step 3: Implementierung** (ersetzt den Stub komplett)

```rust
use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use serde::Deserialize;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

#[derive(Deserialize)]
pub struct StreamQuery {
    pub log_type: Option<String>,
}

pub fn passes_filter(json_line: &str, log_type: Option<&str>) -> bool {
    match log_type {
        None => true,
        Some(t) => json_line.contains(&format!("\"log_type\":\"{t}\"")),
    }
}

pub async fn sse_stream(
    State(events): State<tokio::sync::broadcast::Sender<String>>,
    Query(q): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(line) if passes_filter(&line, q.log_type.as_deref()) => {
            Some(Ok(Event::default().event("log").data(line)))
        }
        Ok(_) => None,
        Err(BroadcastStreamRecvError::Lagged(n)) => {
            Some(Ok(Event::default().event("lagged").data(n.to_string())))
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
```

- [ ] **Step 4: Tests grün**

Run: `cargo test -p uip-api`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): sse live stream from writer broadcast"
```

---

### Task 13: uip — main-Verdrahtung + Graceful Shutdown

**Files:**
- Modify: `crates/uip/src/main.rs`

- [ ] **Step 1: Implementierung**

```rust
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use uip_core::{Config, LookupCache};
use uip_ingest::firewall::FirewallCtx;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Config::from_env();
    let pool = uip_core::connect(&cfg.database_url).await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;

    let cache = Arc::new(LookupCache::new());
    let (log_tx, log_rx) = tokio::sync::mpsc::channel(8192);
    let (event_tx, _) = tokio::sync::broadcast::channel(1024);

    let writer = tokio::spawn(uip_ingest::writer::run_writer(
        log_rx, pool.clone(), cache, event_tx.clone(),
    ));

    let udp_sock = tokio::net::UdpSocket::bind(&cfg.syslog_addr).await?;
    tracing::info!(addr = %cfg.syslog_addr, "syslog listener up");
    let fw_ctx = FirewallCtx {
        wan_interfaces: cfg.wan_interfaces.clone(),
        wan_ips: Default::default(),
    };
    tokio::spawn(uip_ingest::udp::run_udp(udp_sock, log_tx, fw_ctx));

    let app = uip_api::router(pool, event_tx);
    let listener = tokio::net::TcpListener::bind(&cfg.http_addr).await?;
    tracing::info!(addr = %cfg.http_addr, "http listener up");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;

    // UDP-Task endet mit dem Prozess; der Writer endet, sobald sein Kanal schließt.
    drop(writer);
    Ok(())
}
```

- [ ] **Step 2: End-to-End-Handprobe**

```bash
cargo run -p uip &   # DATABASE_URL via .env; Ports: UIP_SYSLOG_ADDR=0.0.0.0:5514 setzen (514 braucht root)
sleep 2
printf 'Feb  8 16:43:49 UDR kernel: [WAN_IN-D]IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=443' | nc -u -w1 127.0.0.1 5514
sleep 1
curl -s localhost:8080/api/logs | head -c 400
curl -s -N localhost:8080/api/stream &   # zweites Terminal: weitere nc-Zeile → Event erscheint
```

Expected: `/api/logs` liefert die Firewall-Zeile mit `"direction":"inbound"`, `"rule_action":"block"`; SSE-Client zeigt `event: log` beim nächsten Datagramm.

- [ ] **Step 3: Clippy + alle Tests**

Run: `cargo clippy --workspace -- -D warnings && cargo test --workspace`
Expected: sauber.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: wire receiver, writer, api in main"
```

---

### Task 14: SolidJS-Shell mit Live-Stream

Minimal: Vite-Scaffold, eine Tabelle, initiale Ladung via `/api/logs`, danach SSE-Prepend, Cap 500 Zeilen. Kein Router, kein Theming (Phase 3).

**Files:**
- Create: `ui/package.json`, `ui/vite.config.ts`, `ui/tsconfig.json`, `ui/index.html`, `ui/src/index.tsx`, `ui/src/App.tsx`, `ui/src/api.ts`

- [ ] **Step 1: Scaffold**

```bash
cd ui && npm create vite@latest . -- --template solid-ts
npm install
```

`vite.config.ts` um Dev-Proxy ergänzen:

```ts
import { defineConfig } from 'vite';
import solid from 'vite-plugin-solid';

export default defineConfig({
  plugins: [solid()],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
});
```

- [ ] **Step 2: API-Typen + Fetch**

`ui/src/api.ts`:

```ts
export interface LogRow {
  id: number;
  timestamp: string;
  log_type: string | null;
  direction: string | null;
  rule_action: string | null;
  rule_name: string | null;
  iface_in: string | null;
  iface_out: string | null;
  protocol: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  dns_query: string | null;
  dhcp_event: string | null;
  wifi_event: string | null;
  raw_log: string | null;
}

export async function fetchLogs(limit = 100): Promise<LogRow[]> {
  const res = await fetch(`/api/logs?limit=${limit}`);
  const body = await res.json();
  return body.rows as LogRow[];
}
```

- [ ] **Step 3: Live-Tabelle**

`ui/src/App.tsx`:

```tsx
import { createSignal, For, onCleanup, onMount } from 'solid-js';
import { fetchLogs, LogRow } from './api';

const MAX_ROWS = 500;

export default function App() {
  const [rows, setRows] = createSignal<LogRow[]>([]);
  const [paused, setPaused] = createSignal(false);

  onMount(async () => {
    setRows(await fetchLogs());
    const es = new EventSource('/api/stream');
    es.addEventListener('log', (e) => {
      if (paused()) return;
      const row = JSON.parse((e as MessageEvent).data) as LogRow;
      setRows((prev) => [row, ...prev].slice(0, MAX_ROWS));
    });
    onCleanup(() => es.close());
  });

  return (
    <main style={{ 'font-family': 'monospace', padding: '1rem' }}>
      <h1>uip</h1>
      <button onClick={() => setPaused(!paused())}>{paused() ? 'Resume' : 'Pause'}</button>
      <table>
        <thead>
          <tr><th>Zeit</th><th>Typ</th><th>Richtung</th><th>Aktion</th><th>Quelle</th><th>Ziel</th><th>Proto</th><th>Detail</th></tr>
        </thead>
        <tbody>
          <For each={rows()}>{(r) => (
            <tr>
              <td>{new Date(r.timestamp).toLocaleTimeString()}</td>
              <td>{r.log_type}</td>
              <td>{r.direction}</td>
              <td>{r.rule_action}</td>
              <td>{r.src_ip}{r.src_port != null ? `:${r.src_port}` : ''}</td>
              <td>{r.dst_ip}{r.dst_port != null ? `:${r.dst_port}` : ''}</td>
              <td>{r.protocol}</td>
              <td>{r.dns_query ?? r.dhcp_event ?? r.wifi_event ?? r.rule_name ?? r.raw_log}</td>
            </tr>
          )}</For>
        </tbody>
      </table>
    </main>
  );
}
```

- [ ] **Step 4: Handprobe**

Run: Backend läuft (Task 13), dann `cd ui && npm run dev`, Browser `http://localhost:5173`, per `nc` Zeilen einspeisen.
Expected: Zeilen erscheinen live oben in der Tabelle; Pause hält den Stream an. Danach `npm run build` → `ui/dist/` entsteht.

- [ ] **Step 5: Commit**

```bash
git add ui && git commit -m "feat(ui): solidjs shell with sse live table"
```

---

### Task 15: Frontend ins Binary einbetten

**Files:**
- Modify: `crates/uip-api/src/static_files.rs` (Stub ersetzen), `crates/uip-api/Cargo.toml`

- [ ] **Step 1: Implementierung**

`static_files.rs`:

```rust
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../ui/dist/"]
struct Assets;

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path).or_else(|| Assets::get("index.html")) {
        Some(f) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], f.data).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
```

Build-Reihenfolge dokumentieren (README-Abschnitt "Build"): erst `cd ui && npm run build`, dann `cargo build --release`. CI: `ui`-Build-Step vor `cargo build` einfügen (`actions/setup-node@v4`, `npm ci && npm run build` in `ui/`). Damit `cargo test` ohne UI-Build läuft: in `ci.yml` den UI-Step VOR die Cargo-Steps setzen.

- [ ] **Step 2: Verifizieren**

Run: `cd ui && npm run build && cd .. && cargo run -p uip` → Browser `http://localhost:8080/`
Expected: Live-Tabelle wird vom Rust-Binary ausgeliefert, SSE läuft ohne Vite-Proxy.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat(api): embed built frontend via rust-embed"
```

### Task 16: LXC-Installer v0

Community-Script-Pattern: `proxmox-lxc.sh` läuft auf dem Proxmox-Host, erzeugt Debian-13-LXC, kopiert `install.sh` hinein und führt es aus. `install.sh` ist idempotent. v0 baut aus dem Git-Checkout (Release-Downloads kommen, wenn es Releases gibt).

**Files:**
- Create: `lxc/proxmox-lxc.sh`, `lxc/install.sh`, `lxc/update.sh`, `lxc/systemd/uip.service`

- [ ] **Step 1: systemd-Unit**

`lxc/systemd/uip.service`:

```ini
[Unit]
Description=uip - UniFi log insight (rust)
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=uip
EnvironmentFile=/etc/uip/uip.env
ExecStart=/usr/local/bin/uip
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/uip

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: install.sh**

`lxc/install.sh`:

```bash
#!/usr/bin/env bash
# uip installer v0 — läuft IM Debian-13-LXC als root.
set -euo pipefail

REPO_URL="${UIP_REPO_URL:-https://github.com/waytoabv/uip-rs.git}"
BRANCH="${UIP_BRANCH:-main}"
DB_NAME=uip
DB_USER=uip
SRC_DIR=/opt/uip-src

msg() { echo -e "\e[1;32m==>\e[0m $*"; }

msg "Pakete"
apt-get update -qq
apt-get install -y -qq curl git build-essential pkg-config libssl-dev \
  postgresql-common gnupg ca-certificates >/dev/null

msg "PostgreSQL 17 + TimescaleDB Repos"
/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y >/dev/null
curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey \
  | gpg --dearmor -o /usr/share/keyrings/timescaledb.gpg
echo "deb [signed-by=/usr/share/keyrings/timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/debian/ $(. /etc/os-release; echo "$VERSION_CODENAME") main" \
  > /etc/apt/sources.list.d/timescaledb.list
apt-get update -qq
apt-get install -y -qq postgresql-17 timescaledb-2-postgresql-17 >/dev/null
timescaledb-tune --quiet --yes >/dev/null
systemctl restart postgresql

msg "Datenbank"
DB_PASS=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}'"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 \
  || sudo -u postgres createdb -O "${DB_USER}" -E UTF8 "${DB_NAME}"
sudo -u postgres psql -d "${DB_NAME}" -c "CREATE EXTENSION IF NOT EXISTS timescaledb"

msg "Rust-Toolchain"
command -v cargo >/dev/null || {
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
  source "$HOME/.cargo/env"
}

msg "Node (Frontend-Build)"
command -v node >/dev/null || {
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
  apt-get install -y -qq nodejs >/dev/null
}

msg "Quellcode + Build"
if [ -d "${SRC_DIR}/.git" ]; then
  git -C "${SRC_DIR}" fetch -q && git -C "${SRC_DIR}" checkout -q "${BRANCH}" && git -C "${SRC_DIR}" pull -q
else
  git clone -q --branch "${BRANCH}" "${REPO_URL}" "${SRC_DIR}"
fi
(cd "${SRC_DIR}/ui" && npm ci --silent && npm run build --silent)
(cd "${SRC_DIR}" && "$HOME/.cargo/bin/cargo" build --release -p uip)
install -m 755 "${SRC_DIR}/target/release/uip" /usr/local/bin/uip

msg "Service"
id -u uip >/dev/null 2>&1 || useradd --system --home /var/lib/uip --create-home --shell /usr/sbin/nologin uip
mkdir -p /etc/uip
if [ ! -f /etc/uip/uip.env ]; then
  cat > /etc/uip/uip.env <<EOF
UIP_DB_URL=postgres://${DB_USER}:${DB_PASS}@127.0.0.1/${DB_NAME}
UIP_HTTP_ADDR=0.0.0.0:8080
UIP_SYSLOG_ADDR=0.0.0.0:514
UIP_WAN_IFACES=ppp0
TZ=$(cat /etc/timezone 2>/dev/null || echo UTC)
EOF
  chmod 600 /etc/uip/uip.env
fi
install -m 644 "${SRC_DIR}/lxc/systemd/uip.service" /etc/systemd/system/uip.service
systemctl daemon-reload
systemctl enable --now uip

msg "Fertig: http://$(hostname -I | awk '{print $1}'):8080 — Syslog auf UDP 514"
```

- [ ] **Step 3: proxmox-lxc.sh**

`lxc/proxmox-lxc.sh`:

```bash
#!/usr/bin/env bash
# Läuft auf dem PROXMOX-HOST: bash -c "$(wget -qLO - https://raw.githubusercontent.com/waytoabv/uip-rs/main/lxc/proxmox-lxc.sh)"
set -euo pipefail

CTID="${CTID:-$(pvesh get /cluster/nextid)}"
HOSTNAME="${HOSTNAME_CT:-uip}"
STORAGE="${STORAGE:-local-lvm}"
DISK_GB="${DISK_GB:-10}"
MEMORY="${MEMORY:-2048}"
CORES="${CORES:-2}"
BRIDGE="${BRIDGE:-vmbr0}"
RAW_BASE="${UIP_RAW_BASE:-https://raw.githubusercontent.com/waytoabv/uip-rs/main}"

TEMPLATE=$(pveam available --section system | awk '/debian-13-standard/ {print $2}' | sort -V | tail -1)
[ -n "$TEMPLATE" ] || { echo "Kein Debian-13-Template gefunden (pveam update ausführen)"; exit 1; }
pveam list local | grep -q "$TEMPLATE" || pveam download local "$TEMPLATE"

echo "==> Erzeuge LXC ${CTID} (${HOSTNAME})"
pct create "$CTID" "local:vztmpl/${TEMPLATE}" \
  --hostname "$HOSTNAME" --cores "$CORES" --memory "$MEMORY" \
  --rootfs "${STORAGE}:${DISK_GB}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
  --features nesting=1 --unprivileged 1 --onboot 1
pct start "$CTID"
sleep 5

echo "==> Installiere uip im Container"
pct exec "$CTID" -- bash -c "curl -fsSL ${RAW_BASE}/lxc/install.sh -o /root/install.sh && bash /root/install.sh"

IP=$(pct exec "$CTID" -- hostname -I | awk '{print $1}')
echo "==> Fertig. UI: http://${IP}:8080 — Gateway-Syslog auf ${IP}:514 richten."
```

- [ ] **Step 4: update.sh**

`lxc/update.sh`:

```bash
#!/usr/bin/env bash
# Läuft IM Container: aktualisiert Quellcode, baut neu, tauscht Binary. Migrationen laufen beim Start.
set -euo pipefail
SRC_DIR=/opt/uip-src
git -C "${SRC_DIR}" pull -q
(cd "${SRC_DIR}/ui" && npm ci --silent && npm run build --silent)
(cd "${SRC_DIR}" && "$HOME/.cargo/bin/cargo" build --release -p uip)
systemctl stop uip
install -m 755 "${SRC_DIR}/target/release/uip" /usr/local/bin/uip
systemctl start uip
echo "uip aktualisiert: $(git -C "${SRC_DIR}" rev-parse --short HEAD)"
```

- [ ] **Step 5: Syntax-Check + ausführbar machen**

Run: `bash -n lxc/install.sh && bash -n lxc/proxmox-lxc.sh && bash -n lxc/update.sh && chmod +x lxc/*.sh`
Expected: keine Ausgabe (Syntax ok).

- [ ] **Step 6: Commit**

```bash
git add lxc && git commit -m "feat(lxc): installer v0 with proxmox create script"
```

---

## Abschluss Phase 1

- [ ] `cargo test --workspace && cargo clippy --workspace -- -D warnings` — alles grün
- [ ] Handprobe Task 13/14 wiederholt mit eingebettetem Frontend
- [ ] README: Build-Abschnitt (ui build → cargo build) + LXC-Install-Einzeiler ergänzen, committen
- [ ] Push; danach superpowers:finishing-a-development-branch

**Bewusst NICHT in Phase 1** (steht in der Spec, kommt später): Enrichment-Worker (Phase 2 liest `enrich_status=0`), volle Filter/Suche, Dashboard, Threat Map, Flow View, UniFi/Pi-hole-Integration, MCP, Auth, Setup-Wizard, Retention-Konfiguration über UI (Timescale-Default 60 Tage steht in der Migration).

