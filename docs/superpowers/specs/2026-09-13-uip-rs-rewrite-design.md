# uip-rs — Kompletter Rewrite von UniFi Insights Plus (Design)

**Datum:** 2026-09-13
**Status:** Abgenommen
**Vorlage:** [jmasarweh/UniFi-Insights-Plus](https://github.com/jmasarweh/UniFi-Insights-Plus) bzw. der eigene Fork [waytoabv/UniFi-Insights-Plus](https://github.com/waytoabv/UniFi-Insights-Plus)

## Ziel

Vollständiger Neuaufbau der UniFi-Syslog-Analyse-Anwendung als natives
LXC-Deployment ohne Docker. Volle Feature-Parität zum Fork, erreicht in
sequenziellen Phasen. Frischer Start: keine Datenmigration aus der
Python/Postgres-Installation; Settings werden manuell neu gesetzt.

## Entscheidungen

| Achse | Entscheidung |
|---|---|
| Sprache/Runtime | Alles Rust, **ein Binary** (`uip`), tokio |
| Receiver | UDP-514-Task, handgeschriebene State-Machine-Parser pro Log-Format, kein Regex |
| Enrichment | Asynchron entkoppelt; **Log-Tabelle ist die Queue** (`enrich_status='pending'` + `FOR UPDATE SKIP LOCKED`, tokio::Notify als Wecker) |
| Datenbank | PostgreSQL 17 + **TimescaleDB** (Hypertable, Compression, Retention-Policy) |
| API | axum im selben Binary, REST + **SSE** Live-Stream, Frontend embedded |
| Frontend | **SolidJS** + Vite + TypeScript |
| Deployment | Proxmox-LXC, Community-Script-Pattern, systemd, kein Docker |
| Repo | `github.com/waytoabv/uip-rs`, privat; Lizenzfrage offen dokumentiert (Original ist BSL 1.1 seit v3.2.0, davor MIT) |
| Migration | Keine — Logs laufen per Retention aus, Neuinstallation startet leer |

## 1. Architektur

Ein Rust-Binary, tokio-Runtime, drei logische Ebenen als Tasks — plus
PostgreSQL+TimescaleDB im selben LXC:

```
UDP 514 ──▶ receiver task ──▶ parser (state machine pro Format) ──▶ batch writer ──▶ TimescaleDB
                                                                        │ (INSERT, enrich_status='pending', Notify)
                                                                        ▼
                                    enrichment workers ◀── SKIP-LOCKED-Batches + tokio::Notify
                                    (MaxMind lokal, rDNS, AbuseIPDB)

axum ──▶ REST /api/* + SSE /api/stream + statisches SolidJS-Bundle
```

Cargo-Workspace, Crates nach Verantwortung:

| Crate | Zweck |
|---|---|
| `uip-core` | Gemeinsame Typen, Config, DB-Pool (sqlx) |
| `uip-ingest` | UDP-Receiver, Parser, Batch-Writer |
| `uip-enrich` | Enrichment-Worker, MaxMind/rDNS/AbuseIPDB-Clients |
| `uip-api` | axum-Routen, SSE, embedded Frontend |
| `uip` | main: verdrahtet Tasks, Graceful Shutdown |

Parser: kein Regex. Handgeschriebene State Machines pro Log-Format
(Firewall/iptables, DHCP, Wi-Fi/hostapd, DNS, System), `nom` nur wo es
sich anbietet. Jeder Parser ist eine pure Funktion `&[u8] →
Option<ParsedLog>` mit tabellengetriebenen Tests aus echten Log-Zeilen
(Fixtures aus dem Fork-Testbestand übernehmen).

Enrichment entkoppelt: Raw-Log landet sofort in der DB. Worker holt
Batches, dedupliziert IPs, füllt GeoIP/ASN/rDNS/Threat-Score nach.
Restart-sicher; Backfill = Status zurücksetzen, gleicher Codepfad.

## 2. Datenbank

- PostgreSQL 17 + TimescaleDB. `logs` als Hypertable (Chunk-Intervall
  1 Tag), Compression nach 7 Tagen, Retention über Timescale-Policies
  statt Cleanup-Cron (konfigurierbar pro Log-Typ, Default 60 Tage,
  DNS 10 Tage).
- Normalisiertes Schema wie im Fork-Redesign: Lookup-Tabellen für
  Interfaces, Services, Länder, ASN, Rule-Namen. Konzept übernehmen,
  DDL neu schreiben.
- `settings`, `wan_mappings`, `interface_labels`, `vpn_interfaces`,
  `ip_enrichment`-Cache als normale Tabellen.
- sqlx mit compile-time-geprüften Queries; Migrationen via `sqlx migrate`.

## 3. API + Live-Stream

- axum, REST-Endpunkte analog zum Fork: `/api/logs` (cursor-basiert),
  `/api/dashboard/*`, `/api/settings`, ….
- SSE `/api/stream`: Broadcast-Channel vom Batch-Writer, serverseitig
  gefiltert nach den Query-Parametern der jeweiligen Verbindung.
  Reconnect mit `Last-Event-ID` → Lücke wird per Cursor-Query gefüllt.
- Statisches Frontend direkt aus dem Binary (`rust-embed` o.ä.) — ein
  Artefakt, kein nginx.

## 4. Frontend

- SolidJS + Vite + TypeScript. Feature-Parität zum Fork-UI:
  Live-Stream-Tabelle (fine-grained Row-Updates, kein VDOM-Diffing),
  Filter-Panel + typaware Suche, Dashboard, Threat Map, Flow View
  (Sankey + Zone Matrix), Settings, Dark/Light-Theming.
- Charts/Map: framework-agnostische Libs des Forks weiterverwenden
  (Leaflet/d3), sonst Solid-nativer Ersatz.

## 5. LXC-Deployment

- Community-Script-Pattern wie im Fork: `proxmox-lxc.sh` auf dem
  Proxmox-Host (`bash -c "$(wget -qLO - …)"`) erzeugt Debian-13-LXC und
  ruft darin `install.sh` auf: PostgreSQL+TimescaleDB aus Paketquellen,
  `uip`-Binary (Release-Download oder lokaler Build), systemd-Unit,
  geoip-Refresh-Timer.
- Update-Script tauscht nur das Binary und führt `sqlx migrate run` aus.
- Kein Docker, nirgends.

## 6. Phasen

Jede Phase durchläuft ihren eigenen Spec→Plan→Implementierung-Zyklus.

1. **Fundament** — Repo, Workspace, Schema+Migrationen, Receiver +
   Parser + Batch-Writer, Minimal-API (`/api/logs`, SSE), SolidJS-Shell
   mit Live-Stream, LXC-Installer v0. Ab hier produktiv nutzbar.
2. **Enrichment** — Worker-Queue, MaxMind GeoIP/ASN (Auto-Update +
   Hot-Reload), rDNS, AbuseIPDB (Score, Blacklist-Seed, Backfill),
   Direction-/VPN-Klassifikation, Multi-WAN-Mapping.
3. **UI-Parität** — volle Filter/Suche, Dashboard-Aggregate, Threat
   Map, Flow View, Theming, CSV-Export.
4. **Integrationen** — UniFi API (Discovery, Device-Namen, Firewall
   Syslog Manager), Pi-hole, Setup-Wizard.
5. **Extras** — MCP-Server, Backup/Restore, Retention-Settings,
   Update-Tooling, Docs; Browser-Extension prüfen (evtl. reicht
   API-Anpassung statt Rewrite).

## 7. Fehlerbehandlung & Tests

- Unparsebares Log → `raw`-Spalte + Typ `parse_failed`, nie verwerfen.
- Externe APIs: Timeout, Retry mit Backoff, Circuit Breaker.
  Enrichment-Fehler markiert Zeile `failed`; periodischer Retry-Sweep.
- Tests: Parser-Corpus (Fixtures aus dem Fork), sqlx-Tests gegen
  Wegwerf-DB, API-Integrationstests, Vitest fürs Frontend.
- CI via GitHub Actions.

## 8. Lizenz & Attribution

Original war MIT, ist seit v3.2.0 BSL 1.1 (Licensor: Jamil Masarweh /
PREVIZIA UK LTD, Change License Apache 2.0 nach vier Jahren). Der Fork
enthält BSL-Code. uip-rs ist ein Rewrite ohne Code-Übernahme; Schema-
und Parsing-*Konzepte* dienen als Vorlage. Repo bleibt privat, README
verweist aufs Original, es wird keine eigene Lizenz behauptet, bis die
Frage geklärt ist.
