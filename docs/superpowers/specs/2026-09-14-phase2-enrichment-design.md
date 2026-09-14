# Phase 2 — Enrichment (Design)

**Datum:** 2026-09-14
**Status:** Entwurf
**Vorgänger:** [Phase 1](2026-09-13-uip-rs-rewrite-design.md) — Ingest-Pipeline, API, Live-Stream, LXC-Installer

## Ziel

Rohe Log-Zeilen liegen bereits in der Hypertable und tragen
`enrich_status = 0`. Phase 2 baut den Worker, der sie asynchron anreichert:
GeoIP (Land, Stadt, Koordinaten), ASN, Reverse DNS und Threat-Score aus
AbuseIPDB. Ingest-Latenz bleibt davon unberührt — der Writer wartet nie auf
eine externe API.

## Leitgedanke

Die Log-Tabelle ist die Queue (so in Phase 1 entschieden). Der Worker nimmt
Zeilen in Batches an, arbeitet außerhalb jeder offenen Transaktion und
schreibt das Ergebnis zurück. Ein Absturz kostet höchstens einen Batch, nie
eine Zeile.

## 1. Zustandsmodell

`logs.enrich_status` bekommt eine vierte Ausprägung:

| Wert | Bedeutung |
|---|---|
| 0 | pending — wartet auf den Worker |
| 1 | done — fertig angereichert (oder nichts anzureichern) |
| 2 | failed — dauerhaft gescheitert, wird nicht erneut versucht |
| 3 | in progress — ein Worker hat die Zeile übernommen |

**Claim ohne gehaltene Sperre.** Ein `SELECT … FOR UPDATE SKIP LOCKED`, das
über die externen API-Aufrufe offen bleibt, hielte eine Transaktion
sekundenlang offen und blockierte Autovacuum. Stattdessen zwei Schritte:

```sql
UPDATE logs SET enrich_status = 3
WHERE (timestamp, id) IN (
    SELECT timestamp, id FROM logs
    WHERE enrich_status = 0
    ORDER BY timestamp DESC
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
RETURNING …;
```

Das committet sofort. Die langsame Arbeit passiert danach, der Rückschreibvorgang
ist ein zweites, kurzes `UPDATE`.

**Verwaiste Claims.** Stürzt der Prozess zwischen Claim und Rückschreiben ab,
bleiben Zeilen auf 3 stehen. Beim Start setzt der Worker deshalb einmal alles
von 3 auf 0 zurück. Das setzt genau einen schreibenden Prozess voraus — was
für das LXC-Deployment gilt und hier dokumentiert, nicht erzwungen wird.

**Wecker.** Der Batch-Writer aus Phase 1 signalisiert nach jedem Flush über
ein `tokio::sync::Notify`. Der Worker wartet auf das Notify *oder* einen
Timer (2 s), je nachdem was zuerst kommt; der Timer allein deckt Backfill und
verpasste Signale ab.

## 2. Was überhaupt angereichert wird

Nicht jede Zeile hat eine anreicherbare Adresse. Der Worker bestimmt pro Zeile
eine **Remote-IP**:

- Firewall: bei `inbound` die Quelle, bei `outbound` das Ziel, sonst die erste
  öffentliche der beiden.
- DNS: die Quelle nur, wenn sie öffentlich ist (meist nicht) — DNS-Zeilen
  bleiben daher fast immer ohne Anreicherung.
- DHCP/WiFi/System: keine.

Ausgeschlossen sind private, Loopback-, Link-local-, Multicast- und
Broadcast-Adressen sowie die eigenen WAN-IPs und Gateway-Adressen aus
`system_config`. Findet sich keine Remote-IP, geht die Zeile direkt auf
`enrich_status = 1` — sie ist fertig, es gab nur nichts zu tun.

Innerhalb eines Batches werden Adressen dedupliziert: 200 Zeilen mit derselben
Angreifer-IP kosten einen Lookup, nicht zweihundert.

## 3. Die drei Quellen

Jede implementiert dasselbe Interface, damit der Worker gegen Fakes getestet
werden kann und eine fehlende Konfiguration nur diese eine Quelle abschaltet.

### GeoIP und ASN (MaxMind, lokal)

Zwei mmdb-Dateien (`GeoLite2-City`, `GeoLite2-ASN`) unter
`/var/lib/uip/geoip/`. Kein Netzwerk im Anfragepfad, also für jede öffentliche
IP. Liefert Land, Stadt, Koordinaten, AS-Nummer und AS-Name.

**Hot-Reload ohne Signal.** Ein Timer prüft alle fünf Minuten die mtime der
Dateien; ändert sie sich, wird neu geladen und der `ArcSwap` getauscht. Der
Fork brauchte dafür SIGUSR1-Plumbing zwischen Update-Skript und Prozess — die
mtime-Prüfung kommt ohne aus und funktioniert auch, wenn jemand die Dateien
von Hand tauscht.

### Reverse DNS

`hickory-resolver` gegen die System-Resolver. PTR-Lookups sind langsam und oft
erfolglos, deshalb: 24-Stunden-TTL-Cache im Speicher, 2 s Timeout, und ein
Fehlschlag ist kein Zeilenfehler, sondern einfach kein rDNS. Abschaltbar über
`UIP_RDNS_ENABLED=false`.

### AbuseIPDB

Nur für **blockierte Firewall-Zeilen**. Das ist die Regel des Forks und sie
ist richtig: das kostenlose Kontingent liegt bei 1000 Abfragen pro Tag, und
erlaubter Traffic braucht keinen Threat-Score.

- Persistenter Cache in `ip_enrichment`; ein Treffer jünger als vier Tage
  wird nicht erneut abgefragt.
- Das Kontingent kommt aus den Response-Headern (`X-RateLimit-Remaining`,
  `X-RateLimit-Reset`) und wird in `system_config` gehalten, überlebt also
  Neustarts.
- Auf `429` pausiert der Client bis zum Reset-Zeitpunkt. Zeilen bleiben dabei
  auf `pending` statt auf `failed` zu laufen — das Kontingent kommt zurück,
  der Score kann nachgereicht werden.
- Ohne API-Key ist die Quelle schlicht aus; alles andere reichert weiter an.

## 4. Fehler und Wiederholung

Ein Fehlschlag einer einzelnen Quelle ist kein Zeilenfehler: die Zeile wird mit
dem geschrieben, was da ist, und gilt als `done`. `failed` (2) bekommt nur, wem
der Rückschreibvorgang selbst nicht gelingt — und der Worker protokolliert das
mit der Zeilen-Id.

Ausnahme ist das AbuseIPDB-Kontingent: erschöpft es sich mitten im Batch, gehen
die betroffenen Zeilen zurück auf `pending`, nicht auf `done`. Sonst bliebe der
Score dauerhaft leer.

## 5. Schema-Änderungen (Migration 0002)

```sql
CREATE TABLE ip_enrichment (
    ip                   INET PRIMARY KEY,
    geo_country          VARCHAR(2),
    geo_city             VARCHAR(100),
    geo_lat              DECIMAL(9,6),
    geo_lon              DECIMAL(9,6),
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
```

Die Tabelle ist Cache *und* Wahrheit für IP-Fakten. `logs` behält seine
denormalisierten Spalten (Phase 1 hat sie bereits angelegt), weil die
Dashboard-Aggregate aus Phase 3 sonst bei jeder Abfrage joinen müssten — und
weil ein Land, das zum Zeitpunkt des Logs galt, historisch korrekt bleibt,
auch wenn die IP später jemand anderem gehört.

`logs` bekommt zusätzlich die in Phase 1 noch fehlenden AbuseIPDB-Spalten
(`threat_categories`, `abuse_total_reports`, `abuse_last_reported`,
`abuse_is_tor`, `abuse_usage_type`) sowie einen Index auf `threat_score`.

## 6. Konfiguration

Alles über `system_config` (JSONB), mit Env-Overrides für den Erststart:

| Schlüssel | Env | Default |
|---|---|---|
| `wan_ips` | `UIP_WAN_IPS` | leer |
| `gateway_ips` | — | leer |
| `rdns_enabled` | `UIP_RDNS_ENABLED` | true |
| `abuseipdb_api_key` | `UIP_ABUSEIPDB_KEY` | leer (= aus) |
| `geoip_dir` | `UIP_GEOIP_DIR` | `/var/lib/uip/geoip` |

Die WAN-IPs fließen außerdem in den `FirewallCtx` des Parsers zurück, der sie
in Phase 1 nur als leere Menge bekommen hat. Damit funktioniert die
Multi-WAN-Richtungserkennung zum ersten Mal vollständig.

## 7. LXC

`geoipupdate` wird mitinstalliert, `/etc/GeoIP.conf` aus Account-ID und
Lizenzschlüssel erzeugt (beim Install abgefragt oder per Env vorgegeben), und
ein systemd-Timer läuft wöchentlich. Der Worker merkt die neuen Dateien über
die mtime-Prüfung von selbst.

## 8. Tests

- Worker-Mechanik gegen **Fake-Enricher**: Claim, Dedup, Rückschreiben,
  Startup-Reset, „nichts anzureichern" — alles ohne Netz, gegen eine echte
  Wegwerf-DB via `#[sqlx::test]`.
- Remote-IP-Auswahl und Ausschlusslisten als reine Funktionstests.
- GeoIP gegen die offiziellen MaxMind-Testdatenbanken (MIT-lizenziert,
  in `crates/uip-enrich/tests/data/` abgelegt). Fehlen sie, überspringt der
  Test sich selbst statt fehlzuschlagen.
- AbuseIPDB-Client gegen einen lokalen HTTP-Stub: Header-Auswertung,
  429-Pause, Cache-Treffer.
- Kein Test ruft je eine echte externe API.

## 9. Bewusst nicht in Phase 2

Blacklist-Vorbefüllung und aktiver Backfill älterer Zeilen (beides setzt nur
`enrich_status` zurück und läuft dann durch denselben Worker — es ist eine
Frage der Bedienoberfläche, nicht der Mechanik), Pi-hole, UniFi-Integration,
Dashboard-Aggregate.
