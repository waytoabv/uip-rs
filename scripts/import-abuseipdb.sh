#!/usr/bin/env bash
# Übernimmt die AbuseIPDB-Ergebnisse einer UniFi-Insights-Plus-Instanz.
#
# Die Auskünfte sind bezahlt — mit Kontingent, nicht mit Geld, aber tausend
# Abfragen am Tag sind schnell aufgebraucht. Was dort schon nachgeschlagen
# wurde, muss hier nicht noch einmal gefragt werden.
#
# Läuft auf dem uip-Container und braucht nichts außer `psql`, das die
# PostgreSQL-Installation ohnehin mitbringt.
set -euo pipefail

usage() {
  cat <<'TXT'
Übernimmt AbuseIPDB-Ergebnisse aus einer Fork-Instanz in diese Datenbank.

  import-abuseipdb.sh --from-dsn <postgres://…>  [Optionen]
  import-abuseipdb.sh --from-csv <datei.csv>     [Optionen]

Quelle (eine von beiden):
  --from-dsn <dsn>   Die Datenbank der alten Instanz, direkt erreichbar.
  --from-csv <datei> Ein Auszug, der dort erzeugt wurde — siehe unten.

Optionen:
  --to-dsn <dsn>     Zieldatenbank. Vorgabe: UIP_DB_URL aus /etc/uip/uip.env.
  --backfill-logs    Trägt die Werte zusätzlich in bereits gespeicherte
                     Log-Zeilen ein, die noch keinen Score haben — nur für die
                     mitgebrachten Adressen. Sucht im ganzen Bestand und
                     dauert entsprechend.
  --dry-run          Zeigt, was käme, und schreibt nichts.
  -h, --help         Dieser Text.

Steht die alte Datenbank in einem Docker-Container und ist ihr Port nicht nach
außen gelegt, ist der CSV-Weg der einfachere. Auf dem alten Host:

  docker exec -i <container> psql -U unifi -d unifi_logs --csv \
    -c "SELECT ip, threat_score, threat_categories, abuse_total_reports,
               abuse_last_reported, abuse_is_tor, abuse_usage_type,
               looked_up_at AS abuse_looked_up_at
        FROM ip_threats" > abuse.csv

Die Datei dann hierher kopieren und mit --from-csv übergeben.

Zweimal ausgeführt ändert sich nichts: übernommen wird nur, was hier fehlt
oder älter ist als der mitgebrachte Stand.
TXT
}

FROM_DSN=""
FROM_CSV=""
TO_DSN=""
BACKFILL=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
  --from-dsn) FROM_DSN="${2:?--from-dsn braucht eine Adresse}"; shift 2 ;;
  --from-csv) FROM_CSV="${2:?--from-csv braucht eine Datei}"; shift 2 ;;
  --to-dsn) TO_DSN="${2:?--to-dsn braucht eine Adresse}"; shift 2 ;;
  --backfill-logs) BACKFILL=1; shift ;;
  --dry-run) DRY_RUN=1; shift ;;
  -h | --help) usage; exit 0 ;;
  *) echo "Unbekannte Option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n "$FROM_DSN" && -n "$FROM_CSV" ]] || [[ -z "$FROM_DSN" && -z "$FROM_CSV" ]]; then
  echo "Genau eine Quelle angeben: --from-dsn oder --from-csv." >&2
  exit 2
fi

# Das Ziel steht in der Umgebungsdatei des Dienstes, wenn es nicht genannt wird.
if [[ -z "$TO_DSN" && -r /etc/uip/uip.env ]]; then
  TO_DSN="$(sed -n 's/^UIP_DB_URL=//p' /etc/uip/uip.env | head -1)"
fi
if [[ -z "$TO_DSN" ]]; then
  echo "Keine Zieldatenbank: --to-dsn angeben oder UIP_DB_URL in /etc/uip/uip.env hinterlegen." >&2
  exit 2
fi

command -v psql >/dev/null || { echo "psql fehlt." >&2; exit 1; }

msg() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }

# ── Quelle einlesen ─────────────────────────────────────────────────────────
CSV="$(mktemp)"
trap 'rm -f "$CSV"' EXIT

if [[ -n "$FROM_DSN" ]]; then
  msg "Lese aus der alten Datenbank"
  # Die Fork-Tabelle heißt ip_threats und nennt den Zeitpunkt looked_up_at.
  # `abuse_hostnames` und `abuse_is_whitelisted` gibt es hier nicht — sie
  # bleiben zurück, weil es keine Spalte gäbe, in die sie gehörten.
  psql "$FROM_DSN" --csv -c "
    SELECT ip, threat_score, threat_categories, abuse_total_reports,
           abuse_last_reported, abuse_is_tor, abuse_usage_type,
           looked_up_at AS abuse_looked_up_at
    FROM ip_threats
    ORDER BY ip" >"$CSV"
else
  [[ -r "$FROM_CSV" ]] || { echo "Datei nicht lesbar: $FROM_CSV" >&2; exit 1; }
  cp "$FROM_CSV" "$CSV"
fi

ROWS=$(($(wc -l <"$CSV") - 1)) # ohne Kopfzeile
if ((ROWS <= 0)); then
  warn "Nichts zu übernehmen — die Quelle ist leer."
  exit 0
fi
msg "${ROWS} Einträge gelesen"

if ((DRY_RUN)); then
  msg "Probelauf — es wird nichts geschrieben. Die ersten Zeilen:"
  head -4 "$CSV"
  exit 0
fi

# ── Ins Ziel schreiben ──────────────────────────────────────────────────────
# Erst in eine Sitzungstabelle, dann ein einziges UPSERT: so bleibt es eine
# Transaktion, und ein Fehler mittendrin hinterlässt keinen halben Import.
# Der Nachtrag in die Log-Zeilen hängt an derselben Sitzung — nur dort steht
# noch, welche Adressen mitgebracht wurden, und genau darauf soll er sich
# beschränken: wer vier Einträge mitbringt, erwartet keine Änderung an
# dreitausend Zeilen, nur weil der Cache noch anderes kennt.
BACKFILL_SQL=""
if ((BACKFILL)); then
  BACKFILL_SQL="
UPDATE logs l SET
    threat_score        = e.threat_score,
    threat_categories   = e.threat_categories,
    abuse_total_reports = e.abuse_total_reports,
    abuse_last_reported = e.abuse_last_reported,
    abuse_is_tor        = e.abuse_is_tor,
    abuse_usage_type    = e.abuse_usage_type
FROM ip_enrichment e
JOIN incoming i ON i.ip = e.ip
WHERE l.log_type_id = 1
  AND l.threat_score IS NULL
  AND e.threat_score IS NOT NULL
  AND (l.src_ip = e.ip OR l.dst_ip = e.ip);"
  msg "Trage die Werte auch in gespeicherte Log-Zeilen ein (das dauert)"
fi

msg "Schreibe nach ip_enrichment"
psql "$TO_DSN" -v ON_ERROR_STOP=1 <<SQL
BEGIN;

CREATE TEMP TABLE incoming (
    ip                   INET PRIMARY KEY,
    threat_score         INTEGER,
    threat_categories    TEXT[],
    abuse_total_reports  INTEGER,
    abuse_last_reported  TIMESTAMPTZ,
    abuse_is_tor         BOOLEAN,
    abuse_usage_type     TEXT,
    abuse_looked_up_at   TIMESTAMPTZ
) ON COMMIT DROP;

\copy incoming FROM '$CSV' CSV HEADER

INSERT INTO ip_enrichment (
    ip, threat_score, threat_categories, abuse_total_reports,
    abuse_last_reported, abuse_is_tor, abuse_usage_type, abuse_looked_up_at)
SELECT ip, threat_score, threat_categories, abuse_total_reports,
       abuse_last_reported, abuse_is_tor, abuse_usage_type,
       COALESCE(abuse_looked_up_at, NOW())
FROM incoming
ON CONFLICT (ip) DO UPDATE SET
    threat_score        = EXCLUDED.threat_score,
    threat_categories   = EXCLUDED.threat_categories,
    abuse_total_reports = EXCLUDED.abuse_total_reports,
    abuse_last_reported = EXCLUDED.abuse_last_reported,
    abuse_is_tor        = EXCLUDED.abuse_is_tor,
    abuse_usage_type    = EXCLUDED.abuse_usage_type,
    abuse_looked_up_at  = EXCLUDED.abuse_looked_up_at
-- Was hier schon steht und neuer ist, bleibt: ein Import darf eine frische
-- Auskunft nicht durch eine alte ersetzen.
WHERE ip_enrichment.abuse_looked_up_at IS NULL
   OR EXCLUDED.abuse_looked_up_at > ip_enrichment.abuse_looked_up_at;

${BACKFILL_SQL}

COMMIT;
SQL

TOTAL=$(psql "$TO_DSN" -tAc "SELECT count(*) FROM ip_enrichment WHERE threat_score IS NOT NULL")
msg "Fertig — ${TOTAL} Adressen mit Score in ip_enrichment"
