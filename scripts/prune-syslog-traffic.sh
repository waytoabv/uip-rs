#!/usr/bin/env bash
# Wirft die Firewall-Zeilen über den eigenen Syslog-Weg aus der Datenbank.
#
# Der Empfänger verwirft sie seit dem Umbau schon beim Schreiben, aber was
# davor hereinkam, liegt noch da — bei einem Gateway, das jede Entscheidung
# meldet, sind das schnell Millionen Zeilen, die nur eines sagen: dass die
# Verbindung steht.
#
# Angewandt wird dieselbe Regel wie zur Laufzeit (`Collector::is_own_syslog`
# in crates/uip-ingest/src/collector.rs): nur Firewall-Zeilen, nur der
# Syslog-Port, und nur wenn eine der beiden Seiten dieser Empfänger ist.
# Syslog zwischen zwei anderen Rechnern bleibt liegen — das ist gewöhnlicher
# Verkehr.
set -euo pipefail

usage() {
  cat <<'TXT'
Löscht die gespeicherten Firewall-Zeilen über den eigenen Syslog-Weg.

  prune-syslog-traffic.sh [--dry-run] [Optionen]

Optionen:
  --dry-run          Zählt nur und löscht nichts.
  --address <ip>     Adresse dieses Empfängers. Mehrfach möglich. Ohne Angabe
                     das, was der laufende Dienst von sich selbst gelernt hat.
  --port <n>         Syslog-Port. Vorgabe: der gelernte, sonst 514.
  --dsn <dsn>        Datenbank. Vorgabe: UIP_DB_URL aus /etc/uip/uip.env.
  --batch <n>        Zeilen je Durchgang. Vorgabe 50000.
  -h, --help         Dieser Text.

Gelöscht wird in Stapeln, nicht in einer einzigen Anweisung: bei Millionen
Zeilen hielte die eine Transaktion sonst minutenlang Sperren auf einer Tabelle,
in die gleichzeitig geschrieben wird.

Danach lohnt sich ein VACUUM — der Platz wird sonst erst beim nächsten
Autovacuum frei.
TXT
}

DRY_RUN=0
PORT=""
DSN=""
BATCH=50000
ADDRESSES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
  --dry-run) DRY_RUN=1; shift ;;
  --address) ADDRESSES+=("${2:?--address braucht eine Adresse}"); shift 2 ;;
  --port) PORT="${2:?--port braucht eine Zahl}"; shift 2 ;;
  --dsn) DSN="${2:?--dsn braucht eine Adresse}"; shift 2 ;;
  --batch) BATCH="${2:?--batch braucht eine Zahl}"; shift 2 ;;
  -h | --help) usage; exit 0 ;;
  *) echo "Unbekannte Option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$DSN" && -r /etc/uip/uip.env ]]; then
  DSN="$(sed -n 's/^UIP_DB_URL=//p' /etc/uip/uip.env | head -1)"
fi
[[ -n "$DSN" ]] || { echo "Keine Datenbank: --dsn angeben oder UIP_DB_URL hinterlegen." >&2; exit 2; }
command -v psql >/dev/null || { echo "psql fehlt." >&2; exit 1; }

msg() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }

q() { psql "$DSN" -v ON_ERROR_STOP=1 -tAc "$1"; }

# ── Wer sind wir, und auf welchem Port? ─────────────────────────────────────
# Der Dienst schreibt beides nach `syslog_stats`, sobald er das erste Datagramm
# gesehen hat. Das ist verlässlicher als eine Eingabe: gelernt wird die
# Adresse, unter der die Geräte ihn tatsächlich erreichen.
if [[ ${#ADDRESSES[@]} -eq 0 ]]; then
  mapfile -t ADDRESSES < <(q "SELECT jsonb_array_elements_text(value -> 'addresses')
                              FROM system_config WHERE key = 'syslog_stats'" || true)
fi
if [[ -z "$PORT" ]]; then
  PORT="$(q "SELECT value ->> 'port' FROM system_config WHERE key = 'syslog_stats'" || true)"
  PORT="${PORT:-514}"
fi

if [[ ${#ADDRESSES[@]} -eq 0 ]]; then
  echo "Keine eigene Adresse bekannt. Der Dienst hat noch kein Datagramm gesehen —" >&2
  echo "dann --address angeben, sonst würde hier fremder Verkehr gelöscht." >&2
  exit 2
fi

LIST="$(printf "'%s'," "${ADDRESSES[@]}")"
LIST="${LIST%,}"
WHERE="l.log_type_id = 1
   AND (   (l.dst_port = ${PORT} AND l.dst_ip = ANY (ARRAY[${LIST}]::inet[]))
        OR (l.src_port = ${PORT} AND l.src_ip = ANY (ARRAY[${LIST}]::inet[])))"

msg "Empfänger: ${ADDRESSES[*]} auf Port ${PORT}"

TOTAL="$(q "SELECT count(*) FROM logs l WHERE ${WHERE}")"
if [[ "$TOTAL" == "0" ]]; then
  msg "Nichts zu löschen."
  exit 0
fi
msg "$(printf "%'d" "$TOTAL" 2>/dev/null || echo "$TOTAL") Zeilen betroffen"

if ((DRY_RUN)); then
  msg "Probelauf — es wird nichts gelöscht. Ein Beispiel:"
  psql "$DSN" -c "SELECT l.timestamp, host(l.src_ip) AS src, l.src_port,
                         host(l.dst_ip) AS dst, l.dst_port
                  FROM logs l WHERE ${WHERE} ORDER BY l.timestamp DESC LIMIT 3"
  exit 0
fi

# ── Stapelweise löschen ────────────────────────────────────────────────────
DELETED=0
while :; do
  N="$(q "WITH doomed AS (
            SELECT l.timestamp, l.id FROM logs l WHERE ${WHERE} LIMIT ${BATCH}),
          gone AS (
            DELETE FROM logs d USING doomed
            WHERE d.timestamp = doomed.timestamp AND d.id = doomed.id
            RETURNING 1)
          SELECT count(*) FROM gone")"
  DELETED=$((DELETED + N))
  [[ "$N" == "0" ]] && break
  printf '\r    %s gelöscht' "$DELETED"
done
printf '\n'
msg "Fertig — ${DELETED} Zeilen gelöscht"
warn "Der Platz wird erst mit einem VACUUM frei: psql \"\$DSN\" -c 'VACUUM (ANALYZE) logs'"
