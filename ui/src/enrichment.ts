/**
 * Der Nachtrag der Anreicherung, angewandt auf eine schon gezeigte Zeile.
 *
 * Eigene Datei und kein Solid-Import: so bleibt sie mit `--environment node`
 * prüfbar, ohne dass ein DOM gebraucht wird. `LogEntry` kommt als reiner Typ
 * herein und verschwindet beim Übersetzen wieder.
 */
import type { LogEntry } from './LogsView';

/** Was der Strom als `enriched` nachreicht. */
export interface Enrichment {
  ip: string;
  geo_country: string | null;
  geo_city: string | null;
  geo_lat: number | null;
  geo_lon: number | null;
  asn_number: number | null;
  asn_name: string | null;
  rdns: string | null;
  threat_score: number | null;
  threat_categories: string[] | null;
  abuse_is_tor: boolean | null;
}

/**
 * Trägt einen Nachtrag in eine Zeile ein — nur dort, wo sie noch nichts weiß.
 *
 * Der Bezug ist die Adresse: betroffen ist jede Zeile, in der sie als Quelle
 * oder Ziel vorkommt. Vorhandene Werte bleiben unangetastet; eine über
 * `/api/logs` geladene Zeile hat ihre Angaben aus der Datenbank, und die ist
 * die verlässlichere Quelle.
 *
 * Ändert sich nichts, kommt **dieselbe** Zeile zurück, nicht eine gleiche.
 * `<For>` in Solid vergleicht Referenzen: ein neues Objekt heißt ein neuer
 * DOM-Knoten, und damit ein neu geladenes Flaggenbild. Bei einem
 * wiederkehrenden Ziel kam der Nachtrag mehrmals pro Sekunde — sichtbar als
 * flackernde Flagge.
 */
export function applyEnrichment(row: LogEntry, facts: Enrichment): LogEntry {
  if (row.src_ip !== facts.ip && row.dst_ip !== facts.ip) return row;

  const FIELDS = [
    'geo_country',
    'geo_city',
    'geo_lat',
    'geo_lon',
    'asn_number',
    'asn_name',
    'rdns',
    'threat_score',
    'threat_categories',
    'abuse_is_tor',
  ] as const;

  const patch: Partial<LogEntry> = {};
  for (const key of FIELDS) {
    if (row[key] == null && facts[key] != null) {
      (patch as Record<string, unknown>)[key] = facts[key];
    }
  }
  return Object.keys(patch).length === 0 ? row : { ...row, ...patch };
}
