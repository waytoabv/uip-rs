// Der Filterzustand der Log-Ansicht, spiegelbildlich zu `LogFilter` im
// Backend (crates/uip-api/src/filters.rs). Jedes Feld ist ein einfacher
// String statt eines typisierten Werts, weil es 1:1 aus Formularfeldern
// kommt und 1:1 in einen Query-String geht — die eigentliche Typisierung
// (Adresse, Netz, Port, …) übernimmt ohnehin der Suchparser im Backend.

export interface FilterState {
  log_type: string;
  action: string;
  direction: string;
  iface: string;
  proto: string;
  country: string;
  port: string;
  threat_min: string;
  range: string;
  q: string;
}

export function emptyFilters(): FilterState {
  return {
    log_type: '',
    action: '',
    direction: '',
    iface: '',
    proto: '',
    country: '',
    port: '',
    threat_min: '',
    range: '',
    q: '',
  };
}

export const LOG_TYPES = ['firewall', 'dns', 'dhcp', 'wifi', 'system'];
export const ACTIONS = ['allow', 'block', 'redirect'];
export const DIRECTIONS = ['inbound', 'outbound', 'local', 'inter_vlan', 'vpn', 'nat'];

export const RANGE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: '1h', label: '1 Std' },
  { value: '6h', label: '6 Std' },
  { value: '24h', label: '24 Std' },
  { value: '7d', label: '7 Tage' },
  { value: '30d', label: '30 Tage' },
];

// Felder, die als Ganzzahl beim Backend ankommen müssen (`Option<i32>`).
// Ein ungültiger Wert würde dort den kompletten Request mit 400 scheitern
// lassen, statt einfach nichts zu filtern — deshalb wird hier vorher
// aussortiert statt dem Server die Fehlerbehandlung zu überlassen.
const NUMERIC_FIELDS = new Set<keyof FilterState>(['port', 'threat_min']);

function isValidNumber(value: string): boolean {
  return /^\d+$/.test(value.trim());
}

// Baut aus dem Filterzustand einen Query-String. Leere Werte fehlen ganz;
// numerische Felder mit ungültigem Inhalt werden verworfen statt den
// Request zu brechen.
export function toQuery(state: FilterState): string {
  const params = new URLSearchParams();
  for (const key of Object.keys(state) as (keyof FilterState)[]) {
    const value = state[key].trim();
    if (value === '') continue;
    if (NUMERIC_FIELDS.has(key) && !isValidNumber(value)) continue;
    params.set(key, value);
  }
  return params.toString();
}

export interface Chip {
  key: keyof FilterState;
  label: string;
}

const RANGE_LABELS: Record<string, string> = Object.fromEntries(
  RANGE_OPTIONS.map((r) => [r.value, r.label]),
);

const FIELD_LABELS: Record<keyof FilterState, string> = {
  log_type: 'Typ',
  action: 'Aktion',
  direction: 'Richtung',
  iface: 'Schnittstelle',
  proto: 'Protokoll',
  country: 'Land',
  port: 'Port',
  threat_min: 'Threat ≥',
  range: 'Zeitraum',
  q: 'Suche',
};

// Liefert je einen Chip für jeden aktiven Filter — zum Anzeigen und, über
// den `key`, zum gezielten Löschen genau dieses einen Filters.
export function describe(state: FilterState): Chip[] {
  return (Object.keys(state) as (keyof FilterState)[])
    .filter((key) => state[key].trim() !== '')
    .map((key) => {
      const raw = state[key];
      const value = key === 'range' ? (RANGE_LABELS[raw] ?? raw) : raw;
      return { key, label: `${FIELD_LABELS[key]}: ${value}` };
    });
}
