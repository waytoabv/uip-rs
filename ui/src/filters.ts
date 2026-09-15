// Der Filterzustand der Log-Ansicht, spiegelbildlich zu `LogFilter` im
// Backend (crates/uip-api/src/filters.rs). Jedes Feld ist ein einfacher
// String statt eines typisierten Werts, weil es 1:1 aus Formularfeldern
// kommt und 1:1 in einen Query-String geht — die eigentliche Typisierung
// (Adresse, Netz, Port, …) übernimmt ohnehin der Suchparser im Backend.
//
// `log_type` / `action` / `direction` sind komma-getrennte Listen der
// AKTIVEN Werte — wie im Backend (`comma_list`). Ein leerer String heißt
// "alle", nicht "keiner": das spiegelt die Pillen-UI, in der alle Typen
// aktiv aussehen, bis man eine abwählt.
//
// `ip`, `rule`, `sport`, `dport`, `asn` und `service` haben kein eigenes
// Backend-Feld — es gibt nur `q` mit Präfixen (`rule:`, `sport:`, …) oder,
// für `ip`/`service`, gar kein Präfix nötig. `toQuery` setzt sie zu einem
// einzigen `q`-Parameter zusammen; die getrennten Felder existieren nur,
// damit jedes einen eigenen, einzeln entfernbaren Filter-Chip bekommt.

export interface FilterState {
  log_type: string;
  action: string;
  direction: string;
  iface: string;
  // Gerichtet: eine Zelle der Zonenmatrix ist Verkehr von X nach Y, und
  // `iface` allein träfe auch die Gegenrichtung.
  iface_in: string;
  iface_out: string;
  proto: string;
  country: string;
  port: string;
  threat_min: string;
  range: string;
  ip: string;
  rule: string;
  sport: string;
  dport: string;
  asn: string;
  service: string;
  q: string;
}

export function emptyFilters(): FilterState {
  return {
    log_type: '',
    action: '',
    direction: '',
    iface: '',
    iface_in: '',
    iface_out: '',
    proto: '',
    country: '',
    port: '',
    threat_min: '',
    range: '',
    ip: '',
    rule: '',
    sport: '',
    dport: '',
    asn: '',
    service: '',
    q: '',
  };
}

export const LOG_TYPES = ['firewall', 'dns', 'dhcp', 'wifi', 'system'] as const;
// 'unknown' meint Zeilen ohne erkannte Aktion (etwa DNS) — im Backend
// kein Id-Wert, sondern `rule_action_id IS NULL`.
export const ACTIONS = ['allow', 'block', 'redirect', 'unknown'] as const;
// 'local' ist eine gültige Backend-Richtung ohne eigene Pille — sobald eine
// der fünf hier abgewählt wird, verschwindet 'local' aus der Auswahl mit,
// genau wie im Original.
export const DIRECTIONS = ['inbound', 'outbound', 'inter_vlan', 'nat', 'vpn'] as const;

export const RANGE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: '1h', label: '1h' },
  { value: '6h', label: '6h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  // Kein eigener Fall im Backend nötig — `range_start` liest "60d"/"90d"
  // genau wie jeden anderen "<Zahl>d"-Wert.
  { value: '60d', label: '60d' },
  { value: '90d', label: '90d' },
  { value: '180d', label: '180d' },
  { value: '365d', label: '365d' },
];

/**
 * Schaltet `value` in einer komma-Liste um. Ein leerer String bedeutet
 * "alle aktiv" (das Backend-Feld ist dann leer = ungefiltert); wählt man
 * wieder alle einzeln an, wird daraus erneut der leere String statt einer
 * ausgeschriebenen Liste aller Werte — beides wirkt gleich, aber nur der
 * leere String ist der neutrale Zustand.
 */
export function toggleMulti(current: string, all: readonly string[], value: string): string {
  const active = current.trim() === '' ? all : current.split(',').filter(Boolean);
  const next = active.includes(value) ? active.filter((v) => v !== value) : [...active, value];
  return next.length === all.length ? '' : next.join(',');
}

/** Ob `value` in der komma-Liste (oder, bei leerem Feld, "in allen") aktiv ist. */
export function isMultiActive(current: string, all: readonly string[], value: string): boolean {
  const active = current.trim() === '' ? all : current.split(',').filter(Boolean);
  return active.includes(value);
}

// Felder, die als Ganzzahl beim Backend ankommen müssen (`Option<i32>`) oder
// nur als getypter `sport:`/`dport:`-Suchbegriff Sinn ergeben. Ein ungültiger
// Wert würde dort entweder den Request mit 400 scheitern lassen oder, bei den
// Suchbegriffen, in eine bedeutungslose Volltextsuche zurückfallen (der
// Parser erkennt `sport:abc` nicht als Port und durchsucht dann irrelevante
// Spalten) — deshalb wird hier vorher aussortiert statt dem Server oder dem
// Suchparser die Fehlerbehandlung zu überlassen.
const NUMERIC_FIELDS = new Set<keyof FilterState>(['port', 'threat_min', 'sport', 'dport']);

function isValidNumber(value: string): boolean {
  return /^\d+$/.test(value.trim());
}

/** Umschließt einen Begriff in Anführungszeichen, wenn er Leerzeichen enthält. */
function quoteIfNeeded(value: string): string {
  return /\s/.test(value) ? `"${value}"` : value;
}

// Backend-Parameter, die 1:1 aus dem gleichnamigen Feld übernommen werden.
const DIRECT_PARAMS = [
  'log_type',
  'action',
  'direction',
  'iface',
  'proto',
  'country',
  'port',
  'threat_min',
  'range',
] as const satisfies readonly (keyof FilterState)[];

/**
 * Setzt die Felder ohne eigenen Backend-Parameter zu einem einzigen
 * `q`-Suchausdruck zusammen. Reihenfolge ist beliebig — der Parser UNDet
 * ohnehin alle Begriffe.
 */
function composeQ(state: FilterState): string {
  const parts: string[] = [];
  if (state.ip.trim()) parts.push(quoteIfNeeded(state.ip.trim()));
  if (state.rule.trim()) parts.push(`rule:${quoteIfNeeded(state.rule.trim())}`);
  if (isValidNumber(state.sport)) parts.push(`sport:${state.sport.trim()}`);
  if (isValidNumber(state.dport)) parts.push(`dport:${state.dport.trim()}`);
  if (state.asn.trim()) parts.push(`asn:${quoteIfNeeded(state.asn.trim())}`);
  // "Service" hat keine eigene Spalte und kein Präfix — bleibt ein
  // ungerichteter Begriff, der über die generische Spaltenliste sucht.
  if (state.service.trim()) parts.push(quoteIfNeeded(state.service.trim()));
  if (state.q.trim()) parts.push(state.q.trim());
  return parts.join(' ');
}

// Baut aus dem Filterzustand einen Query-String. Leere Werte fehlen ganz;
// numerische Felder mit ungültigem Inhalt werden verworfen statt den
// Request zu brechen.
export function toQuery(state: FilterState): string {
  const params = new URLSearchParams();
  for (const key of DIRECT_PARAMS) {
    const value = state[key].trim();
    if (value === '') continue;
    if (NUMERIC_FIELDS.has(key) && !isValidNumber(value)) continue;
    params.set(key, value);
  }
  const q = composeQ(state);
  if (q) params.set('q', q);
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
  log_type: 'Type',
  action: 'Action',
  direction: 'Direction',
  iface: 'Interface',
  iface_in: 'From',
  iface_out: 'To',
  proto: 'Protocol',
  country: 'Country',
  port: 'Port',
  threat_min: 'Threat ≥',
  range: 'Range',
  ip: 'IP',
  rule: 'Rule',
  sport: 'Src port',
  dport: 'Dst port',
  asn: 'ASN',
  service: 'Service',
  q: 'Search',
};

// Fields whose "all selected" state (empty string) means no chip should
// show — the pill rows already make that visible.
// Nur der Log-Typ bekommt keinen Chip: seine Pillen zeigen ihren Zustand
// selbst, und ein Chip daneben wäre dieselbe Aussage zweimal. Aktion und
// Richtung dagegen erscheinen als Chip — so hält es der Fork auch, und ohne
// sie behauptete die Zeile "No filters", während gefiltert wird.
const NO_CHIP_FIELDS = new Set<keyof FilterState>(['log_type']);

// Liefert je einen Chip für jeden aktiven Filter — zum Anzeigen und, über
// den `key`, zum gezielten Löschen genau dieses einen Filters.
export function describe(state: FilterState): Chip[] {
  return (Object.keys(state) as (keyof FilterState)[])
    .filter((key) => !NO_CHIP_FIELDS.has(key) && state[key].trim() !== '')
    .map((key) => {
      const raw = state[key];
      const value = key === 'range' ? (RANGE_LABELS[raw] ?? raw) : raw;
      return { key, label: `${FIELD_LABELS[key]}: ${value}` };
    });
}
