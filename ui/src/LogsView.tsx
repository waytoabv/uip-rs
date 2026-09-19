import { createEffect, createSignal, For, Show, onCleanup, untrack } from 'solid-js';
import CountryFlag from './CountryFlag';
import { countryName } from './country';
import {
  actionPillClass,
  decodeThreatCategories,
  directionColorClass,
  directionGlyph,
  isHighThreat,
  localSide,
  logTypePillClass,
  networkPath,
  normalizeRuleDesc,
  protocolName,
  rawMessage,
  shortenHost,
  serviceName,
  threatDotClass,
} from './LogHelpers';
import LogRowDetail from './LogRowDetail';
import { namedNetworkPath } from './interfaceLabels';
import { ruleLabel } from './firewallRules';
import { deviceName } from './deviceNames';
import { applyEnrichment, type Enrichment } from './enrichment';

const PAGE_SIZE = 50;
/** TIME, TYPE, ACTION, SOURCE, dir, DESTINATION, COUNTRY, ASN, NETWORK, PROTO, SERVICE, RULE/INFO, ABUSEIPDB, CATEGORIES */
const COLUMN_COUNT = 14;

/** Spalten, die sich über das „Columns"-Menü ein- und ausblenden lassen —
 *  dieselbe Auswahl wie in der Vorlage (`LogStream.jsx`, `TOGGLEABLE_COLUMNS`). */
const TOGGLEABLE_COLUMNS: Array<{ key: string; label: string }> = [
  { key: 'country', label: 'Country' },
  { key: 'asn', label: 'ASN' },
  { key: 'proto', label: 'Protocol' },
  { key: 'rule', label: 'Rule / Info' },
  { key: 'threat', label: 'AbuseIPDB' },
  { key: 'categories', label: 'Categories' },
];
const TOGGLEABLE_KEYS = new Set(TOGGLEABLE_COLUMNS.map((c) => c.key));
const COLUMNS_STORAGE_KEY = 'uip-log-hidden-columns';

function loadHiddenColumns(): Set<string> {
  try {
    const raw = localStorage.getItem(COLUMNS_STORAGE_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((k): k is string => typeof k === 'string' && TOGGLEABLE_KEYS.has(k)));
  } catch {
    return new Set();
  }
}

/**
 * Eine Log-Zeile, wie `/api/logs` und `/api/stream` sie liefern (siehe
 * `crates/uip-api/src/logs.rs`). Umfangreicher als die einfache `LogRow` aus
 * `api.ts`, die nur die Felder trägt, die die erste Fassung brauchte.
 */
export interface LogEntry {
  id: number;
  timestamp: string;
  log_type: string | null;
  direction: string | null;
  rule_action: string | null;
  rule_name: string | null;
  rule_desc: string | null;
  iface_in: string | null;
  iface_out: string | null;
  protocol: string | null;
  hostname: string | null;
  /// Name aus dem UniFi-Controller, je Seite aufgelöst.
  src_device: string | null;
  dst_device: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  mac_address: string | null;
  dns_query: string | null;
  dns_type: string | null;
  dns_answer: string | null;
  dhcp_event: string | null;
  wifi_event: string | null;
  raw_log: string | null;
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
  /** Aus der IANA-Registry aufgelöst (`crates/uip-api/src/services.rs`).
   *  Fehlt ganz bei frisch über den Live-Stream eingetroffenen Zeilen, die
   *  `LiveRow` (noch ohne Anreicherung) sendet — dafür bleibt `serviceName`
   *  aus `LogHelpers` die Rückfallebene. */
  service?: string | null;
}

interface LogsResponse {
  rows: LogEntry[];
  next_cursor: string | null;
}

function logsUrl(query: string, before: string | undefined): string {
  const params = new URLSearchParams(query);
  params.set('limit', String(PAGE_SIZE));
  if (before) params.set('before', before);
  else params.delete('before');
  return `/api/logs?${params.toString()}`;
}

async function fetchLogsPage(query: string, before: string | undefined): Promise<LogsResponse> {
  const res = await fetch(logsUrl(query, before));
  if (!res.ok) return { rows: [], next_cursor: null };
  const body = (await res.json()) as Partial<LogsResponse>;
  return { rows: body.rows ?? [], next_cursor: body.next_cursor ?? null };
}

/** Firewall zeigt die Regel, alles andere die jeweils aussagekräftigste Nutzlast. */
function infoFor(row: LogEntry): string {
  if (row.log_type === 'firewall') {
    // Der Controller zuerst: die Beschreibung in der Log-Zeile ist bei
    // neunundzwanzig Zeichen abgeschnitten, und den Vorgaberegeln fehlt sie
    // ganz — dort stünde sonst `LOCAL_WAN-A-2147483647`.
    return ruleLabel(row.rule_name) ?? normalizeRuleDesc(row.rule_desc) ?? row.rule_name ?? '—';
  }
  return row.dns_query ?? row.hostname ?? row.wifi_event ?? row.dhcp_event ?? rawMessage(row.raw_log) ?? '—';
}

/** Im Tooltip steht zusätzlich der rohe Regelname — danach sucht, wer die
 *  Regel im Controller wiederfinden will. */
function infoTitle(row: LogEntry): string {
  const text = infoFor(row);
  return row.rule_name && row.rule_name !== text ? `${text} · ${row.rule_name}` : text;
}

/** Dienstname für die SERVICE-Spalte: `row.service` (server-seitig aus der
 *  IANA-Tabelle) hat Vorrang, die lokale Portliste ist nur die Rückfallebene
 *  für Zeilen, die dieses Feld (noch) nicht tragen. */
function serviceFor(row: LogEntry): string {
  return row.service ?? serviceName(row.dst_port);
}

/** Gerätename (eigene Seite) bzw. rDNS (Gegenseite) — siehe `localSide` in LogHelpers. */
function addressName(row: LogEntry, side: 'src' | 'dst'): string | null {
  // Der Name aus dem Controller zuerst: ihn hat ein Mensch vergeben, und er
  // gilt für beide Seiten. Erst danach die Notlösungen — der DHCP-Hostname
  // für die eigene Seite, rDNS für die Gegenstelle.
  const fromController = side === 'src' ? row.src_device : row.dst_device;
  if (fromController) return fromController;
  // Zeilen aus dem Live-Strom tragen das Feld nicht: sie werden weitergereicht,
  // sobald sie geschrieben sind, ohne den Umweg über die Auflösung beim Lesen.
  // Für sie gilt dieselbe Tabelle, nur hier nachgeschlagen.
  const fromTable = deviceName(side === 'src' ? row.src_ip : row.dst_ip);
  if (fromTable) return fromTable;
  const local = localSide(row.direction, row.src_ip, row.dst_ip);
  return side === local ? row.hostname : row.rdns;
}

function formatClock(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime())
    ? '—'
    : d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/** Tag und Monat, wie die Vorlage sie unter der Uhrzeit zeigt: "8 Feb". */
function formatDateShort(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime())
    ? '—'
    : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}

function TypePill(props: { type: string | null }) {
  return (
    <Show when={props.type} fallback={<span class="text-gray-500 dark:text-gray-400 text-[12px]">—</span>}>
      <span
        class={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${logTypePillClass(props.type)}`}
      >
        {props.type}
      </span>
    </Show>
  );
}

function ActionPill(props: { action: string | null; dhcpEvent: string | null; wifiEvent: string | null }) {
  const label = () => props.action ?? props.dhcpEvent ?? props.wifiEvent ?? null;
  return (
    <Show when={label()} fallback={<span class="text-gray-500 dark:text-gray-400 text-[12px]">—</span>}>
      <span
        class={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${actionPillClass(label())}`}
      >
        {label()}
      </span>
    </Show>
  );
}

/**
 * Adresse und Port, immer zwei Zeilen hoch.
 *
 * Die Zeitspalte ist ohnehin zweizeilig, die Zeilenhöhe steht damit fest — und
 * eine Adresszelle, die mal ein- und mal zweizeilig ist, macht daraus einen
 * Sprung bei jeder eintreffenden Zeile. Innerhalb dieser zwei Zeilen wird der
 * Platz je nach Inhalt anders aufgeteilt:
 *
 * - Mit Namen: oben der Name (gekürzt, ganz im Tooltip), unten Adresse:Port.
 * - Ohne Namen, IPv6: die Adresse darf beide Zeilen nutzen. Achtunddreißig
 *   Zeichen auf einer Zeile zwängen die Spalte auf 266 Pixel, über zwei sind
 *   es 133 — bei einer Spalte, die sonst 160 braucht, ist das der Unterschied
 *   zwischen Passen und Scrollen.
 * - Ohne Namen, IPv4: Adresse oben, Port unten. Kurz genug für eine Zeile.
 */
function AddressCell(props: { ip: string | null; port: number | null; name: string | null }) {
  const isV6 = () => !!props.ip?.includes(':');
  const withPort = () => (props.port == null ? props.ip : `${props.ip}:${props.port}`);
  return (
    <Show when={props.ip} fallback={<span class="text-gray-500 dark:text-gray-400">—</span>}>
      <div class="leading-tight">
        <Show
          when={props.name}
          fallback={
            <Show
              when={isV6()}
              fallback={
                <>
                  <div class="truncate text-[13px] text-gray-700 dark:text-gray-200">{props.ip}</div>
                  <div class="truncate text-[11px] text-gray-500 dark:text-gray-400">
                    <Show when={props.port != null}>:{props.port}</Show>
                  </div>
                </>
              }
            >
              {/* `break-all`, weil eine Adresse keine Wortgrenzen hat, an denen
                  ein Umbruch sinnvoll wäre. */}
              <div class="cell-wrap-2 break-all text-[13px] text-gray-700 dark:text-gray-200" title={withPort() ?? undefined}>
                {withPort()}
              </div>
            </Show>
          }
        >
          <div
            class="truncate text-[13px] text-gray-700 dark:text-gray-200"
            title={props.name ?? undefined}
          >
            {shortenHost(props.name)}
          </div>
          <div class="truncate text-[11px] text-gray-500 dark:text-gray-400" title={withPort() ?? undefined}>
            {withPort()}
          </div>
        </Show>
      </div>
    </Show>
  );
}

function CountryCell(props: { code: string | null }) {
  return (
    <Show when={props.code} fallback={<span class="text-gray-500 dark:text-gray-400">—</span>}>
      <span class="inline-flex items-center justify-center" title={countryName(props.code)}>
        <CountryFlag code={props.code} />
      </span>
    </Show>
  );
}

/**
 * Der Name des Netzbetreibers, nötigenfalls über zwei Zeilen.
 *
 * Die Namen sind meist kurz und selten lang: Median sechzehn Zeichen, aber
 * „Verein zur Foerderung eines Deutschen Forschungsnetzes e.V." sind
 * neunundfünfzig. Eine Spalte, die den längsten Fall einzeilig fasst, wäre für
 * neun von zehn Zeilen zu breit — über zwei Zeilen passt auch der Ausreißer in
 * eine Breite, die dem Regelfall entspricht.
 */
function AsnCell(props: { name: string | null }) {
  return (
    <Show when={props.name} fallback={<span class="text-gray-500 dark:text-gray-400">—</span>}>
      <div class="cell-wrap-2 text-[12px] text-gray-600 dark:text-gray-400" title={props.name ?? undefined}>
        {props.name}
      </div>
    </Show>
  );
}

function ThreatCell(props: { score: number | null }) {
  return (
    <Show when={props.score != null} fallback={<span class="text-gray-500 dark:text-gray-400">—</span>}>
      <span class="inline-flex items-center gap-1.5">
        <span class={`w-1.5 h-1.5 rounded-full ${threatDotClass(props.score)}`} />
        <span class="text-gray-600 dark:text-gray-300 text-[13px]">{props.score}</span>
      </span>
    </Show>
  );
}

function CategoriesCell(props: { categories: string[] | null }) {
  const text = () => decodeThreatCategories(props.categories);
  return (
    <Show when={text()} fallback={<span class="text-gray-500 dark:text-gray-400">—</span>}>
      <span
        class="text-[11px] leading-[1.35] text-purple-600/70 dark:text-purple-400/70"
        title={text() ?? undefined}
      >
        {text()}
      </span>
    </Show>
  );
}


// v2: die Breiten davor entstanden ohne Obergrenzen je Spalte und würden
// die neuen überstimmen, ohne dass jemand sie gezogen hätte.
const WIDTHS_STORAGE_KEY = 'uip-log-column-widths-v2';

/** Von Hand gezogene Spaltenbreiten, sofern welche gespeichert sind. */
function storedWidths(): Record<string, number> {
  try {
    const raw = localStorage.getItem(WIDTHS_STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as Record<string, number>) : {};
    return typeof parsed === 'object' && parsed ? parsed : {};
  } catch {
    return {};
  }
}

const [columnWidths, setColumnWidths] = createSignal<Record<string, number>>(storedWidths());

/**
 * Die einmal gemessenen Spaltenbreiten der geladenen Seite.
 *
 * Inhaltsbreite ohne Messung hieße: jede eintreffende Zeile, die irgendwo
 * länger ist, legt die ganze Tabelle neu aus — das sichtbare Springen. Also
 * einmal messen, wenn eine Seite geladen ist, und die Breiten danach halten;
 * was später länger ist, wird gekürzt statt die Tabelle umzubauen. Neu
 * gemessen wird, wenn sich die Daten ändern: Filter, Seite, Refresh.
 */
const [measured, setMeasured] = createSignal<Record<string, number>>({});
// Was die Spalten ohne jede Schranke bräuchten. Getrennt gehalten, weil die
// Verteilung des freien Platzes bei jeder Fensterbreite neu ausfällt, der
// Inhalt aber derselbe bleibt — beim Ziehen am Fensterrand wird damit nur
// gerechnet und nicht neu gemessen.
const [natural, setNatural] = createSignal<Record<string, number>>({});
const [headings, setHeadings] = createSignal<Record<string, number>>({});

/** Schmaler als das ist unlesbar. */
const MIN_COLUMN = 48;

/**
 * Wie breit eine Spalte höchstens werden darf, auch wenn ihr längster Wert
 * mehr verlangt.
 *
 * Die Zahlen kommen aus einer Tagesmenge echter Daten, nicht aus dem Gefühl:
 * Betreibernamen haben einen Median von 16 Zeichen bei Ausreißern bis 59,
 * Rückwärtsauflösungen 19 bei Ausreißern bis 53, Regelbeschreibungen 28 bei
 * höchstens 33. Eine Spalte am längsten Fall auszurichten hieße, sie für neun
 * von zehn Zeilen zu breit zu machen — die Ausreißer brechen stattdessen um
 * (ASN, IPv6) oder werden gekürzt, mit dem ganzen Wert im Tooltip.
 */
const COLUMN_MAX: Record<string, number> = {
  time: 76,
  type: 92,
  action: 80,
  // Gemessener Inhalt: 166 px. Mehr ist Luft zwischen Quelle, Pfeil und Ziel.
  source: 172,
  destination: 172,
  country: 72,
  asn: 176,
  // Netznamen tragen beide Seiten: „#1 - VLAN15 - Intern → #0 - VLAN 10 - Server".
  network: 264,
  proto: 60,
  service: 96,
  rule_info: 200,
  // „ABUSEIPDB" sind neun Großbuchstaben mit Sperrung — bei 88 endete die
  // Überschrift selbst im Auslassungszeichen, und eine Spalte, deren Name
  // nicht dasteht, erklärt ihren Inhalt nicht mehr.
  abuseipdb: 108,
  // Keine Schranke für die Breite, die gezeichnet wird — nur für die, mit der
  // die übrigen Spalten rechnen (siehe `roomShare`). Die Kategorienliste steht
  // vollständig da; dass sie dafür über den rechten Fensterrand hinausragen
  // darf, kostet nichts, weil rechts von ihr nichts mehr kommt.
  categories: 420,
};
const MAX_COLUMN_FALLBACK = 240;

/**
 * Die letzte Spalte. Sie wird nie gestaucht.
 *
 * Alle anderen Spalten teilen sich die Fensterbreite und kürzen ein, was nicht
 * hineinpasst — sonst schöbe eine lange Liste die Spalten rechts davon aus dem
 * Bild. Hinter der letzten ist aber nichts mehr, was verschoben werden könnte:
 * sie darf so breit werden, wie ihr längster Wert es verlangt, und der Behälter
 * scrollt seitwärts.
 */
const FULL_WIDTH_COLUMN = 'categories';

/**
 * Was eine Spalte vom Fensterplatz mitrechnet.
 *
 * Für die letzte Spalte ist das ihre Schranke, nicht ihre wirkliche Breite:
 * Sonst nähme ihr voller Text den übrigen Spalten den freien Platz weg, den sie
 * vorher hatten, und die Tabelle sähe links anders aus als vor dieser Änderung.
 */
const roomShare = (key: string, px: number) =>
  key === FULL_WIDTH_COLUMN ? Math.min(px, COLUMN_MAX[key] ?? MAX_COLUMN_FALLBACK) : px;

/**
 * Untergrenzen für Spalten, die auch einmal leer sein können.
 *
 * Gemessen wird eine Seite, nicht der Datenbestand: hat auf ihr keine Zeile
 * eine ASN, ist die Spalte so breit wie das Wort „ASN" — und die erste Zeile
 * aus dem Live-Strom, die eine hat, steht dann in 48 Pixeln. Diese Werte sind
 * die Breite, die der übliche Inhalt braucht, nicht der längste.
 */
const COLUMN_MIN: Record<string, number> = {
  source: 150,
  destination: 150,
  asn: 120,
  network: 150,
  rule_info: 130,
  categories: 160,
};

/**
 * Eine Kopfzelle, so breit wie ihr Inhalt — und von Hand verstellbar.
 *
 * Ohne gesetzte Breite bestimmt der Inhalt die Spalte (`table-auto` plus
 * `w-max` an der Tabelle), und was nicht ins Fenster passt, wird seitwärts
 * gescrollt. Der Preis dafür ist Bewegung: trifft über den Live-Stream ein
 * längerer Wert ein, wächst seine Spalte und schiebt alles rechts davon. Wen
 * das bei einer bestimmten Spalte stört, der zieht sie auf eine feste Breite —
 * ab dann gilt die, und sie bleibt über `localStorage` erhalten.
 */
function Th(props: { key: string; label: string; center?: boolean }) {
  // Von Hand gezogen schlägt gemessen: wer zieht, meint es.
  const width = () => columnWidths()[props.key] ?? measured()[props.key];

  const startDrag = (e: MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    // Ohne gesetzte Breite ist die gemessene der Ausgangspunkt — sonst spränge
    // die Spalte beim ersten Ziehen auf einen willkürlichen Wert.
    const cell = (e.currentTarget as HTMLElement).parentElement as HTMLElement | null;
    const startW = width() ?? Math.round(cell?.getBoundingClientRect().width ?? 80);
    const onMove = (ev: MouseEvent) => {
      // Unter 40 Pixel ist eine Spalte nicht mehr lesbar, nur noch im Weg.
      const next = Math.max(40, startW + ev.clientX - startX);
      setColumnWidths((prev) => ({ ...prev, [props.key]: next }));
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      try {
        localStorage.setItem(WIDTHS_STORAGE_KEY, JSON.stringify(columnWidths()));
      } catch {
        // Kein Speicher (privates Fenster) — die Breite gilt dann nur jetzt.
      }
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  return (
    <th
      data-col={props.key}
      style={width() == null ? undefined : { width: `${width()}px` }}
      class={`relative whitespace-nowrap px-2 py-2 text-[12px] font-medium uppercase tracking-wider text-gray-600 dark:text-gray-400 ${
        props.center ? 'text-center' : ''
      }`}
    >
      {props.label}
      <span
        onMouseDown={startDrag}
        title="Drag to resize"
        class="absolute right-0 top-0 h-full w-1 cursor-col-resize select-none hover:bg-gray-400/50 dark:hover:bg-gray-500/50"
      />
    </th>
  );
}

/** Die Log-Tabelle mit ihrem Live-Stream, seitenweise blätterbar über den Cursor der API. */
export default function LogsView(props: { query: string }) {
  const [rows, setRows] = createSignal<LogEntry[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [paused, setPaused] = createSignal(false);
  // Ob der Live-Stream gerade pausiert ist, weil der aktive Filter nach
  // Feldern fragt, die erst die Anreicherung liefert (Land, Threat-Score).
  const [suspended, setSuspended] = createSignal(false);
  const [lastUpdate, setLastUpdate] = createSignal<Date | null>(null);
  const [expandedId, setExpandedId] = createSignal<number | null>(null);
  const [total, setTotal] = createSignal<{ total: number; exact: boolean } | null>(null);
  const [hiddenColumns, setHiddenColumns] = createSignal<Set<string>>(loadHiddenColumns());
  const [showColumnsMenu, setShowColumnsMenu] = createSignal(false);
  let columnsMenuRef: HTMLDivElement | undefined;

  // Cursor-Stack für Zurück-Blättern: Index 0 ist die erste Seite (kein
  // `before`), jeder weitere Eintrag ist der Cursor, mit dem diese Seite
  // geladen wurde.
  const [beforeStack, setBeforeStack] = createSignal<(string | undefined)[]>([undefined]);
  const [nextCursor, setNextCursor] = createSignal<string | null>(null);

  const atFirstPage = () => beforeStack().length === 1;
  const pageNumber = () => beforeStack().length;

  const showCol = (key: string) => !hiddenColumns().has(key);
  const visibleColumnCount = () => COLUMN_COUNT - hiddenColumns().size;

  let tableRef: HTMLTableElement | undefined;

  /**
   * Misst die Spalten der gerade geladenen Seite und hält sie fest.
   *
   * Läuft im Bild nach dem Zeichnen: vorher steht die Tabelle auf
   * Inhaltsbreite, danach auf genau diesen Werten. Der eine Zwischenschritt
   * ist derselbe Inhalt in derselben Breite — zu sehen ist er nicht.
   */
  /**
   * Die Summe der gesetzten Spaltenbreiten.
   *
   * `w-max` bestimmt die Tabellenbreite aus dem Inhalt, nicht aus diesen
   * Werten — bei `table-fixed` landet die Differenz dann vollständig in der
   * letzten Spalte. Gemessen waren das 673 Pixel Luft in „Categories", während
   * zwischen Quelle und Ziel nichts zusammenrückte. Also die Breite
   * ausdrücklich setzen.
   */
  const tableWidth = () => {
    const w = measured();
    const keys = Object.keys(w);
    if (!keys.length) return undefined;
    const sum = keys.reduce((n, k) => n + (columnWidths()[k] ?? w[k]), 0);
    return `${sum}px`;
  };

  /**
   * Die Breite der Überschrift selbst, samt Innenabstand.
   *
   * Eine Obergrenze darunter ist keine: dann steht in der Spalte „COUN…", und
   * eine Spalte, deren Name nicht dasteht, erklärt ihren Inhalt nicht mehr.
   * Gemessen statt in der Liste oben mitgepflegt — die Werte hängen an
   * Schriftart und Sperrung, und beide ändern sich, ohne dass jemand an diese
   * Zahlen denkt.
   */
  const headingWidth = (th: HTMLElement) => {
    const range = document.createRange();
    range.selectNodeContents(th);
    let text = 0;
    for (const rect of range.getClientRects()) text = Math.max(text, rect.width);
    const style = getComputedStyle(th);
    return Math.ceil(text + parseFloat(style.paddingLeft) + parseFloat(style.paddingRight));
  };

  /**
   * Aus dem, was die Spalten bräuchten, das, was sie bekommen.
   *
   * Zuerst gilt die Schranke — sonst nimmt eine einzige lange Kategorienliste
   * die halbe Tabelle. Bleibt danach Platz im Fenster, geht er an die Spalten
   * zurück, die an ihrer Schranke abgeschnitten wurden, und zwar im Verhältnis
   * dessen, was ihnen fehlt. Vorher stand rechts eine handbreit Schwarz,
   * während links „MacBook…" und „#1 - VLAN15 - In…" abschnitten: Schranken
   * allein sagen, wie breit eine Spalte höchstens sein darf, und niemand sagte,
   * was mit dem Rest geschieht.
   */
  const fitColumns = (want: Record<string, number>, heads: Record<string, number>) => {
    const out: Record<string, number> = {};
    let sum = 0;
    for (const [key, w] of Object.entries(want)) {
      const heading = heads[key] ?? 0;
      const cap = Math.max(COLUMN_MAX[key] ?? MAX_COLUMN_FALLBACK, heading);
      const min = Math.min(cap, Math.max(COLUMN_MIN[key] ?? MIN_COLUMN, heading));
      out[key] =
        key === FULL_WIDTH_COLUMN
          ? Math.max(COLUMN_MIN[key] ?? MIN_COLUMN, heading, w)
          : Math.min(cap, Math.max(min, w));
      sum += roomShare(key, out[key]);
    }

    const room = tableRef?.parentElement?.clientWidth ?? 0;
    let slack = room - sum;
    if (slack <= 0) return out;

    // Nur wer beschnitten wurde, bekommt etwas ab — und keine Spalte mehr, als
    // ihr Inhalt verlangt. Was danach noch frei ist, bleibt frei: die letzte
    // Spalte auf die Fensterbreite aufzublasen war der Fehler davor.
    const short = Object.keys(out).filter((k) => k !== FULL_WIDTH_COLUMN && want[k] > out[k]);
    const missing = short.reduce((n, k) => n + want[k] - out[k], 0);
    if (missing <= 0) return out;
    for (const key of short) {
      const share = Math.floor((slack * (want[key] - out[key])) / missing);
      const add = Math.min(share, want[key] - out[key]);
      out[key] += add;
    }
    return out;
  };

  const measureColumns = () => {
    if (!tableRef) return;
    const want: Record<string, number> = {};
    const heads: Record<string, number> = {};
    for (const th of tableRef.querySelectorAll<HTMLElement>('thead th[data-col]')) {
      const key = th.dataset.col;
      if (!key) continue;
      // Ungebremst gemessen: die Tabelle steht in diesem Augenblick auf
      // Inhaltsbreite, die Zelle ist also so breit, wie ihr Text es verlangt.
      const w = Math.round(th.getBoundingClientRect().width);
      if (w > 0) {
        want[key] = w;
        heads[key] = headingWidth(th);
      }
    }
    if (!Object.keys(want).length) return;
    setNatural(want);
    setHeadings(heads);
    setMeasured(fitColumns(want, heads));
  };

  /**
   * Lässt Spalten in freien Platz nachwachsen, ohne je zu schrumpfen.
   *
   * Gemessen wird einmal je Seite, damit die Tabelle unter dem Live-Strom
   * stillsteht. Der Preis: eine Zeile, die danach hereinkommt, bringt einen
   * längeren Namen mit, als die Spalte breit ist — und schneidet ab, während
   * rechts noch eine Handbreit Fenster frei liegt. Also nach jeder Änderung
   * nachsehen, was überläuft, und nur so viel verteilen, wie ohnehin frei war.
   * Breiter werden sieht man nicht; schmaler würde man sehen, deshalb nie.
   */
  const growIntoSlack = () => {
    if (!tableRef) return;
    const w = measured();
    const keys = Object.keys(w);
    if (!keys.length) return;
    const room = tableRef.parentElement?.clientWidth ?? 0;
    const sum = keys.reduce((n, k) => n + roomShare(k, columnWidths()[k] ?? w[k]), 0);
    // Die letzte Spalte wächst auch ohne freien Platz — darum hier kein
    // frühes Aussteigen mehr, sondern nur eine Verteilmasse, die null sein darf.
    const slack = Math.max(0, room - sum);

    const cols = [...tableRef.querySelectorAll<HTMLElement>('thead th[data-col]')].map(
      (th) => th.dataset.col ?? '',
    );
    const need: Record<string, number> = {};
    const fixed = columnWidths();
    const ask = (key: string, px: number) => {
      // Von Hand gezogene Spalten bleiben, wie sie gezogen wurden.
      if (px > 0 && !(key in fixed)) need[key] = Math.max(need[key] ?? 0, Math.ceil(px));
    };
    for (const tr of tableRef.querySelectorAll<HTMLElement>('tbody tr.log-row')) {
      (Array.from(tr.children) as HTMLElement[]).forEach((td, i) => {
        const key = cols[i];
        if (!key) return;
        ask(key, td.scrollWidth - td.clientWidth);
        for (const el of td.querySelectorAll<HTMLElement>('*')) {
          ask(key, el.scrollWidth - el.clientWidth);
          // Zweizeilige Zellen laufen nicht seitwärts über, sie hören auf.
          // Was fehlt, steckt in den Zeilen, die nicht mehr gezeichnet werden.
          if (el.clientWidth > 0 && el.clientHeight > 0 && el.scrollHeight - el.clientHeight > 1) {
            ask(key, el.clientWidth * (el.scrollHeight / el.clientHeight - 1));
          }
        }
      });
    }

    // Was der letzten Spalte fehlt, bekommt sie ganz: sie nimmt es keinem weg.
    const fullNeed = need[FULL_WIDTH_COLUMN] ?? 0;
    delete need[FULL_WIDTH_COLUMN];

    const wanted = Object.values(need).reduce((n, px) => n + px, 0);
    if (wanted <= 0 && fullNeed <= 0) return;
    const grown: Record<string, number> = {};
    setMeasured((prev) => {
      const next = { ...prev };
      for (const [key, px] of Object.entries(need)) {
        next[key] = (next[key] ?? 0) + Math.min(px, Math.floor((slack * px) / wanted));
        grown[key] = next[key];
      }
      if (fullNeed > 0) {
        next[FULL_WIDTH_COLUMN] = (next[FULL_WIDTH_COLUMN] ?? 0) + fullNeed;
        grown[FULL_WIDTH_COLUMN] = next[FULL_WIDTH_COLUMN];
      }
      return next;
    });
    // Was hier nachgewachsen ist, ist die wahre Wunschbreite dieser Spalte —
    // sonst rechnete die nächste Fensteränderung wieder mit dem Stand von
    // vorhin und nähme es ihr weg.
    setNatural((prev) => {
      const next = { ...prev };
      for (const [key, px] of Object.entries(grown)) next[key] = Math.max(next[key] ?? 0, px);
      return next;
    });
  };

  // Nach jeder Änderung an den Zeilen einmal nachsehen. Im Bild nach dem
  // Zeichnen, sonst steht dort noch die Seite davor.
  createEffect(() => {
    rows();
    if (!Object.keys(untrack(measured)).length) return;
    requestAnimationFrame(growIntoSlack);
  });

  // Ein breiteres Fenster heißt mehr Platz zu verteilen, ein schmaleres
  // weniger. Gerechnet wird mit den gemerkten Wunschbreiten, gemessen wird
  // nicht neu — die Tabelle steht dabei ja längst auf festen Breiten.
  createEffect(() => {
    let lastRoom = 0;
    const onResize = () => {
      const want = natural();
      if (!Object.keys(want).length) return;
      const room = tableRef?.parentElement?.clientWidth ?? 0;
      const next = fitColumns(want, headings());
      // Beim Aufziehen darf keine Spalte schmaler werden. Platz zu gewinnen
      // und dabei zu verlieren ist genau das, was man an einer Tabelle sieht.
      if (room >= lastRoom) {
        const now = measured();
        for (const key of Object.keys(next)) next[key] = Math.max(next[key], now[key] ?? 0);
      }
      lastRoom = room;
      setMeasured(next);
      // Ein breiteres Fenster kann auch das nachholen, was seit dem Messen
      // hereingekommen ist.
      requestAnimationFrame(growIntoSlack);
    };
    window.addEventListener('resize', onResize);
    onCleanup(() => window.removeEventListener('resize', onResize));
  });

  // Neue Daten heißen neue Breiten: verwerfen, dann legt der Browser die
  // Tabelle wieder nach Inhalt aus. Gemessen wird nicht hier, sondern im
  // Effekt darunter — ein `requestAnimationFrame` direkt nach dem Laden traf
  // manchmal einen Zeitpunkt, an dem die Zeilen noch nicht standen, und dann
  // blieb die Messung für diese Seite ganz aus.
  const remeasure = () => setMeasured({});

  // Solange Zeilen da sind, aber keine Breiten, wird gemessen. Der Effekt
  // läuft bei jeder Änderung an beidem erneut, hebt sich also selbst auf,
  // sobald es etwas zu messen gab.
  createEffect(() => {
    if (rows().length === 0 || Object.keys(measured()).length > 0) return;
    requestAnimationFrame(() => requestAnimationFrame(measureColumns));
  });

  function toggleColumn(key: string) {
    setHiddenColumns((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      try {
        localStorage.setItem(COLUMNS_STORAGE_KEY, JSON.stringify([...next]));
      } catch {
        /* private Browsing o.ä. — Auswahl bleibt für diese Sitzung gültig */
      }
      return next;
    });
    // Eine Spalte weniger heißt mehr Platz für die übrigen.
    remeasure();
  }

  // Schließt das Columns-Menü bei einem Klick außerhalb.
  createEffect(() => {
    if (!showColumnsMenu()) return;
    const handler = (e: MouseEvent) => {
      if (columnsMenuRef && !columnsMenuRef.contains(e.target as Node)) setShowColumnsMenu(false);
    };
    document.addEventListener('mousedown', handler);
    onCleanup(() => document.removeEventListener('mousedown', handler));
  });

  /** Die Gesamtzahl für die Fußzeile — eigener Aufruf, damit das Blättern
   *  nicht darauf wartet. */
  function loadTotal(query: string) {
    setTotal(null);
    fetch(`/api/logs/count${query ? `?${query}` : ''}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((b) => setTotal(b ? { total: b.total, exact: b.exact } : null))
      .catch(() => setTotal(null));
  }

  function loadPage(query: string, before: string | undefined) {
    setLoading(true);
    fetchLogsPage(query, before)
      .then((body) => {
        setRows(body.rows);
        setNextCursor(body.next_cursor);
        setLastUpdate(new Date());
        remeasure();
      })
      .catch(() => {
        setRows([]);
        setNextCursor(null);
      })
      .finally(() => setLoading(false));
  }

  // Ändert sich der Filter, springt die Ansicht zurück auf Seite 1 und baut
  // die SSE-Verbindung mit dem neuen Query-String neu auf — `EventSource`
  // kann ihre URL nachträglich nicht ändern.
  createEffect(() => {
    const q = props.query;
    setSuspended(false);
    setExpandedId(null);
    setBeforeStack([undefined]);
    loadTotal(q);
    loadPage(q, undefined);

    const es = new EventSource(`/api/stream${q ? `?${q}` : ''}`);
    es.addEventListener('log', (e) => {
      // Neue Zeilen laufen nur oben ein, solange man die neueste Seite
      // ansieht — sonst würden sie in eine ältere, bewusst aufgerufene Seite
      // hineinrutschen.
      if (paused() || !atFirstPage()) return;
      const row = JSON.parse((e as MessageEvent).data) as LogEntry;
      setRows((prev) => [row, ...prev].slice(0, PAGE_SIZE));
      setLastUpdate(new Date());
    });
    // Nachtrag der Anreicherung: die Zeile ging hier raus, bevor Land, ASN
    // und rDNS feststanden. Ohne das blieben genau die Zeilen, denen man beim
    // Eintreffen zusieht, für immer ohne diese Angaben — während die
    // Datenbank sie längst hat.
    es.addEventListener('enriched', (e) => {
      const facts = JSON.parse((e as MessageEvent).data) as Enrichment;
      setRows((prev) => {
        const next = prev.map((row) => applyEnrichment(row, facts));
        // Betrifft der Nachtrag keine sichtbare Zeile, bleibt auch das Array
        // dasselbe: ein neues löst sonst bei jedem Ereignis einen Abgleich der
        // ganzen Liste aus, und die kommen im Sekundentakt.
        return next.some((row, i) => row !== prev[i]) ? next : prev;
      });
    });
    es.addEventListener('suspended', () => setSuspended(true));
    onCleanup(() => es.close());
  });

  const goNext = () => {
    const cursor = nextCursor();
    if (!cursor) return;
    setExpandedId(null);
    setBeforeStack((prev) => [...prev, cursor]);
    loadPage(props.query, cursor);
  };

  const goPrev = () => {
    const stack = beforeStack();
    if (stack.length <= 1) return;
    const next = stack.slice(0, -1);
    setExpandedId(null);
    setBeforeStack(next);
    loadPage(props.query, next[next.length - 1]);
  };

  /** Lädt die aktuell sichtbare Seite neu, ohne den Cursor-Stack zu ändern. */
  const refreshPage = () => {
    const stack = beforeStack();
    loadPage(props.query, stack[stack.length - 1]);
    loadTotal(props.query);
  };

  const exportHref = () => `/api/export${props.query ? `?${props.query}` : ''}`;

  const start = () => (rows().length === 0 ? 0 : (pageNumber() - 1) * PAGE_SIZE + 1);
  const end = () => (pageNumber() - 1) * PAGE_SIZE + rows().length;

  const isLive = () => !paused() && atFirstPage();

  return (
    <div class="flex flex-col h-full bg-white dark:bg-gray-950 text-gray-700 dark:text-gray-200">
      {/* Werkzeugleiste */}
      <div class="flex items-center justify-between px-3 py-1.5 border-b border-gray-200/50 dark:border-gray-800/50">
        <div class="flex items-center gap-3">
          <button
            onClick={() => setPaused((v) => !v)}
            class={`flex items-center gap-1.5 text-[11px] transition-colors ${
              isLive() ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-800 dark:text-amber-400'
            }`}
          >
            <span class={`w-1.5 h-1.5 rounded-full ${isLive() ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            {paused() ? 'Resume' : isLive() ? 'Live' : 'Paused'}
          </button>
          <Show when={lastUpdate()}>
            <span class="text-[10px] text-gray-600 dark:text-gray-400">Updated {lastUpdate()!.toLocaleTimeString('en-GB')}</span>
          </Show>
        </div>
        <div class="flex items-center gap-3">
          <div class="relative inline-flex items-center" ref={columnsMenuRef}>
            <button
              onClick={() => setShowColumnsMenu((v) => !v)}
              class={`text-[11px] transition-colors ${
                hiddenColumns().size > 0
                  ? 'text-amber-800 dark:text-amber-400'
                  : 'text-gray-400 hover:text-gray-700 dark:hover:text-gray-200'
              }`}
            >
              Columns
              {hiddenColumns().size > 0
                ? ` (${TOGGLEABLE_COLUMNS.length - hiddenColumns().size}/${TOGGLEABLE_COLUMNS.length})`
                : ''}
            </button>
            <Show when={showColumnsMenu()}>
              <div class="absolute right-0 top-full mt-1 w-40 bg-white dark:bg-gray-950 border border-gray-200 dark:border-gray-700 rounded shadow-lg z-20 py-1">
                <For each={TOGGLEABLE_COLUMNS}>
                  {(col) => (
                    <label class="flex items-center gap-2 px-3 py-1.5 text-xs text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={showCol(col.key)}
                        onChange={() => toggleColumn(col.key)}
                        class="h-3.5 w-3.5 accent-blue-600"
                      />
                      {col.label}
                    </label>
                  )}
                </For>
                <div class="border-t border-gray-200 dark:border-gray-700 mt-1 pt-1 px-3 pb-1">
                  <button
                    onClick={() => setShowColumnsMenu(false)}
                    class="w-full text-xs text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-gray-200 py-1 transition-colors"
                  >
                    Done
                  </button>
                </div>
              </div>
            </Show>
          </div>
          <button
            onClick={refreshPage}
            class="text-[11px] text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
          >
            ↻ Refresh
          </button>
          <a
            href={exportHref()}
            class="text-[11px] text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
          >
            ↓ Export CSV
          </a>
        </div>
      </div>

      <Show when={suspended()}>
        <p class="px-2 py-1.5 text-[11px] text-amber-800 dark:text-amber-400 bg-amber-500/10 border-b border-amber-500/30">
          Live-Stream pausiert: dieser Filter fragt nach Feldern (Land, Threat-Score, ASN), die erst nach der
          Anreicherung bekannt sind.
        </p>
      </Show>

      {/* Tabelle */}
      <div class="flex-1 overflow-auto">
        {/* `w-max`, nicht `w-full`: die Tabelle wird so breit, wie ihr Inhalt
            es verlangt, und der Behälter darüber scrollt seitwärts. Mit
            `w-full` staucht der Browser stattdessen alle Spalten auf die
            Fensterbreite zusammen. */}
        {/* `table-fixed`, sobald gemessen wurde: dann gelten die Breiten und
            eine längere Live-Zeile kürzt sich ein, statt die Tabelle
            umzubauen. Davor `auto`, damit überhaupt etwas zu messen ist. */}
        <table
          ref={tableRef}
          style={{ width: tableWidth(), 'min-width': tableWidth() }}
          class={`log-table text-left border-collapse ${
            Object.keys(measured()).length ? 'table-fixed' : 'w-max'
          }`}
        >
          <thead class="sticky top-0 z-10 bg-gray-100 dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
            <tr>
              <Th key="time" label="Time" />
              <Th key="type" label="Type" />
              <Th key="action" label="Action" />
              <Th key="source" label="Source" />
              <th class="px-1 py-2" data-col="direction"></th>
              <Th key="destination" label="Destination" />
              <Show when={showCol('country')}>
                <Th key="country" label="Country" center />
              </Show>
              <Show when={showCol('asn')}>
                <Th key="asn" label="ASN" />
              </Show>
              <Th key="network" label="Network" />
              <Show when={showCol('proto')}>
                <Th key="proto" label="Proto" />
              </Show>
              <Th key="service" label="Service" />
              <Show when={showCol('rule')}>
                <Th key="rule_info" label="Rule / Info" />
              </Show>
              <Show when={showCol('threat')}>
                <Th key="abuseipdb" label="AbuseIPDB" />
              </Show>
              <Show when={showCol('categories')}>
                <Th key="categories" label="Categories" />
              </Show>
            </tr>
          </thead>
          <tbody>
            <Show
              when={!loading()}
              fallback={
                <tr>
                  <td colSpan={visibleColumnCount()} class="text-center py-10 text-gray-500 text-sm">
                    Lädt…
                  </td>
                </tr>
              }
            >
              <Show
                when={rows().length > 0}
                fallback={
                  <tr>
                    <td colSpan={visibleColumnCount()} class="text-center py-10 text-gray-500 text-sm">
                      No logs match this filter. Try a wider time range or reset the filters.
                    </td>
                  </tr>
                }
              >
                <For each={rows()}>
                  {(row, i) => {
                    const expanded = () => expandedId() === row.id;
                    const tint = isHighThreat(row.threat_score);
                    return (
                      <>
                        <tr
                          onClick={() => setExpandedId((cur) => (cur === row.id ? null : row.id))}
                          class={`log-row cursor-pointer transition-colors hover:bg-gray-100 dark:hover:bg-gray-800/30 ${
                            expanded() ? '' : 'border-b border-gray-200/50 dark:border-gray-800/50'
                          } ${
                            tint
                              ? 'bg-red-100/60 dark:bg-red-950/10'
                              : i() % 2
                                ? 'bg-gray-50/70 dark:bg-white/[0.02]'
                                : ''
                          }`}
                        >
                          <td class="px-2 py-1.5" title={row.timestamp}>
                            <div class="text-[13px] font-light text-gray-500 dark:text-gray-400">
                              {formatClock(row.timestamp)}
                            </div>
                            <div class="text-[11px] font-bold text-gray-900 dark:text-white">
                              {formatDateShort(row.timestamp)}
                            </div>
                          </td>
                          <td class="px-2 py-1.5">
                            <TypePill type={row.log_type} />
                          </td>
                          <td class="px-2 py-1.5">
                            <ActionPill action={row.rule_action} dhcpEvent={row.dhcp_event} wifiEvent={row.wifi_event} />
                          </td>
                          <td class="px-2 py-1.5">
                            <AddressCell ip={row.src_ip} port={row.src_port} name={addressName(row, 'src')} />
                          </td>
                          <td
                            class={`px-1 py-1.5 text-center text-sm ${directionColorClass(row.direction)}`}
                            title={row.direction ?? undefined}
                          >
                            {directionGlyph(row.direction)}
                          </td>
                          <td class="px-2 py-1.5">
                            <AddressCell ip={row.dst_ip} port={row.dst_port} name={addressName(row, 'dst')} />
                          </td>
                          <Show when={showCol('country')}>
                            <td class="px-2 py-1.5 text-center">
                              <CountryCell code={row.geo_country} />
                            </td>
                          </Show>
                          <Show when={showCol('asn')}>
                            <td class="px-2 py-1.5">
                              <AsnCell name={row.asn_name} />
                            </td>
                          </Show>
                          {/* Beschriftet, wo der Controller einen Namen kennt.
                              Die rohen Kennungen bleiben im Tooltip — wer
                              `br15` sucht, soll es finden. */}
                          <td
                            class="px-2 py-1.5 text-[12px] text-gray-600 dark:text-gray-300"
                            title={networkPath(row.iface_in, row.iface_out)}
                          >
                            {namedNetworkPath(row.iface_in, row.iface_out)}
                          </td>
                          <Show when={showCol('proto')}>
                            <td class="px-2 py-1.5 text-[12px] uppercase text-gray-600 dark:text-gray-400">{protocolName(row.protocol) ?? '—'}</td>
                          </Show>
                          <td class="px-2 py-1.5 text-[12px] text-gray-600 dark:text-gray-400" title={serviceFor(row)}>
                            {serviceFor(row)}
                          </td>
                          <Show when={showCol('rule')}>
                            <td
                              class="px-2 py-1.5 text-[12px] text-gray-600 dark:text-gray-400"
                              title={infoTitle(row)}
                            >
                              {infoFor(row)}
                            </td>
                          </Show>
                          <Show when={showCol('threat')}>
                            <td class="px-2 py-1.5 text-[13px]">
                              <ThreatCell score={row.threat_score} />
                            </td>
                          </Show>
                          <Show when={showCol('categories')}>
                            <td class="px-2 py-1.5">
                              <CategoriesCell categories={row.threat_categories} />
                            </td>
                          </Show>
                        </tr>
                        <Show when={expanded()}>
                          <tr class="border-b border-gray-200/50 dark:border-gray-800/50">
                            <td colSpan={visibleColumnCount()} class="p-0">
                              <LogRowDetail log={row} />
                            </td>
                          </tr>
                        </Show>
                      </>
                    );
                  }}
                </For>
              </Show>
            </Show>
          </tbody>
        </table>
      </div>

      {/* Fußzeile */}
      <div class="flex items-center justify-between px-3 py-2 border-t border-gray-200 dark:border-gray-800 text-[11px] text-gray-400">
        <span>
          {rows().length === 0
            ? 'No results'
            : `${start()}–${end()} of ${
                total() ? `${total()!.exact ? '' : '~'}${total()!.total.toLocaleString('en-GB')}` : '…'
              }`}
        </span>
        <div class="flex items-center gap-1">
          <button
            disabled={atFirstPage()}
            onClick={goPrev}
            class="px-2 py-1 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 disabled:text-gray-300 dark:disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            «
          </button>
          <span class="px-2 text-gray-600 dark:text-gray-300">Page {pageNumber()}</span>
          <button
            disabled={!nextCursor()}
            onClick={goNext}
            class="px-2 py-1 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 disabled:text-gray-300 dark:disabled:text-gray-700 disabled:cursor-not-allowed"
          >
            »
          </button>
        </div>
      </div>
    </div>
  );
}
